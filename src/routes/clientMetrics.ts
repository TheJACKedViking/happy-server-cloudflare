import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { checkRateLimit, type RateLimitConfig } from '@/lib/rate-limit';
import {
    ValidationMetricsRequestSchema,
    RestoreMetricsRequestSchema,
    ClientMetricsResponseSchema,
    ClientMetricsUnauthorizedErrorSchema,
    ClientMetricsInternalErrorSchema,
    ClientMetricsRateLimitExceededSchema,
} from '@/schemas/clientMetrics';

/**
 * Environment bindings for client metrics routes
 */
interface Env {
    DB: D1Database;
    CLIENT_METRICS?: AnalyticsEngineDataset;
    /** KV namespace for rate limiting (HAP-826) */
    RATE_LIMIT_KV?: KVNamespace;
}

/**
 * Rate limit configuration for client metrics endpoints (HAP-826)
 *
 * Client metrics are batched and sent periodically, so we use
 * a moderate rate limit. 50 requests per minute per user is sufficient.
 */
export const CLIENT_METRICS_RATE_LIMIT: RateLimitConfig = {
    maxRequests: 50,
    windowMs: 60_000, // 1 minute
    expirationTtl: 120, // 2 minutes (covers window + cleanup margin)
};

/**
 * Client metrics routes module (HAP-577)
 *
 * Implements client-side metrics ingestion endpoint:
 * - POST /v1/analytics/client/validation - Ingest validation failure metrics
 *
 * Metrics are written to Cloudflare Analytics Engine for dashboard visualization.
 * Writes are fire-and-forget for minimal latency impact on clients.
 *
 * Analytics Engine Schema for validation metrics:
 * - blob1: metric category = 'validation'
 * - blob2: failure type = 'schema' | 'unknown' | 'strict' | 'summary'
 * - blob3: context (unknown type name for 'unknown', '_total' for aggregates)
 * - double1: count
 * - double2: session duration in ms
 * - index1: account ID (for per-user grouping)
 *
 * Rate limiting (HAP-826):
 * - 50 requests per minute per user ID
 * - Returns 429 with Retry-After header when exceeded
 * - Uses KV-backed rate limiting when available, memory fallback otherwise
 *
 * @see HAP-577 Add validation failure metrics for message schema parsing
 * @see HAP-826 Add rate limiting to analytics ingestion endpoints
 */
const clientMetricsRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all client metrics routes
clientMetricsRoutes.use('/v1/analytics/client/*', authMiddleware());

// ============================================================================
// POST /v1/analytics/client/validation - Ingest Validation Metrics
// ============================================================================

const ingestValidationMetricsRoute = createRoute({
    method: 'post',
    path: '/v1/analytics/client/validation',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: ValidationMetricsRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ClientMetricsResponseSchema,
                },
            },
            description: 'Metrics successfully ingested',
        },
        401: {
            content: {
                'application/json': {
                    schema: ClientMetricsUnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        429: {
            content: {
                'application/json': {
                    schema: ClientMetricsRateLimitExceededSchema,
                },
            },
            headers: {
                'Retry-After': {
                    schema: { type: 'string' },
                    description: 'Seconds until the rate limit resets',
                },
                'X-RateLimit-Limit': {
                    schema: { type: 'string' },
                    description: 'Maximum requests per window',
                },
                'X-RateLimit-Remaining': {
                    schema: { type: 'string' },
                    description: 'Remaining requests in current window',
                },
            },
            description: 'Too Many Requests - rate limit exceeded (50 per minute)',
        },
        500: {
            content: {
                'application/json': {
                    schema: ClientMetricsInternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Analytics', 'Client Metrics'],
    summary: 'Ingest validation metrics',
    description:
        'Ingest batched validation failure metrics from the client. ' +
        'Metrics include schema failures, unknown types, and strict validation failures. ' +
        'Data is stored in Cloudflare Analytics Engine for dashboard visualization.',
});

/**
 * POST /v1/analytics/client/validation handler
 *
 * Writes multiple data points to Analytics Engine:
 * 1. Summary data point with total counts
 * 2. Individual data points for each unknown type (for breakdown analysis)
 */
// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
clientMetricsRoutes.openapi(ingestValidationMetricsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get(
        'userId'
    );
    const metrics = c.req.valid('json');
    // Check rate limit (HAP-826)
    const rateLimitResult = await checkRateLimit(
        c.env.RATE_LIMIT_KV,
        'client-metrics-validation',
        userId,
        CLIENT_METRICS_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
        return c.json(
            {
                error: 'Rate limit exceeded' as const,
                retryAfter: rateLimitResult.retryAfter,
            },
            429,
            {
                'Retry-After': String(rateLimitResult.retryAfter),
                'X-RateLimit-Limit': String(rateLimitResult.limit),
                'X-RateLimit-Remaining': '0',
            }
        );
    }

    try {
        // Check if Analytics Engine is configured (HAP-827)
        if (!c.env.CLIENT_METRICS) {
            // Accept request but indicate metrics were not ingested
            // Returns 200 to avoid breaking clients, but surfaces the drop
            console.warn('[ClientMetrics] CLIENT_METRICS binding not configured, metrics dropped');
            return c.json(
                {
                    success: true,
                    dataPointsWritten: 0,
                    ingested: false,
                    warning: 'Analytics Engine binding not configured',
                },
                200,
                { 'X-Ingested': 'false' }
            );
        }

        let dataPointsWritten = 0;

        // Write summary data point with aggregate counts
        c.env.CLIENT_METRICS.writeDataPoint({
            blobs: [
                'validation',           // blob1: metric category
                'summary',              // blob2: this is a summary record
                '_total',               // blob3: aggregate marker
            ],
            doubles: [
                metrics.schemaFailures + metrics.unknownTypes + metrics.strictValidationFailures, // double1: total failures
                metrics.sessionDurationMs, // double2: session duration
                metrics.schemaFailures,    // double3: schema failures
                metrics.strictValidationFailures, // double4: strict failures
            ],
            indexes: [
                userId, // index1: account ID for per-user grouping
            ],
        });
        dataPointsWritten++;

        // Write individual data points for each failure type (if non-zero)
        if (metrics.schemaFailures > 0) {
            c.env.CLIENT_METRICS.writeDataPoint({
                blobs: ['validation', 'schema', '_count'],
                doubles: [metrics.schemaFailures, metrics.sessionDurationMs, 0, 0],
                indexes: [userId],
            });
            dataPointsWritten++;
        }

        if (metrics.strictValidationFailures > 0) {
            c.env.CLIENT_METRICS.writeDataPoint({
                blobs: ['validation', 'strict', '_count'],
                doubles: [metrics.strictValidationFailures, metrics.sessionDurationMs, 0, 0],
                indexes: [userId],
            });
            dataPointsWritten++;
        }

        // Write individual data points for each unknown type (for breakdown)
        for (const entry of metrics.unknownTypeBreakdown) {
            c.env.CLIENT_METRICS.writeDataPoint({
                blobs: [
                    'validation',       // blob1: metric category
                    'unknown',          // blob2: failure type
                    entry.typeName,     // blob3: the specific unknown type name
                ],
                doubles: [
                    entry.count,                // double1: count for this type
                    metrics.sessionDurationMs,  // double2: session duration
                    0,                          // double3: reserved
                    0,                          // double4: reserved
                ],
                indexes: [
                    userId, // index1: account ID
                ],
            });
            dataPointsWritten++;
        }

        return c.json({ success: true, dataPointsWritten });
    } catch (error) {
        console.error('[ClientMetrics] Failed to ingest validation metrics:', error);
        return c.json({ error: 'Failed to ingest metrics' }, 500);
    }
});

// ============================================================================
// POST /v1/analytics/client/restore - Ingest Restore Metrics (HAP-688)
// ============================================================================

const ingestRestoreMetricsRoute = createRoute({
    method: 'post',
    path: '/v1/analytics/client/restore',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: RestoreMetricsRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ClientMetricsResponseSchema,
                },
            },
            description: 'Metrics successfully ingested',
        },
        401: {
            content: {
                'application/json': {
                    schema: ClientMetricsUnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        429: {
            content: {
                'application/json': {
                    schema: ClientMetricsRateLimitExceededSchema,
                },
            },
            headers: {
                'Retry-After': {
                    schema: { type: 'string' },
                    description: 'Seconds until the rate limit resets',
                },
                'X-RateLimit-Limit': {
                    schema: { type: 'string' },
                    description: 'Maximum requests per window',
                },
                'X-RateLimit-Remaining': {
                    schema: { type: 'string' },
                    description: 'Remaining requests in current window',
                },
            },
            description: 'Too Many Requests - rate limit exceeded (50 per minute)',
        },
        500: {
            content: {
                'application/json': {
                    schema: ClientMetricsInternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Analytics', 'Client Metrics'],
    summary: 'Ingest session restore metrics',
    description:
        'Ingest session restore metrics from the client. ' +
        'Tracks restore operations including success, timeout, and duration. ' +
        'Helps understand timeout patterns and actual success rates (HAP-659 follow-up).',
});

/**
 * POST /v1/analytics/client/restore handler (HAP-688)
 *
 * Writes restore metrics to Analytics Engine:
 * - blob1: metric category = 'restore'
 * - blob2: outcome = 'success' | 'failure' | 'timeout'
 * - blob3: session ID (truncated for privacy)
 * - double1: duration in ms
 * - double2: 1 if timed out, 0 otherwise
 * - index1: account ID (for per-user grouping)
 */
// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
clientMetricsRoutes.openapi(ingestRestoreMetricsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get(
        'userId'
    );
    const metrics = c.req.valid('json');
    // Check rate limit (HAP-826)
    const rateLimitResult = await checkRateLimit(
        c.env.RATE_LIMIT_KV,
        'client-metrics-restore',
        userId,
        CLIENT_METRICS_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
        return c.json(
            {
                error: 'Rate limit exceeded' as const,
                retryAfter: rateLimitResult.retryAfter,
            },
            429,
            {
                'Retry-After': String(rateLimitResult.retryAfter),
                'X-RateLimit-Limit': String(rateLimitResult.limit),
                'X-RateLimit-Remaining': '0',
            }
        );
    }

    try {
        // Check if Analytics Engine is configured (HAP-827)
        if (!c.env.CLIENT_METRICS) {
            // Accept request but indicate metrics were not ingested
            // Returns 200 to avoid breaking clients, but surfaces the drop
            console.warn('[ClientMetrics] CLIENT_METRICS binding not configured, restore metrics dropped');
            return c.json(
                {
                    success: true,
                    dataPointsWritten: 0,
                    ingested: false,
                    warning: 'Analytics Engine binding not configured',
                },
                200,
                { 'X-Ingested': 'false' }
            );
        }

        // Determine outcome category for analysis
        let outcome: string;
        if (metrics.success) {
            outcome = 'success';
        } else if (metrics.timedOut) {
            outcome = 'timeout';
        } else {
            outcome = 'failure';
        }

        // Write single data point for this restore operation
        c.env.CLIENT_METRICS.writeDataPoint({
            blobs: [
                'restore',                              // blob1: metric category
                outcome,                                // blob2: outcome type
                metrics.sessionId.slice(0, 8),          // blob3: truncated session ID (privacy)
            ],
            doubles: [
                metrics.durationMs,                     // double1: operation duration
                metrics.timedOut ? 1 : 0,               // double2: timeout flag
                metrics.success ? 1 : 0,                // double3: success flag
                0,                                      // double4: reserved
            ],
            indexes: [
                userId,                                 // index1: account ID for per-user grouping
            ],
        });

        return c.json({ success: true, dataPointsWritten: 1 });
    } catch (error) {
        console.error('[ClientMetrics] Failed to ingest restore metrics:', error);
        return c.json({ error: 'Failed to ingest metrics' }, 500);
    }
});

export default clientMetricsRoutes;
