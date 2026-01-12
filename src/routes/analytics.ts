import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { checkRateLimit, type RateLimitConfig } from '@/lib/rate-limit';
import {
    SyncMetricRequestSchema,
    SyncMetricResponseSchema,
    AnalyticsUnauthorizedErrorSchema,
    AnalyticsInternalErrorSchema,
    AnalyticsRateLimitExceededSchema,
} from '@/schemas/analytics';

/**
 * Environment bindings for analytics routes
 */
interface Env {
    DB: D1Database;
    SYNC_METRICS?: AnalyticsEngineDataset;
    /** KV namespace for rate limiting (HAP-826) */
    RATE_LIMIT_KV?: KVNamespace;
}

/**
 * Rate limit configuration for analytics ingestion endpoints (HAP-826)
 *
 * Analytics ingestion is high-volume but low-risk, so we allow
 * a higher request rate than auth endpoints.
 * 100 requests per minute per user should accommodate even heavy sync activity.
 */
export const ANALYTICS_RATE_LIMIT: RateLimitConfig = {
    maxRequests: 100,
    windowMs: 60_000, // 1 minute
    expirationTtl: 120, // 2 minutes (covers window + cleanup margin)
};

/**
 * Analytics routes module
 *
 * Implements sync metrics ingestion endpoint:
 * - POST /v1/analytics/sync - Ingest sync performance metrics
 *
 * Metrics are written to Cloudflare Analytics Engine for later analysis.
 * Writes are fire-and-forget for minimal latency impact on clients.
 *
 * Rate limiting (HAP-826):
 * - 100 requests per minute per user ID
 * - Returns 429 with Retry-After header when exceeded
 * - Uses KV-backed rate limiting when available, memory fallback otherwise
 *
 * @see HAP-546 Analytics Engine Binding + Ingestion Endpoint
 * @see HAP-826 Add rate limiting to analytics ingestion endpoints
 */
const analyticsRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all analytics routes
analyticsRoutes.use('/v1/analytics/*', authMiddleware());

// ============================================================================
// POST /v1/analytics/sync - Ingest Sync Metrics
// ============================================================================

const ingestSyncMetricRoute = createRoute({
    method: 'post',
    path: '/v1/analytics/sync',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: SyncMetricRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: SyncMetricResponseSchema,
                },
            },
            description: 'Metric successfully ingested',
        },
        401: {
            content: {
                'application/json': {
                    schema: AnalyticsUnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        429: {
            content: {
                'application/json': {
                    schema: AnalyticsRateLimitExceededSchema,
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
            description: 'Too Many Requests - rate limit exceeded (100 per minute)',
        },
        500: {
            content: {
                'application/json': {
                    schema: AnalyticsInternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Analytics'],
    summary: 'Ingest sync metrics',
    description:
        'Ingest sync performance metrics from the client. ' +
        'Metrics are stored in Cloudflare Analytics Engine for later analysis. ' +
        'Writes are fire-and-forget - this endpoint returns immediately. ' +
        'Rate limited to 100 requests per minute per user.',
});

/**
 * Data point structure for Analytics Engine
 *
 * Maps sync metrics to Analytics Engine data point format:
 * - blob1: type ('messages' | 'profile' | 'artifacts')
 * - blob2: mode ('full' | 'incremental' | 'cached')
 * - blob3: sessionId (optional, empty string if not provided)
 * - blob4: cacheStatus ('hit' | 'miss' | '') - HAP-808: explicit cache hit/miss tracking
 * - double1: bytesReceived
 * - double2: itemsReceived
 * - double3: itemsSkipped
 * - double4: durationMs
 * - index1: accountId (for per-user sampling/grouping)
 */

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
analyticsRoutes.openapi(ingestSyncMetricRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get(
        'userId'
    );
    const metric = c.req.valid('json');

    // Check rate limit (HAP-826)
    const rateLimitResult = await checkRateLimit(
        c.env.RATE_LIMIT_KV,
        'analytics-sync',
        userId,
        ANALYTICS_RATE_LIMIT
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
        if (!c.env.SYNC_METRICS) {
            // Accept request but indicate metrics were not ingested
            // Returns 200 to avoid breaking clients, but surfaces the drop
            console.warn('[Analytics] SYNC_METRICS binding not configured, metric dropped');
            return c.json(
                {
                    success: true,
                    ingested: false,
                    warning: 'Analytics Engine binding not configured',
                },
                200,
                { 'X-Ingested': 'false' }
            );
        }

        // Write data point to Analytics Engine (fire-and-forget)
        // The writeDataPoint method returns void and writes asynchronously
        c.env.SYNC_METRICS.writeDataPoint({
            blobs: [
                metric.type, // blob1: sync type
                metric.mode, // blob2: sync mode
                metric.sessionId ?? '', // blob3: session ID (empty if not provided)
                metric.cacheStatus ?? '', // blob4: cache status (HAP-808)
            ],
            doubles: [
                metric.bytesReceived, // double1: bytes received
                metric.itemsReceived, // double2: items received
                metric.itemsSkipped, // double3: items skipped
                metric.durationMs, // double4: duration in ms
            ],
            indexes: [
                userId, // index1: account ID for per-user sampling
            ],
        });

        return c.json({ success: true });
    } catch (error) {
        console.error('[Analytics] Failed to ingest sync metric:', error);
        return c.json({ error: 'Failed to ingest metric' }, 500);
    }
});

export default analyticsRoutes;
