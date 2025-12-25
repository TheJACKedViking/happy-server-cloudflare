import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import {
    SyncMetricRequestSchema,
    SyncMetricResponseSchema,
    AnalyticsUnauthorizedErrorSchema,
    AnalyticsInternalErrorSchema,
} from '@/schemas/analytics';

/**
 * Environment bindings for analytics routes
 */
interface Env {
    DB: D1Database;
    SYNC_METRICS?: AnalyticsEngineDataset;
}

/**
 * Analytics routes module
 *
 * Implements sync metrics ingestion endpoint:
 * - POST /v1/analytics/sync - Ingest sync performance metrics
 *
 * Metrics are written to Cloudflare Analytics Engine for later analysis.
 * Writes are fire-and-forget for minimal latency impact on clients.
 *
 * @see HAP-546 Analytics Engine Binding + Ingestion Endpoint
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
        'Writes are fire-and-forget - this endpoint returns immediately.',
});

/**
 * Data point structure for Analytics Engine
 *
 * Maps sync metrics to Analytics Engine data point format:
 * - blob1: type ('messages' | 'profile' | 'artifacts')
 * - blob2: mode ('full' | 'incremental' | 'cached')
 * - blob3: sessionId (optional, empty string if not provided)
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

    try {
        // Check if Analytics Engine is configured
        if (!c.env.SYNC_METRICS) {
            // Silently accept but don't store - allows graceful degradation
            console.warn('[Analytics] SYNC_METRICS binding not configured, metric dropped');
            return c.json({ success: true });
        }

        // Write data point to Analytics Engine (fire-and-forget)
        // The writeDataPoint method returns void and writes asynchronously
        c.env.SYNC_METRICS.writeDataPoint({
            blobs: [
                metric.type, // blob1: sync type
                metric.mode, // blob2: sync mode
                metric.sessionId ?? '', // blob3: session ID (empty if not provided)
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
