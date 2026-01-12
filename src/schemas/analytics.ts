import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for analytics ingestion endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for sync metrics ingestion:
 * - POST /v1/analytics/sync - Ingest sync performance metrics
 *
 * The metrics format matches what happy-app sends after each sync operation.
 * Data is stored in Cloudflare Analytics Engine for later querying.
 *
 * @see HAP-546 Analytics Engine Binding + Ingestion Endpoint
 * @see HAP-497 Client-side sync metrics logging
 * @see HAP-826 Add rate limiting to analytics ingestion endpoints
 */

// ============================================================================
// Sync Metric Types
// ============================================================================

/**
 * Schema for sync type enum
 * Defines the types of data being synced
 */
const SyncTypeSchema = z
    .enum(['messages', 'profile', 'artifacts'])
    .openapi({
        description: 'Type of data being synced',
        example: 'messages',
    });

/**
 * Schema for sync mode enum
 * Defines how the sync was performed
 */
const SyncModeSchema = z
    .enum(['full', 'incremental', 'cached'])
    .openapi({
        description: 'Mode of sync operation',
        example: 'incremental',
    });

// ============================================================================
// POST /v1/analytics/sync - Sync Metrics Ingestion
// ============================================================================

/**
 * Schema for cache status enum (HAP-808)
 * Defines whether the sync operation resulted in a cache hit or miss
 */
const CacheStatusSchema = z
    .enum(['hit', 'miss'])
    .openapi({
        description: 'Cache status for the sync operation (HAP-808)',
        example: 'hit',
    });

/**
 * Schema for sync metrics request body
 *
 * Matches the SyncMetrics type from happy-app's sync logging.
 * All numeric fields are required to ensure complete data points.
 */
export const SyncMetricRequestSchema = z
    .object({
        type: SyncTypeSchema,
        mode: SyncModeSchema,
        sessionId: z.string().nullish().openapi({
            description: 'Optional session ID for session-specific syncs',
            example: 'cmed556s4002bvb2020igg8jf',
        }),
        /**
         * HAP-808: Explicit cache status for accurate cache hit rate tracking.
         * - 'hit': Data was served from cache (e.g., HTTP 304, local cache)
         * - 'miss': Data was fetched from server
         * Optional for backward compatibility with older clients.
         */
        cacheStatus: CacheStatusSchema.nullish().openapi({
            description: 'Cache status: hit (served from cache) or miss (fetched from server)',
            example: 'hit',
        }),
        bytesReceived: z.number().int().min(0).openapi({
            description: 'Number of bytes received during sync',
            example: 15360,
        }),
        itemsReceived: z.number().int().min(0).openapi({
            description: 'Number of items received during sync',
            example: 42,
        }),
        itemsSkipped: z.number().int().min(0).openapi({
            description: 'Number of items skipped (already cached)',
            example: 5,
        }),
        durationMs: z.number().int().min(0).openapi({
            description: 'Duration of sync operation in milliseconds',
            example: 1250,
        }),
    })
    .openapi('SyncMetricRequest');

/**
 * Schema for sync metrics success response
 *
 * HAP-827: Added `ingested` field to indicate whether metrics were actually
 * written to Analytics Engine. When the binding is not configured, the server
 * returns success (to avoid breaking clients) but sets `ingested: false`.
 */
export const SyncMetricResponseSchema = z
    .object({
        success: z.boolean().openapi({
            description: 'Whether the request was processed successfully',
            example: true,
        }),
        ingested: z.boolean().optional().openapi({
            description:
                'Whether the metric was actually written to Analytics Engine. ' +
                'False when the binding is not configured. Omitted for backward compatibility when true.',
            example: true,
        }),
        warning: z.string().optional().openapi({
            description:
                'Warning message when metrics could not be ingested. ' +
                'Present when ingested=false to explain why.',
            example: 'Analytics Engine binding not configured',
        }),
    })
    .openapi('SyncMetricResponse');

// ============================================================================
// Error Responses
// ============================================================================

/**
 * Schema for 401 Unauthorized error
 */
export const AnalyticsUnauthorizedErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Unauthorized',
        }),
    })
    .openapi('AnalyticsUnauthorizedError');

/**
 * Schema for 500 Internal Server Error
 */
export const AnalyticsInternalErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Failed to ingest metric',
        }),
    })
    .openapi('AnalyticsInternalError');


/**
 * Schema for 429 Rate Limit Exceeded error (HAP-826)
 */
export const AnalyticsRateLimitExceededSchema = z
    .object({
        error: z.literal('Rate limit exceeded').openapi({
            description: 'Error message',
        }),
        retryAfter: z.number().openapi({
            description: 'Seconds until rate limit resets',
            example: 45,
        }),
    })
    .openapi('AnalyticsRateLimitExceeded');

// ============================================================================
// Type Exports
// ============================================================================

// Types inferred from schemas were previously exported, but they are currently unused and were removed to reduce API surface.
