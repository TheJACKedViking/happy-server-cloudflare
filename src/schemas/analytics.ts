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
 */
export const SyncMetricResponseSchema = z
    .object({
        success: z.boolean().openapi({
            description: 'Whether the metric was successfully ingested',
            example: true,
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

// ============================================================================
// Type Exports
// ============================================================================

export type SyncMetricRequest = z.infer<typeof SyncMetricRequestSchema>;
export type SyncMetricResponse = z.infer<typeof SyncMetricResponseSchema>;
