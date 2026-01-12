import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for client-side metrics ingestion (HAP-577)
 *
 * These schemas define the request/response contracts for client metrics:
 * - POST /v1/analytics/client - Ingest client-side metrics (validation failures, etc.)
 *
 * Data is stored in Cloudflare Analytics Engine for dashboard visualization.
 * Metrics are batched client-side and sent periodically for efficiency.
 *
 * @see HAP-577 Add validation failure metrics for message schema parsing
 * @see HAP-826 Add rate limiting to analytics ingestion endpoints
 */

// ============================================================================
// Validation Metrics Types
// ============================================================================

/**
 * Schema for unknown type breakdown entry
 * Tracks which specific unknown types were encountered
 */
const UnknownTypeBreakdownSchema = z
    .object({
        typeName: z.string().openapi({
            description: 'The unknown type name encountered',
            example: 'thinking',
        }),
        count: z.number().int().min(0).openapi({
            description: 'Number of times this type was encountered',
            example: 5,
        }),
    })
    .openapi('UnknownTypeBreakdown');

/**
 * Schema for validation metrics request body
 *
 * Contains aggregated validation failure statistics from the client.
 * Stats are batched and sent periodically (not per-failure) for efficiency.
 */
export const ValidationMetricsRequestSchema = z
    .object({
        schemaFailures: z.number().int().min(0).openapi({
            description: 'Count of messages that failed initial Zod schema validation',
            example: 2,
        }),
        unknownTypes: z.number().int().min(0).openapi({
            description: 'Count of messages with unknown output data types',
            example: 5,
        }),
        strictValidationFailures: z.number().int().min(0).openapi({
            description: 'Count of messages that passed loose but failed strict validation',
            example: 0,
        }),
        unknownTypeBreakdown: z.array(UnknownTypeBreakdownSchema).openapi({
            description: 'Breakdown of unknown type names and their counts',
            example: [{ typeName: 'thinking', count: 3 }, { typeName: 'status', count: 2 }],
        }),
        sessionDurationMs: z.number().int().min(0).openapi({
            description: 'App session duration at time of report (milliseconds)',
            example: 300000,
        }),
        firstFailureAt: z.number().int().nullish().openapi({
            description: 'Timestamp of first validation failure in session (epoch ms)',
            example: 1703606400000,
        }),
        lastFailureAt: z.number().int().nullish().openapi({
            description: 'Timestamp of most recent validation failure (epoch ms)',
            example: 1703607500000,
        }),
    })
    .openapi('ValidationMetricsRequest');

/**
 * Schema for client metrics success response
 *
 * HAP-827: Added `ingested` field to indicate whether metrics were actually
 * written to Analytics Engine. When the binding is not configured, the server
 * returns success (to avoid breaking clients) but sets `ingested: false`.
 */
export const ClientMetricsResponseSchema = z
    .object({
        success: z.boolean().openapi({
            description: 'Whether the request was processed successfully',
            example: true,
        }),
        dataPointsWritten: z.number().int().min(0).openapi({
            description: 'Number of data points written to Analytics Engine',
            example: 4,
        }),
        ingested: z.boolean().optional().openapi({
            description:
                'Whether the metrics were actually written to Analytics Engine. ' +
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
    .openapi('ClientMetricsResponse');

// ============================================================================
// Error Responses
// ============================================================================

/**
 * Schema for 401 Unauthorized error
 */
export const ClientMetricsUnauthorizedErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Unauthorized',
        }),
    })
    .openapi('ClientMetricsUnauthorizedError');

/**
 * Schema for 500 Internal Server Error
 */
export const ClientMetricsInternalErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Failed to ingest metrics',
        }),
    })
    .openapi('ClientMetricsInternalError');

/**
 * Schema for 429 Rate Limit Exceeded error (HAP-826)
 */
export const ClientMetricsRateLimitExceededSchema = z
    .object({
        error: z.literal('Rate limit exceeded').openapi({
            description: 'Error message',
        }),
        retryAfter: z.number().openapi({
            description: 'Seconds until rate limit resets',
            example: 45,
        }),
    })
    .openapi('ClientMetricsRateLimitExceeded');

// ============================================================================
// Restore Metrics Types (HAP-688)
// ============================================================================

/**
 * Schema for session restore metrics request body
 *
 * Tracks restore operations to understand timeout patterns and success rates.
 * Helps answer: "What is the actual success rate of restores that timeout?"
 */
export const RestoreMetricsRequestSchema = z
    .object({
        sessionId: z.string().openapi({
            description: 'The session ID being restored',
            example: 'sess_abc123',
        }),
        machineId: z.string().openapi({
            description: 'The machine ID where the session is restored',
            example: 'mach_xyz789',
        }),
        success: z.boolean().openapi({
            description: 'Whether the restore was successful',
            example: true,
        }),
        timedOut: z.boolean().openapi({
            description: 'Whether the operation timed out (may have succeeded despite timeout)',
            example: false,
        }),
        durationMs: z.number().int().min(0).openapi({
            description: 'Duration of the restore operation in milliseconds',
            example: 45000,
        }),
        newSessionId: z.string().nullish().openapi({
            description: 'The new session ID if successful',
            example: 'sess_def456',
        }),
    })
    .openapi('RestoreMetricsRequest');

// ============================================================================
// Type Exports
// ============================================================================

// Types inferred from schemas were previously exported, but they are currently unused and were removed to reduce API surface.
