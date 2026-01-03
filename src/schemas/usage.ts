import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for usage reporting endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for usage query routes:
 * - POST /v1/usage/query - Query aggregated usage data
 *
 * The usage data structure matches the format expected by happy-app's apiUsage.ts client.
 */

// ============================================================================
// Common Schemas
// ============================================================================

/**
 * Schema for groupBy aggregation period
 * @internal Used for composing request/response schemas
 */
const GroupBySchema = z
    .enum(['hour', 'day'])
    .openapi('GroupBy');

/**
 * Schema for a single usage data point
 *
 * Represents aggregated usage for a time period (hour or day).
 * All numeric values are already summed across all reports in that period.
 * @internal Used for composing response schemas
 */
const UsageDataPointSchema = z
    .object({
        timestamp: z.number().int().openapi({
            description: 'Unix timestamp (seconds) for the start of this aggregation period',
            example: 1705010400,
        }),
        tokens: z.record(z.string(), z.number()).openapi({
            description: 'Token counts by type (input, output, cache_creation, cache_read)',
            example: { input: 15000, output: 3000, cache_creation: 500, cache_read: 12000 },
        }),
        cost: z.record(z.string(), z.number()).openapi({
            description: 'Cost breakdown by type in USD',
            example: { input: 0.015, output: 0.045, cache_creation: 0.001, cache_read: 0.003 },
        }),
        reportCount: z.number().int().openapi({
            description: 'Number of usage reports aggregated in this period',
            example: 42,
        }),
    })
    .openapi('UsageDataPoint');

// ============================================================================
// POST /v1/usage/query - Query Usage Data
// ============================================================================

/**
 * Schema for usage query request body
 */
export const UsageQueryRequestSchema = z
    .object({
        sessionId: z.string().nullish().openapi({
            description: 'Optional session ID to filter usage for a specific session',
            example: 'cmed556s4002bvb2020igg8jf',
        }),
        startTime: z.number().int().positive().nullish().openapi({
            description: 'Optional start time filter as Unix timestamp (seconds)',
            example: 1704931200,
        }),
        endTime: z.number().int().positive().nullish().openapi({
            description: 'Optional end time filter as Unix timestamp (seconds)',
            example: 1705017600,
        }),
        groupBy: GroupBySchema.nullish().openapi({
            description: 'Aggregation period - hour or day (defaults to day)',
            example: 'day',
        }),
    })
    .openapi('UsageQueryRequest');

/**
 * Schema for usage query response
 *
 * Returns an array of usage data points sorted by timestamp (ascending).
 * The groupBy and totalReports fields provide context for the aggregation.
 */
export const UsageQueryResponseSchema = z
    .object({
        usage: z.array(UsageDataPointSchema).openapi({
            description: 'Array of aggregated usage data points sorted by timestamp',
        }),
        groupBy: GroupBySchema.openapi({
            description: 'The aggregation period used for this response',
            example: 'day',
        }),
        totalReports: z.number().int().openapi({
            description: 'Total number of usage reports included in the response',
            example: 156,
        }),
    })
    .openapi('UsageQueryResponse');

// ============================================================================
// Error Responses
// ============================================================================

/**
 * Schema for 401 Unauthorized error
 */
export const UnauthorizedErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Unauthorized',
        }),
    })
    .openapi('UsageUnauthorizedError');

/**
 * Schema for 404 Not Found error (session not found/not owned)
 */
export const NotFoundErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Session not found',
        }),
    })
    .openapi('UsageNotFoundError');

/**
 * Schema for 500 Internal Server Error
 */
export const InternalErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Failed to query usage reports',
        }),
    })
    .openapi('UsageInternalError');

// ============================================================================
// GET /v1/usage/limits - Get Plan Limits
// ============================================================================

/**
 * Schema for a single usage limit entry
 * Mirrors the UsageLimitSchema from @happy/protocol for OpenAPI documentation
 */
const UsageLimitItemSchema = z
    .object({
        id: z.string().min(1).openapi({
            description: 'Unique identifier for this limit type',
            example: 'opus_tokens',
        }),
        label: z.string().min(1).openapi({
            description: 'Human-readable label for display',
            example: 'Opus Tokens',
        }),
        percentageUsed: z.number().min(0).max(100).openapi({
            description: 'Percentage of limit used (0-100)',
            example: 75.5,
        }),
        resetsAt: z.number().nullable().openapi({
            description: 'Unix timestamp (ms) when this limit resets, null if no reset',
            example: 1735689600000,
        }),
        resetDisplayType: z.enum(['countdown', 'datetime']).openapi({
            description: 'How to display the reset time in UI',
            example: 'countdown',
        }),
        description: z.string().optional().openapi({
            description: 'Optional description for additional context',
            example: 'Monthly Opus token limit',
        }),
    })
    .openapi('UsageLimitItem');

/**
 * Schema for GET /v1/usage/limits response
 * Matches the PlanLimitsResponseSchema from @happy/protocol
 */
export const GetUsageLimitsResponseSchema = z
    .object({
        sessionLimit: UsageLimitItemSchema.optional().openapi({
            description: 'Session limit if applicable (e.g., concurrent session count)',
        }),
        weeklyLimits: z.array(UsageLimitItemSchema).openapi({
            description: 'Weekly/rolling limits (tokens, requests, etc.)',
        }),
        lastUpdatedAt: z.number().openapi({
            description: 'Unix timestamp (ms) when limits were last fetched/updated',
            example: 1735689600000,
        }),
        limitsAvailable: z.boolean().openapi({
            description: 'Whether limit information is available from the provider',
            example: true,
        }),
        provider: z.string().optional().openapi({
            description: 'Optional provider identifier (e.g., "anthropic", "openai")',
            example: 'anthropic',
        }),
    })
    .openapi('GetUsageLimitsResponse');
