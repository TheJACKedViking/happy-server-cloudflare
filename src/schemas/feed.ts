import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for activity feed endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for feed routes:
 * - GET /v1/feed - Get user activity feed with cursor-based pagination
 */

// ============================================================================
// Common Schemas
// ============================================================================

/**
 * Schema for feed item body content
 * The body is a JSON object that can contain various activity types
 * @internal Used for composing response schemas
 */
const FeedBodySchema = z
    .object({
        type: z.string().openapi({
            description: 'Type of feed activity',
            example: 'session-created',
        }),
    })
    .passthrough()
    .openapi('FeedBody');

/**
 * Schema for a single feed item
 * @internal Used for composing response schemas
 */
const FeedItemSchema = z
    .object({
        id: z.string().openapi({
            description: 'Unique feed item identifier',
            example: 'feed_abc123',
        }),
        body: FeedBodySchema.openapi({
            description: 'Feed item content (activity data)',
        }),
        repeatKey: z.string().nullable().openapi({
            description: 'Key for deduplication of repeated events',
            example: 'session_created_xyz789',
        }),
        cursor: z.string().openapi({
            description: 'Cursor for pagination (use with before/after)',
            example: 'cursor_42',
        }),
        createdAt: z.number().int().openapi({
            description: 'Item creation timestamp (Unix milliseconds)',
            example: 1705010400000,
        }),
    })
    .openapi('FeedItem');

// ============================================================================
// GET /v1/feed - Get Activity Feed
// ============================================================================

/**
 * Schema for feed query parameters
 */
export const FeedQuerySchema = z.object({
    before: z.string().optional().openapi({
        param: {
            name: 'before',
            in: 'query',
        },
        description: 'Cursor to get items before (older items)',
        example: 'cursor_42',
    }),
    after: z.string().optional().openapi({
        param: {
            name: 'after',
            in: 'query',
        },
        description: 'Cursor to get items after (newer items)',
        example: 'cursor_10',
    }),
    limit: z
        .string()
        .default('50')
        .transform((v) => parseInt(v, 10))
        .pipe(z.number().int().min(1).max(200))
        .optional()
        .openapi({
            param: {
                name: 'limit',
                in: 'query',
            },
            description: 'Maximum number of items (1-200, default 50)',
            example: '50',
        }),
});

/**
 * Schema for feed response
 */
export const FeedResponseSchema = z
    .object({
        items: z.array(FeedItemSchema).openapi({
            description: 'Array of feed items ordered by most recent',
        }),
        hasMore: z.boolean().openapi({
            description: 'Whether there are more items available',
            example: true,
        }),
    })
    .openapi('FeedResponse');

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
    .openapi('UnauthorizedError');

/**
 * Schema for 400 Bad Request error
 */
export const BadRequestErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Invalid cursor format',
        }),
    })
    .openapi('BadRequestError');
