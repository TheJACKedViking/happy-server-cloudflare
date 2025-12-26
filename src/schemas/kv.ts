import { z } from '@hono/zod-openapi';

// ============================================================================
// Key-Value Storage Schemas
// ============================================================================

/**
 * Single KV item
 * @internal Used for composing response schemas
 */
const KVItemSchema = z
    .object({
        key: z.string().openapi({
            description: 'Storage key',
            example: 'settings:theme',
        }),
        value: z.string().openapi({
            description: 'Stored value (base64 encoded encrypted data)',
            example: 'base64EncodedValue...',
        }),
        version: z.number().openapi({
            description: 'Version number for optimistic concurrency',
            example: 1,
        }),
    })
    .openapi('KVItem');

/**
 * Path parameter for key
 */
export const KVKeyParamSchema = z
    .object({
        key: z.string().openapi({
            description: 'Storage key',
            example: 'settings:theme',
        }),
    })
    .openapi('KVKeyParam');

/**
 * Response for single key get
 */
export const KVGetResponseSchema = KVItemSchema.openapi('KVGetResponse');

/**
 * Query parameters for list
 */
export const KVListQuerySchema = z
    .object({
        prefix: z.string().optional().openapi({
            description: 'Filter by key prefix',
            example: 'settings:',
        }),
        limit: z.coerce.number().int().min(1).max(1000).default(100).openapi({
            description: 'Maximum number of items to return',
            example: 100,
        }),
    })
    .openapi('KVListQuery');

/**
 * Response for list
 */
export const KVListResponseSchema = z
    .object({
        items: z.array(KVItemSchema),
    })
    .openapi('KVListResponse');

/**
 * Request for bulk get
 */
export const KVBulkGetRequestSchema = z
    .object({
        keys: z
            .array(z.string())
            .min(1)
            .max(100)
            .openapi({
                description: 'Keys to retrieve',
                example: ['settings:theme', 'settings:notifications'],
            }),
    })
    .openapi('KVBulkGetRequest');

/**
 * Response for bulk get
 */
export const KVBulkGetResponseSchema = z
    .object({
        values: z.array(KVItemSchema),
    })
    .openapi('KVBulkGetResponse');

/**
 * Single mutation in batch
 * @internal Used for composing request schemas
 */
const KVMutationSchema = z
    .object({
        key: z.string().openapi({
            description: 'Storage key',
            example: 'settings:theme',
        }),
        value: z.string().nullable().openapi({
            description: 'New value (null to delete)',
            example: 'base64EncodedValue...',
        }),
        version: z.number().openapi({
            description: 'Expected current version (-1 for new keys)',
            example: 1,
        }),
    })
    .openapi('KVMutation');

/**
 * Request for atomic batch mutation
 */
export const KVMutateRequestSchema = z
    .object({
        mutations: z.array(KVMutationSchema).min(1).max(100),
    })
    .openapi('KVMutateRequest');

/**
 * Success result for mutation
 */
export const KVMutateSuccessSchema = z
    .object({
        success: z.literal(true),
        results: z.array(
            z.object({
                key: z.string(),
                version: z.number(),
            })
        ),
    })
    .openapi('KVMutateSuccess');

/**
 * Conflict result for mutation
 */
export const KVMutateConflictSchema = z
    .object({
        success: z.literal(false),
        errors: z.array(
            z.object({
                key: z.string(),
                error: z.literal('version-mismatch'),
                version: z.number(),
                value: z.string().nullable(),
            })
        ),
    })
    .openapi('KVMutateConflict');

/**
 * Error responses
 */
export const KVNotFoundSchema = z
    .object({
        error: z.literal('Key not found'),
    })
    .openapi('KVNotFound');

export const KVInternalErrorSchema = z
    .object({
        error: z.string(),
    })
    .openapi('KVInternalError');

export const UnauthorizedErrorSchema = z
    .object({
        error: z.literal('Unauthorized'),
    })
    .openapi('UnauthorizedError');
