import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for access key management endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for all access key routes.
 * Access keys provide session-scoped encryption keys for machine access.
 * Composite unique key: (accountId + machineId + sessionId)
 */

// ============================================================================
// Common Schemas
// ============================================================================

/**
 * Schema for access key object returned in API responses
 * @internal Used for composing response schemas
 */
const AccessKeySchema = z
    .object({
        data: z.string().openapi({
            description: 'Encrypted access key data',
            example: 'eyJrZXkiOiJ2YWx1ZSJ9',
        }),
        dataVersion: z.number().int().openapi({
            description: 'Data version for conflict resolution',
            example: 3,
        }),
        createdAt: z.number().int().openapi({
            description: 'Access key creation timestamp (Unix milliseconds)',
            example: 1705010400000,
        }),
        updatedAt: z.number().int().openapi({
            description: 'Access key last update timestamp (Unix milliseconds)',
            example: 1705014000000,
        }),
    })
    .openapi('AccessKey');

// ============================================================================
// GET /v1/access-keys/:sessionId/:machineId - Get Access Key
// ============================================================================

/**
 * Schema for access key path parameters
 */
export const AccessKeyParamsSchema = z.object({
    sessionId: z.string().openapi({
        param: {
            name: 'sessionId',
            in: 'path',
        },
        description: 'Session identifier',
        example: 'cmed556s4002bvb2020igg8jf',
    }),
    machineId: z.string().openapi({
        param: {
            name: 'machineId',
            in: 'path',
        },
        description: 'Machine identifier',
        example: 'machine_abc123',
    }),
});

/**
 * Schema for get access key response (nullable if not found)
 */
export const GetAccessKeyResponseSchema = z
    .object({
        accessKey: AccessKeySchema.nullable().openapi({
            description: 'Access key data or null if not found',
        }),
    })
    .openapi('GetAccessKeyResponse');

// ============================================================================
// POST /v1/access-keys/:sessionId/:machineId - Create Access Key
// ============================================================================

/**
 * Schema for creating an access key
 */
export const CreateAccessKeyRequestSchema = z
    .object({
        data: z.string().min(1).openapi({
            description: 'Encrypted access key data',
            example: 'eyJrZXkiOiJ2YWx1ZSJ9',
        }),
    })
    .openapi('CreateAccessKeyRequest');

/**
 * Schema for successful access key creation
 */
export const CreateAccessKeyResponseSchema = z
    .object({
        success: z.boolean().openapi({
            description: 'Whether the operation succeeded',
            example: true,
        }),
        accessKey: AccessKeySchema.optional().openapi({
            description: 'Newly created access key',
        }),
        error: z.string().optional().openapi({
            description: 'Error message if success is false',
            example: 'Access key already exists',
        }),
    })
    .openapi('CreateAccessKeyResponse');

// ============================================================================
// PUT /v1/access-keys/:sessionId/:machineId - Update Access Key
// ============================================================================

/**
 * Schema for updating an access key with version control
 */
export const UpdateAccessKeyRequestSchema = z
    .object({
        data: z.string().min(1).openapi({
            description: 'Updated encrypted access key data',
            example: 'eyJrZXkiOiJuZXdfdmFsdWUifQ==',
        }),
        expectedVersion: z.number().int().min(0).openapi({
            description: 'Expected current version (for optimistic locking)',
            example: 2,
        }),
    })
    .openapi('UpdateAccessKeyRequest');

/**
 * Schema for successful access key update
 * @internal Used in union type
 */
const UpdateAccessKeySuccessResponseSchema = z
    .object({
        success: z.literal(true).openapi({
            description: 'Update succeeded',
        }),
        version: z.number().int().openapi({
            description: 'New version after update',
            example: 3,
        }),
    })
    .openapi('UpdateAccessKeySuccessResponse');

/**
 * Schema for access key update version mismatch
 * @internal Used in union type
 */
const UpdateAccessKeyVersionMismatchResponseSchema = z
    .object({
        success: z.literal(false).openapi({
            description: 'Update failed due to version mismatch',
        }),
        error: z.literal('version-mismatch').openapi({
            description: 'Error type',
        }),
        currentVersion: z.number().int().openapi({
            description: 'Current version in database',
            example: 3,
        }),
        currentData: z.string().openapi({
            description: 'Current data in database',
            example: 'eyJrZXkiOiJjdXJyZW50X3ZhbHVlIn0=',
        }),
    })
    .openapi('UpdateAccessKeyVersionMismatchResponse');

/**
 * Union type for access key update responses
 */
export const UpdateAccessKeyResponseSchema = z.union([
    UpdateAccessKeySuccessResponseSchema,
    UpdateAccessKeyVersionMismatchResponseSchema,
]);

// ============================================================================
// Error Responses
// ============================================================================

/**
 * Schema for 404 Not Found error
 */
export const NotFoundErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Session or machine not found',
        }),
    })
    .openapi('NotFoundError');

/**
 * Schema for 409 Conflict error
 */
export const ConflictErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Access key already exists',
        }),
    })
    .openapi('ConflictError');

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

