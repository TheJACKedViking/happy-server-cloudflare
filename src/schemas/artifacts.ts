import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for artifact management endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for all artifact routes.
 * Artifacts store encrypted binary data (header + body) with version control.
 */

// ============================================================================
// Common Schemas
// ============================================================================

/**
 * Schema for artifact object returned in API responses
 * @internal Used for composing response schemas
 */
const ArtifactSchema = z
    .object({
        id: z.string().openapi({
            description: 'Unique artifact identifier (UUID)',
            example: '123e4567-e89b-12d3-a456-426614174000',
        }),
        header: z.string().openapi({
            description: 'Base64-encoded encrypted artifact header',
            example: 'YWJjZGVmZ2hpamtsbW5vcA==',
        }),
        headerVersion: z.number().int().openapi({
            description: 'Header version for conflict resolution',
            example: 3,
        }),
        dataEncryptionKey: z.string().openapi({
            description: 'Base64-encoded data encryption key',
            example: 'ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
        }),
        seq: z.number().int().openapi({
            description: 'Sequence number for optimistic concurrency control',
            example: 7,
        }),
        createdAt: z.number().int().openapi({
            description: 'Artifact creation timestamp (Unix milliseconds)',
            example: 1705010400000,
        }),
        updatedAt: z.number().int().openapi({
            description: 'Artifact last update timestamp (Unix milliseconds)',
            example: 1705014000000,
        }),
    })
    .openapi('Artifact');

/**
 * Schema for full artifact with body (GET /v1/artifacts/:id)
 * @internal Used for composing response schemas
 */
const FullArtifactSchema = ArtifactSchema.extend({
    body: z.string().openapi({
        description: 'Base64-encoded encrypted artifact body',
        example: 'cXJzdHV2d3h5ejAxMjM0NTY3ODk=',
    }),
    bodyVersion: z.number().int().openapi({
        description: 'Body version for conflict resolution',
        example: 5,
    }),
}).openapi('FullArtifact');

// ============================================================================
// GET /v1/artifacts - List Artifacts
// ============================================================================

/**
 * Schema for list artifacts response
 */
export const ListArtifactsResponseSchema = z
    .object({
        artifacts: z.array(ArtifactSchema).openapi({
            description: 'Array of artifacts ordered by most recent',
        }),
    })
    .openapi('ListArtifactsResponse');

// ============================================================================
// GET /v1/artifacts/:id - Get Artifact
// ============================================================================

/**
 * Schema for artifact ID path parameter
 */
export const ArtifactIdParamSchema = z.object({
    id: z.string().openapi({
        param: {
            name: 'id',
            in: 'path',
        },
        description: 'Artifact identifier',
        example: '123e4567-e89b-12d3-a456-426614174000',
    }),
});

/**
 * Schema for get artifact response
 */
export const GetArtifactResponseSchema = z
    .object({
        artifact: FullArtifactSchema.openapi({
            description: 'Requested artifact with full body',
        }),
    })
    .openapi('GetArtifactResponse');

// ============================================================================
// POST /v1/artifacts - Create Artifact
// ============================================================================

/**
 * Schema for creating an artifact
 */
export const CreateArtifactRequestSchema = z
    .object({
        id: z.string().uuid().openapi({
            description: 'Client-provided UUID for artifact (must be unique)',
            example: '123e4567-e89b-12d3-a456-426614174000',
        }),
        header: z.string().min(1).openapi({
            description: 'Base64-encoded encrypted artifact header',
            example: 'YWJjZGVmZ2hpamtsbW5vcA==',
        }),
        body: z.string().min(1).openapi({
            description: 'Base64-encoded encrypted artifact body',
            example: 'cXJzdHV2d3h5ejAxMjM0NTY3ODk=',
        }),
        dataEncryptionKey: z.string().min(1).openapi({
            description: 'Base64-encoded data encryption key',
            example: 'ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
        }),
    })
    .openapi('CreateArtifactRequest');

/**
 * Schema for successful artifact creation
 */
export const CreateArtifactResponseSchema = z
    .object({
        artifact: FullArtifactSchema.openapi({
            description: 'Newly created artifact',
        }),
    })
    .openapi('CreateArtifactResponse');

// ============================================================================
// POST /v1/artifacts/:id - Update Artifact
// ============================================================================

/**
 * Schema for updating an artifact with version control
 */
export const UpdateArtifactRequestSchema = z
    .object({
        header: z.string().optional().openapi({
            description: 'Base64-encoded updated header (if updating header)',
            example: 'YWJjZGVmZ2hpamtsbW5vcA==',
        }),
        expectedHeaderVersion: z.number().int().min(0).optional().openapi({
            description: 'Expected current header version (for optimistic locking)',
            example: 2,
        }),
        body: z.string().optional().openapi({
            description: 'Base64-encoded updated body (if updating body)',
            example: 'cXJzdHV2d3h5ejAxMjM0NTY3ODk=',
        }),
        expectedBodyVersion: z.number().int().min(0).optional().openapi({
            description: 'Expected current body version (for optimistic locking)',
            example: 4,
        }),
    })
    .openapi('UpdateArtifactRequest');

/**
 * Schema for successful artifact update
 * @internal Used in union type
 */
const UpdateArtifactSuccessResponseSchema = z
    .object({
        success: z.literal(true).openapi({
            description: 'Update succeeded',
        }),
        headerVersion: z.number().int().optional().openapi({
            description: 'New header version (if header was updated)',
            example: 3,
        }),
        bodyVersion: z.number().int().optional().openapi({
            description: 'New body version (if body was updated)',
            example: 5,
        }),
    })
    .openapi('UpdateArtifactSuccessResponse');

/**
 * Schema for artifact update version mismatch
 * @internal Used in union type
 */
const UpdateArtifactVersionMismatchResponseSchema = z
    .object({
        success: z.literal(false).openapi({
            description: 'Update failed due to version mismatch',
        }),
        error: z.literal('version-mismatch').openapi({
            description: 'Error type',
        }),
        currentHeaderVersion: z.number().int().optional().openapi({
            description: 'Current header version (if header mismatch)',
            example: 3,
        }),
        currentHeader: z.string().optional().openapi({
            description: 'Current header value (if header mismatch)',
            example: 'YWJjZGVmZ2hpamtsbW5vcA==',
        }),
        currentBodyVersion: z.number().int().optional().openapi({
            description: 'Current body version (if body mismatch)',
            example: 5,
        }),
        currentBody: z.string().optional().openapi({
            description: 'Current body value (if body mismatch)',
            example: 'cXJzdHV2d3h5ejAxMjM0NTY3ODk=',
        }),
    })
    .openapi('UpdateArtifactVersionMismatchResponse');

/**
 * Union type for artifact update responses
 */
export const UpdateArtifactResponseSchema = z.union([
    UpdateArtifactSuccessResponseSchema,
    UpdateArtifactVersionMismatchResponseSchema,
]);

// ============================================================================
// DELETE /v1/artifacts/:id - Delete Artifact
// ============================================================================

/**
 * Schema for successful artifact deletion
 */
export const DeleteArtifactResponseSchema = z
    .object({
        success: z.literal(true).openapi({
            description: 'Always true for successful deletion',
            example: true,
        }),
    })
    .openapi('DeleteArtifactResponse');

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
            example: 'Artifact not found',
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
            example: 'Artifact with this ID already exists for another account',
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

