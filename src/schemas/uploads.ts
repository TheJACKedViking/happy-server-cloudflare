import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for file upload endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for all upload routes.
 */

// ============================================================================
// Common Schemas
// ============================================================================

/**
 * Schema for uploaded file metadata in API responses
 */
export const UploadedFileSchema = z
    .object({
        id: z.string().openapi({
            description: 'Unique file identifier (cuid2)',
            example: 'clm8z0xyz000008l5g1h9e2ab',
        }),
        path: z.string().openapi({
            description: 'Storage path in R2 bucket',
            example: 'avatars/user123/clm8z0xyz000008l5g1h9e2ab.jpg',
        }),
        originalName: z.string().openapi({
            description: 'Original filename as uploaded',
            example: 'profile-photo.jpg',
        }),
        contentType: z.string().openapi({
            description: 'MIME type of the file',
            example: 'image/jpeg',
        }),
        size: z.number().int().openapi({
            description: 'File size in bytes',
            example: 245678,
        }),
        width: z.number().int().optional().openapi({
            description: 'Image width in pixels (images only)',
            example: 800,
        }),
        height: z.number().int().optional().openapi({
            description: 'Image height in pixels (images only)',
            example: 600,
        }),
        thumbhash: z.string().optional().openapi({
            description: 'Thumbhash for placeholder images',
            example: 'YTkGJwaRhWUIs4dYh4dIeFeHQw==',
        }),
        createdAt: z.number().int().openapi({
            description: 'Upload timestamp (Unix milliseconds)',
            example: 1705010400000,
        }),
        updatedAt: z.number().int().openapi({
            description: 'Last update timestamp (Unix milliseconds)',
            example: 1705014000000,
        }),
    })
    .openapi('UploadedFile');

/**
 * Schema for file ID in URL parameters
 */
export const FileIdParamSchema = z.object({
    id: z.string().openapi({
        description: 'File ID',
        example: 'clm8z0xyz000008l5g1h9e2ab',
        param: {
            in: 'path',
            name: 'id',
        },
    }),
});

/**
 * Schema for file path in URL parameters
 */
export const FilePathParamSchema = z.object({
    path: z.string().openapi({
        description: 'Full file path in R2',
        example: 'avatars/user123/clm8z0xyz000008l5g1h9e2ab.jpg',
        param: {
            in: 'path',
            name: 'path',
        },
    }),
});

// ============================================================================
// List Files
// ============================================================================

export const ListFilesQuerySchema = z.object({
    category: z
        .enum(['avatars', 'documents', 'files'])
        .optional()
        .openapi({
            description: 'Filter by file category',
            example: 'documents',
        }),
    limit: z
        .string()
        .optional()
        .transform((val) => (val ? parseInt(val, 10) : 50))
        .pipe(z.number().int().min(1).max(200))
        .openapi({
            description: 'Maximum files to return (1-200)',
            example: '50',
        }),
    cursor: z.string().optional().openapi({
        description: 'Pagination cursor from previous response',
    }),
});

export const ListFilesResponseSchema = z
    .object({
        files: z.array(UploadedFileSchema).openapi({
            description: 'List of uploaded files',
        }),
        nextCursor: z.string().optional().openapi({
            description: 'Cursor for next page, absent if no more results',
        }),
    })
    .openapi('ListFilesResponse');

// ============================================================================
// Upload File (Multipart Form)
// ============================================================================

/**
 * Note: For file uploads, we use multipart/form-data.
 * The actual file validation happens in the route handler since
 * Zod OpenAPI doesn't fully support multipart form data schemas.
 */

export const UploadFileQuerySchema = z.object({
    category: z
        .enum(['avatars', 'documents', 'files'])
        .optional()
        .default('files')
        .openapi({
            description: 'File category for organization',
            example: 'documents',
        }),
    reuseKey: z.string().optional().openapi({
        description: 'Optional key for deduplication (returns existing file if matches)',
        example: 'profile-avatar-v2',
    }),
});

export const UploadFileResponseSchema = z
    .object({
        success: z.literal(true),
        file: UploadedFileSchema,
    })
    .openapi('UploadFileResponse');

export const UploadFileErrorSchema = z
    .object({
        success: z.literal(false),
        error: z.string().openapi({
            description: 'Error message',
            example: 'File size exceeds maximum 5MB for avatars',
        }),
        code: z
            .enum([
                'invalid-type',
                'size-exceeded',
                'upload-failed',
                'missing-file',
            ])
            .openapi({
                description: 'Error code',
            }),
    })
    .openapi('UploadFileError');

// ============================================================================
// Get File
// ============================================================================

export const GetFileResponseSchema = z
    .object({
        file: UploadedFileSchema,
        url: z.string().url().openapi({
            description: 'Direct download URL (temporary, expires in 1 hour)',
            example: 'https://example.com/uploads/avatars/...',
        }),
    })
    .openapi('GetFileResponse');

// ============================================================================
// Delete File
// ============================================================================

export const DeleteFileResponseSchema = z
    .object({
        success: z.literal(true),
    })
    .openapi('DeleteFileResponse');

// ============================================================================
// Avatar-specific Schemas
// ============================================================================

export const UploadAvatarQuerySchema = z.object({
    reuseKey: z.string().optional().openapi({
        description: 'Reuse key for avatar deduplication',
        example: 'profile-avatar',
    }),
});

export const UploadAvatarResponseSchema = z
    .object({
        success: z.literal(true),
        avatar: z
            .object({
                id: z.string(),
                path: z.string(),
                contentType: z.string(),
                size: z.number().int(),
                width: z.number().int().optional(),
                height: z.number().int().optional(),
                thumbhash: z.string().optional(),
            })
            .openapi({
                description: 'Uploaded avatar metadata',
            }),
    })
    .openapi('UploadAvatarResponse');

// ============================================================================
// Error Schemas (shared)
// ============================================================================

export const UnauthorizedErrorSchema = z
    .object({
        error: z.literal('Unauthorized'),
    })
    .openapi('UnauthorizedError');

export const NotFoundErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'File not found',
        }),
    })
    .openapi('NotFoundError');

export const BadRequestErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Invalid request',
        }),
    })
    .openapi('BadRequestError');
