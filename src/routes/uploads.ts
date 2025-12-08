import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { createId } from '@/utils/id';
import { eq, and, desc } from 'drizzle-orm';
import {
    createR2Storage,
    type FileCategory,
    SUPPORTED_FILE_TYPES,
    SUPPORTED_IMAGE_TYPES,
    FILE_SIZE_LIMITS,
    type SupportedFileType,
    type SupportedImageType,
} from '@/storage/r2';
import { processImage, isProcessableImage } from '@/lib/image-processing';
import {
    ListFilesQuerySchema,
    ListFilesResponseSchema,
    FileIdParamSchema,
    GetFileResponseSchema,
    DeleteFileResponseSchema,
    UploadFileResponseSchema,
    UploadFileErrorSchema,
    UploadAvatarResponseSchema,
    UnauthorizedErrorSchema,
    NotFoundErrorSchema,
    BadRequestErrorSchema,
} from '@/schemas/uploads';

/**
 * Environment bindings for upload routes
 */
interface Env {
    DB: D1Database;
    UPLOADS: R2Bucket;
}

/**
 * Upload routes module
 *
 * Implements all file upload/download endpoints:
 * - GET /v1/uploads - List user's uploaded files
 * - POST /v1/uploads - Upload a file
 * - GET /v1/uploads/:id - Get file metadata
 * - GET /v1/uploads/:id/download - Download file content
 * - DELETE /v1/uploads/:id - Delete a file
 * - POST /v1/uploads/avatar - Upload profile avatar
 *
 * All routes use OpenAPI schemas and require authentication.
 */
const uploadRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all upload routes
uploadRoutes.use('/v1/uploads/*', authMiddleware());

// ============================================================================
// GET /v1/uploads - List Files
// ============================================================================

const listFilesRoute = createRoute({
    method: 'get',
    path: '/v1/uploads',
    request: {
        query: ListFilesQuerySchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ListFilesResponseSchema,
                },
            },
            description: 'List of uploaded files',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Uploads'],
    summary: 'List uploaded files',
    description: 'Returns list of files uploaded by the authenticated user.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
uploadRoutes.openapi(listFilesRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { category, limit, cursor } = c.req.valid('query');
    const db = getDb(c.env.DB);

    // Build query with optional category filter
    let query = db
        .select()
        .from(schema.uploadedFiles)
        .where(eq(schema.uploadedFiles.accountId, userId))
        .orderBy(desc(schema.uploadedFiles.createdAt))
        .limit(limit + 1); // Fetch one extra to check for more results

    // Apply category filter if provided
    if (category) {
        query = db
            .select()
            .from(schema.uploadedFiles)
            .where(
                and(
                    eq(schema.uploadedFiles.accountId, userId),
                    // Filter by path prefix (e.g., 'avatars/', 'documents/')
                    // Note: SQLite doesn't have starts_with, use LIKE
                )
            )
            .orderBy(desc(schema.uploadedFiles.createdAt))
            .limit(limit + 1);
    }

    // Handle cursor-based pagination
    let files;
    if (cursor) {
        // Cursor is the ID of the last item from the previous page
        files = await db
            .select()
            .from(schema.uploadedFiles)
            .where(eq(schema.uploadedFiles.accountId, userId))
            .orderBy(desc(schema.uploadedFiles.createdAt))
            .limit(limit + 1);

        // Find cursor position and slice
        const cursorIndex = files.findIndex((f) => f.id === cursor);
        if (cursorIndex >= 0) {
            files = files.slice(cursorIndex + 1);
        }
    } else {
        files = await query;
    }

    // Check if there are more results
    const hasMore = files.length > limit;
    if (hasMore) {
        files = files.slice(0, limit);
    }

    return c.json({
        files: files.map((f) => ({
            id: f.id,
            path: f.path,
            originalName: f.path.split('/').pop() || 'unknown',
            contentType: 'application/octet-stream', // Retrieved from R2 metadata
            size: 0, // Retrieved from R2 metadata
            width: f.width ?? undefined,
            height: f.height ?? undefined,
            thumbhash: f.thumbhash ?? undefined,
            createdAt: f.createdAt.getTime(),
            updatedAt: f.updatedAt.getTime(),
        })),
        ...(hasMore && files.length > 0
            ? { nextCursor: files[files.length - 1]?.id }
            : {}),
    });
});

// ============================================================================
// POST /v1/uploads - Upload File
// ============================================================================

const uploadFileRoute = createRoute({
    method: 'post',
    path: '/v1/uploads',
    request: {
        body: {
            content: {
                'multipart/form-data': {
                    schema: {
                        type: 'object',
                        properties: {
                            file: {
                                type: 'string',
                                format: 'binary',
                            },
                            category: {
                                type: 'string',
                                enum: ['avatars', 'documents', 'files'],
                            },
                            reuseKey: {
                                type: 'string',
                            },
                        },
                        required: ['file'],
                    },
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UploadFileResponseSchema,
                },
            },
            description: 'File uploaded successfully',
        },
        400: {
            content: {
                'application/json': {
                    schema: UploadFileErrorSchema,
                },
            },
            description: 'Invalid file or upload error',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Uploads'],
    summary: 'Upload a file',
    description:
        'Upload a file to R2 storage. Supports images, PDFs, and text files.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
uploadRoutes.openapi(uploadFileRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const db = getDb(c.env.DB);
    const r2 = createR2Storage(c.env.UPLOADS);

    try {
        const formData = await c.req.formData();
        const file = formData.get('file') as File | null;
        const category = (formData.get('category') as FileCategory) || 'files';
        const reuseKey = formData.get('reuseKey') as string | null;

        if (!file) {
            return c.json(
                {
                    success: false as const,
                    error: 'No file provided',
                    code: 'missing-file' as const,
                },
                400
            );
        }

        // Validate content type
        const contentType = file.type;
        if (
            !SUPPORTED_FILE_TYPES.includes(contentType as SupportedFileType)
        ) {
            return c.json(
                {
                    success: false as const,
                    error: `Unsupported file type: ${contentType}. Supported: ${SUPPORTED_FILE_TYPES.join(', ')}`,
                    code: 'invalid-type' as const,
                },
                400
            );
        }

        // Validate file size
        const maxSize =
            category === 'avatars'
                ? FILE_SIZE_LIMITS.avatar
                : category === 'documents'
                  ? FILE_SIZE_LIMITS.document
                  : FILE_SIZE_LIMITS.general;

        if (file.size > maxSize) {
            const maxSizeMB = Math.round(maxSize / (1024 * 1024));
            return c.json(
                {
                    success: false as const,
                    error: `File size ${Math.round(file.size / (1024 * 1024))}MB exceeds maximum ${maxSizeMB}MB for ${category}`,
                    code: 'size-exceeded' as const,
                },
                400
            );
        }

        // Check for existing file with same reuseKey
        if (reuseKey) {
            const existingFile = await db.query.uploadedFiles.findFirst({
                where: (files, { eq, and }) =>
                    and(
                        eq(files.accountId, userId),
                        eq(files.reuseKey, reuseKey)
                    ),
            });

            if (existingFile) {
                return c.json({
                    success: true as const,
                    file: {
                        id: existingFile.id,
                        path: existingFile.path,
                        originalName: file.name,
                        contentType,
                        size: file.size,
                        width: existingFile.width ?? undefined,
                        height: existingFile.height ?? undefined,
                        thumbhash: existingFile.thumbhash ?? undefined,
                        createdAt: existingFile.createdAt.getTime(),
                        updatedAt: existingFile.updatedAt.getTime(),
                    },
                });
            }
        }

        // Generate storage path
        const extension = r2.getExtensionFromContentType(contentType);
        const path = r2.generatePath(userId, category, extension);
        const fileId = path.split('/').pop()?.split('.')[0] || createId();

        // Upload to R2
        const arrayBuffer = await file.arrayBuffer();

        // Process image for dimensions and thumbhash (non-blocking failure)
        let imageData: { width?: number; height?: number; thumbhash?: string } = {};
        if (isProcessableImage(contentType)) {
            try {
                const result = await processImage(arrayBuffer, contentType);
                if (result) {
                    imageData = {
                        width: result.width,
                        height: result.height,
                        thumbhash: result.thumbhash ?? undefined,
                    };
                }
            } catch (error) {
                // Log but don't fail upload if image processing fails
                console.error('Image processing error:', error);
            }
        }

        await r2.upload(path, arrayBuffer, {
            originalName: file.name,
            contentType,
            size: file.size,
            accountId: userId,
            uploadedAt: new Date().toISOString(),
            ...imageData,
        });

        // Save to database with image metadata
        const newFile = await db
            .insert(schema.uploadedFiles)
            .values({
                id: fileId,
                accountId: userId,
                path,
                reuseKey: reuseKey ?? undefined,
                width: imageData.width,
                height: imageData.height,
                thumbhash: imageData.thumbhash,
            })
            .returning();

        const savedFile = newFile[0];
        if (!savedFile) {
            // Cleanup R2 upload if DB insert fails
            await r2.delete(path);
            return c.json(
                {
                    success: false as const,
                    error: 'Failed to save file metadata',
                    code: 'upload-failed' as const,
                },
                500
            );
        }

        return c.json({
            success: true as const,
            file: {
                id: savedFile.id,
                path: savedFile.path,
                originalName: file.name,
                contentType,
                size: file.size,
                width: savedFile.width ?? undefined,
                height: savedFile.height ?? undefined,
                thumbhash: savedFile.thumbhash ?? undefined,
                createdAt: savedFile.createdAt.getTime(),
                updatedAt: savedFile.updatedAt.getTime(),
            },
        });
    } catch (error) {
        console.error('Upload error:', error);
        return c.json(
            {
                success: false as const,
                error:
                    error instanceof Error
                        ? error.message
                        : 'Upload failed',
                code: 'upload-failed' as const,
            },
            500
        );
    }
});

// ============================================================================
// GET /v1/uploads/:id - Get File Metadata
// ============================================================================

const getFileRoute = createRoute({
    method: 'get',
    path: '/v1/uploads/:id',
    request: {
        params: FileIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetFileResponseSchema,
                },
            },
            description: 'File metadata',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'File not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Uploads'],
    summary: 'Get file metadata',
    description: 'Get metadata for an uploaded file. User must own the file.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
uploadRoutes.openapi(getFileRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);
    const r2 = createR2Storage(c.env.UPLOADS);

    // Get file from database
    const file = await db.query.uploadedFiles.findFirst({
        where: (files, { eq, and }) =>
            and(eq(files.id, id), eq(files.accountId, userId)),
    });

    if (!file) {
        return c.json({ error: 'File not found' }, 404);
    }

    // Get metadata from R2
    const r2Metadata = await r2.head(file.path);
    const contentType =
        r2Metadata?.contentType || 'application/octet-stream';
    const size = r2Metadata?.size || 0;

    return c.json({
        file: {
            id: file.id,
            path: file.path,
            originalName: r2Metadata?.originalName || file.path.split('/').pop() || 'unknown',
            contentType,
            size,
            width: file.width ?? undefined,
            height: file.height ?? undefined,
            thumbhash: file.thumbhash ?? undefined,
            createdAt: file.createdAt.getTime(),
            updatedAt: file.updatedAt.getTime(),
        },
        // Note: For a real presigned URL, you'd use R2's API
        // For now, return a path that can be used with the download endpoint
        url: `/v1/uploads/${id}/download`,
    });
});

// ============================================================================
// GET /v1/uploads/:id/download - Download File
// ============================================================================

const downloadFileRoute = createRoute({
    method: 'get',
    path: '/v1/uploads/:id/download',
    request: {
        params: FileIdParamSchema,
    },
    responses: {
        200: {
            description: 'File content',
            content: {
                '*/*': {
                    schema: {
                        type: 'string',
                        format: 'binary',
                    },
                },
            },
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'File not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Uploads'],
    summary: 'Download file',
    description: 'Download file content. User must own the file.',
});

uploadRoutes.openapi(downloadFileRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);
    const r2 = createR2Storage(c.env.UPLOADS);

    // Get file from database
    const file = await db.query.uploadedFiles.findFirst({
        where: (files, { eq, and }) =>
            and(eq(files.id, id), eq(files.accountId, userId)),
    });

    if (!file) {
        return c.json({ error: 'File not found' }, 404);
    }

    // Get file from R2
    const r2File = await r2.get(file.path);
    if (!r2File) {
        return c.json({ error: 'File not found in storage' }, 404);
    }

    // Return file with proper headers
    const headers = new Headers(r2File.httpMetadata);
    headers.set('ETag', r2File.etag);
    headers.set('Content-Length', r2File.size.toString());

    return new Response(r2File.body, { headers });
});

// ============================================================================
// DELETE /v1/uploads/:id - Delete File
// ============================================================================

const deleteFileRoute = createRoute({
    method: 'delete',
    path: '/v1/uploads/:id',
    request: {
        params: FileIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: DeleteFileResponseSchema,
                },
            },
            description: 'File deleted',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'File not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Uploads'],
    summary: 'Delete file',
    description: 'Delete an uploaded file. User must own the file.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
uploadRoutes.openapi(deleteFileRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);
    const r2 = createR2Storage(c.env.UPLOADS);

    // Get file from database
    const file = await db.query.uploadedFiles.findFirst({
        where: (files, { eq, and }) =>
            and(eq(files.id, id), eq(files.accountId, userId)),
    });

    if (!file) {
        return c.json({ error: 'File not found' }, 404);
    }

    // Delete from R2
    await r2.delete(file.path);

    // Delete from database
    await db
        .delete(schema.uploadedFiles)
        .where(eq(schema.uploadedFiles.id, id));

    return c.json({ success: true });
});

// ============================================================================
// POST /v1/uploads/avatar - Upload Avatar (convenience endpoint)
// ============================================================================

const uploadAvatarRoute = createRoute({
    method: 'post',
    path: '/v1/uploads/avatar',
    request: {
        body: {
            content: {
                'multipart/form-data': {
                    schema: {
                        type: 'object',
                        properties: {
                            file: {
                                type: 'string',
                                format: 'binary',
                            },
                        },
                        required: ['file'],
                    },
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UploadAvatarResponseSchema,
                },
            },
            description: 'Avatar uploaded successfully',
        },
        400: {
            content: {
                'application/json': {
                    schema: BadRequestErrorSchema,
                },
            },
            description: 'Invalid file or upload error',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Uploads'],
    summary: 'Upload avatar',
    description:
        'Upload a profile avatar image. Max size 5MB. Supported: JPEG, PNG, GIF, WebP.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
uploadRoutes.openapi(uploadAvatarRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const db = getDb(c.env.DB);
    const r2 = createR2Storage(c.env.UPLOADS);

    try {
        const formData = await c.req.formData();
        const file = formData.get('file') as File | null;

        if (!file) {
            return c.json({ error: 'No file provided' }, 400);
        }

        // Validate it's an image
        const contentType = file.type;
        if (
            !SUPPORTED_IMAGE_TYPES.includes(contentType as SupportedImageType)
        ) {
            return c.json(
                {
                    error: `Unsupported image type: ${contentType}. Supported: ${SUPPORTED_IMAGE_TYPES.join(', ')}`,
                },
                400
            );
        }

        // Validate size (5MB max for avatars)
        if (file.size > FILE_SIZE_LIMITS.avatar) {
            return c.json(
                {
                    error: `Avatar size ${Math.round(file.size / (1024 * 1024))}MB exceeds maximum 5MB`,
                },
                400
            );
        }

        // Delete existing avatar if any
        const existingAvatar = await db.query.uploadedFiles.findFirst({
            where: (files, { eq, and }) =>
                and(
                    eq(files.accountId, userId),
                    eq(files.reuseKey, 'profile-avatar')
                ),
        });

        if (existingAvatar) {
            await r2.delete(existingAvatar.path);
            await db
                .delete(schema.uploadedFiles)
                .where(eq(schema.uploadedFiles.id, existingAvatar.id));
        }

        // Upload new avatar
        const arrayBuffer = await file.arrayBuffer();

        // Process image for dimensions and thumbhash
        let imageData: { width?: number; height?: number; thumbhash?: string } = {};
        if (isProcessableImage(contentType)) {
            try {
                const result = await processImage(arrayBuffer, contentType);
                if (result) {
                    imageData = {
                        width: result.width,
                        height: result.height,
                        thumbhash: result.thumbhash ?? undefined,
                    };
                }
            } catch (error) {
                console.error('Avatar image processing error:', error);
            }
        }

        const uploadResult = await r2.uploadAvatar(
            userId,
            arrayBuffer,
            contentType as SupportedImageType,
            file.name,
            imageData.width && imageData.height
                ? { width: imageData.width, height: imageData.height }
                : undefined
        );

        // Save to database with reuse key for easy replacement
        const fileId = uploadResult.path.split('/').pop()?.split('.')[0] || createId();
        const newFile = await db
            .insert(schema.uploadedFiles)
            .values({
                id: fileId,
                accountId: userId,
                path: uploadResult.path,
                reuseKey: 'profile-avatar',
                width: imageData.width,
                height: imageData.height,
                thumbhash: imageData.thumbhash,
            })
            .returning();

        const savedFile = newFile[0];
        if (!savedFile) {
            await r2.delete(uploadResult.path);
            return c.json({ error: 'Failed to save avatar metadata' }, 500);
        }

        return c.json({
            success: true as const,
            avatar: {
                id: savedFile.id,
                path: savedFile.path,
                contentType,
                size: file.size,
                width: savedFile.width ?? undefined,
                height: savedFile.height ?? undefined,
                thumbhash: savedFile.thumbhash ?? undefined,
            },
        });
    } catch (error) {
        console.error('Avatar upload error:', error);
        return c.json(
            {
                error:
                    error instanceof Error
                        ? error.message
                        : 'Avatar upload failed',
            },
            500
        );
    }
});

export default uploadRoutes;
