/**
 * R2 Storage Abstraction Layer
 *
 * Provides typed utilities for interacting with Cloudflare R2 object storage.
 * Handles file uploads, downloads, and metadata management with proper error handling.
 *
 * @module storage/r2
 */

import { createId } from '@paralleldrive/cuid2';

/**
 * Supported file types for upload validation
 */
export const SUPPORTED_IMAGE_TYPES = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/svg+xml',
] as const;

export const SUPPORTED_DOCUMENT_TYPES = [
    'application/pdf',
    'text/plain',
    'application/json',
    'text/markdown',
] as const;

export const SUPPORTED_FILE_TYPES = [
    ...SUPPORTED_IMAGE_TYPES,
    ...SUPPORTED_DOCUMENT_TYPES,
] as const;

export type SupportedFileType = (typeof SUPPORTED_FILE_TYPES)[number];
export type SupportedImageType = (typeof SUPPORTED_IMAGE_TYPES)[number];
export type SupportedDocumentType = (typeof SUPPORTED_DOCUMENT_TYPES)[number];

/**
 * Maximum file size limits in bytes
 */
export const FILE_SIZE_LIMITS = {
    /** Maximum size for avatar uploads (5 MB) */
    avatar: 5 * 1024 * 1024,
    /** Maximum size for document uploads (50 MB) */
    document: 50 * 1024 * 1024,
    /** Maximum size for general file uploads (100 MB) */
    general: 100 * 1024 * 1024,
} as const;

/**
 * File categories for organizing uploads in R2
 */
export type FileCategory = 'avatars' | 'documents' | 'files';

/**
 * Metadata stored with uploaded files in R2
 */
export interface R2FileMetadata {
    /** Original filename */
    originalName: string;
    /** MIME type of the file */
    contentType: string;
    /** Size in bytes */
    size: number;
    /** User who uploaded the file */
    accountId: string;
    /** Upload timestamp (ISO string) */
    uploadedAt: string;
    /** Optional image dimensions */
    width?: number;
    height?: number;
    /** Optional thumbhash for image placeholders */
    thumbhash?: string;
}

/**
 * Result of a successful file upload
 */
export interface UploadResult {
    /** Unique file ID (cuid2) */
    id: string;
    /** Full path in R2 bucket */
    path: string;
    /** HTTP ETag for caching */
    etag: string;
    /** Size in bytes */
    size: number;
    /** MIME content type */
    contentType: string;
}

/**
 * Result of a file retrieval operation
 */
export interface FileResult {
    /** File content as ReadableStream */
    body: ReadableStream;
    /** HTTP metadata (content-type, cache-control, etc.) */
    httpMetadata: Headers;
    /** Custom metadata stored with the file */
    customMetadata: R2FileMetadata;
    /** HTTP ETag */
    etag: string;
    /** File size in bytes */
    size: number;
}

/**
 * R2 Storage client for managing file operations
 */
export class R2Storage {
    private bucket: R2Bucket;

    constructor(bucket: R2Bucket) {
        this.bucket = bucket;
    }

    /**
     * Generate a unique storage path for a file
     *
     * @param accountId - User ID for namespacing
     * @param category - File category (avatars, documents, files)
     * @param extension - File extension (e.g., '.jpg', '.pdf')
     * @returns Unique path in format: {category}/{accountId}/{id}{extension}
     */
    generatePath(
        accountId: string,
        category: FileCategory,
        extension: string
    ): string {
        const id = createId();
        // Ensure extension starts with a dot
        const ext = extension.startsWith('.') ? extension : `.${extension}`;
        return `${category}/${accountId}/${id}${ext}`;
    }

    /**
     * Extract file extension from content type or filename
     */
    getExtensionFromContentType(contentType: string): string {
        const extensionMap: Record<string, string> = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'image/svg+xml': '.svg',
            'application/pdf': '.pdf',
            'text/plain': '.txt',
            'application/json': '.json',
            'text/markdown': '.md',
        };
        return extensionMap[contentType] || '.bin';
    }

    /**
     * Validate file before upload
     *
     * @param contentType - MIME type of the file
     * @param size - File size in bytes
     * @param category - Upload category for size limit check
     * @throws Error if validation fails
     */
    validateFile(
        contentType: string,
        size: number,
        category: FileCategory = 'files'
    ): void {
        // Validate content type
        if (!SUPPORTED_FILE_TYPES.includes(contentType as SupportedFileType)) {
            throw new Error(
                `Unsupported file type: ${contentType}. Supported types: ${SUPPORTED_FILE_TYPES.join(', ')}`
            );
        }

        // Validate size based on category
        const maxSize =
            category === 'avatars'
                ? FILE_SIZE_LIMITS.avatar
                : category === 'documents'
                  ? FILE_SIZE_LIMITS.document
                  : FILE_SIZE_LIMITS.general;

        if (size > maxSize) {
            const maxSizeMB = Math.round(maxSize / (1024 * 1024));
            throw new Error(
                `File size ${Math.round(size / (1024 * 1024))}MB exceeds maximum ${maxSizeMB}MB for ${category}`
            );
        }
    }

    /**
     * Upload a file to R2
     *
     * @param path - Storage path (use generatePath to create)
     * @param body - File content as ArrayBuffer, Blob, or ReadableStream
     * @param metadata - File metadata to store
     * @param options - Additional R2 put options
     * @returns Upload result with path and metadata
     */
    async upload(
        path: string,
        body: ArrayBuffer | Blob | ReadableStream,
        metadata: R2FileMetadata,
        options?: Partial<R2PutOptions>
    ): Promise<UploadResult> {
        const result = await this.bucket.put(path, body, {
            httpMetadata: {
                contentType: metadata.contentType,
                cacheControl: 'public, max-age=31536000', // 1 year cache
            },
            customMetadata: {
                originalName: metadata.originalName,
                accountId: metadata.accountId,
                uploadedAt: metadata.uploadedAt,
                size: metadata.size.toString(),
                ...(metadata.width && { width: metadata.width.toString() }),
                ...(metadata.height && { height: metadata.height.toString() }),
                ...(metadata.thumbhash && { thumbhash: metadata.thumbhash }),
            },
            ...options,
        });

        if (!result) {
            throw new Error('Failed to upload file to R2');
        }

        return {
            id: path.split('/').pop()?.split('.')[0] || createId(),
            path,
            etag: result.httpEtag,
            size: result.size,
            contentType: metadata.contentType,
        };
    }

    /**
     * Upload an avatar image
     *
     * Convenience method with avatar-specific validation and path generation.
     *
     * @param accountId - User ID
     * @param body - Image data
     * @param contentType - Image MIME type
     * @param originalName - Original filename
     * @param dimensions - Optional width/height
     * @returns Upload result
     */
    async uploadAvatar(
        accountId: string,
        body: ArrayBuffer | Blob,
        contentType: SupportedImageType,
        originalName: string,
        dimensions?: { width: number; height: number }
    ): Promise<UploadResult> {
        // Validate it's actually an image type (runtime check)
        if (!SUPPORTED_IMAGE_TYPES.includes(contentType as SupportedImageType)) {
            throw new Error(
                `Unsupported file type: ${contentType}. Avatar must be an image: ${SUPPORTED_IMAGE_TYPES.join(', ')}`
            );
        }

        const size =
            body instanceof ArrayBuffer ? body.byteLength : body.size;
        this.validateFile(contentType, size, 'avatars');

        const extension = this.getExtensionFromContentType(contentType);
        const path = this.generatePath(accountId, 'avatars', extension);

        const metadata: R2FileMetadata = {
            originalName,
            contentType,
            size,
            accountId,
            uploadedAt: new Date().toISOString(),
            ...dimensions,
        };

        return this.upload(path, body, metadata);
    }

    /**
     * Upload a document
     *
     * Convenience method with document-specific validation.
     */
    async uploadDocument(
        accountId: string,
        body: ArrayBuffer | Blob,
        contentType: SupportedDocumentType | SupportedImageType,
        originalName: string
    ): Promise<UploadResult> {
        const size =
            body instanceof ArrayBuffer ? body.byteLength : body.size;
        this.validateFile(contentType, size, 'documents');

        const extension = this.getExtensionFromContentType(contentType);
        const path = this.generatePath(accountId, 'documents', extension);

        const metadata: R2FileMetadata = {
            originalName,
            contentType,
            size,
            accountId,
            uploadedAt: new Date().toISOString(),
        };

        return this.upload(path, body, metadata);
    }

    /**
     * Get a file from R2
     *
     * @param path - Storage path
     * @returns File result with body and metadata, or null if not found
     */
    async get(path: string): Promise<FileResult | null> {
        const object = await this.bucket.get(path);

        if (!object) {
            return null;
        }

        const headers = new Headers();
        object.writeHttpMetadata(headers);

        // Parse custom metadata back to typed object
        const customMetadata: R2FileMetadata = {
            originalName: object.customMetadata?.originalName || 'unknown',
            contentType:
                object.customMetadata?.contentType ||
                object.httpMetadata?.contentType ||
                'application/octet-stream',
            size: parseInt(object.customMetadata?.size || '0', 10),
            accountId: object.customMetadata?.accountId || 'unknown',
            uploadedAt:
                object.customMetadata?.uploadedAt || object.uploaded.toISOString(),
            ...(object.customMetadata?.width && {
                width: parseInt(object.customMetadata.width, 10),
            }),
            ...(object.customMetadata?.height && {
                height: parseInt(object.customMetadata.height, 10),
            }),
            ...(object.customMetadata?.thumbhash && {
                thumbhash: object.customMetadata.thumbhash,
            }),
        };

        return {
            body: object.body,
            httpMetadata: headers,
            customMetadata,
            etag: object.httpEtag,
            size: object.size,
        };
    }

    /**
     * Get file metadata without downloading the body
     *
     * @param path - Storage path
     * @returns File metadata or null if not found
     */
    async head(path: string): Promise<R2FileMetadata | null> {
        const object = await this.bucket.head(path);

        if (!object) {
            return null;
        }

        return {
            originalName: object.customMetadata?.originalName || 'unknown',
            contentType:
                object.customMetadata?.contentType ||
                object.httpMetadata?.contentType ||
                'application/octet-stream',
            size: object.size,
            accountId: object.customMetadata?.accountId || 'unknown',
            uploadedAt:
                object.customMetadata?.uploadedAt || object.uploaded.toISOString(),
            ...(object.customMetadata?.width && {
                width: parseInt(object.customMetadata.width, 10),
            }),
            ...(object.customMetadata?.height && {
                height: parseInt(object.customMetadata.height, 10),
            }),
            ...(object.customMetadata?.thumbhash && {
                thumbhash: object.customMetadata.thumbhash,
            }),
        };
    }

    /**
     * Delete a file from R2
     *
     * @param path - Storage path
     */
    async delete(path: string): Promise<void> {
        await this.bucket.delete(path);
    }

    /**
     * Delete multiple files from R2
     *
     * @param paths - Array of storage paths to delete
     */
    async deleteMany(paths: string[]): Promise<void> {
        if (paths.length === 0) return;
        await this.bucket.delete(paths);
    }

    /**
     * List files in a directory with optional prefix filtering
     *
     * @param prefix - Path prefix to filter (e.g., 'avatars/user123/')
     * @param options - Pagination options
     * @returns List of objects matching the prefix
     */
    async list(
        prefix: string,
        options?: { limit?: number; cursor?: string }
    ): Promise<{ objects: R2Object[]; cursor?: string; truncated: boolean }> {
        const result = await this.bucket.list({
            prefix,
            limit: options?.limit || 100,
            cursor: options?.cursor,
        });

        return {
            objects: result.objects,
            cursor: result.truncated ? result.cursor : undefined,
            truncated: result.truncated,
        };
    }

    /**
     * Check if a file exists
     *
     * @param path - Storage path
     * @returns true if file exists
     */
    async exists(path: string): Promise<boolean> {
        const result = await this.bucket.head(path);
        return result !== null;
    }

    /**
     * Copy a file within the bucket
     *
     * @param sourcePath - Source path
     * @param destinationPath - Destination path
     * @returns The copied object
     */
    async copy(sourcePath: string, destinationPath: string): Promise<R2Object> {
        const source = await this.bucket.get(sourcePath);
        if (!source) {
            throw new Error(`Source file not found: ${sourcePath}`);
        }

        const result = await this.bucket.put(destinationPath, source.body, {
            httpMetadata: source.httpMetadata,
            customMetadata: source.customMetadata,
        });

        if (!result) {
            throw new Error('Failed to copy file');
        }

        return result;
    }
}

/**
 * Create an R2Storage instance from environment binding
 *
 * @param uploads - R2 bucket binding from environment
 * @returns R2Storage instance
 */
export function createR2Storage(uploads: R2Bucket): R2Storage {
    return new R2Storage(uploads);
}
