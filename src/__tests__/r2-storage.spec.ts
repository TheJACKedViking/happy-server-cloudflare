/**
 * Unit Tests for R2 Storage Abstraction Layer
 *
 * Tests all R2 storage operations including:
 * - File uploads (general, avatar, document)
 * - File retrieval (get, head)
 * - File deletion (single, bulk)
 * - File listing with pagination
 * - File existence checks
 * - File copying
 * - Validation logic
 * - Error handling paths
 *
 * @module __tests__/r2-storage.spec
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    R2Storage,
    createR2Storage,
    SUPPORTED_FILE_TYPES,
    SUPPORTED_IMAGE_TYPES,
    SUPPORTED_DOCUMENT_TYPES,
    FILE_SIZE_LIMITS,
    type R2FileMetadata,
    type SupportedImageType,
    type SupportedDocumentType,
} from '@/storage/r2';

/**
 * Enhanced Mock R2 Bucket for comprehensive testing
 * Extends the basic mock with full R2Bucket interface support
 */
function createEnhancedMockR2() {
    const files = new Map<
        string,
        {
            body: ArrayBuffer;
            customMetadata?: Record<string, string>;
            httpMetadata?: R2HTTPMetadata;
            size: number;
            uploaded: Date;
        }
    >();

    const mockR2Object = (
        key: string,
        file: {
            body: ArrayBuffer;
            customMetadata?: Record<string, string>;
            httpMetadata?: R2HTTPMetadata;
            size: number;
            uploaded: Date;
        }
    ): R2ObjectBody => ({
        key,
        version: 'v1',
        size: file.size,
        etag: 'mock-etag-123',
        httpEtag: '"mock-etag-123"',
        checksums: { toJSON: () => ({}) },
        uploaded: file.uploaded,
        httpMetadata: file.httpMetadata || { contentType: 'application/octet-stream' },
        customMetadata: file.customMetadata || {},
        range: undefined,
        storageClass: 'Standard',
        body: new ReadableStream({
            start(controller) {
                controller.enqueue(new Uint8Array(file.body));
                controller.close();
            },
        }),
        bodyUsed: false,
        arrayBuffer: async () => file.body,
        text: async () => new TextDecoder().decode(file.body),
        json: async () => JSON.parse(new TextDecoder().decode(file.body)),
        blob: async () => new Blob([file.body]),
        writeHttpMetadata: (headers: Headers) => {
            if (file.httpMetadata?.contentType) {
                headers.set('content-type', file.httpMetadata.contentType);
            }
            if (file.httpMetadata?.cacheControl) {
                headers.set('cache-control', file.httpMetadata.cacheControl);
            }
        },
    });

    const mockR2ObjectHead = (
        key: string,
        file: {
            body: ArrayBuffer;
            customMetadata?: Record<string, string>;
            httpMetadata?: R2HTTPMetadata;
            size: number;
            uploaded: Date;
        }
    ): R2Object => ({
        key,
        version: 'v1',
        size: file.size,
        etag: 'mock-etag-123',
        httpEtag: '"mock-etag-123"',
        checksums: { toJSON: () => ({}) },
        uploaded: file.uploaded,
        httpMetadata: file.httpMetadata || { contentType: 'application/octet-stream' },
        customMetadata: file.customMetadata || {},
        range: undefined,
        storageClass: 'Standard',
        writeHttpMetadata: (headers: Headers) => {
            if (file.httpMetadata?.contentType) {
                headers.set('content-type', file.httpMetadata.contentType);
            }
        },
    });

    return {
        get: vi.fn(async (key: string): Promise<R2ObjectBody | null> => {
            const file = files.get(key);
            if (!file) return null;
            return mockR2Object(key, file);
        }),

        put: vi.fn(
            async (
                key: string,
                body: ArrayBuffer | ArrayBufferView | ReadableStream | string | Blob | null,
                options?: R2PutOptions
            ): Promise<R2Object | null> => {
                let buffer: ArrayBuffer;
                let size: number;

                if (body === null) {
                    buffer = new ArrayBuffer(0);
                    size = 0;
                } else if (body instanceof ArrayBuffer) {
                    buffer = body;
                    size = body.byteLength;
                } else if (body instanceof Blob) {
                    buffer = await body.arrayBuffer();
                    size = body.size;
                } else if (typeof body === 'string') {
                    buffer = new TextEncoder().encode(body).buffer;
                    size = buffer.byteLength;
                } else if (ArrayBuffer.isView(body)) {
                    buffer = body.buffer.slice(
                        body.byteOffset,
                        body.byteOffset + body.byteLength
                    );
                    size = body.byteLength;
                } else {
                    // ReadableStream - read all chunks
                    const reader = body.getReader();
                    const chunks: Uint8Array[] = [];
                    let totalSize = 0;

                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        if (value) {
                            chunks.push(value);
                            totalSize += value.length;
                        }
                    }

                    buffer = new ArrayBuffer(totalSize);
                    const view = new Uint8Array(buffer);
                    let offset = 0;
                    for (const chunk of chunks) {
                        view.set(chunk, offset);
                        offset += chunk.length;
                    }
                    size = totalSize;
                }

                const fileData = {
                    body: buffer,
                    customMetadata: options?.customMetadata,
                    httpMetadata: options?.httpMetadata,
                    size,
                    uploaded: new Date(),
                };

                files.set(key, fileData);

                return {
                    key,
                    version: 'v1',
                    size,
                    etag: 'mock-etag-123',
                    httpEtag: '"mock-etag-123"',
                    checksums: { toJSON: () => ({}) },
                    uploaded: fileData.uploaded,
                    httpMetadata: fileData.httpMetadata || {},
                    customMetadata: fileData.customMetadata || {},
                    range: undefined,
                    storageClass: 'Standard',
                    writeHttpMetadata: () => {},
                };
            }
        ),

        head: vi.fn(async (key: string): Promise<R2Object | null> => {
            const file = files.get(key);
            if (!file) return null;
            return mockR2ObjectHead(key, file);
        }),

        delete: vi.fn(async (keys: string | string[]): Promise<void> => {
            if (Array.isArray(keys)) {
                for (const key of keys) {
                    files.delete(key);
                }
            } else {
                files.delete(keys);
            }
        }),

        list: vi.fn(
            async (
                options?: R2ListOptions
            ): Promise<R2Objects> => {
                const prefix = options?.prefix || '';
                const limit = options?.limit || 1000;
                const cursor = options?.cursor;

                const matchingKeys = Array.from(files.keys())
                    .filter((key) => key.startsWith(prefix))
                    .sort();

                let startIndex = 0;
                if (cursor) {
                    const cursorIndex = matchingKeys.indexOf(cursor);
                    if (cursorIndex >= 0) {
                        startIndex = cursorIndex + 1;
                    }
                }

                const paginatedKeys = matchingKeys.slice(startIndex, startIndex + limit);
                const truncated = startIndex + limit < matchingKeys.length;

                const objects: R2Object[] = paginatedKeys.map((key) => {
                    const file = files.get(key)!;
                    return mockR2ObjectHead(key, file);
                });

                return {
                    objects,
                    truncated,
                    cursor: truncated ? paginatedKeys[paginatedKeys.length - 1] : undefined,
                    delimitedPrefixes: [],
                };
            }
        ),

        // Test helpers
        _files: files,
        _clear: () => files.clear(),
        _seed: (
            key: string,
            data: ArrayBuffer,
            metadata?: Record<string, string>,
            httpMetadata?: R2HTTPMetadata
        ) => {
            files.set(key, {
                body: data,
                customMetadata: metadata,
                httpMetadata,
                size: data.byteLength,
                uploaded: new Date(),
            });
        },
    } as unknown as R2Bucket & {
        _files: Map<string, unknown>;
        _clear: () => void;
        _seed: (
            key: string,
            data: ArrayBuffer,
            metadata?: Record<string, string>,
            httpMetadata?: R2HTTPMetadata
        ) => void;
    };
}

describe('R2 Storage Abstraction Layer', () => {
    let mockBucket: ReturnType<typeof createEnhancedMockR2>;
    let storage: R2Storage;

    beforeEach(() => {
        vi.clearAllMocks();
        mockBucket = createEnhancedMockR2();
        storage = new R2Storage(mockBucket as unknown as R2Bucket);
    });

    describe('createR2Storage factory function', () => {
        it('should create an R2Storage instance from bucket binding', () => {
            const bucket = createEnhancedMockR2();
            const r2Storage = createR2Storage(bucket as unknown as R2Bucket);

            expect(r2Storage).toBeInstanceOf(R2Storage);
        });
    });

    describe('Constants and Type Exports', () => {
        it('should export supported image types', () => {
            expect(SUPPORTED_IMAGE_TYPES).toContain('image/jpeg');
            expect(SUPPORTED_IMAGE_TYPES).toContain('image/png');
            expect(SUPPORTED_IMAGE_TYPES).toContain('image/gif');
            expect(SUPPORTED_IMAGE_TYPES).toContain('image/webp');
            expect(SUPPORTED_IMAGE_TYPES).toContain('image/svg+xml');
            expect(SUPPORTED_IMAGE_TYPES.length).toBe(5);
        });

        it('should export supported document types', () => {
            expect(SUPPORTED_DOCUMENT_TYPES).toContain('application/pdf');
            expect(SUPPORTED_DOCUMENT_TYPES).toContain('text/plain');
            expect(SUPPORTED_DOCUMENT_TYPES).toContain('application/json');
            expect(SUPPORTED_DOCUMENT_TYPES).toContain('text/markdown');
            expect(SUPPORTED_DOCUMENT_TYPES.length).toBe(4);
        });

        it('should export combined supported file types', () => {
            expect(SUPPORTED_FILE_TYPES.length).toBe(9);
            // Should include all image types
            SUPPORTED_IMAGE_TYPES.forEach((type) => {
                expect(SUPPORTED_FILE_TYPES).toContain(type);
            });
            // Should include all document types
            SUPPORTED_DOCUMENT_TYPES.forEach((type) => {
                expect(SUPPORTED_FILE_TYPES).toContain(type);
            });
        });

        it('should export file size limits', () => {
            expect(FILE_SIZE_LIMITS.avatar).toBe(5 * 1024 * 1024); // 5 MB
            expect(FILE_SIZE_LIMITS.document).toBe(50 * 1024 * 1024); // 50 MB
            expect(FILE_SIZE_LIMITS.general).toBe(100 * 1024 * 1024); // 100 MB
        });
    });

    describe('generatePath', () => {
        it('should generate a unique path with category, accountId, and extension', () => {
            const path = storage.generatePath('user123', 'avatars', '.jpg');

            expect(path).toMatch(/^avatars\/user123\/[a-z0-9]+\.jpg$/);
        });

        it('should add dot prefix to extension if missing', () => {
            const path = storage.generatePath('user456', 'documents', 'pdf');

            expect(path).toMatch(/^documents\/user456\/[a-z0-9]+\.pdf$/);
        });

        it('should handle extension with dot prefix', () => {
            const path = storage.generatePath('user789', 'files', '.txt');

            expect(path).toMatch(/^files\/user789\/[a-z0-9]+\.txt$/);
        });

        it('should generate unique paths on successive calls', () => {
            const path1 = storage.generatePath('user1', 'avatars', '.jpg');
            const path2 = storage.generatePath('user1', 'avatars', '.jpg');

            expect(path1).not.toBe(path2);
        });
    });

    describe('getExtensionFromContentType', () => {
        it('should return correct extension for image types', () => {
            expect(storage.getExtensionFromContentType('image/jpeg')).toBe('.jpg');
            expect(storage.getExtensionFromContentType('image/png')).toBe('.png');
            expect(storage.getExtensionFromContentType('image/gif')).toBe('.gif');
            expect(storage.getExtensionFromContentType('image/webp')).toBe('.webp');
            expect(storage.getExtensionFromContentType('image/svg+xml')).toBe('.svg');
        });

        it('should return correct extension for document types', () => {
            expect(storage.getExtensionFromContentType('application/pdf')).toBe('.pdf');
            expect(storage.getExtensionFromContentType('text/plain')).toBe('.txt');
            expect(storage.getExtensionFromContentType('application/json')).toBe('.json');
            expect(storage.getExtensionFromContentType('text/markdown')).toBe('.md');
        });

        it('should return .bin for unknown content types', () => {
            expect(storage.getExtensionFromContentType('application/octet-stream')).toBe(
                '.bin'
            );
            expect(storage.getExtensionFromContentType('video/mp4')).toBe('.bin');
            expect(storage.getExtensionFromContentType('audio/mpeg')).toBe('.bin');
            expect(storage.getExtensionFromContentType('unknown/type')).toBe('.bin');
        });
    });

    describe('validateFile', () => {
        describe('content type validation', () => {
            it('should accept supported image types', () => {
                SUPPORTED_IMAGE_TYPES.forEach((type) => {
                    expect(() =>
                        storage.validateFile(type, 1024, 'avatars')
                    ).not.toThrow();
                });
            });

            it('should accept supported document types', () => {
                SUPPORTED_DOCUMENT_TYPES.forEach((type) => {
                    expect(() =>
                        storage.validateFile(type, 1024, 'documents')
                    ).not.toThrow();
                });
            });

            it('should reject unsupported content types', () => {
                expect(() => storage.validateFile('video/mp4', 1024, 'files')).toThrow(
                    'Unsupported file type: video/mp4'
                );
                expect(() =>
                    storage.validateFile('application/octet-stream', 1024, 'files')
                ).toThrow('Unsupported file type: application/octet-stream');
            });

            it('should include supported types in error message', () => {
                try {
                    storage.validateFile('video/mp4', 1024, 'files');
                    expect.fail('Should have thrown');
                } catch (e) {
                    const error = e as Error;
                    expect(error.message).toContain('Supported types:');
                    expect(error.message).toContain('image/jpeg');
                }
            });
        });

        describe('size validation', () => {
            it('should accept files within avatar size limit', () => {
                expect(() =>
                    storage.validateFile('image/jpeg', FILE_SIZE_LIMITS.avatar, 'avatars')
                ).not.toThrow();
                expect(() =>
                    storage.validateFile(
                        'image/jpeg',
                        FILE_SIZE_LIMITS.avatar - 1,
                        'avatars'
                    )
                ).not.toThrow();
            });

            it('should reject files exceeding avatar size limit', () => {
                expect(() =>
                    storage.validateFile(
                        'image/jpeg',
                        FILE_SIZE_LIMITS.avatar + 1,
                        'avatars'
                    )
                ).toThrow(/exceeds maximum 5MB for avatars/);
            });

            it('should accept files within document size limit', () => {
                expect(() =>
                    storage.validateFile(
                        'application/pdf',
                        FILE_SIZE_LIMITS.document,
                        'documents'
                    )
                ).not.toThrow();
            });

            it('should reject files exceeding document size limit', () => {
                expect(() =>
                    storage.validateFile(
                        'application/pdf',
                        FILE_SIZE_LIMITS.document + 1,
                        'documents'
                    )
                ).toThrow(/exceeds maximum 50MB for documents/);
            });

            it('should accept files within general size limit', () => {
                expect(() =>
                    storage.validateFile(
                        'image/png',
                        FILE_SIZE_LIMITS.general,
                        'files'
                    )
                ).not.toThrow();
            });

            it('should reject files exceeding general size limit', () => {
                expect(() =>
                    storage.validateFile(
                        'image/png',
                        FILE_SIZE_LIMITS.general + 1,
                        'files'
                    )
                ).toThrow(/exceeds maximum 100MB for files/);
            });

            it('should use general category as default', () => {
                // Should use general limit (100MB) when no category specified
                expect(() =>
                    storage.validateFile(
                        'text/plain',
                        FILE_SIZE_LIMITS.general
                    )
                ).not.toThrow();
            });
        });
    });

    describe('upload', () => {
        const testMetadata: R2FileMetadata = {
            originalName: 'test.txt',
            contentType: 'text/plain',
            size: 12,
            accountId: 'user123',
            uploadedAt: new Date().toISOString(),
        };

        it('should upload an ArrayBuffer and return result', async () => {
            const body = new TextEncoder().encode('test content').buffer;
            const path = 'files/user123/abc.txt';

            const result = await storage.upload(path, body as ArrayBuffer, testMetadata);

            expect(result.path).toBe(path);
            expect(result.etag).toBe('"mock-etag-123"');
            expect(result.size).toBe(12);
            expect(result.contentType).toBe('text/plain');
            expect(result.id).toBe('abc');
        });

        it('should upload a Blob and return result', async () => {
            const body = new Blob(['blob content'], { type: 'text/plain' });
            const path = 'files/user123/def.txt';
            const metadata: R2FileMetadata = {
                ...testMetadata,
                size: 12,
            };

            const result = await storage.upload(path, body, metadata);

            expect(result.path).toBe(path);
            expect(mockBucket.put).toHaveBeenCalledWith(
                path,
                body,
                expect.objectContaining({
                    httpMetadata: expect.objectContaining({
                        contentType: 'text/plain',
                    }),
                })
            );
        });

        it('should upload a ReadableStream and return result', async () => {
            const chunks = new TextEncoder().encode('stream content');
            const body = new ReadableStream({
                start(controller) {
                    controller.enqueue(chunks);
                    controller.close();
                },
            });
            const path = 'files/user123/ghi.txt';

            const result = await storage.upload(path, body, testMetadata);

            expect(result.path).toBe(path);
            expect(mockBucket.put).toHaveBeenCalled();
        });

        it('should set correct HTTP metadata', async () => {
            const body = new ArrayBuffer(10);
            const path = 'files/user123/test.txt';

            await storage.upload(path, body, testMetadata);

            expect(mockBucket.put).toHaveBeenCalledWith(
                path,
                body,
                expect.objectContaining({
                    httpMetadata: {
                        contentType: 'text/plain',
                        cacheControl: 'public, max-age=31536000',
                    },
                })
            );
        });

        it('should set custom metadata including optional fields', async () => {
            const body = new ArrayBuffer(10);
            const path = 'avatars/user123/photo.jpg';
            const metadata: R2FileMetadata = {
                originalName: 'photo.jpg',
                contentType: 'image/jpeg',
                size: 10,
                accountId: 'user123',
                uploadedAt: new Date().toISOString(),
                width: 800,
                height: 600,
                thumbhash: 'abc123thumbhash',
            };

            await storage.upload(path, body, metadata);

            expect(mockBucket.put).toHaveBeenCalledWith(
                path,
                body,
                expect.objectContaining({
                    customMetadata: expect.objectContaining({
                        originalName: 'photo.jpg',
                        accountId: 'user123',
                        width: '800',
                        height: '600',
                        thumbhash: 'abc123thumbhash',
                    }),
                })
            );
        });

        it('should pass additional R2PutOptions', async () => {
            const body = new ArrayBuffer(10);
            const path = 'files/user123/test.txt';
            const options: Partial<R2PutOptions> = {
                onlyIf: { etagMatches: 'some-etag' },
            };

            await storage.upload(path, body, testMetadata, options);

            expect(mockBucket.put).toHaveBeenCalledWith(
                path,
                body,
                expect.objectContaining({
                    onlyIf: { etagMatches: 'some-etag' },
                })
            );
        });

        it('should throw error when upload returns null', async () => {
            mockBucket.put = vi.fn().mockResolvedValue(null);
            const body = new ArrayBuffer(10);
            const path = 'files/user123/test.txt';

            await expect(storage.upload(path, body, testMetadata)).rejects.toThrow(
                'Failed to upload file to R2'
            );
        });

        it('should extract ID from path correctly', async () => {
            const body = new ArrayBuffer(10);
            const path = 'avatars/user123/myfileid.jpg';

            const result = await storage.upload(path, body, testMetadata);

            expect(result.id).toBe('myfileid');
        });

        it('should generate new ID when path has no valid file ID', async () => {
            const body = new ArrayBuffer(10);
            const path = '/'; // Edge case: no valid filename

            const result = await storage.upload(path, body, testMetadata);

            // Should generate a new ID when extraction fails
            expect(result.id).toBeDefined();
            expect(result.id.length).toBeGreaterThan(0);
        });
    });

    describe('uploadAvatar', () => {
        it('should upload avatar with ArrayBuffer body', async () => {
            const body = new ArrayBuffer(1024);
            const result = await storage.uploadAvatar(
                'user123',
                body,
                'image/jpeg',
                'photo.jpg'
            );

            expect(result.path).toMatch(/^avatars\/user123\/[a-z0-9]+\.jpg$/);
            expect(result.contentType).toBe('image/jpeg');
        });

        it('should upload avatar with Blob body', async () => {
            const body = new Blob([new ArrayBuffer(1024)], { type: 'image/png' });
            const result = await storage.uploadAvatar(
                'user456',
                body,
                'image/png',
                'avatar.png'
            );

            expect(result.path).toMatch(/^avatars\/user456\/[a-z0-9]+\.png$/);
            expect(result.contentType).toBe('image/png');
        });

        it('should upload avatar with dimensions', async () => {
            const body = new ArrayBuffer(1024);
            const result = await storage.uploadAvatar(
                'user123',
                body,
                'image/webp',
                'photo.webp',
                { width: 256, height: 256 }
            );

            expect(result.path).toMatch(/\.webp$/);
            expect(mockBucket.put).toHaveBeenCalledWith(
                expect.any(String),
                expect.any(ArrayBuffer),
                expect.objectContaining({
                    customMetadata: expect.objectContaining({
                        width: '256',
                        height: '256',
                    }),
                })
            );
        });

        it('should reject non-image types for avatar', async () => {
            const body = new ArrayBuffer(1024);

            await expect(
                storage.uploadAvatar(
                    'user123',
                    body,
                    // Force non-image type for testing
                    'application/pdf' as unknown as SupportedImageType,
                    'doc.pdf'
                )
            ).rejects.toThrow('Unsupported file type: application/pdf');
        });

        it('should reject avatar exceeding size limit', async () => {
            const body = new ArrayBuffer(FILE_SIZE_LIMITS.avatar + 1);

            await expect(
                storage.uploadAvatar('user123', body, 'image/jpeg', 'large.jpg')
            ).rejects.toThrow(/exceeds maximum 5MB for avatars/);
        });

        it('should accept all supported image types', async () => {
            for (const type of SUPPORTED_IMAGE_TYPES) {
                const body = new ArrayBuffer(100);
                const extension = storage.getExtensionFromContentType(type);

                const result = await storage.uploadAvatar(
                    'user123',
                    body,
                    type as SupportedImageType,
                    `photo${extension}`
                );

                expect(result.contentType).toBe(type);
            }
        });
    });

    describe('uploadDocument', () => {
        it('should upload document with ArrayBuffer body', async () => {
            const body = new ArrayBuffer(2048);
            const result = await storage.uploadDocument(
                'user123',
                body,
                'application/pdf',
                'report.pdf'
            );

            expect(result.path).toMatch(/^documents\/user123\/[a-z0-9]+\.pdf$/);
            expect(result.contentType).toBe('application/pdf');
        });

        it('should upload document with Blob body', async () => {
            const body = new Blob([new ArrayBuffer(2048)], { type: 'text/plain' });
            const result = await storage.uploadDocument(
                'user456',
                body,
                'text/plain',
                'notes.txt'
            );

            expect(result.path).toMatch(/^documents\/user456\/[a-z0-9]+\.txt$/);
            expect(result.contentType).toBe('text/plain');
        });

        it('should accept image types for documents', async () => {
            const body = new ArrayBuffer(1024);
            const result = await storage.uploadDocument(
                'user123',
                body,
                'image/png',
                'screenshot.png'
            );

            expect(result.path).toMatch(/\.png$/);
        });

        it('should accept all document types', async () => {
            for (const type of SUPPORTED_DOCUMENT_TYPES) {
                const body = new ArrayBuffer(100);

                const result = await storage.uploadDocument(
                    'user123',
                    body,
                    type as SupportedDocumentType,
                    `file${storage.getExtensionFromContentType(type)}`
                );

                expect(result.contentType).toBe(type);
            }
        });

        it('should reject documents exceeding size limit', async () => {
            const body = new ArrayBuffer(FILE_SIZE_LIMITS.document + 1);

            await expect(
                storage.uploadDocument('user123', body, 'application/pdf', 'huge.pdf')
            ).rejects.toThrow(/exceeds maximum 50MB for documents/);
        });
    });

    describe('get', () => {
        beforeEach(() => {
            // Seed a test file
            mockBucket._seed(
                'files/user123/test.txt',
                new TextEncoder().encode('test content').buffer as ArrayBuffer,
                {
                    originalName: 'test.txt',
                    accountId: 'user123',
                    uploadedAt: '2024-01-01T00:00:00.000Z',
                    size: '12',
                    width: '100',
                    height: '200',
                    thumbhash: 'testhash',
                },
                { contentType: 'text/plain', cacheControl: 'public, max-age=31536000' }
            );
        });

        it('should return file result for existing file', async () => {
            const result = await storage.get('files/user123/test.txt');

            expect(result).not.toBeNull();
            expect(result!.size).toBe(12);
            expect(result!.etag).toBe('"mock-etag-123"');
            expect(result!.body).toBeInstanceOf(ReadableStream);
        });

        it('should return null for non-existent file', async () => {
            const result = await storage.get('files/user123/nonexistent.txt');

            expect(result).toBeNull();
        });

        it('should parse custom metadata correctly', async () => {
            const result = await storage.get('files/user123/test.txt');

            expect(result!.customMetadata.originalName).toBe('test.txt');
            expect(result!.customMetadata.accountId).toBe('user123');
            expect(result!.customMetadata.size).toBe(12);
            expect(result!.customMetadata.width).toBe(100);
            expect(result!.customMetadata.height).toBe(200);
            expect(result!.customMetadata.thumbhash).toBe('testhash');
        });

        it('should set HTTP headers from metadata', async () => {
            const result = await storage.get('files/user123/test.txt');

            expect(result!.httpMetadata.get('content-type')).toBe('text/plain');
        });

        it('should handle missing custom metadata with defaults', async () => {
            // Seed file without custom metadata
            mockBucket._seed(
                'files/user123/bare.txt',
                new ArrayBuffer(10),
                undefined, // No custom metadata
                { contentType: 'text/plain' }
            );

            const result = await storage.get('files/user123/bare.txt');

            expect(result!.customMetadata.originalName).toBe('unknown');
            expect(result!.customMetadata.accountId).toBe('unknown');
            expect(result!.customMetadata.size).toBe(0);
            expect(result!.customMetadata.width).toBeUndefined();
            expect(result!.customMetadata.height).toBeUndefined();
            expect(result!.customMetadata.thumbhash).toBeUndefined();
        });

        it('should fallback to httpMetadata contentType when customMetadata missing', async () => {
            mockBucket._seed(
                'files/user123/nocontenttype.txt',
                new ArrayBuffer(10),
                {}, // Empty custom metadata
                { contentType: 'application/json' }
            );

            const result = await storage.get('files/user123/nocontenttype.txt');

            expect(result!.customMetadata.contentType).toBe('application/json');
        });
    });

    describe('head', () => {
        beforeEach(() => {
            mockBucket._seed(
                'avatars/user123/photo.jpg',
                new ArrayBuffer(5000),
                {
                    originalName: 'photo.jpg',
                    accountId: 'user123',
                    uploadedAt: '2024-01-15T12:00:00.000Z',
                    width: '800',
                    height: '600',
                    thumbhash: 'photohash',
                },
                { contentType: 'image/jpeg' }
            );
        });

        it('should return metadata for existing file', async () => {
            const result = await storage.head('avatars/user123/photo.jpg');

            expect(result).not.toBeNull();
            expect(result!.originalName).toBe('photo.jpg');
            expect(result!.accountId).toBe('user123');
            expect(result!.size).toBe(5000);
            expect(result!.width).toBe(800);
            expect(result!.height).toBe(600);
            expect(result!.thumbhash).toBe('photohash');
        });

        it('should return null for non-existent file', async () => {
            const result = await storage.head('avatars/user123/nonexistent.jpg');

            expect(result).toBeNull();
        });

        it('should handle missing optional metadata', async () => {
            mockBucket._seed(
                'files/user123/simple.txt',
                new ArrayBuffer(100),
                {
                    originalName: 'simple.txt',
                    accountId: 'user123',
                    uploadedAt: '2024-01-01T00:00:00.000Z',
                },
                { contentType: 'text/plain' }
            );

            const result = await storage.head('files/user123/simple.txt');

            expect(result!.width).toBeUndefined();
            expect(result!.height).toBeUndefined();
            expect(result!.thumbhash).toBeUndefined();
        });

        it('should use defaults for missing required metadata', async () => {
            mockBucket._seed('files/user123/nometa.bin', new ArrayBuffer(50));

            const result = await storage.head('files/user123/nometa.bin');

            expect(result!.originalName).toBe('unknown');
            expect(result!.accountId).toBe('unknown');
            // Content type defaults to application/octet-stream
            expect(result!.contentType).toBe('application/octet-stream');
        });
    });

    describe('delete', () => {
        beforeEach(() => {
            mockBucket._seed('files/user123/delete-me.txt', new ArrayBuffer(100));
        });

        it('should delete a file', async () => {
            await storage.delete('files/user123/delete-me.txt');

            expect(mockBucket.delete).toHaveBeenCalledWith('files/user123/delete-me.txt');
        });

        it('should not throw for non-existent file', async () => {
            await expect(
                storage.delete('files/user123/nonexistent.txt')
            ).resolves.not.toThrow();
        });
    });

    describe('deleteMany', () => {
        beforeEach(() => {
            mockBucket._seed('files/user123/file1.txt', new ArrayBuffer(100));
            mockBucket._seed('files/user123/file2.txt', new ArrayBuffer(200));
            mockBucket._seed('files/user123/file3.txt', new ArrayBuffer(300));
        });

        it('should delete multiple files', async () => {
            const paths = [
                'files/user123/file1.txt',
                'files/user123/file2.txt',
                'files/user123/file3.txt',
            ];

            await storage.deleteMany(paths);

            expect(mockBucket.delete).toHaveBeenCalledWith(paths);
        });

        it('should handle empty array without calling delete', async () => {
            await storage.deleteMany([]);

            expect(mockBucket.delete).not.toHaveBeenCalled();
        });

        it('should handle single item array', async () => {
            await storage.deleteMany(['files/user123/file1.txt']);

            expect(mockBucket.delete).toHaveBeenCalledWith(['files/user123/file1.txt']);
        });
    });

    describe('list', () => {
        beforeEach(() => {
            // Seed multiple files for listing tests
            for (let i = 1; i <= 5; i++) {
                mockBucket._seed(
                    `files/user123/file${i}.txt`,
                    new ArrayBuffer(i * 100),
                    { originalName: `file${i}.txt`, accountId: 'user123' }
                );
            }
            mockBucket._seed(
                'avatars/user123/photo.jpg',
                new ArrayBuffer(5000),
                { originalName: 'photo.jpg', accountId: 'user123' }
            );
        });

        it('should list files with prefix', async () => {
            const result = await storage.list('files/user123/');

            expect(result.objects.length).toBe(5);
            expect(result.truncated).toBe(false);
            expect(result.cursor).toBeUndefined();
        });

        it('should return empty list for non-matching prefix', async () => {
            const result = await storage.list('documents/user123/');

            expect(result.objects.length).toBe(0);
            expect(result.truncated).toBe(false);
        });

        it('should respect limit option', async () => {
            const result = await storage.list('files/user123/', { limit: 2 });

            expect(result.objects.length).toBe(2);
            expect(result.truncated).toBe(true);
            expect(result.cursor).toBeDefined();
        });

        it('should handle cursor-based pagination', async () => {
            // Get first page
            const page1 = await storage.list('files/user123/', { limit: 2 });
            expect(page1.objects.length).toBe(2);
            expect(page1.truncated).toBe(true);

            // Get second page using cursor
            const page2 = await storage.list('files/user123/', {
                limit: 2,
                cursor: page1.cursor,
            });
            expect(page2.objects.length).toBe(2);
            expect(page2.truncated).toBe(true);

            // Get third page
            const page3 = await storage.list('files/user123/', {
                limit: 2,
                cursor: page2.cursor,
            });
            expect(page3.objects.length).toBe(1);
            expect(page3.truncated).toBe(false);
        });

        it('should use default limit of 100', async () => {
            // Add more files to test default limit
            for (let i = 6; i <= 50; i++) {
                mockBucket._seed(`files/user123/file${i}.txt`, new ArrayBuffer(100));
            }

            const result = await storage.list('files/user123/');

            expect(result.objects.length).toBe(50);
        });
    });

    describe('exists', () => {
        beforeEach(() => {
            mockBucket._seed('files/user123/exists.txt', new ArrayBuffer(100));
        });

        it('should return true for existing file', async () => {
            const exists = await storage.exists('files/user123/exists.txt');

            expect(exists).toBe(true);
        });

        it('should return false for non-existent file', async () => {
            const exists = await storage.exists('files/user123/not-there.txt');

            expect(exists).toBe(false);
        });
    });

    describe('copy', () => {
        beforeEach(() => {
            mockBucket._seed(
                'files/user123/original.txt',
                new TextEncoder().encode('original content').buffer as ArrayBuffer,
                {
                    originalName: 'original.txt',
                    accountId: 'user123',
                    uploadedAt: '2024-01-01T00:00:00.000Z',
                },
                { contentType: 'text/plain', cacheControl: 'public, max-age=86400' }
            );
        });

        it('should copy file to new location', async () => {
            const result = await storage.copy(
                'files/user123/original.txt',
                'files/user123/copy.txt'
            );

            expect(result).toBeDefined();
            expect(result.key).toBe('files/user123/copy.txt');

            // Verify copy was created
            const copy = await storage.exists('files/user123/copy.txt');
            expect(copy).toBe(true);
        });

        it('should preserve metadata when copying', async () => {
            await storage.copy(
                'files/user123/original.txt',
                'files/user123/copy-with-meta.txt'
            );

            // Check put was called with original metadata
            expect(mockBucket.put).toHaveBeenCalledWith(
                'files/user123/copy-with-meta.txt',
                expect.any(ReadableStream),
                expect.objectContaining({
                    customMetadata: expect.objectContaining({
                        originalName: 'original.txt',
                        accountId: 'user123',
                    }),
                })
            );
        });

        it('should throw error when source file not found', async () => {
            await expect(
                storage.copy('files/user123/nonexistent.txt', 'files/user123/dest.txt')
            ).rejects.toThrow('Source file not found: files/user123/nonexistent.txt');
        });

        it('should throw error when copy operation fails', async () => {
            // Make put return null for this test
            const originalPut = mockBucket.put;
            mockBucket.put = vi.fn().mockResolvedValue(null);

            await expect(
                storage.copy('files/user123/original.txt', 'files/user123/failed.txt')
            ).rejects.toThrow('Failed to copy file');

            mockBucket.put = originalPut;
        });

        it('should allow copying to different category', async () => {
            const result = await storage.copy(
                'files/user123/original.txt',
                'documents/user123/archived.txt'
            );

            expect(result.key).toBe('documents/user123/archived.txt');
        });

        it('should allow copying to different user namespace', async () => {
            const result = await storage.copy(
                'files/user123/original.txt',
                'files/user456/shared.txt'
            );

            expect(result.key).toBe('files/user456/shared.txt');
        });
    });

    describe('Error Handling Edge Cases', () => {
        it('should handle R2 bucket errors gracefully', async () => {
            mockBucket.get = vi.fn().mockRejectedValue(new Error('R2 unavailable'));

            await expect(storage.get('any/path')).rejects.toThrow('R2 unavailable');
        });

        it('should handle upload errors', async () => {
            mockBucket.put = vi.fn().mockRejectedValue(new Error('Upload failed'));

            await expect(
                storage.upload('path', new ArrayBuffer(10), {
                    originalName: 'test',
                    contentType: 'text/plain',
                    size: 10,
                    accountId: 'user',
                    uploadedAt: new Date().toISOString(),
                })
            ).rejects.toThrow('Upload failed');
        });

        it('should handle list errors', async () => {
            mockBucket.list = vi.fn().mockRejectedValue(new Error('List failed'));

            await expect(storage.list('prefix/')).rejects.toThrow('List failed');
        });

        it('should handle delete errors', async () => {
            mockBucket.delete = vi.fn().mockRejectedValue(new Error('Delete failed'));

            await expect(storage.delete('path')).rejects.toThrow('Delete failed');
        });
    });

    describe('Metadata Parsing Edge Cases', () => {
        it('should handle malformed size metadata in get', async () => {
            mockBucket._seed(
                'files/user123/badsize.txt',
                new ArrayBuffer(100),
                { size: 'not-a-number' }
            );

            const result = await storage.get('files/user123/badsize.txt');

            // parseInt('not-a-number', 10) returns NaN
            expect(result!.customMetadata.size).toBeNaN();
        });

        it('should handle malformed dimension metadata in get', async () => {
            mockBucket._seed(
                'files/user123/baddims.txt',
                new ArrayBuffer(100),
                { width: 'invalid', height: 'invalid' }
            );

            const result = await storage.get('files/user123/baddims.txt');

            expect(result!.customMetadata.width).toBeNaN();
            expect(result!.customMetadata.height).toBeNaN();
        });

        it('should handle malformed dimension metadata in head', async () => {
            mockBucket._seed(
                'files/user123/baddims2.txt',
                new ArrayBuffer(100),
                { width: 'bad', height: 'bad' }
            );

            const result = await storage.head('files/user123/baddims2.txt');

            expect(result!.width).toBeNaN();
            expect(result!.height).toBeNaN();
        });
    });
});
