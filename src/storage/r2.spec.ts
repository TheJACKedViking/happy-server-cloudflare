import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    R2Storage,
    createR2Storage,
    SUPPORTED_FILE_TYPES,
    SUPPORTED_IMAGE_TYPES,
    SUPPORTED_DOCUMENT_TYPES,
    FILE_SIZE_LIMITS,
} from './r2';

/**
 * Mock R2 Bucket implementation for testing
 */
function createMockR2Bucket(): R2Bucket {
    const storage = new Map<string, { body: Uint8Array; metadata: R2ObjectBody }>();

    return {
        put: vi.fn(async (key: string, value: ArrayBuffer | Blob | ReadableStream, options?: R2PutOptions) => {
            const buffer = value instanceof ArrayBuffer
                ? new Uint8Array(value)
                : value instanceof Blob
                    ? new Uint8Array(await value.arrayBuffer())
                    : new Uint8Array(0); // ReadableStream would need special handling

            const obj: R2Object = {
                key,
                version: 'v1',
                size: buffer.byteLength,
                etag: `"${Date.now()}"`,
                httpEtag: `"${Date.now()}"`,
                checksums: { toJSON: () => ({}) } as R2Checksums,
                httpMetadata: options?.httpMetadata as R2HTTPMetadata || {},
                customMetadata: options?.customMetadata || {},
                uploaded: new Date(),
                storageClass: 'Standard',
                range: { offset: 0, length: buffer.byteLength },
                writeHttpMetadata: vi.fn((headers: Headers) => {
                    if (options?.httpMetadata) {
                        const hm = options.httpMetadata as R2HTTPMetadata;
                        if (hm.contentType) headers.set('Content-Type', hm.contentType);
                        if (hm.cacheControl) headers.set('Cache-Control', hm.cacheControl);
                    }
                }),
            };

            storage.set(key, { body: buffer, metadata: obj as unknown as R2ObjectBody });
            return obj;
        }),

        get: vi.fn(async (key: string): Promise<R2ObjectBody | null> => {
            const item = storage.get(key);
            if (!item) return null;

            const body = new ReadableStream({
                start(controller) {
                    controller.enqueue(item.body);
                    controller.close();
                },
            });

            return {
                ...item.metadata,
                body,
                bodyUsed: false,
                arrayBuffer: async () => item.body.buffer,
                text: async () => new TextDecoder().decode(item.body),
                json: async () => JSON.parse(new TextDecoder().decode(item.body)),
                blob: async () => new Blob([item.body]),
            } as unknown as R2ObjectBody;
        }),

        head: vi.fn(async (key: string): Promise<R2Object | null> => {
            const item = storage.get(key);
            if (!item) return null;
            return item.metadata as unknown as R2Object;
        }),

        delete: vi.fn(async (keys: string | string[]) => {
            const keysArray = Array.isArray(keys) ? keys : [keys];
            for (const key of keysArray) {
                storage.delete(key);
            }
        }),

        list: vi.fn(async (options?: R2ListOptions) => {
            const objects: R2Object[] = [];
            for (const [key, item] of storage.entries()) {
                if (!options?.prefix || key.startsWith(options.prefix)) {
                    objects.push(item.metadata as unknown as R2Object);
                }
            }

            const limit = options?.limit || 1000;
            const truncated = objects.length > limit;

            return {
                objects: objects.slice(0, limit),
                truncated,
                cursor: truncated ? 'next-cursor' : undefined,
                delimitedPrefixes: [],
            };
        }),

        createMultipartUpload: vi.fn(),
        resumeMultipartUpload: vi.fn(),
    } as unknown as R2Bucket;
}

describe('R2Storage', () => {
    let mockBucket: R2Bucket;
    let r2: R2Storage;

    beforeEach(() => {
        mockBucket = createMockR2Bucket();
        r2 = new R2Storage(mockBucket);
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    describe('generatePath', () => {
        it('should generate unique paths with proper structure', () => {
            const path1 = r2.generatePath('user123', 'avatars', '.jpg');
            const path2 = r2.generatePath('user123', 'avatars', '.jpg');

            expect(path1).toMatch(/^avatars\/user123\/[a-z0-9]+\.jpg$/);
            expect(path2).toMatch(/^avatars\/user123\/[a-z0-9]+\.jpg$/);
            expect(path1).not.toBe(path2); // Unique IDs
        });

        it('should handle extension without leading dot', () => {
            const path = r2.generatePath('user123', 'documents', 'pdf');
            expect(path).toMatch(/^documents\/user123\/[a-z0-9]+\.pdf$/);
        });

        it('should support different categories', () => {
            const avatarPath = r2.generatePath('user1', 'avatars', '.png');
            const docPath = r2.generatePath('user1', 'documents', '.pdf');
            const filePath = r2.generatePath('user1', 'files', '.txt');

            expect(avatarPath).toContain('avatars/');
            expect(docPath).toContain('documents/');
            expect(filePath).toContain('files/');
        });
    });

    describe('getExtensionFromContentType', () => {
        it('should return correct extension for supported types', () => {
            expect(r2.getExtensionFromContentType('image/jpeg')).toBe('.jpg');
            expect(r2.getExtensionFromContentType('image/png')).toBe('.png');
            expect(r2.getExtensionFromContentType('image/gif')).toBe('.gif');
            expect(r2.getExtensionFromContentType('image/webp')).toBe('.webp');
            expect(r2.getExtensionFromContentType('application/pdf')).toBe('.pdf');
            expect(r2.getExtensionFromContentType('text/plain')).toBe('.txt');
            expect(r2.getExtensionFromContentType('application/json')).toBe('.json');
            expect(r2.getExtensionFromContentType('text/markdown')).toBe('.md');
        });

        it('should return .bin for unknown types', () => {
            expect(r2.getExtensionFromContentType('application/octet-stream')).toBe('.bin');
            expect(r2.getExtensionFromContentType('unknown/type')).toBe('.bin');
        });
    });

    describe('validateFile', () => {
        it('should accept supported file types', () => {
            expect(() => r2.validateFile('image/jpeg', 1000)).not.toThrow();
            expect(() => r2.validateFile('application/pdf', 1000)).not.toThrow();
            expect(() => r2.validateFile('text/plain', 1000)).not.toThrow();
        });

        it('should reject unsupported file types', () => {
            expect(() => r2.validateFile('video/mp4', 1000)).toThrow(
                /Unsupported file type/
            );
            expect(() => r2.validateFile('application/exe', 1000)).toThrow(
                /Unsupported file type/
            );
        });

        it('should enforce avatar size limits (5MB)', () => {
            const maxSize = FILE_SIZE_LIMITS.avatar;

            expect(() => r2.validateFile('image/jpeg', maxSize, 'avatars')).not.toThrow();
            expect(() => r2.validateFile('image/jpeg', maxSize + 1, 'avatars')).toThrow(
                /exceeds maximum 5MB/
            );
        });

        it('should enforce document size limits (50MB)', () => {
            const maxSize = FILE_SIZE_LIMITS.document;

            expect(() => r2.validateFile('application/pdf', maxSize, 'documents')).not.toThrow();
            expect(() => r2.validateFile('application/pdf', maxSize + 1, 'documents')).toThrow(
                /exceeds maximum 50MB/
            );
        });

        it('should enforce general file size limits (100MB)', () => {
            const maxSize = FILE_SIZE_LIMITS.general;

            expect(() => r2.validateFile('image/png', maxSize, 'files')).not.toThrow();
            expect(() => r2.validateFile('image/png', maxSize + 1, 'files')).toThrow(
                /exceeds maximum 100MB/
            );
        });
    });

    describe('upload', () => {
        it('should upload a file with metadata', async () => {
            const content = new TextEncoder().encode('Hello, World!');
            const path = 'files/user123/test.txt';

            const result = await r2.upload(path, content.buffer as ArrayBuffer, {
                originalName: 'hello.txt',
                contentType: 'text/plain',
                size: content.byteLength,
                accountId: 'user123',
                uploadedAt: new Date().toISOString(),
            });

            expect(result.path).toBe(path);
            expect(result.size).toBe(content.byteLength);
            expect(result.contentType).toBe('text/plain');
            expect(result.etag).toBeDefined();

            expect(mockBucket.put).toHaveBeenCalledWith(
                path,
                content.buffer as ArrayBuffer,
                expect.objectContaining({
                    httpMetadata: expect.objectContaining({
                        contentType: 'text/plain',
                    }),
                    customMetadata: expect.objectContaining({
                        originalName: 'hello.txt',
                        accountId: 'user123',
                    }),
                })
            );
        });

        it('should include image dimensions in metadata when provided', async () => {
            const content = new Uint8Array(100);
            const path = 'avatars/user123/photo.jpg';

            await r2.upload(path, content.buffer as ArrayBuffer, {
                originalName: 'photo.jpg',
                contentType: 'image/jpeg',
                size: 100,
                accountId: 'user123',
                uploadedAt: new Date().toISOString(),
                width: 800,
                height: 600,
            });

            expect(mockBucket.put).toHaveBeenCalledWith(
                path,
                content.buffer as ArrayBuffer,
                expect.objectContaining({
                    customMetadata: expect.objectContaining({
                        width: '800',
                        height: '600',
                    }),
                })
            );
        });
    });

    describe('uploadAvatar', () => {
        it('should upload avatar with proper validation', async () => {
            const content = new Uint8Array(1000);

            const result = await r2.uploadAvatar(
                'user123',
                content.buffer as ArrayBuffer,
                'image/jpeg',
                'profile.jpg',
                { width: 200, height: 200 }
            );

            expect(result.path).toMatch(/^avatars\/user123\/[a-z0-9]+\.jpg$/);
            expect(mockBucket.put).toHaveBeenCalled();
        });

        it('should reject non-image files for avatars', async () => {
            const content = new Uint8Array(1000);

            await expect(
                r2.uploadAvatar(
                    'user123',
                    content.buffer as ArrayBuffer,
                    // @ts-expect-error - Testing invalid type
                    'application/pdf',
                    'doc.pdf'
                )
            ).rejects.toThrow(/Unsupported file type/);
        });

        it('should reject oversized avatars', async () => {
            const content = new Uint8Array(FILE_SIZE_LIMITS.avatar + 1);

            await expect(
                r2.uploadAvatar(
                    'user123',
                    content.buffer as ArrayBuffer,
                    'image/jpeg',
                    'big.jpg'
                )
            ).rejects.toThrow(/exceeds maximum/);
        });
    });

    describe('get', () => {
        it('should return file with metadata', async () => {
            // First upload a file
            const content = new TextEncoder().encode('Test content');
            await r2.upload('files/user123/test.txt', content.buffer as ArrayBuffer, {
                originalName: 'test.txt',
                contentType: 'text/plain',
                size: content.byteLength,
                accountId: 'user123',
                uploadedAt: new Date().toISOString(),
            });

            const result = await r2.get('files/user123/test.txt');

            expect(result).not.toBeNull();
            expect(result?.body).toBeDefined();
            expect(result?.customMetadata.originalName).toBe('test.txt');
            expect(result?.customMetadata.accountId).toBe('user123');
        });

        it('should return null for non-existent files', async () => {
            const result = await r2.get('files/nonexistent.txt');
            expect(result).toBeNull();
        });
    });

    describe('head', () => {
        it('should return metadata without body', async () => {
            const content = new TextEncoder().encode('Test');
            await r2.upload('files/user123/test.txt', content.buffer as ArrayBuffer, {
                originalName: 'test.txt',
                contentType: 'text/plain',
                size: content.byteLength,
                accountId: 'user123',
                uploadedAt: new Date().toISOString(),
            });

            const metadata = await r2.head('files/user123/test.txt');

            expect(metadata).not.toBeNull();
            expect(metadata?.originalName).toBe('test.txt');
            expect(metadata?.size).toBe(content.byteLength);
        });

        it('should return null for non-existent files', async () => {
            const result = await r2.head('files/nonexistent.txt');
            expect(result).toBeNull();
        });
    });

    describe('delete', () => {
        it('should delete a file', async () => {
            const content = new TextEncoder().encode('Test');
            await r2.upload('files/user123/test.txt', content.buffer as ArrayBuffer, {
                originalName: 'test.txt',
                contentType: 'text/plain',
                size: content.byteLength,
                accountId: 'user123',
                uploadedAt: new Date().toISOString(),
            });

            await r2.delete('files/user123/test.txt');

            expect(mockBucket.delete).toHaveBeenCalledWith('files/user123/test.txt');

            // Verify file is gone
            const result = await r2.get('files/user123/test.txt');
            expect(result).toBeNull();
        });
    });

    describe('deleteMany', () => {
        it('should delete multiple files', async () => {
            const paths = ['files/user123/a.txt', 'files/user123/b.txt'];

            await r2.deleteMany(paths);

            expect(mockBucket.delete).toHaveBeenCalledWith(paths);
        });

        it('should handle empty array', async () => {
            await r2.deleteMany([]);
            expect(mockBucket.delete).not.toHaveBeenCalled();
        });
    });

    describe('list', () => {
        it('should list files with prefix', async () => {
            // Upload some files
            const content = new Uint8Array(10);
            await r2.upload('avatars/user123/a.jpg', content.buffer as ArrayBuffer, {
                originalName: 'a.jpg',
                contentType: 'image/jpeg',
                size: 10,
                accountId: 'user123',
                uploadedAt: new Date().toISOString(),
            });
            await r2.upload('avatars/user123/b.jpg', content.buffer as ArrayBuffer, {
                originalName: 'b.jpg',
                contentType: 'image/jpeg',
                size: 10,
                accountId: 'user123',
                uploadedAt: new Date().toISOString(),
            });

            const result = await r2.list('avatars/user123/');

            expect(result.objects.length).toBe(2);
            expect(result.truncated).toBe(false);
        });
    });

    describe('exists', () => {
        it('should return true for existing files', async () => {
            const content = new TextEncoder().encode('Test');
            await r2.upload('files/user123/test.txt', content.buffer as ArrayBuffer, {
                originalName: 'test.txt',
                contentType: 'text/plain',
                size: content.byteLength,
                accountId: 'user123',
                uploadedAt: new Date().toISOString(),
            });

            const exists = await r2.exists('files/user123/test.txt');
            expect(exists).toBe(true);
        });

        it('should return false for non-existent files', async () => {
            const exists = await r2.exists('files/nonexistent.txt');
            expect(exists).toBe(false);
        });
    });
});

describe('createR2Storage', () => {
    it('should create R2Storage instance', () => {
        const mockBucket = createMockR2Bucket();
        const storage = createR2Storage(mockBucket);
        expect(storage).toBeInstanceOf(R2Storage);
    });
});

describe('Constants', () => {
    describe('SUPPORTED_FILE_TYPES', () => {
        it('should include all image types', () => {
            for (const type of SUPPORTED_IMAGE_TYPES) {
                expect(SUPPORTED_FILE_TYPES).toContain(type);
            }
        });

        it('should include all document types', () => {
            for (const type of SUPPORTED_DOCUMENT_TYPES) {
                expect(SUPPORTED_FILE_TYPES).toContain(type);
            }
        });
    });

    describe('FILE_SIZE_LIMITS', () => {
        it('should have correct limits', () => {
            expect(FILE_SIZE_LIMITS.avatar).toBe(5 * 1024 * 1024); // 5MB
            expect(FILE_SIZE_LIMITS.document).toBe(50 * 1024 * 1024); // 50MB
            expect(FILE_SIZE_LIMITS.general).toBe(100 * 1024 * 1024); // 100MB
        });
    });
});
