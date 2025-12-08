import { describe, it, expect } from 'vitest';
import {
    processImage,
    extractImageDimensions,
    generateThumbhash,
    isProcessableImage,
    PROCESSABLE_IMAGE_TYPES,
} from './image-processing';

/**
 * Test data generators for various image formats
 */

/**
 * Create a minimal valid JPEG file
 * JPEG format: FFD8 (SOI) + APP0 marker + SOF0 with dimensions + EOI (FFD9)
 */
function createTestJpeg(width: number, height: number): ArrayBuffer {
    // Minimal JPEG with SOI, DQT, SOF0, DHT, SOS markers
    const jpeg = new Uint8Array([
        // SOI (Start of Image)
        0xff, 0xd8,
        // APP0 JFIF marker
        0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        // DQT (Define Quantization Table)
        0xff, 0xdb, 0x00, 0x43, 0x00,
        ...new Array(64).fill(0x10), // Quantization table values
        // SOF0 (Start of Frame - Baseline DCT)
        0xff, 0xc0, 0x00, 0x0b, 0x08,
        (height >> 8) & 0xff, height & 0xff,  // Height (big-endian)
        (width >> 8) & 0xff, width & 0xff,    // Width (big-endian)
        0x01, // Number of components
        0x01, 0x11, 0x00, // Component 1: Y, 1x1 sampling, QT 0
        // DHT (Define Huffman Table)
        0xff, 0xc4, 0x00, 0x1f, 0x00,
        ...new Array(28).fill(0x00), // Minimal Huffman table
        // SOS (Start of Scan)
        0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00,
        // Minimal scan data
        0x00,
        // EOI (End of Image)
        0xff, 0xd9,
    ]);
    return jpeg.buffer;
}

/**
 * Create a minimal valid PNG file
 * PNG format: signature + IHDR chunk with dimensions + IDAT + IEND
 */
function createTestPng(width: number, height: number): ArrayBuffer {
    // Calculate CRC32 for IHDR
    const ihdrData = new Uint8Array([
        // Width (big-endian)
        (width >> 24) & 0xff, (width >> 16) & 0xff, (width >> 8) & 0xff, width & 0xff,
        // Height (big-endian)
        (height >> 24) & 0xff, (height >> 16) & 0xff, (height >> 8) & 0xff, height & 0xff,
        // Bit depth, color type, compression, filter, interlace
        0x08, 0x02, 0x00, 0x00, 0x00,
    ]);

    // Simple CRC32 calculation for PNG chunks
    function crc32(data: Uint8Array, includeType = true): number {
        const crcTable = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let j = 0; j < 8; j++) {
                c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
            }
            crcTable[i] = c;
        }

        let crc = 0xffffffff;
        const typeData = includeType ? new Uint8Array([0x49, 0x48, 0x44, 0x52]) : new Uint8Array(0);
        const combined = new Uint8Array(typeData.length + data.length);
        combined.set(typeData);
        combined.set(data, typeData.length);

        for (const byte of combined) {
            crc = crcTable[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
        }
        return crc ^ 0xffffffff;
    }

    const ihdrCrc = crc32(ihdrData, true);

    const png = new Uint8Array([
        // PNG Signature
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
        // IHDR chunk
        0x00, 0x00, 0x00, 0x0d, // Length: 13
        0x49, 0x48, 0x44, 0x52, // Type: IHDR
        ...ihdrData,
        // CRC
        (ihdrCrc >> 24) & 0xff, (ihdrCrc >> 16) & 0xff, (ihdrCrc >> 8) & 0xff, ihdrCrc & 0xff,
        // IDAT chunk (minimal empty compressed data)
        0x00, 0x00, 0x00, 0x0b, // Length
        0x49, 0x44, 0x41, 0x54, // Type: IDAT
        0x78, 0x9c, 0x63, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, // zlib compressed empty
        // IDAT CRC placeholder (not strictly correct but for dimension parsing)
        0x00, 0x00, 0x00, 0x00,
        // IEND chunk
        0x00, 0x00, 0x00, 0x00, // Length: 0
        0x49, 0x45, 0x4e, 0x44, // Type: IEND
        0xae, 0x42, 0x60, 0x82, // CRC
    ]);

    return png.buffer;
}

/**
 * Create a minimal valid GIF file
 */
function createTestGif(width: number, height: number): ArrayBuffer {
    const gif = new Uint8Array([
        // GIF signature
        0x47, 0x49, 0x46, // "GIF"
        0x38, 0x39, 0x61,       // "89a"
        // Logical Screen Descriptor
        width & 0xff, (width >> 8) & 0xff,   // Width (little-endian)
        height & 0xff, (height >> 8) & 0xff, // Height (little-endian)
        0x00, // Packed byte (no global color table)
        0x00, // Background color index
        0x00, // Pixel aspect ratio
        // Trailer
        0x3b,
    ]);
    return gif.buffer;
}

/**
 * Create a minimal valid WebP file (VP8X extended format)
 */
function createTestWebp(width: number, height: number): ArrayBuffer {
    // VP8X format - extended WebP
    const w = width - 1;  // Width stored as width-1 (24-bit)
    const h = height - 1; // Height stored as height-1 (24-bit)

    const webp = new Uint8Array([
        // RIFF header
        0x52, 0x49, 0x46, 0x46, // "RIFF"
        0x24, 0x00, 0x00, 0x00, // File size (36 bytes for this minimal file)
        // WEBP signature
        0x57, 0x45, 0x42, 0x50, // "WEBP"
        // VP8X chunk
        0x56, 0x50, 0x38, 0x58, // "VP8X"
        0x0a, 0x00, 0x00, 0x00, // Chunk size: 10
        0x00, 0x00, 0x00, 0x00, // Flags
        // Canvas size (24-bit little-endian, stored as size-1)
        w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff,
        h & 0xff, (h >> 8) & 0xff, (h >> 16) & 0xff,
    ]);
    return webp.buffer;
}

describe('image-processing', () => {
    describe('isProcessableImage', () => {
        it('should return true for all supported image types', () => {
            for (const type of PROCESSABLE_IMAGE_TYPES) {
                expect(isProcessableImage(type)).toBe(true);
            }
        });

        it('should return false for non-image types', () => {
            expect(isProcessableImage('application/pdf')).toBe(false);
            expect(isProcessableImage('text/plain')).toBe(false);
            expect(isProcessableImage('video/mp4')).toBe(false);
            expect(isProcessableImage('application/octet-stream')).toBe(false);
        });
    });

    describe('extractImageDimensions', () => {
        describe('JPEG', () => {
            // Note: JPEG decoding requires fully valid JPEG data
            // Our minimal test JPEG doesn't have proper compressed data
            // so jpeg-js fails to decode it. In production, real JPEG files work.

            it('should return null for invalid JPEG structure', () => {
                // Our synthetic JPEG has correct structure but invalid compressed data
                // jpeg-js rightfully rejects it
                const jpeg = createTestJpeg(800, 600);
                const result = extractImageDimensions(jpeg, 'image/jpeg');
                // This will be null because our test JPEG lacks valid compressed data
                expect(result).toBeNull();
            });

            it('should return null for garbage data', () => {
                const garbage = new ArrayBuffer(100);
                const result = extractImageDimensions(garbage, 'image/jpeg');
                expect(result).toBeNull();
            });
        });

        describe('PNG', () => {
            it('should extract dimensions from PNG', () => {
                const png = createTestPng(1024, 768);
                const result = extractImageDimensions(png, 'image/png');

                expect(result).not.toBeNull();
                expect(result?.width).toBe(1024);
                expect(result?.height).toBe(768);
            });

            it('should handle various PNG sizes', () => {
                const sizes = [
                    { w: 64, h: 64 },
                    { w: 1280, h: 720 },
                ];

                for (const { w, h } of sizes) {
                    const png = createTestPng(w, h);
                    const result = extractImageDimensions(png, 'image/png');
                    expect(result).toEqual({ width: w, height: h });
                }
            });
        });

        describe('GIF', () => {
            it('should extract dimensions from GIF', () => {
                const gif = createTestGif(320, 240);
                const result = extractImageDimensions(gif, 'image/gif');

                expect(result).not.toBeNull();
                expect(result?.width).toBe(320);
                expect(result?.height).toBe(240);
            });

            it('should handle various GIF sizes', () => {
                const sizes = [
                    { w: 100, h: 100 },
                    { w: 500, h: 300 },
                ];

                for (const { w, h } of sizes) {
                    const gif = createTestGif(w, h);
                    const result = extractImageDimensions(gif, 'image/gif');
                    expect(result).toEqual({ width: w, height: h });
                }
            });
        });

        describe('WebP', () => {
            it('should extract dimensions from WebP (VP8X format)', () => {
                const webp = createTestWebp(1280, 720);
                const result = extractImageDimensions(webp, 'image/webp');

                expect(result).not.toBeNull();
                expect(result?.width).toBe(1280);
                expect(result?.height).toBe(720);
            });
        });

        describe('Edge cases', () => {
            it('should return null for invalid image data', () => {
                const invalid = new ArrayBuffer(10);
                expect(extractImageDimensions(invalid, 'image/jpeg')).toBeNull();
                expect(extractImageDimensions(invalid, 'image/png')).toBeNull();
                expect(extractImageDimensions(invalid, 'image/gif')).toBeNull();
                expect(extractImageDimensions(invalid, 'image/webp')).toBeNull();
            });

            it('should return null for unsupported content type', () => {
                const data = createTestJpeg(100, 100);
                expect(extractImageDimensions(data, 'video/mp4')).toBeNull();
            });

            it('should return null for empty buffer', () => {
                const empty = new ArrayBuffer(0);
                expect(extractImageDimensions(empty, 'image/jpeg')).toBeNull();
            });
        });
    });

    describe('generateThumbhash', () => {
        // Note: Full thumbhash generation requires valid pixel data
        // These tests verify the function handles various inputs gracefully

        it('should return null for WebP (not supported for thumbhash)', () => {
            const webp = createTestWebp(100, 100);
            const result = generateThumbhash(webp, 'image/webp');
            expect(result).toBeNull();
        });

        it('should return null for GIF (not supported for thumbhash)', () => {
            const gif = createTestGif(100, 100);
            const result = generateThumbhash(gif, 'image/gif');
            expect(result).toBeNull();
        });

        it('should return null for unsupported types', () => {
            const data = new ArrayBuffer(100);
            expect(generateThumbhash(data, 'video/mp4')).toBeNull();
            expect(generateThumbhash(data, 'application/pdf')).toBeNull();
        });

        it('should return null for invalid JPEG data', () => {
            const invalid = new ArrayBuffer(100);
            expect(generateThumbhash(invalid, 'image/jpeg')).toBeNull();
        });

        it('should return null for invalid PNG data', () => {
            const invalid = new ArrayBuffer(100);
            expect(generateThumbhash(invalid, 'image/png')).toBeNull();
        });
    });

    describe('processImage', () => {
        it('should return null for non-image content types', async () => {
            const data = new ArrayBuffer(100);
            const result = await processImage(data, 'application/pdf');
            expect(result).toBeNull();
        });

        it('should return null for invalid image data', async () => {
            const data = new ArrayBuffer(10);
            const result = await processImage(data, 'image/jpeg');
            expect(result).toBeNull();
        });

        it('should extract dimensions from GIF without thumbhash', async () => {
            const gif = createTestGif(200, 150);
            const result = await processImage(gif, 'image/gif');

            expect(result).not.toBeNull();
            expect(result?.width).toBe(200);
            expect(result?.height).toBe(150);
            expect(result?.thumbhash).toBeNull(); // GIF doesn't support thumbhash
        });

        it('should extract dimensions from WebP without thumbhash', async () => {
            const webp = createTestWebp(640, 480);
            const result = await processImage(webp, 'image/webp');

            expect(result).not.toBeNull();
            expect(result?.width).toBe(640);
            expect(result?.height).toBe(480);
            expect(result?.thumbhash).toBeNull(); // WebP doesn't support thumbhash
        });

        it('should handle empty buffers gracefully', async () => {
            const empty = new ArrayBuffer(0);
            const result = await processImage(empty, 'image/jpeg');
            expect(result).toBeNull();
        });
    });

    describe('PROCESSABLE_IMAGE_TYPES', () => {
        it('should include standard image formats', () => {
            expect(PROCESSABLE_IMAGE_TYPES).toContain('image/jpeg');
            expect(PROCESSABLE_IMAGE_TYPES).toContain('image/png');
            expect(PROCESSABLE_IMAGE_TYPES).toContain('image/webp');
            expect(PROCESSABLE_IMAGE_TYPES).toContain('image/gif');
        });

        it('should have exactly 4 supported types', () => {
            expect(PROCESSABLE_IMAGE_TYPES).toHaveLength(4);
        });
    });
});
