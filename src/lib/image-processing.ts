/**
 * Image Processing Module
 *
 * Provides image dimension extraction and thumbhash generation for uploaded images.
 * Supports JPEG, PNG, WebP, and GIF formats with graceful fallback.
 *
 * @module lib/image-processing
 */

import { rgbaToThumbHash } from 'thumbhash';
import * as jpeg from 'jpeg-js';
import UPNG from 'upng-js';

/**
 * Result of image processing
 */
export interface ImageProcessingResult {
    /** Image width in pixels */
    width: number;
    /** Image height in pixels */
    height: number;
    /** Base64-encoded thumbhash for placeholder generation */
    thumbhash: string | null;
}

/**
 * Supported image MIME types for processing
 */
export const PROCESSABLE_IMAGE_TYPES = [
    'image/jpeg',
    'image/png',
    'image/webp',
    'image/gif',
] as const;

export type ProcessableImageType = (typeof PROCESSABLE_IMAGE_TYPES)[number];

/**
 * Check if a content type is a processable image
 */
export function isProcessableImage(contentType: string): contentType is ProcessableImageType {
    return PROCESSABLE_IMAGE_TYPES.includes(contentType as ProcessableImageType);
}

/**
 * Maximum dimension for thumbhash generation (images are resized to this)
 */
const THUMBHASH_MAX_DIM = 100;

/**
 * Maximum image resolution to process (in megapixels)
 * Prevents memory issues with very large images
 */
const MAX_MEGAPIXELS = 25;

/**
 * Safely get byte from array with default 0
 */
function getByte(data: Uint8Array, index: number): number {
    return data[index] ?? 0;
}

/**
 * Extract dimensions from JPEG image
 */
function extractJpegDimensions(data: Uint8Array): { width: number; height: number } | null {
    try {
        const decoded = jpeg.decode(data, {
            useTArray: true,
            maxResolutionInMP: MAX_MEGAPIXELS,
            maxMemoryUsageInMB: 256,
        });
        return { width: decoded.width, height: decoded.height };
    } catch {
        return null;
    }
}

/**
 * Extract dimensions from PNG image
 */
function extractPngDimensions(data: Uint8Array): { width: number; height: number } | null {
    try {
        // Create a proper ArrayBuffer from Uint8Array
        // Use ArrayBuffer constructor to ensure we get ArrayBuffer (not SharedArrayBuffer)
        const buffer = new ArrayBuffer(data.byteLength);
        new Uint8Array(buffer).set(data);
        const decoded = UPNG.decode(buffer);
        return { width: decoded.width, height: decoded.height };
    } catch {
        return null;
    }
}

/**
 * Extract dimensions from WebP image header
 * WebP uses RIFF container format
 */
function extractWebpDimensions(data: Uint8Array): { width: number; height: number } | null {
    try {
        // Check RIFF header
        if (getByte(data, 0) !== 0x52 || getByte(data, 1) !== 0x49 ||
            getByte(data, 2) !== 0x46 || getByte(data, 3) !== 0x46) {
            return null;
        }
        // Check WEBP signature
        if (getByte(data, 8) !== 0x57 || getByte(data, 9) !== 0x45 ||
            getByte(data, 10) !== 0x42 || getByte(data, 11) !== 0x50) {
            return null;
        }

        // VP8 chunk starts at byte 12
        const chunkId = String.fromCharCode(
            getByte(data, 12), getByte(data, 13), getByte(data, 14), getByte(data, 15)
        );

        if (chunkId === 'VP8 ') {
            // Lossy VP8 format
            // Skip chunk size (4 bytes) and VP8 bitstream header (3 bytes)
            const frameTag = getByte(data, 23) | (getByte(data, 24) << 8) | (getByte(data, 25) << 16);
            const keyFrame = !(frameTag & 1);

            if (keyFrame) {
                // Width and height at bytes 26-29 (little-endian)
                const width = (getByte(data, 26) | (getByte(data, 27) << 8)) & 0x3fff;
                const height = (getByte(data, 28) | (getByte(data, 29) << 8)) & 0x3fff;
                return { width, height };
            }
        } else if (chunkId === 'VP8L') {
            // Lossless VP8L format
            // Skip chunk size (4 bytes) and signature byte (1 byte)
            const bits = getByte(data, 21) | (getByte(data, 22) << 8) |
                        (getByte(data, 23) << 16) | (getByte(data, 24) << 24);
            const width = (bits & 0x3fff) + 1;
            const height = ((bits >> 14) & 0x3fff) + 1;
            return { width, height };
        } else if (chunkId === 'VP8X') {
            // Extended VP8X format
            // Canvas width and height at bytes 24-29 (little-endian, 24-bit values)
            const width = 1 + (getByte(data, 24) | (getByte(data, 25) << 8) | (getByte(data, 26) << 16));
            const height = 1 + (getByte(data, 27) | (getByte(data, 28) << 8) | (getByte(data, 29) << 16));
            return { width, height };
        }

        return null;
    } catch {
        return null;
    }
}

/**
 * Extract dimensions from GIF image header
 */
function extractGifDimensions(data: Uint8Array): { width: number; height: number } | null {
    try {
        // Check GIF signature (GIF87a or GIF89a)
        const signature = String.fromCharCode(getByte(data, 0), getByte(data, 1), getByte(data, 2));
        if (signature !== 'GIF') {
            return null;
        }

        // Width at bytes 6-7, height at bytes 8-9 (little-endian)
        const width = getByte(data, 6) | (getByte(data, 7) << 8);
        const height = getByte(data, 8) | (getByte(data, 9) << 8);

        return { width, height };
    } catch {
        return null;
    }
}

/**
 * Extract image dimensions based on content type
 */
export function extractImageDimensions(
    data: ArrayBuffer,
    contentType: string
): { width: number; height: number } | null {
    const uint8 = new Uint8Array(data);

    switch (contentType) {
        case 'image/jpeg':
            return extractJpegDimensions(uint8);
        case 'image/png':
            return extractPngDimensions(uint8);
        case 'image/webp':
            return extractWebpDimensions(uint8);
        case 'image/gif':
            return extractGifDimensions(uint8);
        default:
            return null;
    }
}

/**
 * Resize RGBA pixel data to fit within maxDim while preserving aspect ratio
 */
function resizeRgba(
    rgba: Uint8Array,
    width: number,
    height: number,
    maxDim: number
): { rgba: Uint8Array; width: number; height: number } {
    // Calculate new dimensions
    const scale = Math.min(maxDim / width, maxDim / height, 1);
    const newWidth = Math.round(width * scale);
    const newHeight = Math.round(height * scale);

    if (newWidth === width && newHeight === height) {
        return { rgba, width, height };
    }

    // Simple nearest-neighbor resize for thumbhash (quality not critical)
    const resized = new Uint8Array(newWidth * newHeight * 4);

    for (let y = 0; y < newHeight; y++) {
        for (let x = 0; x < newWidth; x++) {
            const srcX = Math.floor(x * width / newWidth);
            const srcY = Math.floor(y * height / newHeight);
            const srcIdx = (srcY * width + srcX) * 4;
            const dstIdx = (y * newWidth + x) * 4;

            resized[dstIdx] = rgba[srcIdx] ?? 0;
            resized[dstIdx + 1] = rgba[srcIdx + 1] ?? 0;
            resized[dstIdx + 2] = rgba[srcIdx + 2] ?? 0;
            resized[dstIdx + 3] = rgba[srcIdx + 3] ?? 0;
        }
    }

    return { rgba: resized, width: newWidth, height: newHeight };
}

/**
 * Generate thumbhash from JPEG image data
 */
function generateJpegThumbhash(data: Uint8Array): string | null {
    try {
        const decoded = jpeg.decode(data, {
            useTArray: true,
            maxResolutionInMP: MAX_MEGAPIXELS,
            maxMemoryUsageInMB: 256,
        });

        // jpeg-js returns RGBA data
        const rgba = new Uint8Array(decoded.width * decoded.height * 4);
        for (let i = 0; i < decoded.width * decoded.height; i++) {
            rgba[i * 4] = decoded.data[i * 4] ?? 0;
            rgba[i * 4 + 1] = decoded.data[i * 4 + 1] ?? 0;
            rgba[i * 4 + 2] = decoded.data[i * 4 + 2] ?? 0;
            rgba[i * 4 + 3] = 255; // JPEG doesn't have alpha
        }

        // Resize for thumbhash
        const resized = resizeRgba(rgba, decoded.width, decoded.height, THUMBHASH_MAX_DIM);

        // Generate thumbhash
        const hash = rgbaToThumbHash(resized.width, resized.height, resized.rgba);
        return arrayToBase64(hash);
    } catch {
        return null;
    }
}

/**
 * Generate thumbhash from PNG image data
 */
function generatePngThumbhash(data: Uint8Array): string | null {
    try {
        // Create a proper ArrayBuffer from Uint8Array
        // Use ArrayBuffer constructor to ensure we get ArrayBuffer (not SharedArrayBuffer)
        const buffer = new ArrayBuffer(data.byteLength);
        new Uint8Array(buffer).set(data);
        const decoded = UPNG.decode(buffer);
        const frames = UPNG.toRGBA8(decoded);

        if (!frames || frames.length === 0) {
            return null;
        }

        // Use first frame - frames[0] is guaranteed to exist after length check
        const firstFrame = frames[0];
        if (!firstFrame) {
            return null;
        }
        const rgba = new Uint8Array(firstFrame);

        // Resize for thumbhash
        const resized = resizeRgba(rgba, decoded.width, decoded.height, THUMBHASH_MAX_DIM);

        // Generate thumbhash
        const hash = rgbaToThumbHash(resized.width, resized.height, resized.rgba);
        return arrayToBase64(hash);
    } catch {
        return null;
    }
}

/**
 * Convert Uint8Array to base64 string
 */
function arrayToBase64(array: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < array.length; i++) {
        binary += String.fromCharCode(array[i] ?? 0);
    }
    return btoa(binary);
}

/**
 * Generate thumbhash for an image
 * Only supports JPEG and PNG for full thumbhash generation
 */
export function generateThumbhash(
    data: ArrayBuffer,
    contentType: string
): string | null {
    const uint8 = new Uint8Array(data);

    switch (contentType) {
        case 'image/jpeg':
            return generateJpegThumbhash(uint8);
        case 'image/png':
            return generatePngThumbhash(uint8);
        // WebP and GIF would require additional decoders
        // For now, we skip thumbhash for these formats
        case 'image/webp':
        case 'image/gif':
            return null;
        default:
            return null;
    }
}

/**
 * Process an image to extract dimensions and generate thumbhash
 *
 * @param data - Image data as ArrayBuffer
 * @param contentType - MIME type of the image
 * @returns Processing result with dimensions and thumbhash, or null if processing fails
 */
export async function processImage(
    data: ArrayBuffer,
    contentType: string
): Promise<ImageProcessingResult | null> {
    if (!isProcessableImage(contentType)) {
        return null;
    }

    try {
        // Extract dimensions first (fast operation)
        const dimensions = extractImageDimensions(data, contentType);

        if (!dimensions) {
            return null;
        }

        // Check if image is too large to process
        const megapixels = (dimensions.width * dimensions.height) / 1_000_000;
        if (megapixels > MAX_MEGAPIXELS) {
            // Still return dimensions, but skip thumbhash
            return {
                ...dimensions,
                thumbhash: null,
            };
        }

        // Generate thumbhash (may fail for WebP/GIF)
        const thumbhash = generateThumbhash(data, contentType);

        return {
            ...dimensions,
            thumbhash,
        };
    } catch (error) {
        console.error('Image processing failed:', error);
        return null;
    }
}
