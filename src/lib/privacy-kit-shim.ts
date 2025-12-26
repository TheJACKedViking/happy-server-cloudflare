/**
 * Encoding utilities for Cloudflare Workers
 *
 * This module provides base64 and hex encoding/decoding functions
 * that work in Cloudflare Workers, using @stablelib packages.
 *
 * These functions match the API of privacy-kit's encoding utilities,
 * allowing existing code that used privacy-kit for encoding to work
 * without modification.
 *
 * @see HAP-264 for jose-based authentication (replaces privacy-kit tokens)
 * @see HAP-26 for discovery of privacy-kit incompatibility
 */

import * as base64 from '@stablelib/base64';
import * as hex from '@stablelib/hex';

/**
 * Encode a Uint8Array to base64 string
 * @param data - Binary data to encode
 * @returns Base64 encoded string
 */
export function encodeBase64(data: Uint8Array | Buffer): string {
    // Handle both Uint8Array and Buffer
    const uint8 = data instanceof Uint8Array ? data : new Uint8Array(data);
    return base64.encode(uint8);
}

/**
 * Decode a base64 string to Uint8Array
 * @param str - Base64 encoded string
 * @returns Decoded binary data
 */
export function decodeBase64(str: string): Uint8Array {
    return base64.decode(str);
}

/**
 * Encode a Uint8Array to hex string
 * @param data - Binary data to encode
 * @returns Hex encoded string (lowercase)
 */
export function encodeHex(data: Uint8Array | Buffer): string {
    const uint8 = data instanceof Uint8Array ? data : new Uint8Array(data);
    return hex.encode(uint8, true); // lowercase
}

