/**
 * Encryption utilities for Cloudflare Workers
 *
 * This module provides symmetric encryption/decryption using TweetNaCl's secretbox
 * (XSalsa20-Poly1305) with key derivation from HAPPY_MASTER_SECRET.
 *
 * The API matches happy-server's privacy-kit KeyTree pattern:
 * - Path-based key derivation (e.g., ['user', userId, 'vendors', vendor, 'token'])
 * - Symmetric encryption with authenticated encryption (encrypt-then-MAC)
 *
 * @see HAP-286 for AI token encryption implementation
 * @see apps/server/docker/sources/modules/encrypt.ts for original implementation
 */

import nacl from 'tweetnacl';
import { encodeBase64, decodeBase64 } from '@/lib/privacy-kit-shim';

// Cache derived keys for performance (path string -> key)
// Limit cache size to prevent unbounded memory growth in long-lived Workers
const MAX_KEY_CACHE_SIZE = 1000;
const keyCache = new Map<string, Uint8Array>();

let masterKey: Uint8Array | null = null;
let initialized = false;

/**
 * Initialize the encryption module with the master secret.
 *
 * Must be called once at Worker startup with the master secret.
 *
 * @param masterSecret - The master secret from getMasterSecret(env)
 * @throws Error if masterSecret is empty or invalid
 *
 * @example
 * ```typescript
 * // In Worker fetch handler or middleware
 * import { getMasterSecret } from '@/config/env';
 * const secret = getMasterSecret(env);
 * if (secret) await initEncryption(secret);
 * ```
 */
export async function initEncryption(masterSecret: string): Promise<void> {
    if (initialized) {
        return;
    }

    if (!masterSecret || masterSecret.length < 32) {
        throw new Error(
            'HAPPY_MASTER_SECRET must be at least 32 characters. ' +
            'Generate a secure secret with: openssl rand -hex 32. ' +
            'For local development, add it to .dev.vars. ' +
            'For production, use: wrangler secret put HAPPY_MASTER_SECRET. ' +
            'See docs/SECRETS.md for detailed configuration instructions.'
        );
    }

    // Derive a 32-byte master key from the secret using HKDF
    const secretBytes = new TextEncoder().encode(masterSecret);
    const baseKey = await crypto.subtle.importKey('raw', secretBytes, 'HKDF', false, [
        'deriveBits',
    ]);

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode('happy-server-encryption'),
            info: new TextEncoder().encode('master-key'),
        },
        baseKey,
        256 // 32 bytes
    );

    masterKey = new Uint8Array(derivedBits);
    initialized = true;
}

/**
 * Check if encryption is initialized
 */
export function isEncryptionInitialized(): boolean {
    return initialized;
}

/**
 * Reset encryption state (for testing only)
 */
export function resetEncryption(): void {
    masterKey = null;
    initialized = false;
    keyCache.clear();
}

/**
 * Derive a unique encryption key for a given path.
 *
 * Uses HKDF to derive a 32-byte key from the master key and path.
 * Keys are cached for performance.
 *
 * @param path - Path components for key derivation (e.g., ['user', 'abc', 'token'])
 * @returns 32-byte derived key
 */
async function deriveKey(path: string[]): Promise<Uint8Array> {
    if (!masterKey) {
        throw new Error(
            'Encryption not initialized. ' +
            'In Cloudflare Workers, initEncryption must be called at startup. ' +
            'This is typically done in src/middleware/encryption.ts or alongside auth initialization. ' +
            'Ensure initEncryption() is called in your Worker fetch handler before any encryption operations. ' +
            'See docs/SECRETS.md for HAPPY_MASTER_SECRET configuration.'
        );
    }

    const pathString = path.join('/');

    // Check cache first
    const cached = keyCache.get(pathString);
    if (cached) {
        return cached;
    }

    // Derive key using HKDF with path as info
    const baseKey = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, [
        'deriveBits',
    ]);

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode('path-derived-key'),
            info: new TextEncoder().encode(pathString),
        },
        baseKey,
        256 // 32 bytes for secretbox
    );

    const key = new Uint8Array(derivedBits);

    // Cache for future use (with size limit to prevent memory growth)
    if (keyCache.size >= MAX_KEY_CACHE_SIZE) {
        // Remove oldest entry (first key in Map maintains insertion order)
        const firstKey = keyCache.keys().next().value;
        if (firstKey) {
            keyCache.delete(firstKey);
        }
    }
    keyCache.set(pathString, key);

    return key;
}

/**
 * Encrypt a string using TweetNaCl secretbox.
 *
 * Returns a Uint8Array containing: nonce (24 bytes) || ciphertext
 *
 * @param path - Key derivation path (e.g., ['user', userId, 'vendors', vendor, 'token'])
 * @param plaintext - String to encrypt
 * @returns Encrypted bytes (nonce + ciphertext)
 *
 * @example
 * ```typescript
 * const encrypted = await encryptString(
 *     ['user', userId, 'vendors', 'openai', 'token'],
 *     'sk-...'
 * );
 * // Store encrypted as blob in D1
 * ```
 */
export async function encryptString(path: string[], plaintext: string): Promise<Uint8Array> {
    const key = await deriveKey(path);
    const plaintextBytes = new TextEncoder().encode(plaintext);

    // Generate random nonce (24 bytes for secretbox)
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

    // Encrypt
    const ciphertext = nacl.secretbox(plaintextBytes, nonce, key);

    // Return nonce || ciphertext
    const result = new Uint8Array(nonce.length + ciphertext.length);
    result.set(nonce, 0);
    result.set(ciphertext, nonce.length);

    return result;
}

/**
 * Encrypt raw bytes using TweetNaCl secretbox.
 *
 * @param path - Key derivation path
 * @param plaintext - Bytes to encrypt
 * @returns Encrypted bytes (nonce + ciphertext)
 */
export async function encryptBytes(path: string[], plaintext: Uint8Array): Promise<Uint8Array> {
    const key = await deriveKey(path);

    // Generate random nonce (24 bytes for secretbox)
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

    // Encrypt
    const ciphertext = nacl.secretbox(plaintext, nonce, key);

    // Return nonce || ciphertext
    const result = new Uint8Array(nonce.length + ciphertext.length);
    result.set(nonce, 0);
    result.set(ciphertext, nonce.length);

    return result;
}

/**
 * Decrypt bytes to a string using TweetNaCl secretbox.
 *
 * @param path - Key derivation path (must match encryption path)
 * @param encrypted - Encrypted bytes (nonce + ciphertext)
 * @returns Decrypted string
 * @throws Error if decryption fails (wrong key, corrupted data, or tampered)
 *
 * @example
 * ```typescript
 * const token = await decryptString(
 *     ['user', userId, 'vendors', 'openai', 'token'],
 *     encryptedBytes
 * );
 * ```
 */
export async function decryptString(path: string[], encrypted: Uint8Array): Promise<string> {
    const key = await deriveKey(path);

    if (encrypted.length < nacl.secretbox.nonceLength) {
        throw new Error('Invalid encrypted data: too short');
    }

    // Extract nonce and ciphertext
    const nonce = encrypted.slice(0, nacl.secretbox.nonceLength);
    const ciphertext = encrypted.slice(nacl.secretbox.nonceLength);

    // Decrypt
    const plaintext = nacl.secretbox.open(ciphertext, nonce, key);

    if (!plaintext) {
        throw new Error('Decryption failed: invalid key or corrupted data');
    }

    return new TextDecoder().decode(plaintext);
}

/**
 * Decrypt bytes using TweetNaCl secretbox.
 *
 * @param path - Key derivation path (must match encryption path)
 * @param encrypted - Encrypted bytes (nonce + ciphertext)
 * @returns Decrypted bytes
 * @throws Error if decryption fails
 */
export async function decryptBytes(path: string[], encrypted: Uint8Array): Promise<Uint8Array> {
    const key = await deriveKey(path);

    if (encrypted.length < nacl.secretbox.nonceLength) {
        throw new Error('Invalid encrypted data: too short');
    }

    // Extract nonce and ciphertext
    const nonce = encrypted.slice(0, nacl.secretbox.nonceLength);
    const ciphertext = encrypted.slice(nacl.secretbox.nonceLength);

    // Decrypt
    const plaintext = nacl.secretbox.open(ciphertext, nonce, key);

    if (!plaintext) {
        throw new Error('Decryption failed: invalid key or corrupted data');
    }

    return plaintext;
}

/**
 * Encrypt a string and return as base64 for JSON-safe storage.
 *
 * @param path - Key derivation path
 * @param plaintext - String to encrypt
 * @returns Base64-encoded encrypted string
 */
export async function encryptStringBase64(path: string[], plaintext: string): Promise<string> {
    const encrypted = await encryptString(path, plaintext);
    return encodeBase64(encrypted);
}

/**
 * Decrypt a base64-encoded encrypted string.
 *
 * @param path - Key derivation path
 * @param encryptedBase64 - Base64-encoded encrypted data
 * @returns Decrypted string
 */
export async function decryptStringBase64(
    path: string[],
    encryptedBase64: string
): Promise<string> {
    const encrypted = decodeBase64(encryptedBase64);
    return decryptString(path, encrypted);
}

/**
 * Get cache statistics (for debugging/monitoring)
 */
export function getEncryptionCacheStats(): { keyCount: number } {
    return {
        keyCount: keyCache.size,
    };
}

/**
 * Clear the key cache (use when rotating secrets)
 */
export function clearKeyCache(): void {
    keyCache.clear();
}
