/**
 * Tests for encryption utilities
 *
 * @see HAP-286 for AI token encryption implementation
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
    initEncryption,
    resetEncryption,
    isEncryptionInitialized,
    encryptString,
    decryptString,
    encryptBytes,
    decryptBytes,
    encryptStringBase64,
    decryptStringBase64,
    getEncryptionCacheStats,
    clearKeyCache,
} from './encryption';

describe('encryption', () => {
    const TEST_SECRET = 'test-master-secret-at-least-32-characters-long';

    beforeEach(() => {
        resetEncryption();
    });

    afterEach(() => {
        resetEncryption();
    });

    describe('initEncryption', () => {
        it('should initialize successfully with valid secret', async () => {
            await initEncryption(TEST_SECRET);
            expect(isEncryptionInitialized()).toBe(true);
        });

        it('should throw if secret is too short', async () => {
            await expect(initEncryption('short')).rejects.toThrow(
                'HANDY_MASTER_SECRET must be at least 32 characters'
            );
        });

        it('should throw if secret is empty', async () => {
            await expect(initEncryption('')).rejects.toThrow(
                'HANDY_MASTER_SECRET must be at least 32 characters'
            );
        });

        it('should be idempotent (multiple calls are safe)', async () => {
            await initEncryption(TEST_SECRET);
            await initEncryption(TEST_SECRET);
            expect(isEncryptionInitialized()).toBe(true);
        });
    });

    describe('encryptString / decryptString', () => {
        beforeEach(async () => {
            await initEncryption(TEST_SECRET);
        });

        it('should encrypt and decrypt a simple string', async () => {
            const path = ['test', 'token'];
            const plaintext = 'sk-test-api-key-12345';

            const encrypted = await encryptString(path, plaintext);
            const decrypted = await decryptString(path, encrypted);

            expect(decrypted).toBe(plaintext);
        });

        it('should encrypt and decrypt an empty string', async () => {
            const path = ['test', 'empty'];
            const plaintext = '';

            const encrypted = await encryptString(path, plaintext);
            const decrypted = await decryptString(path, encrypted);

            expect(decrypted).toBe(plaintext);
        });

        it('should encrypt and decrypt unicode strings', async () => {
            const path = ['test', 'unicode'];
            const plaintext = 'Hello 世界 🌍 Привет';

            const encrypted = await encryptString(path, plaintext);
            const decrypted = await decryptString(path, encrypted);

            expect(decrypted).toBe(plaintext);
        });

        it('should encrypt and decrypt long strings', async () => {
            const path = ['test', 'long'];
            const plaintext = 'x'.repeat(10000);

            const encrypted = await encryptString(path, plaintext);
            const decrypted = await decryptString(path, encrypted);

            expect(decrypted).toBe(plaintext);
        });

        it('should produce different ciphertext for same plaintext (due to random nonce)', async () => {
            const path = ['test', 'nonce'];
            const plaintext = 'same-text';

            const encrypted1 = await encryptString(path, plaintext);
            const encrypted2 = await encryptString(path, plaintext);

            // Different ciphertexts due to random nonce
            expect(encrypted1).not.toEqual(encrypted2);

            // But both should decrypt to same plaintext
            expect(await decryptString(path, encrypted1)).toBe(plaintext);
            expect(await decryptString(path, encrypted2)).toBe(plaintext);
        });

        it('should fail decryption with wrong path', async () => {
            const plaintext = 'secret-data';
            const encrypted = await encryptString(['path', 'a'], plaintext);

            await expect(decryptString(['path', 'b'], encrypted)).rejects.toThrow(
                'Decryption failed'
            );
        });

        it('should fail decryption with corrupted data', async () => {
            const encrypted = await encryptString(['test'], 'data');

            // Corrupt a byte in the ciphertext (index 30 is in ciphertext area after 24-byte nonce)
            const corrupted = new Uint8Array(encrypted);
            corrupted[30] = (corrupted[30] ?? 0) ^ 0xff;

            await expect(decryptString(['test'], corrupted)).rejects.toThrow('Decryption failed');
        });

        it('should fail decryption with truncated data', async () => {
            const encrypted = await encryptString(['test'], 'data');

            // Truncate to just the nonce
            const truncated = encrypted.slice(0, 24);

            await expect(decryptString(['test'], truncated)).rejects.toThrow('Decryption failed');
        });

        it('should fail decryption with data shorter than nonce length', async () => {
            // Data shorter than 24 bytes (secretbox nonce length)
            const tooShort = new Uint8Array(10);

            await expect(decryptString(['test'], tooShort)).rejects.toThrow(
                'Invalid encrypted data: too short'
            );
        });

        it('should fail decryption with empty data', async () => {
            const emptyData = new Uint8Array(0);

            await expect(decryptString(['test'], emptyData)).rejects.toThrow(
                'Invalid encrypted data: too short'
            );
        });

        it('should throw if encryption not initialized', async () => {
            resetEncryption();
            await expect(encryptString(['test'], 'data')).rejects.toThrow(
                'Encryption not initialized'
            );
        });
    });

    describe('encryptBytes / decryptBytes', () => {
        beforeEach(async () => {
            await initEncryption(TEST_SECRET);
        });

        it('should encrypt and decrypt binary data', async () => {
            const path = ['test', 'binary'];
            const plaintext = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);

            const encrypted = await encryptBytes(path, plaintext);
            const decrypted = await decryptBytes(path, encrypted);

            expect(decrypted).toEqual(plaintext);
        });

        it('should encrypt and decrypt all-zeros', async () => {
            const path = ['test', 'zeros'];
            const plaintext = new Uint8Array(256).fill(0);

            const encrypted = await encryptBytes(path, plaintext);
            const decrypted = await decryptBytes(path, encrypted);

            expect(decrypted).toEqual(plaintext);
        });

        it('should fail decryption with data shorter than nonce length', async () => {
            // Data shorter than 24 bytes (secretbox nonce length)
            const tooShort = new Uint8Array(10);

            await expect(decryptBytes(['test'], tooShort)).rejects.toThrow(
                'Invalid encrypted data: too short'
            );
        });

        it('should fail decryption with empty data', async () => {
            const emptyData = new Uint8Array(0);

            await expect(decryptBytes(['test'], emptyData)).rejects.toThrow(
                'Invalid encrypted data: too short'
            );
        });

        it('should fail decryption with corrupted data', async () => {
            const encrypted = await encryptBytes(['test'], new Uint8Array([1, 2, 3, 4]));

            // Corrupt a byte in the ciphertext (after the 24-byte nonce)
            const corrupted = new Uint8Array(encrypted);
            corrupted[30] = (corrupted[30] ?? 0) ^ 0xff;

            await expect(decryptBytes(['test'], corrupted)).rejects.toThrow(
                'Decryption failed: invalid key or corrupted data'
            );
        });

        it('should fail decryption with wrong path', async () => {
            const plaintext = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
            const encrypted = await encryptBytes(['path', 'a'], plaintext);

            await expect(decryptBytes(['path', 'b'], encrypted)).rejects.toThrow(
                'Decryption failed'
            );
        });
    });

    describe('encryptStringBase64 / decryptStringBase64', () => {
        beforeEach(async () => {
            await initEncryption(TEST_SECRET);
        });

        it('should encrypt to base64 and decrypt back', async () => {
            const path = ['test', 'base64'];
            const plaintext = 'api-key-value';

            const encryptedBase64 = await encryptStringBase64(path, plaintext);

            // Should be valid base64
            expect(typeof encryptedBase64).toBe('string');
            expect(() => atob(encryptedBase64)).not.toThrow();

            const decrypted = await decryptStringBase64(path, encryptedBase64);
            expect(decrypted).toBe(plaintext);
        });
    });

    describe('path-based key derivation', () => {
        beforeEach(async () => {
            await initEncryption(TEST_SECRET);
        });

        it('should derive different keys for different paths', async () => {
            const plaintext = 'same-plaintext';

            const encrypted1 = await encryptString(['user', 'alice', 'token'], plaintext);
            // Encrypt with different path (bob instead of alice)
            await encryptString(['user', 'bob', 'token'], plaintext);

            // Different keys = cross-decryption should fail
            await expect(
                decryptString(['user', 'bob', 'token'], encrypted1)
            ).rejects.toThrow('Decryption failed');
        });

        it('should support complex paths like happy-server', async () => {
            const userId = 'user_abc123';
            const vendor = 'openai';
            const path = ['user', userId, 'vendors', vendor, 'token'];
            const token = 'sk-proj-abc123xyz';

            const encrypted = await encryptString(path, token);
            const decrypted = await decryptString(path, encrypted);

            expect(decrypted).toBe(token);
        });
    });

    describe('key caching', () => {
        beforeEach(async () => {
            await initEncryption(TEST_SECRET);
        });

        it('should cache derived keys', async () => {
            clearKeyCache();
            expect(getEncryptionCacheStats().keyCount).toBe(0);

            await encryptString(['path', 'one'], 'data');
            expect(getEncryptionCacheStats().keyCount).toBe(1);

            await encryptString(['path', 'two'], 'data');
            expect(getEncryptionCacheStats().keyCount).toBe(2);

            // Same path should not increase count
            await encryptString(['path', 'one'], 'more-data');
            expect(getEncryptionCacheStats().keyCount).toBe(2);
        });

        it('should clear cache on clearKeyCache()', async () => {
            await encryptString(['path'], 'data');
            expect(getEncryptionCacheStats().keyCount).toBeGreaterThan(0);

            clearKeyCache();
            expect(getEncryptionCacheStats().keyCount).toBe(0);
        });

        it('should evict oldest entries when cache limit is reached', async () => {
            clearKeyCache();

            // MAX_KEY_CACHE_SIZE is 1000 in the implementation
            // We need to fill the cache to capacity and then add one more to trigger eviction
            const cacheLimit = 1000;

            // Fill the cache to exactly the limit
            for (let i = 0; i < cacheLimit; i++) {
                await encryptString(['cache', 'test', `key-${i}`], 'data');
            }

            // Cache should be at capacity
            expect(getEncryptionCacheStats().keyCount).toBe(cacheLimit);

            // Add one more key - this should trigger eviction of the oldest entry
            await encryptString(['cache', 'test', 'overflow-key'], 'data');

            // Cache should still be at capacity (old entry evicted, new entry added)
            expect(getEncryptionCacheStats().keyCount).toBe(cacheLimit);
        });

        it('should handle edge case when Map.keys().next().value returns undefined', async () => {
            // This tests the defensive guard at line 130: if (firstKey)
            // In practice, this can never happen when keyCache.size >= 1000,
            // but we test it for completeness by mocking the Map.prototype.keys method
            clearKeyCache();

            // Fill the cache to capacity
            const cacheLimit = 1000;
            for (let i = 0; i < cacheLimit; i++) {
                await encryptString(['edge', 'test', `key-${i}`], 'data');
            }

            // Mock Map.prototype.keys to return an iterator that yields undefined
            const mockIterator = {
                next: () => ({ value: undefined, done: false }),
                [Symbol.iterator]: function () {
                    return this;
                },
            };
            const keysSpy = vi.spyOn(Map.prototype, 'keys').mockReturnValue(
                mockIterator as IterableIterator<string>
            );

            try {
                // This should trigger the eviction path, but firstKey will be undefined
                // The code handles this gracefully by checking if (firstKey)
                await encryptString(['edge', 'test', 'trigger-edge-case'], 'data');

                // The cache should have grown by 1 since eviction was skipped
                // (firstKey was undefined so delete was not called)
                expect(getEncryptionCacheStats().keyCount).toBe(cacheLimit + 1);
            } finally {
                // Restore the original method
                keysSpy.mockRestore();
            }
        });
    });

    describe('cross-master-secret isolation', () => {
        it('should not decrypt data encrypted with different master secret', async () => {
            const path = ['test'];
            const plaintext = 'sensitive-data';

            // Encrypt with first secret
            await initEncryption('master-secret-one-32-chars-minimum');
            const encrypted = await encryptString(path, plaintext);

            // Try to decrypt with different secret
            resetEncryption();
            await initEncryption('master-secret-two-32-chars-minimum');

            await expect(decryptString(path, encrypted)).rejects.toThrow('Decryption failed');
        });
    });
});
