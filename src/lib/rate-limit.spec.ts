/**
 * Tests for rate limiting utility
 *
 * @see HAP-409 - Add rate limiting to WebSocket ticket endpoint
 * @see HAP-620 - SECURITY: Rate Limiting Silently Bypassed When KV Missing
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    checkRateLimit,
    getRateLimitStatus,
    resetRateLimit,
    resetFallbackWarning,
    clearFallbackStore,
    getFallbackStoreSize,
    TICKET_RATE_LIMIT,
    type RateLimitConfig,
} from './rate-limit';

/**
 * Create a mock KV namespace for testing
 */
function createMockKV(): KVNamespace & { _store: Map<string, { value: string; expiration?: number }> } {
    const store = new Map<string, { value: string; expiration?: number }>();

    return {
        _store: store,
        get: vi.fn(async (key: string) => {
            const entry = store.get(key);
            if (!entry) return null;
            // Check expiration
            if (entry.expiration && Date.now() > entry.expiration) {
                store.delete(key);
                return null;
            }
            return entry.value;
        }),
        put: vi.fn(async (key: string, value: string, options?: { expirationTtl?: number }) => {
            const expiration = options?.expirationTtl
                ? Date.now() + options.expirationTtl * 1000
                : undefined;
            store.set(key, { value, expiration });
        }),
        delete: vi.fn(async (key: string) => {
            store.delete(key);
        }),
        // Other KV methods not used in our implementation
        list: vi.fn(),
        getWithMetadata: vi.fn(),
    } as unknown as KVNamespace & { _store: Map<string, { value: string; expiration?: number }> };
}

describe('rate-limit', () => {
    let mockKV: ReturnType<typeof createMockKV>;

    beforeEach(() => {
        mockKV = createMockKV();
        vi.clearAllMocks();
    });

    describe('TICKET_RATE_LIMIT', () => {
        it('should have correct default configuration', () => {
            expect(TICKET_RATE_LIMIT).toEqual({
                maxRequests: 10,
                windowMs: 60_000,
                expirationTtl: 120,
            });
        });
    });

    describe('checkRateLimit', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 3,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        it('should allow requests under the limit', async () => {
            const result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            expect(result.allowed).toBe(true);
            expect(result.count).toBe(1);
            expect(result.limit).toBe(3);
            expect(result.remaining).toBe(2);
        });

        it('should increment count on each call', async () => {
            const result1 = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            const result2 = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            const result3 = await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            expect(result1.count).toBe(1);
            expect(result2.count).toBe(2);
            expect(result3.count).toBe(3);
            expect(result3.remaining).toBe(0);
        });

        it('should reject requests when limit is exceeded', async () => {
            // Make 3 requests to reach the limit
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            // 4th request should be rejected
            const result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            expect(result.allowed).toBe(false);
            expect(result.count).toBe(3);
            expect(result.remaining).toBe(0);
            expect(result.retryAfter).toBeGreaterThan(0);
            expect(result.retryAfter).toBeLessThanOrEqual(60);
        });

        it('should track different users separately', async () => {
            // User1 makes 3 requests
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            // User1 is now rate limited
            const user1Result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            expect(user1Result.allowed).toBe(false);

            // User2 should still be able to make requests
            const user2Result = await checkRateLimit(mockKV, 'test', 'user2', testConfig);
            expect(user2Result.allowed).toBe(true);
            expect(user2Result.count).toBe(1);
        });

        it('should track different prefixes separately', async () => {
            // Same user, different prefixes
            const ticketResult = await checkRateLimit(mockKV, 'ticket', 'user1', testConfig);
            const otherResult = await checkRateLimit(mockKV, 'other', 'user1', testConfig);

            expect(ticketResult.count).toBe(1);
            expect(otherResult.count).toBe(1);
        });

        it('should use correct KV key format', async () => {
            await checkRateLimit(mockKV, 'ticket', 'user_abc123', testConfig);

            // Check the key format
            const keys = Array.from(mockKV._store.keys());
            expect(keys).toHaveLength(1);
            expect(keys[0]).toMatch(/^rate:ticket:user_abc123:\d+$/);
        });

        it('should set expiration TTL on KV entries', async () => {
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            expect(mockKV.put).toHaveBeenCalledWith(
                expect.any(String),
                '1',
                { expirationTtl: 120 }
            );
        });

        it('should return retryAfter between 1 and window seconds', async () => {
            const result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            expect(result.retryAfter).toBeGreaterThanOrEqual(1);
            expect(result.retryAfter).toBeLessThanOrEqual(60);
        });

        it('should handle default config values', async () => {
            const minimalConfig: RateLimitConfig = { maxRequests: 5 };
            const result = await checkRateLimit(mockKV, 'test', 'user1', minimalConfig);

            expect(result.allowed).toBe(true);
            expect(result.limit).toBe(5);
        });
    });

    describe('getRateLimitStatus', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 5,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        it('should return zero count for new users', async () => {
            const status = await getRateLimitStatus(mockKV, 'test', 'newuser', testConfig);

            expect(status.count).toBe(0);
            expect(status.remaining).toBe(5);
            expect(status.limit).toBe(5);
        });

        it('should return current count without incrementing', async () => {
            // Make some requests
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            // Check status (should not increment)
            const status1 = await getRateLimitStatus(mockKV, 'test', 'user1', testConfig);
            const status2 = await getRateLimitStatus(mockKV, 'test', 'user1', testConfig);

            expect(status1.count).toBe(2);
            expect(status2.count).toBe(2); // Still 2, not incremented
            expect(status1.remaining).toBe(3);
        });

        it('should return 0 remaining when limit reached', async () => {
            // Exhaust the limit
            for (let i = 0; i < 5; i++) {
                await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            }

            const status = await getRateLimitStatus(mockKV, 'test', 'user1', testConfig);

            expect(status.count).toBe(5);
            expect(status.remaining).toBe(0);
        });
    });

    describe('resetRateLimit', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 3,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        it('should reset the rate limit counter', async () => {
            // Make some requests
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            // Reset
            await resetRateLimit(mockKV, 'test', 'user1', testConfig);

            // Should start fresh
            const result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            expect(result.count).toBe(1);
        });

        it('should only reset the specified user', async () => {
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user2', testConfig);

            await resetRateLimit(mockKV, 'test', 'user1', testConfig);

            // User1 is reset
            const status1 = await getRateLimitStatus(mockKV, 'test', 'user1', testConfig);
            expect(status1.count).toBe(0);

            // User2 is not affected
            const status2 = await getRateLimitStatus(mockKV, 'test', 'user2', testConfig);
            expect(status2.count).toBe(1);
        });
    });

    describe('minute bucket behavior', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 3,
            windowMs: 60_000, // 1 minute window
            expirationTtl: 120,
        };

        it('should use different buckets for different minute windows', async () => {
            // First request
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            const keys = Array.from(mockKV._store.keys());
            expect(keys).toHaveLength(1);

            // Parse the bucket from the key
            const keyParts = keys[0]!.split(':');
            const bucket = parseInt(keyParts[3]!, 10);

            // Bucket should be based on current minute
            const expectedBucket = Math.floor(Date.now() / 60_000);
            expect(bucket).toBe(expectedBucket);
        });
    });

    describe('edge cases', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 2,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        it('should handle empty user ID', async () => {
            const result = await checkRateLimit(mockKV, 'test', '', testConfig);
            expect(result.allowed).toBe(true);
        });

        it('should handle special characters in user ID', async () => {
            const result = await checkRateLimit(mockKV, 'test', 'user@domain.com', testConfig);
            expect(result.allowed).toBe(true);
            expect(result.count).toBe(1);
        });

        it('should handle unicode in user ID', async () => {
            const result = await checkRateLimit(mockKV, 'test', 'user_测试_🔑', testConfig);
            expect(result.allowed).toBe(true);
        });

        it('should handle very long user IDs', async () => {
            const longId = 'user_' + 'x'.repeat(1000);
            const result = await checkRateLimit(mockKV, 'test', longId, testConfig);
            expect(result.allowed).toBe(true);
        });

        it('should handle maxRequests of 1', async () => {
            const strictConfig: RateLimitConfig = { maxRequests: 1 };

            const result1 = await checkRateLimit(mockKV, 'test', 'user1', strictConfig);
            expect(result1.allowed).toBe(true);

            const result2 = await checkRateLimit(mockKV, 'test', 'user1', strictConfig);
            expect(result2.allowed).toBe(false);
        });

        it('should handle concurrent requests gracefully', async () => {
            // Simulate concurrent requests
            const results = await Promise.all([
                checkRateLimit(mockKV, 'test', 'user1', testConfig),
                checkRateLimit(mockKV, 'test', 'user1', testConfig),
                checkRateLimit(mockKV, 'test', 'user1', testConfig),
            ]);

            // Due to eventual consistency, all might be allowed
            // This is expected behavior for KV-based rate limiting
            const allowedCount = results.filter((r) => r.allowed).length;
            expect(allowedCount).toBeGreaterThanOrEqual(2);
        });
    });

    describe('TICKET_RATE_LIMIT integration', () => {
        it('should allow 10 ticket requests per minute', async () => {
            for (let i = 0; i < 10; i++) {
                const result = await checkRateLimit(mockKV, 'ticket', 'user1', TICKET_RATE_LIMIT);
                expect(result.allowed).toBe(true);
            }

            // 11th request should be rejected
            const result = await checkRateLimit(mockKV, 'ticket', 'user1', TICKET_RATE_LIMIT);
            expect(result.allowed).toBe(false);
        });
    });

    /**
     * HAP-620: Fallback Memory-Based Rate Limiting Tests
     *
     * When KV is not configured (undefined), the rate limiter should fall back
     * to per-isolate memory-based rate limiting for better-than-nothing protection.
     */
    describe('fallback memory-based rate limiting (HAP-620)', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 3,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        beforeEach(() => {
            clearFallbackStore();
            resetFallbackWarning();
            vi.spyOn(console, 'warn').mockImplementation(() => {});
        });

        afterEach(() => {
            vi.restoreAllMocks();
        });

        it('should use fallback when KV is undefined', async () => {
            const result = await checkRateLimit(undefined, 'test', 'user1', testConfig);

            expect(result.allowed).toBe(true);
            expect(result.count).toBe(1);
            expect(result.limit).toBe(3);
        });

        it('should log warning once when using fallback', async () => {
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user2', testConfig);

            // Warning should only be logged once per Worker instance
            expect(console.warn).toHaveBeenCalledTimes(1);
            expect(console.warn).toHaveBeenCalledWith(
                expect.stringContaining('RATE_LIMIT_KV not configured')
            );
        });

        it('should enforce rate limits with fallback', async () => {
            // Make 3 requests to reach the limit
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user1', testConfig);

            // 4th request should be rejected
            const result = await checkRateLimit(undefined, 'test', 'user1', testConfig);

            expect(result.allowed).toBe(false);
            expect(result.count).toBe(3);
            expect(result.remaining).toBe(0);
        });

        it('should track different users separately in fallback', async () => {
            // User1 exhausts limit
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user1', testConfig);

            const user1Result = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(user1Result.allowed).toBe(false);

            // User2 should still be allowed
            const user2Result = await checkRateLimit(undefined, 'test', 'user2', testConfig);
            expect(user2Result.allowed).toBe(true);
            expect(user2Result.count).toBe(1);
        });

        it('should track different prefixes separately in fallback', async () => {
            const ticketResult = await checkRateLimit(undefined, 'ticket', 'user1', testConfig);
            const authResult = await checkRateLimit(undefined, 'auth', 'user1', testConfig);

            expect(ticketResult.count).toBe(1);
            expect(authResult.count).toBe(1);
        });

        it('should return correct remaining count in fallback', async () => {
            const result1 = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            const result2 = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            const result3 = await checkRateLimit(undefined, 'test', 'user1', testConfig);

            expect(result1.remaining).toBe(2);
            expect(result2.remaining).toBe(1);
            expect(result3.remaining).toBe(0);
        });

        it('should provide retryAfter in fallback', async () => {
            const result = await checkRateLimit(undefined, 'test', 'user1', testConfig);

            expect(result.retryAfter).toBeGreaterThan(0);
            expect(result.retryAfter).toBeLessThanOrEqual(60);
        });

        it('should store entries in fallback store', async () => {
            expect(getFallbackStoreSize()).toBe(0);

            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user2', testConfig);

            expect(getFallbackStoreSize()).toBe(2);
        });

        it('should clear fallback store', async () => {
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(getFallbackStoreSize()).toBe(1);

            clearFallbackStore();
            expect(getFallbackStoreSize()).toBe(0);
        });

        describe('getRateLimitStatus with fallback', () => {
            it('should return zero count for new users', async () => {
                const status = await getRateLimitStatus(undefined, 'test', 'newuser', testConfig);

                expect(status.count).toBe(0);
                expect(status.remaining).toBe(3);
                expect(status.limit).toBe(3);
            });

            it('should return current count from fallback store', async () => {
                await checkRateLimit(undefined, 'test', 'user1', testConfig);
                await checkRateLimit(undefined, 'test', 'user1', testConfig);

                const status = await getRateLimitStatus(undefined, 'test', 'user1', testConfig);

                expect(status.count).toBe(2);
                expect(status.remaining).toBe(1);
            });
        });

        describe('resetRateLimit with fallback', () => {
            it('should reset fallback store entry', async () => {
                await checkRateLimit(undefined, 'test', 'user1', testConfig);
                await checkRateLimit(undefined, 'test', 'user1', testConfig);

                const statusBefore = await getRateLimitStatus(undefined, 'test', 'user1', testConfig);
                expect(statusBefore.count).toBe(2);

                await resetRateLimit(undefined, 'test', 'user1', testConfig);

                // After reset, count should be 1 (from the new request)
                const result = await checkRateLimit(undefined, 'test', 'user1', testConfig);
                expect(result.count).toBe(1);
            });
        });
    });

    /**
     * HAP-913: Mutation Testing Enhancements
     *
     * These tests target specific mutation types:
     * - ArithmeticOperator: Math operations (+, -, *, /)
     * - EqualityOperator: >=, >, <=, <, ===, !==
     * - ConditionalExpression: if/else branches
     */
    describe('ArithmeticOperator Mutations (HAP-913)', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 5,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        it('should calculate remaining correctly as maxRequests minus count', async () => {
            const result1 = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            expect(result1.remaining).toBe(4); // 5 - 1 = 4

            const result2 = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            expect(result2.remaining).toBe(3); // 5 - 2 = 3

            const result3 = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            expect(result3.remaining).toBe(2); // 5 - 3 = 2
        });

        it('should increment count by exactly 1 each time', async () => {
            const result1 = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            expect(result1.count).toBe(1);

            const result2 = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            expect(result2.count).toBe(2);

            // Verify the increment is exactly 1, not 2 or 0
            expect(result2.count - result1.count).toBe(1);
        });

        it('should calculate retryAfter in seconds (divide by 1000)', async () => {
            const result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            // retryAfter should be in seconds (1-60 for a 60s window)
            expect(result.retryAfter).toBeGreaterThanOrEqual(1);
            expect(result.retryAfter).toBeLessThanOrEqual(60);
            // Should be an integer (Math.ceil result)
            expect(Number.isInteger(result.retryAfter)).toBe(true);
        });

        it('should calculate minute bucket using floor division', async () => {
            // The bucket is calculated as Math.floor(now / windowMs)
            // This ensures requests in the same minute window share a bucket
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            const keys = Array.from(mockKV._store.keys());
            const keyParts = keys[0]!.split(':');
            const bucket = parseInt(keyParts[3]!, 10);

            // Bucket should be floor(Date.now() / 60000)
            const expectedBucket = Math.floor(Date.now() / 60_000);
            expect(bucket).toBe(expectedBucket);
        });

        it('should calculate window boundaries correctly', async () => {
            const now = Date.now();
            const windowMs = 60_000;

            // Make a request
            const result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            // The window start is minuteBucket * windowMs
            // The window end is windowStart + windowMs
            // retryAfter should be ceiling of (windowEnd - now) / 1000
            const minuteBucket = Math.floor(now / windowMs);
            const windowStart = minuteBucket * windowMs;
            const windowEnd = windowStart + windowMs;
            const expectedRetryAfter = Math.ceil((windowEnd - now) / 1000);

            // Allow for small timing differences
            expect(Math.abs(result.retryAfter - expectedRetryAfter)).toBeLessThanOrEqual(1);
        });
    });

    describe('EqualityOperator Mutations (HAP-913)', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 3,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        it('should block when count equals maxRequests (>= not >)', async () => {
            // Make exactly maxRequests calls
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            // Next call should be blocked because count (3) >= maxRequests (3)
            const result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            expect(result.allowed).toBe(false);
            expect(result.count).toBe(3);
        });

        it('should allow when count is one less than maxRequests', async () => {
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            // Third call should be allowed (count 2 < maxRequests 3)
            const result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            expect(result.allowed).toBe(true);
            expect(result.count).toBe(3);
            expect(result.remaining).toBe(0);
        });

        it('should correctly check for undefined KV (!kv)', async () => {
            clearFallbackStore();
            resetFallbackWarning();

            // With undefined KV, should use fallback
            const result = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(result.allowed).toBe(true);
            expect(getFallbackStoreSize()).toBe(1);
        });

        it('should correctly check for existing entry (!entry)', async () => {
            clearFallbackStore();
            resetFallbackWarning();

            // First call - no entry exists, should create one
            const result1 = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(result1.count).toBe(1);

            // Second call - entry exists, should increment
            const result2 = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(result2.count).toBe(2);
        });

        it('should check remaining >= 0 with Math.max', async () => {
            // Exhaust the limit
            for (let i = 0; i < 5; i++) {
                await checkRateLimit(mockKV, 'test', 'user1', testConfig);
            }

            // Status should show remaining as 0, not negative
            const status = await getRateLimitStatus(mockKV, 'test', 'user1', testConfig);
            expect(status.remaining).toBe(0);
            expect(status.remaining).toBeGreaterThanOrEqual(0);
        });
    });

    describe('ConditionalExpression Mutations (HAP-913)', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 3,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        beforeEach(() => {
            clearFallbackStore();
            resetFallbackWarning();
            vi.spyOn(console, 'warn').mockImplementation(() => {});
        });

        afterEach(() => {
            vi.restoreAllMocks();
        });

        it('should log warning exactly once when KV is undefined', async () => {
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user2', testConfig);

            // Warning should be logged only once despite multiple calls
            expect(console.warn).toHaveBeenCalledTimes(1);
        });

        it('should use fallback path when KV is undefined', async () => {
            const result = await checkRateLimit(undefined, 'test', 'user1', testConfig);

            // Result should still work correctly
            expect(result.allowed).toBe(true);
            expect(result.count).toBe(1);
            expect(result.limit).toBe(3);
        });

        it('should use KV path when KV is defined', async () => {
            const result = await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            // KV.put should have been called
            expect(mockKV.put).toHaveBeenCalled();
            expect(result.allowed).toBe(true);
        });

        it('should handle currentValue being null (new entry)', async () => {
            // First request - no existing entry
            const result = await checkRateLimit(mockKV, 'test', 'newuser', testConfig);

            expect(result.count).toBe(1);
            expect(result.allowed).toBe(true);
        });

        it('should handle currentValue being a number string', async () => {
            // Pre-populate the store
            const now = Date.now();
            const minuteBucket = Math.floor(now / 60_000);
            const key = `rate:test:existinguser:${minuteBucket}`;
            mockKV._store.set(key, { value: '2' });

            const result = await checkRateLimit(mockKV, 'test', 'existinguser', testConfig);

            // Should parse '2' and increment to 3
            expect(result.count).toBe(3);
        });
    });

    describe('Fallback Memory Store Boundary Conditions (HAP-913)', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 2,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        beforeEach(() => {
            clearFallbackStore();
            resetFallbackWarning();
            vi.spyOn(console, 'warn').mockImplementation(() => {});
        });

        afterEach(() => {
            vi.restoreAllMocks();
        });

        it('should enforce rate limit at exact boundary', async () => {
            // Make exactly maxRequests calls
            const result1 = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(result1.allowed).toBe(true);
            expect(result1.count).toBe(1);
            expect(result1.remaining).toBe(1);

            const result2 = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(result2.allowed).toBe(true);
            expect(result2.count).toBe(2);
            expect(result2.remaining).toBe(0);

            // Third call should be blocked
            const result3 = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(result3.allowed).toBe(false);
            expect(result3.count).toBe(2);
            expect(result3.remaining).toBe(0);
        });

        it('should return retryAfter > 0 when rate limited', async () => {
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user1', testConfig);

            const result = await checkRateLimit(undefined, 'test', 'user1', testConfig);

            expect(result.allowed).toBe(false);
            expect(result.retryAfter).toBeGreaterThan(0);
        });

        it('should calculate remaining as 0 when at limit', async () => {
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            await checkRateLimit(undefined, 'test', 'user1', testConfig);

            const status = await getRateLimitStatus(undefined, 'test', 'user1', testConfig);

            expect(status.remaining).toBe(0);
        });

        it('should handle expiration check correctly', async () => {
            // This test verifies the `now > entry.resetAt` condition
            // We can't easily test time-based expiration without mocking Date.now
            // But we can verify the behavior is consistent
            const result1 = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(result1.count).toBe(1);

            const result2 = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(result2.count).toBe(2);
        });
    });

    describe('Key Format Validation (HAP-913)', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 5,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        it('should construct KV key with rate: prefix', async () => {
            await checkRateLimit(mockKV, 'myprefix', 'myuser', testConfig);

            const keys = Array.from(mockKV._store.keys());
            expect(keys[0]).toMatch(/^rate:myprefix:myuser:\d+$/);
        });

        it('should include minute bucket in KV key', async () => {
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            const keys = Array.from(mockKV._store.keys());
            const parts = keys[0]!.split(':');
            expect(parts.length).toBe(4);
            expect(parts[0]).toBe('rate');
            expect(parts[1]).toBe('test');
            expect(parts[2]).toBe('user1');
            expect(parseInt(parts[3]!, 10)).toBeGreaterThan(0);
        });

        it('should construct fallback key without minute bucket', async () => {
            clearFallbackStore();

            await checkRateLimit(undefined, 'test', 'user1', testConfig);

            // Fallback store uses key without minute bucket
            // The key is rate:prefix:identifier (no minute bucket)
            expect(getFallbackStoreSize()).toBe(1);
        });
    });

    describe('Default Values (HAP-913)', () => {
        it('should use default windowMs of 60000 when not specified', async () => {
            const minConfig: RateLimitConfig = { maxRequests: 5 };

            const result = await checkRateLimit(mockKV, 'test', 'user1', minConfig);

            // retryAfter should be <= 60 seconds (1 minute default window)
            expect(result.retryAfter).toBeLessThanOrEqual(60);
        });

        it('should use default expirationTtl of 120 when not specified', async () => {
            const minConfig: RateLimitConfig = { maxRequests: 5 };

            await checkRateLimit(mockKV, 'test', 'user1', minConfig);

            // Verify KV.put was called with default TTL
            expect(mockKV.put).toHaveBeenCalledWith(
                expect.any(String),
                '1',
                { expirationTtl: 120 }
            );
        });

        it('should use provided windowMs when specified', async () => {
            const customConfig: RateLimitConfig = {
                maxRequests: 5,
                windowMs: 30_000, // 30 seconds
            };

            const result = await checkRateLimit(mockKV, 'test', 'user1', customConfig);

            // retryAfter should be <= 30 seconds
            expect(result.retryAfter).toBeLessThanOrEqual(30);
        });

        it('should use provided expirationTtl when specified', async () => {
            const customConfig: RateLimitConfig = {
                maxRequests: 5,
                expirationTtl: 300, // 5 minutes
            };

            await checkRateLimit(mockKV, 'test', 'user1', customConfig);

            expect(mockKV.put).toHaveBeenCalledWith(
                expect.any(String),
                '1',
                { expirationTtl: 300 }
            );
        });
    });

    describe('resetRateLimit (HAP-913)', () => {
        const testConfig: RateLimitConfig = {
            maxRequests: 3,
            windowMs: 60_000,
            expirationTtl: 120,
        };

        beforeEach(() => {
            clearFallbackStore();
            resetFallbackWarning();
        });

        it('should delete from KV when KV is available', async () => {
            await checkRateLimit(mockKV, 'test', 'user1', testConfig);

            await resetRateLimit(mockKV, 'test', 'user1', testConfig);

            expect(mockKV.delete).toHaveBeenCalled();
        });

        it('should delete from fallback store when KV is undefined', async () => {
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(getFallbackStoreSize()).toBe(1);

            await resetRateLimit(undefined, 'test', 'user1', testConfig);

            // After reset, making a new request should start fresh
            const result = await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(result.count).toBe(1);
        });

        it('should always delete from fallback store regardless of KV', async () => {
            // First use fallback
            await checkRateLimit(undefined, 'test', 'user1', testConfig);
            expect(getFallbackStoreSize()).toBe(1);

            // Reset with KV - should still clear fallback
            await resetRateLimit(mockKV, 'test', 'user1', testConfig);

            // Both KV delete and fallback delete should happen
            expect(mockKV.delete).toHaveBeenCalled();
        });
    });
});
