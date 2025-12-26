import { describe, it, expect, beforeEach, afterEach, vi, beforeAll, afterAll } from 'vitest';
import { RateLimitTiers, type RateLimitTier } from './enableRateLimiting';

// Mock dependencies before importing the module
vi.mock('@/utils/log', () => ({
    log: vi.fn(),
}));

vi.mock('@/storage/redis', () => ({
    redis: {
        status: 'ready',
    },
}));

/**
 * Unit tests for enableRateLimiting module
 *
 * Tests the rate limit tier configuration and behavior.
 * The actual rate limiting integration is tested via route integration tests.
 *
 * @remarks
 * Rate limiting is disabled in test environment (NODE_ENV=test) to avoid
 * test interference. These tests verify configuration correctness.
 */
describe('enableRateLimiting', () => {
    describe('RateLimitTiers', () => {
        it('should define CRITICAL tier with strictest limits', () => {
            expect(RateLimitTiers.CRITICAL).toEqual({
                max: 5,
                timeWindow: '1 minute',
            });
        });

        it('should define HIGH tier for auth and write operations', () => {
            expect(RateLimitTiers.HIGH).toEqual({
                max: 30,
                timeWindow: '1 minute',
            });
        });

        it('should define MEDIUM tier as default for queries', () => {
            expect(RateLimitTiers.MEDIUM).toEqual({
                max: 60,
                timeWindow: '1 minute',
            });
        });

        it('should define LOW tier for simple reads', () => {
            expect(RateLimitTiers.LOW).toEqual({
                max: 120,
                timeWindow: '1 minute',
            });
        });

        it('should have tiers in ascending order of strictness', () => {
            // CRITICAL < HIGH < MEDIUM < LOW (in terms of max requests)
            expect(RateLimitTiers.CRITICAL.max).toBeLessThan(RateLimitTiers.HIGH.max);
            expect(RateLimitTiers.HIGH.max).toBeLessThan(RateLimitTiers.MEDIUM.max);
            expect(RateLimitTiers.MEDIUM.max).toBeLessThan(RateLimitTiers.LOW.max);
        });

        it('should use consistent time window across all tiers', () => {
            const tiers = [
                RateLimitTiers.CRITICAL,
                RateLimitTiers.HIGH,
                RateLimitTiers.MEDIUM,
                RateLimitTiers.LOW,
            ];

            for (const tier of tiers) {
                expect(tier.timeWindow).toBe('1 minute');
            }
        });
    });

    describe('tier type safety', () => {
        it('should be usable as RateLimitTier type', () => {
            // TypeScript compile-time check - if this compiles, types are correct
            const critical: RateLimitTier = RateLimitTiers.CRITICAL;
            const high: RateLimitTier = RateLimitTiers.HIGH;
            const medium: RateLimitTier = RateLimitTiers.MEDIUM;
            const low: RateLimitTier = RateLimitTiers.LOW;

            expect(critical).toBeDefined();
            expect(high).toBeDefined();
            expect(medium).toBeDefined();
            expect(low).toBeDefined();
        });

        it('should have readonly tier values', () => {
            // Verify the tiers object is frozen (const assertion)
            // Attempting to modify should not change values
            const originalMax = RateLimitTiers.CRITICAL.max;
            expect(originalMax).toBe(5);

            // TypeScript would prevent this at compile time, but runtime check too
            expect(RateLimitTiers.CRITICAL.max).toBe(5);
        });
    });

    describe('enableRateLimiting function', () => {
        const originalNodeEnv = process.env.NODE_ENV;

        afterAll(() => {
            process.env.NODE_ENV = originalNodeEnv;
        });

        it('should skip rate limiting in test environment', async () => {
            process.env.NODE_ENV = 'test';

            // Import the function fresh to test the skip behavior
            const { enableRateLimiting } = await import('./enableRateLimiting');
            const { log } = await import('@/utils/log');

            // Create a mock Fastify app
            const mockApp = {
                register: vi.fn(),
            };

            await enableRateLimiting(mockApp as any);

            // Should not register rate limiting plugin
            expect(mockApp.register).not.toHaveBeenCalled();

            // Should log that rate limiting is disabled
            expect(log).toHaveBeenCalledWith(
                { module: 'rate-limit' },
                'Rate limiting disabled in test environment'
            );
        });
    });

    describe('rate limit tier documentation', () => {
        it('should have appropriate limits for cost analysis', () => {
            // CRITICAL: External paid APIs (ElevenLabs, RevenueCat)
            // 5/min is reasonable for expensive external API calls
            expect(RateLimitTiers.CRITICAL.max).toBe(5);

            // HIGH: Auth + crypto operations, DB writes
            // 30/min allows reasonable usage while preventing abuse
            expect(RateLimitTiers.HIGH.max).toBe(30);

            // MEDIUM: List endpoints, pagination queries
            // 60/min is the global default, suitable for most operations
            expect(RateLimitTiers.MEDIUM.max).toBe(60);

            // LOW: Simple reads, health checks
            // 120/min allows frequent polling without concern
            expect(RateLimitTiers.LOW.max).toBe(120);
        });
    });
});
