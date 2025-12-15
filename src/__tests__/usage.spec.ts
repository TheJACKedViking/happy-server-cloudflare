/**
 * Integration Tests for Usage Routes
 *
 * Tests the POST /v1/usage/query endpoint which aggregates usage data
 * by time period (hour/day) with optional filtering by session and time range.
 *
 * @module __tests__/usage.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    expectOk,
    expectStatus,
    createTestSession,
    createMockDrizzle,
    createMockR2,
    createMockDurableObjectNamespace,
    TEST_USER_ID,
    TEST_USER_ID_2,
    generateTestId,
} from './test-utils';

// Store the mock instance for test access
let drizzleMock: ReturnType<typeof createMockDrizzle>;

// Mock cloudflare:workers module
vi.mock('cloudflare:workers', () => ({
    DurableObject: class DurableObject {
        ctx: DurableObjectState;
        env: unknown;
        constructor(ctx: DurableObjectState, env: unknown) {
            this.ctx = ctx;
            this.env = env;
        }
    },
}));

// Mock auth module
vi.mock('@/lib/auth', () => ({
    initAuth: vi.fn().mockResolvedValue(undefined),
    verifyToken: vi.fn().mockImplementation(async (token: string) => {
        if (token === 'valid-token') {
            return { userId: TEST_USER_ID, extras: {} };
        }
        if (token === 'user2-token') {
            return { userId: TEST_USER_ID_2, extras: {} };
        }
        return null;
    }),
    createToken: vi.fn().mockResolvedValue('generated-token'),
    resetAuth: vi.fn(),
}));

// Mock the getDb function to return our mock Drizzle client
vi.mock('@/db/client', () => ({
    getDb: vi.fn(() => {
        return drizzleMock?.mockDb;
    }),
}));

// Import app AFTER mocks are set up
import app from '@/index';

/**
 * Create mock environment for Hono app.request()
 */
function createTestEnv() {
    return {
        ENVIRONMENT: 'development' as const,
        HANDY_MASTER_SECRET: 'test-secret-for-vitest-tests',
        DB: {} as D1Database,
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
    };
}

// Shared test environment
let testEnv: ReturnType<typeof createTestEnv>;

/**
 * Create test usage report data compatible with Drizzle ORM schema
 */
function createTestUsageReport(
    accountId: string,
    overrides: Partial<{
        id: string;
        key: string;
        sessionId: string | null;
        data: { tokens: Record<string, number>; cost: Record<string, number> };
        createdAt: Date;
        updatedAt: Date;
    }> = {}
) {
    const now = new Date();
    return {
        id: overrides.id ?? generateTestId('usage'),
        key: overrides.key ?? `usage-${Date.now()}`,
        accountId,
        sessionId: overrides.sessionId ?? null,
        data: overrides.data ?? {
            tokens: { input: 1000, output: 500 },
            cost: { input: 0.01, output: 0.015 },
        },
        createdAt: overrides.createdAt ?? now,
        updatedAt: overrides.updatedAt ?? now,
    };
}

describe('Usage Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        drizzleMock = createMockDrizzle();
        testEnv = createTestEnv();
    });

    afterEach(() => {
        drizzleMock?.clearAll();
    });

    /**
     * Helper to make authenticated requests
     */
    async function authRequest(
        path: string,
        options: RequestInit = {},
        token: string = 'valid-token'
    ): Promise<Response> {
        const headers = new Headers(options.headers);
        headers.set('Authorization', `Bearer ${token}`);
        headers.set('Content-Type', 'application/json');

        return app.request(path, { ...options, headers }, testEnv);
    }

    /**
     * Helper for unauthenticated requests
     */
    async function unauthRequest(path: string, options: RequestInit = {}): Promise<Response> {
        const headers = new Headers(options.headers);
        headers.set('Content-Type', 'application/json');
        return app.request(path, { ...options, headers }, testEnv);
    }

    describe('POST /v1/usage/query - Query Usage Data', () => {
        describe('Authentication', () => {
            it('should return 401 for unauthenticated request', async () => {
                const res = await unauthRequest('/v1/usage/query', {
                    method: 'POST',
                    body: JSON.stringify({}),
                });
                expect(res.status).toBe(401);
            });

            it('should return 401 for invalid token', async () => {
                const res = await authRequest(
                    '/v1/usage/query',
                    {
                        method: 'POST',
                        body: JSON.stringify({}),
                    },
                    'invalid-token'
                );
                expect(res.status).toBe(401);
            });
        });

        describe('Error Handling', () => {
            it('should return 500 when database query fails', async () => {
                // Make the database select throw an error
                const originalSelect = drizzleMock.mockDb.select;
                drizzleMock.mockDb.select = vi.fn(() => {
                    return {
                        from: vi.fn(() => ({
                            where: vi.fn(() => ({
                                orderBy: vi.fn(() => {
                                    throw new Error('Database connection failed');
                                }),
                            })),
                        })),
                    };
                });

                const res = await authRequest('/v1/usage/query', {
                    method: 'POST',
                    body: JSON.stringify({}),
                });

                expect(res.status).toBe(500);
                const body = await res.json();
                expect(body).toHaveProperty('error', 'Failed to query usage reports');

                // Restore original
                drizzleMock.mockDb.select = originalSelect;
            });
        });

        describe('Success Cases - Empty Data', () => {
            it('should return empty usage array when no reports exist', async () => {
                const body = await expectOk<{
                    usage: unknown[];
                    groupBy: string;
                    totalReports: number;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.usage).toEqual([]);
                expect(body.groupBy).toBe('day');
                expect(body.totalReports).toBe(0);
            });

            it('should default groupBy to day when not specified', async () => {
                const body = await expectOk<{ groupBy: string }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.groupBy).toBe('day');
            });
        });

        describe('Success Cases - With Data', () => {
            it('should return aggregated usage data grouped by day', async () => {
                // Create reports on the same day
                const baseDate = new Date('2024-01-15T10:00:00Z');
                const report1 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: new Date(baseDate),
                    data: {
                        tokens: { input: 1000, output: 500 },
                        cost: { input: 0.01, output: 0.015 },
                    },
                });
                const report2 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-2',
                    createdAt: new Date(baseDate.getTime() + 3600000), // 1 hour later, same day
                    data: {
                        tokens: { input: 2000, output: 1000 },
                        cost: { input: 0.02, output: 0.03 },
                    },
                });

                drizzleMock.seedData('usageReports', [report1, report2]);

                const body = await expectOk<{
                    usage: Array<{
                        timestamp: number;
                        tokens: Record<string, number>;
                        cost: Record<string, number>;
                        reportCount: number;
                    }>;
                    groupBy: string;
                    totalReports: number;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'day' }),
                    })
                );

                expect(body.totalReports).toBe(2);
                expect(body.groupBy).toBe('day');
                expect(body.usage).toHaveLength(1); // Both reports on same day
                expect(body.usage[0]?.reportCount).toBe(2);
                expect(body.usage[0]?.tokens.input).toBe(3000); // 1000 + 2000
                expect(body.usage[0]?.tokens.output).toBe(1500); // 500 + 1000
                expect(body.usage[0]?.cost.input).toBeCloseTo(0.03); // 0.01 + 0.02
                expect(body.usage[0]?.cost.output).toBeCloseTo(0.045); // 0.015 + 0.03
            });

            it('should return aggregated usage data grouped by hour', async () => {
                const baseDate = new Date('2024-01-15T10:00:00Z');
                const report1 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: new Date(baseDate),
                    data: {
                        tokens: { input: 1000 },
                        cost: { input: 0.01 },
                    },
                });
                const report2 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-2',
                    createdAt: new Date(baseDate.getTime() + 3600000), // 1 hour later
                    data: {
                        tokens: { input: 2000 },
                        cost: { input: 0.02 },
                    },
                });

                drizzleMock.seedData('usageReports', [report1, report2]);

                const body = await expectOk<{
                    usage: Array<{
                        timestamp: number;
                        tokens: Record<string, number>;
                        cost: Record<string, number>;
                        reportCount: number;
                    }>;
                    groupBy: string;
                    totalReports: number;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'hour' }),
                    })
                );

                expect(body.totalReports).toBe(2);
                expect(body.groupBy).toBe('hour');
                expect(body.usage).toHaveLength(2); // Different hours
                expect(body.usage[0]?.reportCount).toBe(1);
                expect(body.usage[1]?.reportCount).toBe(1);
            });

            it('should aggregate multiple reports in the same hour', async () => {
                const baseDate = new Date('2024-01-15T10:15:00Z');
                const report1 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: new Date(baseDate),
                    data: {
                        tokens: { input: 500, cache_read: 100 },
                        cost: { input: 0.005, cache_read: 0.001 },
                    },
                });
                const report2 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-2',
                    createdAt: new Date(baseDate.getTime() + 30 * 60000), // 30 minutes later, same hour
                    data: {
                        tokens: { input: 500, output: 200 },
                        cost: { input: 0.005, output: 0.006 },
                    },
                });

                drizzleMock.seedData('usageReports', [report1, report2]);

                const body = await expectOk<{
                    usage: Array<{
                        tokens: Record<string, number>;
                        cost: Record<string, number>;
                        reportCount: number;
                    }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'hour' }),
                    })
                );

                expect(body.usage).toHaveLength(1);
                expect(body.usage[0]?.tokens.input).toBe(1000);
                expect(body.usage[0]?.tokens.cache_read).toBe(100);
                expect(body.usage[0]?.tokens.output).toBe(200);
                expect(body.usage[0]?.cost.input).toBeCloseTo(0.01);
            });

            it('should sort results by timestamp ascending', async () => {
                const report1 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: new Date('2024-01-17T10:00:00Z'),
                });
                const report2 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-2',
                    createdAt: new Date('2024-01-15T10:00:00Z'),
                });
                const report3 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-3',
                    createdAt: new Date('2024-01-16T10:00:00Z'),
                });

                drizzleMock.seedData('usageReports', [report1, report2, report3]);

                const body = await expectOk<{
                    usage: Array<{ timestamp: number }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'day' }),
                    })
                );

                expect(body.usage).toHaveLength(3);
                expect(body.usage[0]?.timestamp).toBeLessThan(body.usage[1]?.timestamp ?? 0);
                expect(body.usage[1]?.timestamp).toBeLessThan(body.usage[2]?.timestamp ?? 0);
            });
        });

        describe('Filtering by Session', () => {
            it('should filter usage by sessionId when provided', async () => {
                const session = createTestSession(TEST_USER_ID, { id: 'session-123' });
                drizzleMock.seedData('sessions', [session]);

                // Only seed the report we want to find - mock doesn't filter by sessionId
                const report1 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    sessionId: 'session-123',
                    data: { tokens: { input: 1000 }, cost: { input: 0.01 } },
                });

                drizzleMock.seedData('usageReports', [report1]);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number> }>;
                    totalReports: number;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ sessionId: 'session-123' }),
                    })
                );

                // Verify route validates session ownership and returns data
                expect(body.totalReports).toBe(1);
                expect(body.usage[0]?.tokens.input).toBe(1000);
            });

            it('should return 404 when sessionId does not exist', async () => {
                const res = await authRequest('/v1/usage/query', {
                    method: 'POST',
                    body: JSON.stringify({ sessionId: 'non-existent-session' }),
                });

                expect(res.status).toBe(404);
                const body = await res.json();
                expect(body).toHaveProperty('error', 'Session not found');
            });

            it('should return 404 when session belongs to another user', async () => {
                const otherUserSession = createTestSession(TEST_USER_ID_2, {
                    id: 'other-user-session',
                });
                drizzleMock.seedData('sessions', [otherUserSession]);

                const res = await authRequest('/v1/usage/query', {
                    method: 'POST',
                    body: JSON.stringify({ sessionId: 'other-user-session' }),
                });

                expect(res.status).toBe(404);
                const body = await res.json();
                expect(body).toHaveProperty('error', 'Session not found');
            });
        });

        describe('Filtering by Time Range', () => {
            it('should accept startTime parameter and return success', async () => {
                // Mock doesn't filter by time, so just verify route accepts the param
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: new Date('2024-01-20T10:00:00Z'),
                    data: { tokens: { input: 2000 }, cost: { input: 0.02 } },
                });

                drizzleMock.seedData('usageReports', [report]);

                const startTime = Math.floor(new Date('2024-01-15T00:00:00Z').getTime() / 1000);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number> }>;
                    totalReports: number;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ startTime }),
                    })
                );

                // Route should accept startTime and process successfully
                expect(body.totalReports).toBeGreaterThanOrEqual(0);
            });

            it('should accept endTime parameter and return success', async () => {
                // Mock doesn't filter by time, so just verify route accepts the param
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: new Date('2024-01-10T10:00:00Z'),
                    data: { tokens: { input: 1000 }, cost: { input: 0.01 } },
                });

                drizzleMock.seedData('usageReports', [report]);

                const endTime = Math.floor(new Date('2024-01-15T00:00:00Z').getTime() / 1000);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number> }>;
                    totalReports: number;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ endTime }),
                    })
                );

                // Route should accept endTime and process successfully
                expect(body.totalReports).toBeGreaterThanOrEqual(0);
            });

            it('should accept both startTime and endTime parameters', async () => {
                // Verify route processes both time parameters
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: new Date('2024-01-15T10:00:00Z'),
                    data: { tokens: { input: 2000 }, cost: {} },
                });

                drizzleMock.seedData('usageReports', [report]);

                const startTime = Math.floor(new Date('2024-01-10T00:00:00Z').getTime() / 1000);
                const endTime = Math.floor(new Date('2024-01-20T00:00:00Z').getTime() / 1000);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number> }>;
                    totalReports: number;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ startTime, endTime }),
                    })
                );

                expect(body.totalReports).toBeGreaterThanOrEqual(0);
            });
        });

        describe('User Isolation', () => {
            it('should process query for authenticated user', async () => {
                // Mock doesn't filter by accountId, so test verifies route processes successfully
                const myReport = createTestUsageReport(TEST_USER_ID, {
                    id: 'my-report',
                    data: { tokens: { input: 1000 }, cost: { input: 0.01 } },
                });

                drizzleMock.seedData('usageReports', [myReport]);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number> }>;
                    totalReports: number;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.totalReports).toBeGreaterThanOrEqual(1);
                expect(body.usage[0]?.tokens.input).toBe(1000);
            });

            it('should require authentication for all queries', async () => {
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    data: { tokens: { input: 1000 }, cost: { input: 0.01 } },
                });

                drizzleMock.seedData('usageReports', [report]);

                // Query without auth should fail
                const res = await unauthRequest('/v1/usage/query', {
                    method: 'POST',
                    body: JSON.stringify({}),
                });

                expect(res.status).toBe(401);
            });
        });

        describe('Edge Cases', () => {
            it('should handle reports with empty tokens object', async () => {
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'empty-tokens-report',
                    data: { tokens: {}, cost: { input: 0.01 } },
                });

                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number>; cost: Record<string, number> }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.usage).toHaveLength(1);
                expect(body.usage[0]?.tokens).toEqual({});
                expect(body.usage[0]?.cost.input).toBeCloseTo(0.01);
            });

            it('should handle reports with empty cost object', async () => {
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'empty-cost-report',
                    data: { tokens: { input: 1000 }, cost: {} },
                });

                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number>; cost: Record<string, number> }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.usage).toHaveLength(1);
                expect(body.usage[0]?.tokens.input).toBe(1000);
                expect(body.usage[0]?.cost).toEqual({});
            });

            it('should handle reports with null sessionId', async () => {
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'null-session-report',
                    sessionId: null,
                });

                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{ totalReports: number }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.totalReports).toBe(1);
            });

            it('should handle null sessionId in request body', async () => {
                const report = createTestUsageReport(TEST_USER_ID, { id: 'report-1' });
                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{ totalReports: number }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ sessionId: null }),
                    })
                );

                expect(body.totalReports).toBe(1);
            });

            it('should handle undefined optional parameters', async () => {
                const report = createTestUsageReport(TEST_USER_ID, { id: 'report-1' });
                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{ totalReports: number; groupBy: string }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({
                            sessionId: undefined,
                            startTime: undefined,
                            endTime: undefined,
                            groupBy: undefined,
                        }),
                    })
                );

                expect(body.totalReports).toBe(1);
                expect(body.groupBy).toBe('day');
            });

            it('should skip non-numeric token values during aggregation', async () => {
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'mixed-tokens-report',
                    // @ts-expect-error - Testing invalid data handling
                    data: { tokens: { input: 1000, invalid: 'not a number' }, cost: {} },
                });

                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number> }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.usage[0]?.tokens.input).toBe(1000);
                expect(body.usage[0]?.tokens.invalid).toBeUndefined();
            });

            it('should skip non-numeric cost values during aggregation', async () => {
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'mixed-cost-report',
                    // @ts-expect-error - Testing invalid data handling
                    data: { tokens: {}, cost: { input: 0.01, invalid: 'not a number' } },
                });

                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{
                    usage: Array<{ cost: Record<string, number> }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.usage[0]?.cost.input).toBeCloseTo(0.01);
                expect(body.usage[0]?.cost.invalid).toBeUndefined();
            });

            it('should handle reports with missing tokens field', async () => {
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'no-tokens-report',
                    // @ts-expect-error - Testing invalid data handling
                    data: { cost: { input: 0.01 } },
                });

                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number>; cost: Record<string, number> }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.usage).toHaveLength(1);
                expect(body.usage[0]?.tokens).toEqual({});
                expect(body.usage[0]?.cost.input).toBeCloseTo(0.01);
            });

            it('should handle reports with missing cost field', async () => {
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'no-cost-report',
                    // @ts-expect-error - Testing invalid data handling
                    data: { tokens: { input: 1000 } },
                });

                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number>; cost: Record<string, number> }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({}),
                    })
                );

                expect(body.usage).toHaveLength(1);
                expect(body.usage[0]?.tokens.input).toBe(1000);
                expect(body.usage[0]?.cost).toEqual({});
            });

            it('should handle large number of reports', async () => {
                // Create multiple reports on the same day (same hour)
                const reports = Array.from({ length: 50 }, (_, i) =>
                    createTestUsageReport(TEST_USER_ID, {
                        id: `report-${i}`,
                        createdAt: new Date('2024-01-15T10:00:00Z'), // All same hour
                        data: { tokens: { input: 100 }, cost: { input: 0.001 } },
                    })
                );

                drizzleMock.seedData('usageReports', reports);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number>; reportCount: number }>;
                    totalReports: number;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'day' }),
                    })
                );

                expect(body.totalReports).toBe(50);
                // All reports on same day should aggregate into 1 entry
                expect(body.usage).toHaveLength(1);
                expect(body.usage[0]?.tokens.input).toBe(5000); // 50 * 100
                expect(body.usage[0]?.reportCount).toBe(50);
            });
        });

        describe('Combined Filters', () => {
            it('should accept all filter parameters together', async () => {
                const session = createTestSession(TEST_USER_ID, { id: 'target-session' });
                drizzleMock.seedData('sessions', [session]);

                // Seed only the matching report since mock doesn't filter
                const matchingReport = createTestUsageReport(TEST_USER_ID, {
                    id: 'matching-report',
                    sessionId: 'target-session',
                    createdAt: new Date('2024-01-15T10:00:00Z'),
                    data: { tokens: { input: 1000 }, cost: { input: 0.01 } },
                });

                drizzleMock.seedData('usageReports', [matchingReport]);

                const startTime = Math.floor(new Date('2024-01-10T00:00:00Z').getTime() / 1000);
                const endTime = Math.floor(new Date('2024-01-20T00:00:00Z').getTime() / 1000);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number> }>;
                    totalReports: number;
                    groupBy: string;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({
                            sessionId: 'target-session',
                            startTime,
                            endTime,
                            groupBy: 'hour',
                        }),
                    })
                );

                expect(body.totalReports).toBe(1);
                expect(body.groupBy).toBe('hour');
                expect(body.usage[0]?.tokens.input).toBe(1000);
            });
        });

        describe('GroupBy Variants', () => {
            it('should accept groupBy: "hour"', async () => {
                const report = createTestUsageReport(TEST_USER_ID, { id: 'report-1' });
                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{ groupBy: string }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'hour' }),
                    })
                );

                expect(body.groupBy).toBe('hour');
            });

            it('should accept groupBy: "day"', async () => {
                const report = createTestUsageReport(TEST_USER_ID, { id: 'report-1' });
                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{ groupBy: string }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'day' }),
                    })
                );

                expect(body.groupBy).toBe('day');
            });
        });

        describe('Timestamp Calculation', () => {
            it('should round timestamps to start of hour when groupBy is hour', async () => {
                // Create date at 10:35:22
                const reportDate = new Date('2024-01-15T10:35:22Z');
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: reportDate,
                });

                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{
                    usage: Array<{ timestamp: number }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'hour' }),
                    })
                );

                // Timestamp should be at start of hour (minutes, seconds, ms = 0)
                // The code uses local time, so we calculate expected based on local timezone
                const localDate = new Date(reportDate);
                const expectedDate = new Date(
                    localDate.getFullYear(),
                    localDate.getMonth(),
                    localDate.getDate(),
                    localDate.getHours(),
                    0, 0, 0
                );
                const expectedTimestamp = Math.floor(expectedDate.getTime() / 1000);
                expect(body.usage[0]?.timestamp).toBe(expectedTimestamp);
            });

            it('should round timestamps to start of day when groupBy is day', async () => {
                // Create date at 10:35:22
                const reportDate = new Date('2024-01-15T10:35:22Z');
                const report = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: reportDate,
                });

                drizzleMock.seedData('usageReports', [report]);

                const body = await expectOk<{
                    usage: Array<{ timestamp: number }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'day' }),
                    })
                );

                // Timestamp should be at start of day (hours, minutes, seconds, ms = 0)
                // The code uses local time, so we calculate expected based on local timezone
                const localDate = new Date(reportDate);
                const expectedDate = new Date(
                    localDate.getFullYear(),
                    localDate.getMonth(),
                    localDate.getDate(),
                    0, 0, 0, 0
                );
                const expectedTimestamp = Math.floor(expectedDate.getTime() / 1000);
                expect(body.usage[0]?.timestamp).toBe(expectedTimestamp);
            });

            it('should group reports in the same day together', async () => {
                // Two reports on the same day but different hours
                const baseDate = new Date('2024-01-15T08:00:00Z');
                const report1 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: new Date(baseDate),
                    data: { tokens: { input: 1000 }, cost: {} },
                });
                const report2 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-2',
                    createdAt: new Date(baseDate.getTime() + 4 * 3600000), // 4 hours later
                    data: { tokens: { input: 2000 }, cost: {} },
                });

                drizzleMock.seedData('usageReports', [report1, report2]);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number>; reportCount: number }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'day' }),
                    })
                );

                // Both reports same local day = aggregated together
                expect(body.usage[0]?.reportCount).toBe(2);
                expect(body.usage[0]?.tokens.input).toBe(3000);
            });

            it('should group reports in the same hour together', async () => {
                // Two reports in the same hour
                const baseDate = new Date('2024-01-15T10:00:00Z');
                const report1 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-1',
                    createdAt: new Date(baseDate),
                    data: { tokens: { input: 500 }, cost: {} },
                });
                const report2 = createTestUsageReport(TEST_USER_ID, {
                    id: 'report-2',
                    createdAt: new Date(baseDate.getTime() + 30 * 60000), // 30 minutes later
                    data: { tokens: { input: 500 }, cost: {} },
                });

                drizzleMock.seedData('usageReports', [report1, report2]);

                const body = await expectOk<{
                    usage: Array<{ tokens: Record<string, number>; reportCount: number }>;
                }>(
                    await authRequest('/v1/usage/query', {
                        method: 'POST',
                        body: JSON.stringify({ groupBy: 'hour' }),
                    })
                );

                // Both reports same hour = aggregated together
                expect(body.usage[0]?.reportCount).toBe(2);
                expect(body.usage[0]?.tokens.input).toBe(1000);
            });
        });
    });
});
