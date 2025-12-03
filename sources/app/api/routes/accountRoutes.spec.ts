import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createTestApp, authHeader, TEST_USER_ID, randomId } from './__test__/testUtils';
import { accountRoutes } from './accountRoutes';
import type { Fastify } from '../types';

// Mock external dependencies
vi.mock('@/storage/db', () => ({
    db: {
        account: {
            findUnique: vi.fn(),
            findUniqueOrThrow: vi.fn(),
            updateMany: vi.fn(),
        },
        serviceAccountToken: {
            findMany: vi.fn(),
        },
        usageReport: {
            findMany: vi.fn(),
        },
        session: {
            findFirst: vi.fn(),
        },
    },
}));

vi.mock('@/app/events/eventRouter', () => ({
    eventRouter: {
        emitUpdate: vi.fn(),
    },
    buildUpdateAccountUpdate: vi.fn().mockReturnValue({ type: 'account-update', data: {} }),
}));

vi.mock('@/storage/seq', () => ({
    allocateUserSeq: vi.fn().mockResolvedValue(1),
}));

vi.mock('@/utils/log', () => ({
    log: vi.fn(),
}));

vi.mock('@/utils/randomKeyNaked', () => ({
    randomKeyNaked: vi.fn().mockReturnValue('random123'),
}));

vi.mock('@/storage/files', () => ({
    getPublicUrl: vi.fn((path: string) => `https://cdn.example.com/${path}`),
}));

import { db } from '@/storage/db';

describe('accountRoutes', () => {
    let app: Fastify;

    beforeEach(async () => {
        app = createTestApp();
        accountRoutes(app);
        await app.ready();
        vi.clearAllMocks();
    });

    afterEach(async () => {
        await app.close();
    });

    describe('GET /v1/account/profile', () => {
        it('should return user profile for authenticated user', async () => {
            const mockUser = {
                firstName: 'John',
                lastName: 'Doe',
                username: 'johndoe',
                avatar: { path: 'avatars/123.jpg', width: 200, height: 200 },
                githubUser: { profile: { login: 'johndoe', bio: 'Developer' } },
            };
            vi.mocked(db.account.findUniqueOrThrow).mockResolvedValue(mockUser as any);
            vi.mocked(db.serviceAccountToken.findMany).mockResolvedValue([
                { vendor: 'anthropic' } as any,
                { vendor: 'openai' } as any,
            ]);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/account/profile',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.id).toBe(TEST_USER_ID);
            expect(body.firstName).toBe('John');
            expect(body.lastName).toBe('Doe');
            expect(body.username).toBe('johndoe');
            expect(body.avatar.url).toContain('cdn.example.com');
            expect(body.connectedServices).toContain('anthropic');
            expect(body.connectedServices).toContain('openai');
        });

        it('should return 401 without authorization header', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/account/profile',
            });

            expect(response.statusCode).toBe(401);
        });

        it('should return 401 with invalid token', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/account/profile',
                headers: authHeader('invalid-token'),
            });

            expect(response.statusCode).toBe(401);
        });

        it('should return null avatar when user has no avatar', async () => {
            const mockUser = {
                firstName: 'Jane',
                lastName: null,
                username: 'jane',
                avatar: null,
                githubUser: null,
            };
            vi.mocked(db.account.findUniqueOrThrow).mockResolvedValue(mockUser as any);
            vi.mocked(db.serviceAccountToken.findMany).mockResolvedValue([]);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/account/profile',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.avatar).toBeNull();
            expect(body.github).toBeNull();
            expect(body.connectedServices).toHaveLength(0);
        });
    });

    describe('GET /v1/account/settings', () => {
        it('should return settings for authenticated user', async () => {
            vi.mocked(db.account.findUnique).mockResolvedValue({
                settings: '{"theme":"dark"}',
                settingsVersion: 5,
            } as any);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/account/settings',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.settings).toBe('{"theme":"dark"}');
            expect(body.settingsVersion).toBe(5);
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/account/settings',
            });

            expect(response.statusCode).toBe(401);
        });

        it('should return 500 when user not found', async () => {
            vi.mocked(db.account.findUnique).mockResolvedValue(null);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/account/settings',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(500);
            const body = JSON.parse(response.payload);
            expect(body.error).toBe('Failed to get account settings');
        });

        it('should return null settings when user has no settings', async () => {
            vi.mocked(db.account.findUnique).mockResolvedValue({
                settings: null,
                settingsVersion: 0,
            } as any);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/account/settings',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.settings).toBeNull();
            expect(body.settingsVersion).toBe(0);
        });
    });

    describe('POST /v1/account/settings', () => {
        it('should update settings with correct version', async () => {
            vi.mocked(db.account.findUnique).mockResolvedValue({
                settings: '{"old":"data"}',
                settingsVersion: 2,
            } as any);
            vi.mocked(db.account.updateMany).mockResolvedValue({ count: 1 } as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/account/settings',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    settings: '{"new":"data"}',
                    expectedVersion: 2,
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(true);
            expect(body.version).toBe(3);
        });

        it('should return version-mismatch when version does not match', async () => {
            vi.mocked(db.account.findUnique).mockResolvedValue({
                settings: '{"current":"data"}',
                settingsVersion: 5,
            } as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/account/settings',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    settings: '{"new":"data"}',
                    expectedVersion: 3, // Wrong version
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(false);
            expect(body.error).toBe('version-mismatch');
            expect(body.currentVersion).toBe(5);
            expect(body.currentSettings).toBe('{"current":"data"}');
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/account/settings',
                headers: {
                    'Content-Type': 'application/json',
                },
                payload: {
                    settings: '{}',
                    expectedVersion: 0,
                },
            });

            expect(response.statusCode).toBe(401);
        });

        it('should return validation error for missing required fields', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/account/settings',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    // Missing settings and expectedVersion
                },
            });

            expect(response.statusCode).toBe(400);
        });

        it('should handle concurrent update race condition', async () => {
            // First call returns version 2
            vi.mocked(db.account.findUnique)
                .mockResolvedValueOnce({
                    settings: '{"old":"data"}',
                    settingsVersion: 2,
                } as any)
                // Second call (after failed update) returns version 3
                .mockResolvedValueOnce({
                    settings: '{"concurrent":"data"}',
                    settingsVersion: 3,
                } as any);

            // updateMany returns 0 (race condition - someone else updated)
            vi.mocked(db.account.updateMany).mockResolvedValue({ count: 0 } as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/account/settings',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    settings: '{"new":"data"}',
                    expectedVersion: 2,
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(false);
            expect(body.error).toBe('version-mismatch');
            expect(body.currentVersion).toBe(3);
        });

        it('should allow setting settings to null', async () => {
            vi.mocked(db.account.findUnique).mockResolvedValue({
                settings: '{"existing":"data"}',
                settingsVersion: 1,
            } as any);
            vi.mocked(db.account.updateMany).mockResolvedValue({ count: 1 } as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/account/settings',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    settings: null,
                    expectedVersion: 1,
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(true);
        });
    });

    describe('POST /v1/usage/query', () => {
        it('should return aggregated usage data', async () => {
            const now = new Date();
            vi.mocked(db.usageReport.findMany).mockResolvedValue([
                {
                    id: 'report-1',
                    accountId: TEST_USER_ID,
                    sessionId: 'sess-1',
                    createdAt: now,
                    data: {
                        tokens: { input: 100, output: 50 },
                        cost: { input: 0.001, output: 0.002 },
                    },
                },
            ] as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/usage/query',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {},
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.usage).toBeDefined();
            expect(body.groupBy).toBe('day');
            expect(body.totalReports).toBe(1);
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/usage/query',
                headers: {
                    'Content-Type': 'application/json',
                },
                payload: {},
            });

            expect(response.statusCode).toBe(401);
        });

        it('should filter by sessionId', async () => {
            const mockSession = { id: 'sess-123', accountId: TEST_USER_ID };
            vi.mocked(db.session.findFirst).mockResolvedValue(mockSession as any);
            vi.mocked(db.usageReport.findMany).mockResolvedValue([]);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/usage/query',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    sessionId: 'sess-123',
                },
            });

            expect(response.statusCode).toBe(200);
            expect(vi.mocked(db.usageReport.findMany)).toHaveBeenCalledWith(
                expect.objectContaining({
                    where: expect.objectContaining({
                        sessionId: 'sess-123',
                    }),
                })
            );
        });

        it('should return 404 for non-existent session', async () => {
            vi.mocked(db.session.findFirst).mockResolvedValue(null);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/usage/query',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    sessionId: 'non-existent-session',
                },
            });

            expect(response.statusCode).toBe(404);
            const body = JSON.parse(response.payload);
            expect(body.error).toBe('Session not found');
        });

        it('should support groupBy hour', async () => {
            vi.mocked(db.usageReport.findMany).mockResolvedValue([]);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/usage/query',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    groupBy: 'hour',
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.groupBy).toBe('hour');
        });
    });
});
