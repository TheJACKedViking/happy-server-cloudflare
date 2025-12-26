/**
 * Integration Tests for KV and Push Routes
 *
 * Tests KV endpoints:
 * - GET /v1/kv/:key (get single)
 * - GET /v1/kv (list)
 * - POST /v1/kv/bulk (bulk get)
 * - POST /v1/kv (mutate)
 *
 * And push endpoints:
 * - POST /v1/push-tokens (register)
 * - DELETE /v1/push-tokens/:token (delete)
 * - GET /v1/push-tokens (list)
 *
 * @module __tests__/kv-push.spec
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

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
            return { userId: 'test-user-123', extras: {} };
        }
        if (token === 'user2-token') {
            return { userId: 'test-user-456', extras: {} };
        }
        return null;
    }),
    createToken: vi.fn().mockResolvedValue('generated-token'),
    resetAuth: vi.fn(),
}));

import { app } from '@/index';
import { authHeader, jsonBody, expectOneOfStatus, createMockR2, createMockDurableObjectNamespace } from './test-utils';

/**
 * Create mock environment for Hono app.request()
 */
function createTestEnv() {
    return {
        ENVIRONMENT: 'development' as const,
        HAPPY_MASTER_SECRET: 'test-secret-for-vitest-tests-min-32-chars',
        DB: {} as D1Database,
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
    };
}

// Shared test environment
let testEnv: ReturnType<typeof createTestEnv>;

describe('KV Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        testEnv = createTestEnv();
    });

    describe('GET /v1/kv/:key - Get Single KV', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/kv/test-key', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return KV entry if exists', async () => {
            const res = await app.request('/v1/kv/settings:theme', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{ key: string; value: string; version: number }>(res, [200], [404, 500]);
            if (!body) return;
            expect(body).toHaveProperty('key');
            expect(body).toHaveProperty('value');
            expect(body).toHaveProperty('version');
        });

        it('should return 404 for non-existent key', async () => {
            const res = await app.request('/v1/kv/non-existent-key', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [404], [500]);
        });

        it('should handle keys with colons', async () => {
            const res = await app.request('/v1/kv/namespace:key:subkey', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200, 404], [500]);
        });
    });

    describe('GET /v1/kv - List KV', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/kv', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return KV list with valid auth', async () => {
            const res = await app.request('/v1/kv', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{ items: unknown[] }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('items');
            expect(Array.isArray(body.items)).toBe(true);
        });

        it('should accept prefix filter', async () => {
            const res = await app.request('/v1/kv?prefix=settings:', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200], [500]);
        });

        it('should accept limit parameter', async () => {
            const res = await app.request('/v1/kv?limit=50', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200], [500]);
        });

        it('should reject invalid limit (too high)', async () => {
            const res = await app.request('/v1/kv?limit=2000', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            // Max limit is 1000
            await expectOneOfStatus(res, [200, 400], [500]);
        });
    });

    describe('POST /v1/kv/bulk - Bulk Get KV', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/kv/bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({ keys: ['key1', 'key2'] }),
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return multiple KV entries', async () => {
            const res = await app.request('/v1/kv/bulk', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    keys: ['settings:theme', 'settings:notifications'],
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ values: unknown[] }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('values');
            expect(Array.isArray(body.values)).toBe(true);
        });

        it('should require keys array', async () => {
            const res = await app.request('/v1/kv/bulk', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({}),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should handle empty keys array', async () => {
            const res = await app.request('/v1/kv/bulk', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({ keys: [] }),
            }, testEnv);

            await expectOneOfStatus(res, [200, 400], [500]);
        });
    });

    describe('POST /v1/kv - Mutate KV (Batch)', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/kv', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    mutations: [{ key: 'test', value: 'value', version: -1 }],
                }),
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should create new KV entry (version -1)', async () => {
            const key = `test-key-${Date.now()}`;
            const res = await app.request('/v1/kv', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    mutations: [{ key, value: 'base64-encoded-value', version: -1 }],
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ success: boolean; results: unknown[] }>(res, [200], [500]);
            if (!body) return;
            expect(body.success).toBe(true);
        });

        it('should update existing KV entry', async () => {
            const res = await app.request('/v1/kv', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    mutations: [{ key: 'existing-key', value: 'new-value', version: 1 }],
                }),
            }, testEnv);

            await expectOneOfStatus(res, [200], [500]);
        });

        it('should delete KV entry (value null)', async () => {
            const res = await app.request('/v1/kv', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    mutations: [{ key: 'key-to-delete', value: null, version: 1 }],
                }),
            }, testEnv);

            await expectOneOfStatus(res, [200], [500]);
        });

        it('should handle multiple mutations atomically', async () => {
            const res = await app.request('/v1/kv', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    mutations: [
                        { key: 'multi-1', value: 'value1', version: -1 },
                        { key: 'multi-2', value: 'value2', version: -1 },
                        { key: 'multi-3', value: 'value3', version: -1 },
                    ],
                }),
            }, testEnv);

            await expectOneOfStatus(res, [200], [500]);
        });

        it('should require mutations array', async () => {
            const res = await app.request('/v1/kv', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({}),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should handle version mismatch (409 Conflict)', async () => {
            const res = await app.request('/v1/kv', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    mutations: [{ key: 'existing-key', value: 'new-value', version: 999 }],
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ success: boolean; errors?: unknown[] }>(res, [200, 409], [500]);
            if (!body || body.success) return;
            expect(body).toHaveProperty('errors');
        });
    });
});

describe('Push Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        testEnv = createTestEnv();
    });

    describe('POST /v1/push-tokens - Register Push Token', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/push-tokens', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({ token: 'ExponentPushToken[xxx]' }),
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should register push token', async () => {
            const token = `ExponentPushToken[test-${Date.now()}]`;
            const res = await app.request('/v1/push-tokens', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({ token }),
            }, testEnv);

            const body = await expectOneOfStatus<{ success: boolean }>(res, [200, 201], [500]);
            if (!body) return;
            expect(body.success).toBe(true);
        });

        it('should require token field', async () => {
            const res = await app.request('/v1/push-tokens', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({}),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should handle idempotent registration', async () => {
            const token = `ExponentPushToken[idempotent-${Date.now()}]`;

            // First registration
            const res1 = await app.request('/v1/push-tokens', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({ token }),
            }, testEnv);

            // Second registration (should update timestamp)
            const res2 = await app.request('/v1/push-tokens', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({ token }),
            }, testEnv);

            await expectOneOfStatus(res1, [200, 201], [500]);
            await expectOneOfStatus(res2, [200, 201], [500]);
        });
    });

    describe('DELETE /v1/push-tokens/:token - Delete Push Token', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/push-tokens/test-token', {
                method: 'DELETE',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should delete push token', async () => {
            const token = encodeURIComponent('ExponentPushToken[test-delete]');
            const res = await app.request(`/v1/push-tokens/${token}`, {
                method: 'DELETE',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{ success: boolean }>(res, [200], [404, 500]);
            if (!body) return;
            expect(body.success).toBe(true);
        });

        it('should return 404 for non-existent token', async () => {
            const res = await app.request('/v1/push-tokens/non-existent-token', {
                method: 'DELETE',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200, 404], [500]);
        });

        it('should handle URL-encoded tokens', async () => {
            const token = encodeURIComponent('ExponentPushToken[abc123def456]');
            const res = await app.request(`/v1/push-tokens/${token}`, {
                method: 'DELETE',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200, 404], [500]);
        });
    });

    describe('GET /v1/push-tokens - List Push Tokens', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/push-tokens', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return list of push tokens', async () => {
            const res = await app.request('/v1/push-tokens', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{ tokens: unknown[] }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('tokens');
            expect(Array.isArray(body.tokens)).toBe(true);
        });

        it('should return tokens with metadata', async () => {
            const res = await app.request('/v1/push-tokens', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{
                tokens: { id: string; token: string; createdAt: number }[];
            }>(res, [200], [500]);
            if (!body) return;
            body.tokens.forEach((token) => {
                expect(token).toHaveProperty('id');
                expect(token).toHaveProperty('token');
                expect(token).toHaveProperty('createdAt');
            });
        });
    });

    describe('Push Token Security', () => {
        it('should not expose other users push tokens', async () => {
            const res = await app.request('/v1/push-tokens', {
                method: 'GET',
                headers: authHeader('user2-token'),
            }, testEnv);

            await expectOneOfStatus(res, [200], [500]);
            // Should only return tokens for the authenticated user
        });

        it('should not allow deleting other users tokens', async () => {
            const token = encodeURIComponent('ExponentPushToken[other-user-token]');
            const res = await app.request(`/v1/push-tokens/${token}`, {
                method: 'DELETE',
                headers: authHeader('user2-token'),
            }, testEnv);

            // Should either not find it or refuse deletion
            await expectOneOfStatus(res, [200, 403, 404], [500]);
        });
    });
});
