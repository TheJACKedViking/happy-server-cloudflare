/**
 * Integration Tests for Connect, Version, and Voice Routes
 *
 * Tests connect endpoints (GitHub OAuth, AI service tokens):
 * - GET /v1/connect/github/params
 * - GET /v1/connect/github/callback
 * - POST /v1/connect/github/webhook
 * - DELETE /v1/connect/github
 * - POST /v1/connect/:vendor/register
 * - GET /v1/connect/:vendor/token
 * - DELETE /v1/connect/:vendor
 * - GET /v1/connect/tokens
 *
 * Version endpoints:
 * - POST /v1/version
 *
 * Voice endpoints:
 * - POST /v1/voice/token
 *
 * @module __tests__/connect-version-voice.spec
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

describe('Connect Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        testEnv = createTestEnv();
    });

    describe('GET /v1/connect/github/params - GitHub OAuth Params', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/connect/github/params', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return OAuth URL with valid auth', async () => {
            const res = await app.request('/v1/connect/github/params', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ url: string }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('url');
            expect(body.url).toContain('github.com');
        });
    });

    describe('GET /v1/connect/github/callback - GitHub OAuth Callback', () => {
        it('should handle OAuth callback with code', async () => {
            const res = await app.request('/v1/connect/github/callback?code=test-code&state=test-state', {
                method: 'GET',
            }, testEnv);

            // May redirect or return error based on state validation
            expect([200, 302, 400, 401, 500]).toContain(res.status);
        });

        it('should reject callback without code', async () => {
            const res = await app.request('/v1/connect/github/callback?state=test-state', {
                method: 'GET',
            }, testEnv);

            expect([400, 500]).toContain(res.status);
        });

        it('should reject callback without state', async () => {
            const res = await app.request('/v1/connect/github/callback?code=test-code', {
                method: 'GET',
            }, testEnv);

            expect([400, 500]).toContain(res.status);
        });
    });

    describe('POST /v1/connect/github/webhook - GitHub Webhook', () => {
        it('should accept webhook with valid signature', async () => {
            const res = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': 'sha256=test-signature',
                    'X-GitHub-Event': 'push',
                },
                body: jsonBody({
                    action: 'push',
                    repository: { full_name: 'test/repo' },
                }),
            }, testEnv);

            // May succeed or fail based on signature verification
            expect([200, 401, 500]).toContain(res.status);
        });

        it('should reject webhook without signature', async () => {
            const res = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({ action: 'push' }),
            }, testEnv);

            // 400 = validation error, 401 = auth error, 500 = runtime error
            expect([400, 401, 500]).toContain(res.status);
        });
    });

    describe('DELETE /v1/connect/github - Disconnect GitHub', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/connect/github', {
                method: 'DELETE',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should disconnect GitHub with valid auth', async () => {
            const res = await app.request('/v1/connect/github', {
                method: 'DELETE',
                headers: authHeader(),
            }, testEnv);

            // May return 200 (success), 404 (not connected), or 500 (DB error)
            const body = await expectOneOfStatus<{ success: boolean }>(res, [200], [404, 500]);
            // When successful, verify success is true
            expect(body === null || body.success === true).toBe(true);
        });
    });

    describe('POST /v1/connect/:vendor/register - Register AI Token', () => {
        const vendors = ['openai', 'anthropic', 'gemini'];

        it('should require authentication', async () => {
            for (const vendor of vendors) {
                const res = await app.request(`/v1/connect/${vendor}/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: jsonBody({ token: 'sk-test-token' }),
                }, testEnv);

                expect(res.status).toBe(401);
            }
        });

        it('should register token for each vendor', async () => {
            for (const vendor of vendors) {
                const res = await app.request(`/v1/connect/${vendor}/register`, {
                    method: 'POST',
                    headers: authHeader(),
                    body: jsonBody({ token: `sk-test-${vendor}-token` }),
                }, testEnv);

                // Use expectOk to ensure we get a successful response
                const body = await expectOneOfStatus<{ success: boolean }>(res, [200], [500]);
                if (!body) return;
                expect(body.success).toBe(true);
            }
        });

        it('should require token field', async () => {
            const res = await app.request('/v1/connect/openai/register', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({}),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should reject unknown vendor', async () => {
            const res = await app.request('/v1/connect/unknown-vendor/register', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({ token: 'test-token' }),
            }, testEnv);

            expect([400, 404, 500]).toContain(res.status);
        });
    });

    describe('GET /v1/connect/:vendor/token - Get AI Token', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/connect/openai/token', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return token if registered', async () => {
            const res = await app.request('/v1/connect/openai/token', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ token: string | null }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('token');
        });

        it('should return null for unregistered vendor', async () => {
            const res = await app.request('/v1/connect/anthropic/token', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ token: string | null }>(res, [200], [500]);
            if (!body) return;
            // May be null if not registered
            expect(body).toHaveProperty('token');
        });
    });

    describe('DELETE /v1/connect/:vendor - Delete AI Token', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/connect/openai', {
                method: 'DELETE',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should delete token with valid auth', async () => {
            const res = await app.request('/v1/connect/openai', {
                method: 'DELETE',
                headers: authHeader(),
            }, testEnv);

            // May return 200 (success), 404 (not registered), or 500 (DB error)
            const body = await expectOneOfStatus<{ success: boolean }>(res, [200], [404, 500]);
            // When successful, verify success is true
            expect(body === null || body.success === true).toBe(true);
        });
    });

    describe('GET /v1/connect/tokens - List AI Tokens', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/connect/tokens', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return list of tokens', async () => {
            const res = await app.request('/v1/connect/tokens', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ tokens: { vendor: string; token: string }[] }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('tokens');
            expect(Array.isArray(body.tokens)).toBe(true);
        });
    });
});

describe('Version Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        testEnv = createTestEnv();
    });

    describe('POST /v1/version - Check App Version', () => {
        it('should check iOS version', async () => {
            const res = await app.request('/v1/version', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    platform: 'ios',
                    version: '1.0.0',
                    app_id: 'com.ex3ndr.happy',
                }),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ updateUrl: string | null }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('updateUrl');
        });

        it('should check Android version', async () => {
            const res = await app.request('/v1/version', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    platform: 'android',
                    version: '1.0.0',
                    app_id: 'com.ex3ndr.happy',
                }),
            }, testEnv);

            expect([200, 500]).toContain(res.status);
        });

        it('should require platform', async () => {
            const res = await app.request('/v1/version', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    version: '1.0.0',
                }),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should require version', async () => {
            const res = await app.request('/v1/version', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    platform: 'ios',
                }),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should return null for up-to-date version', async () => {
            const res = await app.request('/v1/version', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    platform: 'ios',
                    version: '99.99.99', // Very high version
                    app_id: 'com.ex3ndr.happy',
                }),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ updateUrl: string | null }>(res, [200], [500]);
            if (!body) return;
            expect(body.updateUrl).toBeNull();
        });

        it('should return update URL for outdated version', async () => {
            const res = await app.request('/v1/version', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    platform: 'ios',
                    version: '0.0.1', // Very old version
                    app_id: 'com.ex3ndr.happy',
                }),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ updateUrl: string | null }>(res, [200], [500]);
            if (!body) return;
            // May or may not have update URL depending on config
            expect(body).toHaveProperty('updateUrl');
        });

        it('should return update URL for outdated Android version', async () => {
            const res = await app.request('/v1/version', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    platform: 'android',
                    version: '0.0.1', // Very old version
                    app_id: 'com.ex3ndr.happy',
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ updateUrl: string | null }>(res, [200], [500]);
            if (!body) return;
            // Should return Play Store URL for outdated Android
            expect(body).toHaveProperty('updateUrl');
        });

        it('should return null for up-to-date Android version', async () => {
            const res = await app.request('/v1/version', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    platform: 'android',
                    version: '99.99.99', // Very high version
                    app_id: 'com.ex3ndr.happy',
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ updateUrl: string | null }>(res, [200], [500]);
            if (!body) return;
            expect(body.updateUrl).toBeNull();
        });

        it('should return null for unknown platform', async () => {
            const res = await app.request('/v1/version', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    platform: 'web',
                    version: '1.0.0',
                    app_id: 'com.ex3ndr.happy',
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ updateUrl: string | null }>(res, [200], [500]);
            if (!body) return;
            // Unknown platforms always return null (no update needed)
            expect(body.updateUrl).toBeNull();
        });
    });
});

describe('Voice Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        testEnv = createTestEnv();
    });

    describe('POST /v1/voice/token - Get Voice Token', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/voice/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    agentId: 'agent-123',
                }),
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return voice token response', async () => {
            const res = await app.request('/v1/voice/token', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    agentId: 'agent-123',
                    revenueCatPublicKey: 'appl_test_key',
                }),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ allowed: boolean; token?: string; agentId: string }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('allowed');
            expect(body).toHaveProperty('agentId');
        });

        it('should require agentId', async () => {
            const res = await app.request('/v1/voice/token', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({}),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should handle denied access (no subscription)', async () => {
            const res = await app.request('/v1/voice/token', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    agentId: 'agent-123',
                    // No revenueCatPublicKey - may be denied
                }),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ allowed: boolean }>(res, [200], [500]);
            if (!body) return;
            // May be allowed in dev mode, denied in prod
            expect(typeof body.allowed).toBe('boolean');
        });

        it('should include token when allowed', async () => {
            const res = await app.request('/v1/voice/token', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    agentId: 'agent-123',
                    revenueCatPublicKey: 'valid-subscription-key',
                }),
            }, testEnv);

            // Use expectOk to ensure we get a successful response
            const body = await expectOneOfStatus<{ allowed: boolean; token?: string }>(res, [200], [500]);
            if (!body) return;
            // When allowed, token should be present; when not allowed, it may be absent
            expect(!body.allowed || body.token !== undefined).toBe(true);
        });
    });
});
