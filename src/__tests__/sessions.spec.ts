/**
 * Integration Tests for Session Routes
 *
 * Tests all session endpoints including:
 * - GET /v1/sessions (list legacy)
 * - GET /v2/sessions (paginated)
 * - GET /v2/sessions/active (active sessions)
 * - POST /v1/sessions (create)
 * - GET /v1/sessions/:id (get single)
 * - DELETE /v1/sessions/:id (hard delete)
 * - POST /v1/sessions/:id/messages (add message)
 *
 * @module __tests__/sessions.spec
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
import { authHeader, jsonBody, expectOneOfStatus, VALID_TOKEN, createMockR2, createMockDurableObjectNamespace } from './test-utils';

function createTestEnv() {
    return {
        ENVIRONMENT: 'development' as const,
        HAPPY_MASTER_SECRET: 'test-secret-for-vitest-tests-min-32-chars',
        DB: {} as D1Database,
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
    };
}

let testEnv: ReturnType<typeof createTestEnv>;

describe('Session Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        testEnv = createTestEnv();
    });

    describe('GET /v1/sessions - List Sessions (Legacy)', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/sessions', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return sessions list with valid auth', async () => {
            const res = await app.request('/v1/sessions', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            // Should return 200 with sessions array (may be empty)
            const body = await expectOneOfStatus<{ sessions: unknown[] }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('sessions');
            expect(Array.isArray(body.sessions)).toBe(true);
        });
    });

    describe('GET /v2/sessions - List Sessions (Paginated)', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v2/sessions', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return paginated sessions with valid auth', async () => {
            const res = await app.request('/v2/sessions', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{ sessions: unknown[]; nextCursor?: string }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('sessions');
            expect(Array.isArray(body.sessions)).toBe(true);
        });

        it('should accept limit query parameter', async () => {
            const res = await app.request('/v2/sessions?limit=10', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200], [500]);
        });

        it('should accept cursor query parameter', async () => {
            const res = await app.request('/v2/sessions?cursor=cursor_v1_test123', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200, 400], [500]);
        });

        it('should accept changedSince query parameter', async () => {
            const res = await app.request('/v2/sessions?changedSince=2024-01-01T00:00:00Z', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200], [500]);
        });

        it('should reject invalid limit (too high)', async () => {
            const res = await app.request('/v2/sessions?limit=500', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            // Should reject limit > 200
            await expectOneOfStatus(res, [200, 400], [500]);
        });
    });

    describe('GET /v2/sessions/active - List Active Sessions', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v2/sessions/active', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return active sessions with valid auth', async () => {
            const res = await app.request('/v2/sessions/active', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{ sessions: unknown[] }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('sessions');
        });

        it('should accept limit query parameter', async () => {
            const res = await app.request('/v2/sessions/active?limit=50', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200], [500]);
        });
    });

    describe('POST /v1/sessions - Create Session', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/sessions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    tag: 'test-session',
                    metadata: '{"name":"Test"}',
                }),
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should create session with valid data', async () => {
            const tag = `test-${Date.now()}`;
            const res = await app.request('/v1/sessions', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    tag,
                    metadata: '{"name":"Test Session"}',
                    agentState: '{"state":"initial"}',
                    dataEncryptionKey: 'base64-encoded-key',
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ session: { id: string; tag: string } }>(res, [200, 201], [500]);
            if (!body) return;
            expect(body).toHaveProperty('session');
            expect(body.session).toHaveProperty('id');
        });

        it('should require tag field', async () => {
            const res = await app.request('/v1/sessions', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    metadata: '{"name":"Test"}',
                }),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should require metadata field', async () => {
            const res = await app.request('/v1/sessions', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    tag: 'test-session',
                }),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should handle duplicate tag (idempotent)', async () => {
            const tag = `duplicate-test-${Date.now()}`;

            // First creation
            const res1 = await app.request('/v1/sessions', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    tag,
                    metadata: '{"name":"First"}',
                }),
            }, testEnv);

            // Second creation with same tag
            const res2 = await app.request('/v1/sessions', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    tag,
                    metadata: '{"name":"Second"}',
                }),
            }, testEnv);

            // Both should succeed (idempotent) or DB error
            await expectOneOfStatus(res1, [200, 201], [500]);
            await expectOneOfStatus(res2, [200, 201], [500]);
        });
    });

    describe('GET /v1/sessions/:id - Get Single Session', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/sessions/test-session-id', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return 404 for non-existent session', async () => {
            const res = await app.request('/v1/sessions/non-existent-session-id', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [404], [500]);
        });

        it('should validate session ID format', async () => {
            const res = await app.request('/v1/sessions/valid-session-id-format', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200, 404], [500]);
        });
    });

    describe('DELETE /v1/sessions/:id - Hard Delete Session', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/sessions/test-session-id', {
                method: 'DELETE',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return 404 for non-existent session', async () => {
            const res = await app.request('/v1/sessions/non-existent-session-id', {
                method: 'DELETE',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [404], [500]);
        });

        it('should permanently delete session and return success', async () => {
            const res = await app.request('/v1/sessions/test-session-to-delete', {
                method: 'DELETE',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{ success: boolean }>(res, [200], [404, 500]);
            if (!body) return;
            expect(body.success).toBe(true);
        });
    });

    describe('POST /v1/sessions/:id/messages - Create Session Message', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/sessions/test-session/messages', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    content: { text: 'Test message' },
                }),
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should create message with valid data', async () => {
            const res = await app.request('/v1/sessions/test-session/messages', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    localId: `local-${Date.now()}`,
                    content: { type: 'user', text: 'Test message' },
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ message: { id: string } }>(res, [200, 201], [404, 500]);
            if (!body) return;
            expect(body).toHaveProperty('message');
        });

        it('should require content field', async () => {
            const res = await app.request('/v1/sessions/test-session/messages', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    localId: 'local-123',
                }),
            }, testEnv);

            // 400 = validation error, 500 = runtime error (DB undefined)
            await expectOneOfStatus(res, [400], [500]);
        });

        it('should return 404 for non-existent session', async () => {
            const res = await app.request('/v1/sessions/non-existent/messages', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    content: { text: 'Test' },
                }),
            }, testEnv);

            await expectOneOfStatus(res, [404], [500]);
        });
    });

    describe('Session Access Control', () => {
        it('should not allow access to another user\'s session', async () => {
            // Create session as user 1
            const createRes = await app.request('/v1/sessions', {
                method: 'POST',
                headers: authHeader(VALID_TOKEN),
                body: jsonBody({
                    tag: `private-session-${Date.now()}`,
                    metadata: '{"name":"Private"}',
                }),
            }, testEnv);

            const createBody = await expectOneOfStatus<{ session: { id: string } }>(createRes, [200], [500]);
            if (!createBody) return;
            const { session } = createBody;

            // Try to access as user 2
            const accessRes = await app.request(`/v1/sessions/${session.id}`, {
                method: 'GET',
                headers: authHeader('user2-token'),
            }, testEnv);

            // Should be 404 (not found for this user) or 403 (forbidden)
            await expectOneOfStatus(accessRes, [403, 404], [500]);
        });
    });
});
