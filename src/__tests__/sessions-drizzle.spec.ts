/**
 * Integration Tests for Session Routes with Drizzle ORM Mocking
 *
 * This test file demonstrates the proper pattern for testing route handlers
 * with the mock Drizzle client. It exercises actual business logic instead
 * of accepting 500 errors from database failures.
 *
 * @module __tests__/sessions-drizzle.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    expectOk,
    createTestSession,
    createMockDrizzle,
    createMockR2,
    createMockDurableObjectNamespace,
    TEST_USER_ID,
    TEST_USER_ID_2,
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
        // Return the mock database client
        return drizzleMock?.mockDb;
    }),
}));

// Import app AFTER mocks are set up
import app from '@/index';

/**
 * Create mock environment for Hono app.request()
 * This provides the env object as the third parameter to app.request()
 */
function createTestEnv() {
    return {
        ENVIRONMENT: 'development' as const,
        HANDY_MASTER_SECRET: 'test-secret-for-vitest-tests',
        DB: {} as D1Database, // Placeholder - actual DB calls are intercepted by getDb mock
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
    };
}

// Shared test environment
let testEnv: ReturnType<typeof createTestEnv>;

describe('Session Routes with Drizzle Mocking', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Create fresh mock for each test
        drizzleMock = createMockDrizzle();
        testEnv = createTestEnv();
    });

    afterEach(() => {
        drizzleMock?.clearAll();
    });

    /**
     * Helper to make authenticated requests with proper environment
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
        return app.request(path, options, testEnv);
    }

    describe('GET /v1/sessions - List Sessions (Legacy)', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v1/sessions', { method: 'GET' });
            expect(res.status).toBe(401);
        });

        it('should return empty sessions list for user with no sessions', async () => {
            const body = await expectOk<{ sessions: unknown[] }>(
                await authRequest('/v1/sessions', { method: 'GET' })
            );

            expect(body).toHaveProperty('sessions');
            expect(Array.isArray(body.sessions)).toBe(true);
            expect(body.sessions).toHaveLength(0);
        });

        it('should return sessions for authenticated user', async () => {
            // Seed test data
            const session1 = createTestSession(TEST_USER_ID, { id: 'session-1' });
            const session2 = createTestSession(TEST_USER_ID, { id: 'session-2' });
            drizzleMock.seedData('sessions', [session1, session2]);

            const body = await expectOk<{ sessions: { id: string }[] }>(
                await authRequest('/v1/sessions', { method: 'GET' })
            );

            expect(body.sessions).toHaveLength(2);
            expect(body.sessions.map(s => s.id)).toContain('session-1');
            expect(body.sessions.map(s => s.id)).toContain('session-2');
        });

        it('should not return sessions belonging to other users', async () => {
            // Seed sessions for both users
            const mySession = createTestSession(TEST_USER_ID, { id: 'my-session' });
            const otherSession = createTestSession(TEST_USER_ID_2, { id: 'other-session' });
            drizzleMock.seedData('sessions', [mySession, otherSession]);

            const body = await expectOk<{ sessions: { id: string }[] }>(
                await authRequest('/v1/sessions', { method: 'GET' })
            );

            expect(body.sessions).toHaveLength(1);
            expect(body.sessions[0]?.id).toBe('my-session');
        });

        it('should return sessions ordered by updatedAt descending', async () => {
            const oldDate = new Date(Date.now() - 86400000); // 1 day ago
            const newDate = new Date();

            const oldSession = createTestSession(TEST_USER_ID, {
                id: 'old-session',
                updatedAt: oldDate,
            });
            const newSession = createTestSession(TEST_USER_ID, {
                id: 'new-session',
                updatedAt: newDate,
            });

            // Seed in wrong order to verify sorting
            drizzleMock.seedData('sessions', [oldSession, newSession]);

            const body = await expectOk<{ sessions: { id: string }[] }>(
                await authRequest('/v1/sessions', { method: 'GET' })
            );

            expect(body.sessions).toHaveLength(2);
            expect(body.sessions[0]?.id).toBe('new-session');
            expect(body.sessions[1]?.id).toBe('old-session');
        });

        it('should limit results to 150 sessions', async () => {
            // Create 160 sessions
            const sessions = Array.from({ length: 160 }, (_, i) =>
                createTestSession(TEST_USER_ID, { id: `session-${i}` })
            );
            drizzleMock.seedData('sessions', sessions);

            const body = await expectOk<{ sessions: unknown[] }>(
                await authRequest('/v1/sessions', { method: 'GET' })
            );

            expect(body.sessions.length).toBeLessThanOrEqual(150);
        });
    });

    describe('GET /v2/sessions - List Sessions (Paginated)', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v2/sessions', { method: 'GET' });
            expect(res.status).toBe(401);
        });

        // Note: These tests are skipped because v2 pagination uses db.select().from().where()
        // which requires the full SQL builder mock. The current mock supports db.query.* API.
        // TODO: Add db.select() support to mock-drizzle.ts in a follow-up issue.
        it.skip('should return paginated sessions with nextCursor', async () => {
            // Create more sessions than the default limit
            const sessions = Array.from({ length: 60 }, (_, i) =>
                createTestSession(TEST_USER_ID, { id: `session-${i.toString().padStart(3, '0')}` })
            );
            drizzleMock.seedData('sessions', sessions);

            const body = await expectOk<{ sessions: unknown[]; nextCursor?: string }>(
                await authRequest('/v2/sessions?limit=50', { method: 'GET' })
            );

            expect(body.sessions).toHaveLength(50);
        });

        it.skip('should respect custom limit parameter', async () => {
            const sessions = Array.from({ length: 30 }, (_, i) =>
                createTestSession(TEST_USER_ID, { id: `session-${i}` })
            );
            drizzleMock.seedData('sessions', sessions);

            const body = await expectOk<{ sessions: unknown[] }>(
                await authRequest('/v2/sessions?limit=10', { method: 'GET' })
            );

            expect(body.sessions).toHaveLength(10);
        });

        it('should reject limit > 200', async () => {
            const res = await authRequest('/v2/sessions?limit=500', { method: 'GET' });
            expect(res.status).toBe(400);
        });
    });

    describe('GET /v2/sessions/active - List Active Sessions', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v2/sessions/active', { method: 'GET' });
            expect(res.status).toBe(401);
        });

        it('should only return active sessions from last 15 minutes', async () => {
            const now = new Date();
            const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
            const twentyMinutesAgo = new Date(now.getTime() - 20 * 60 * 1000);

            const recentActiveSession = createTestSession(TEST_USER_ID, {
                id: 'recent-active',
                active: true,
                lastActiveAt: fiveMinutesAgo,
            });
            const oldActiveSession = createTestSession(TEST_USER_ID, {
                id: 'old-active',
                active: true,
                lastActiveAt: twentyMinutesAgo,
            });
            const inactiveSession = createTestSession(TEST_USER_ID, {
                id: 'inactive',
                active: false,
                lastActiveAt: fiveMinutesAgo,
            });

            drizzleMock.seedData('sessions', [
                recentActiveSession,
                oldActiveSession,
                inactiveSession,
            ]);

            const body = await expectOk<{ sessions: { id: string }[] }>(
                await authRequest('/v2/sessions/active', { method: 'GET' })
            );

            // Should only include the recent active session
            const sessionIds = body.sessions.map(s => s.id);
            expect(sessionIds).toContain('recent-active');
            expect(sessionIds).not.toContain('old-active');
            expect(sessionIds).not.toContain('inactive');
        });
    });

    describe('GET /v1/sessions/:id - Get Single Session', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v1/sessions/session-123', { method: 'GET' });
            expect(res.status).toBe(401);
        });

        it('should return 404 for non-existent session', async () => {
            const res = await authRequest('/v1/sessions/non-existent', { method: 'GET' });
            expect(res.status).toBe(404);
        });

        it('should return session details for owned session', async () => {
            const session = createTestSession(TEST_USER_ID, {
                id: 'my-session-123',
                metadata: '{"name":"My Session"}',
            });
            drizzleMock.seedData('sessions', [session]);

            const body = await expectOk<{ session: { id: string; metadata: string } }>(
                await authRequest('/v1/sessions/my-session-123', { method: 'GET' })
            );

            expect(body.session.id).toBe('my-session-123');
            expect(body.session.metadata).toBe('{"name":"My Session"}');
        });

        it('should return 404 for session owned by another user', async () => {
            const otherSession = createTestSession(TEST_USER_ID_2, { id: 'other-session' });
            drizzleMock.seedData('sessions', [otherSession]);

            const res = await authRequest('/v1/sessions/other-session', { method: 'GET' });

            // Should be 404 (not found for this user) or 403 (forbidden)
            expect([403, 404]).toContain(res.status);
        });
    });

    describe('DELETE /v1/sessions/:id - Soft Delete Session', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v1/sessions/session-123', { method: 'DELETE' });
            expect(res.status).toBe(401);
        });

        it('should return 404 for non-existent session', async () => {
            const res = await authRequest('/v1/sessions/non-existent', { method: 'DELETE' });
            expect(res.status).toBe(404);
        });

        it('should soft delete owned session', async () => {
            const session = createTestSession(TEST_USER_ID, {
                id: 'to-delete',
                active: true,
            });
            drizzleMock.seedData('sessions', [session]);

            const body = await expectOk<{ success: boolean }>(
                await authRequest('/v1/sessions/to-delete', { method: 'DELETE' })
            );

            expect(body.success).toBe(true);
        });

        it('should not allow deleting another user session', async () => {
            const otherSession = createTestSession(TEST_USER_ID_2, { id: 'other-session' });
            drizzleMock.seedData('sessions', [otherSession]);

            const res = await authRequest('/v1/sessions/other-session', { method: 'DELETE' });

            expect([403, 404]).toContain(res.status);
        });
    });

    describe('POST /v1/sessions - Create Session', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v1/sessions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    tag: 'test-session',
                    metadata: '{"name":"Test"}',
                }),
            });

            expect(res.status).toBe(401);
        });

        it('should require tag field', async () => {
            const res = await authRequest('/v1/sessions', {
                method: 'POST',
                body: JSON.stringify({
                    metadata: '{"name":"Test"}',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should require metadata field', async () => {
            const res = await authRequest('/v1/sessions', {
                method: 'POST',
                body: JSON.stringify({
                    tag: 'test-session',
                }),
            });

            expect(res.status).toBe(400);
        });

        // Note: This test is skipped because the route uses db.select().from().where()
        // which requires the full SQL builder mock. See TODO in mock-drizzle.ts.
        it.skip('should create a new session with valid data', async () => {
            const tag = `test-${Date.now()}`;

            const body = await expectOk<{ session: { id: string; tag: string } }>(
                await authRequest('/v1/sessions', {
                    method: 'POST',
                    body: JSON.stringify({
                        tag,
                        metadata: '{"name":"New Session"}',
                        agentState: '{"state":"initial"}',
                        // Use valid base64 encoding for dataEncryptionKey
                        dataEncryptionKey: Buffer.from('test-key-data').toString('base64'),
                    }),
                })
            );

            expect(body.session).toHaveProperty('id');
            expect(body.session.tag).toBeDefined();
        });

        // Note: This test is skipped because the route uses db.select().from().where()
        // which requires the full SQL builder mock. See TODO in mock-drizzle.ts.
        it.skip('should return existing session with same tag (idempotent)', async () => {
            const existingSession = createTestSession(TEST_USER_ID, {
                id: 'existing-session',
                tag: 'unique-tag',
            });
            drizzleMock.seedData('sessions', [existingSession]);

            const body = await expectOk<{ session: { id: string } }>(
                await authRequest('/v1/sessions', {
                    method: 'POST',
                    body: JSON.stringify({
                        tag: 'unique-tag',
                        metadata: '{"name":"Duplicate Attempt"}',
                    }),
                })
            );

            expect(body.session.id).toBe('existing-session');
        });
    });

    describe('POST /v1/sessions/:id/messages - Create Session Message', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v1/sessions/session-123/messages', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    content: { text: 'Test message' },
                }),
            });

            expect(res.status).toBe(401);
        });

        // Note: This test is skipped because the route uses db.select().from().where()
        // which requires the full SQL builder mock. See TODO in mock-drizzle.ts.
        it.skip('should require content field', async () => {
            const session = createTestSession(TEST_USER_ID, { id: 'session-123' });
            drizzleMock.seedData('sessions', [session]);

            const res = await authRequest('/v1/sessions/session-123/messages', {
                method: 'POST',
                body: JSON.stringify({
                    localId: 'local-123',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 404 for non-existent session', async () => {
            const res = await authRequest('/v1/sessions/non-existent/messages', {
                method: 'POST',
                body: JSON.stringify({
                    content: { text: 'Test' },
                }),
            });

            expect(res.status).toBe(404);
        });

        // Note: This test is skipped because the route uses db.select().from().where()
        // which requires the full SQL builder mock. See TODO in mock-drizzle.ts.
        it.skip('should create message for owned session', async () => {
            const session = createTestSession(TEST_USER_ID, { id: 'session-123' });
            drizzleMock.seedData('sessions', [session]);

            const body = await expectOk<{ message: { id: string; content: object } }>(
                await authRequest('/v1/sessions/session-123/messages', {
                    method: 'POST',
                    body: JSON.stringify({
                        localId: `local-${Date.now()}`,
                        content: { type: 'user', text: 'Hello world' },
                    }),
                })
            );

            expect(body.message).toHaveProperty('id');
            expect(body.message.content).toBeDefined();
        });
    });
});
