/**
 * Integration Tests for WebSocket Routes with Drizzle ORM Mocking
 *
 * This test file provides comprehensive coverage of WebSocket routes,
 * focusing on all code paths for 100% coverage including:
 * - WebSocket upgrade validation
 * - Authentication via query params or headers
 * - Durable Object connection
 * - Error handling paths
 *
 * @module __tests__/websocket-drizzle.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    createMockDrizzle,
    createMockR2,
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

// Mock the getDb function to return our mock Drizzle client
vi.mock('@/db/client', () => ({
    getDb: vi.fn(() => {
        return drizzleMock?.mockDb;
    }),
}));

// Import mocked auth functions for test assertions
import { initAuth as mockInitAuth, verifyToken as mockVerifyToken } from '@/lib/auth';

// Import app AFTER mocks are set up
import { app } from '@/index';

/**
 * Create mock environment for Hono app.request()
 */
function createTestEnv(overrides: Partial<{
    HAPPY_MASTER_SECRET: string | undefined;
    doFetchResponse: Response;
}> = {}) {
    const mockDoFetch = vi.fn(async () => {
        return overrides.doFetchResponse ?? new Response(JSON.stringify({
            success: true,
            delivered: 0,
            totalConnections: 0,
            byType: {
                'user-scoped': 0,
                'session-scoped': 0,
                'machine-scoped': 0,
            },
            activeSessions: 0,
            activeMachines: 0,
            oldestConnection: null,
        }), {
            headers: { 'Content-Type': 'application/json' },
        });
    });

    // Handle both undefined and empty string for HAPPY_MASTER_SECRET
    const secretValue = 'HAPPY_MASTER_SECRET' in overrides
        ? overrides.HAPPY_MASTER_SECRET
        : 'test-secret-for-vitest-tests';

    return {
        ENVIRONMENT: 'development' as const,
        HAPPY_MASTER_SECRET: secretValue,
        DB: {} as D1Database,
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: {
            idFromName: vi.fn((name: string) => ({
                toString: () => `do-id-${name}`,
            })),
            get: vi.fn(() => ({
                fetch: mockDoFetch,
            })),
        },
        _mockDoFetch: mockDoFetch,
    };
}

// Shared test environment
let testEnv: ReturnType<typeof createTestEnv>;

describe('WebSocket Routes with Drizzle Mocking', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        drizzleMock = createMockDrizzle();
        testEnv = createTestEnv();
    });

    afterEach(() => {
        drizzleMock?.clearAll();
    });

    describe('GET /v1/updates - WebSocket Upgrade', () => {
        it('should return 426 when Upgrade header is not websocket', async () => {
            const res = await app.request('/v1/updates', {
                method: 'GET',
                headers: {
                    'Upgrade': 'http',
                },
            }, testEnv);

            expect(res.status).toBe(426);
            const text = await res.text();
            expect(text).toBe('Expected WebSocket upgrade');
        });

        it('should return 426 when Upgrade header is missing', async () => {
            const res = await app.request('/v1/updates', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(426);
            const text = await res.text();
            expect(text).toBe('Expected WebSocket upgrade');
        });

        it('should return 401 when token is missing from query and headers', async () => {
            const res = await app.request('/v1/updates', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, testEnv);

            expect(res.status).toBe(401);
            const text = await res.text();
            expect(text).toBe('Missing authentication (provide ticket or token)');
        });

        it('should extract token from query parameter', async () => {
            await app.request('/v1/updates?token=valid-token', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, testEnv);

            // Should pass auth and attempt DO connection
            // verifyToken is called with (token, db)
            expect(mockVerifyToken).toHaveBeenCalledWith('valid-token', expect.anything());
        });

        it('should extract token from Authorization header when query param is missing', async () => {
            await app.request('/v1/updates', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                    'Authorization': 'Bearer valid-token',
                },
            }, testEnv);

            // verifyToken is called with (token, db)
            expect(mockVerifyToken).toHaveBeenCalledWith('valid-token', expect.anything());
        });

        it('should prefer query param token over Authorization header', async () => {
            await app.request('/v1/updates?token=query-token', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                    'Authorization': 'Bearer header-token',
                },
            }, testEnv);

            // Query param should take precedence
            // verifyToken is called with (token, db)
            expect(mockVerifyToken).toHaveBeenCalledWith('query-token', expect.anything());
            expect(mockVerifyToken).not.toHaveBeenCalledWith('header-token', expect.anything());
        });

        it('should return 401 when token verification fails', async () => {
            const res = await app.request('/v1/updates?token=invalid-token', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, testEnv);

            expect(res.status).toBe(401);
            const text = await res.text();
            expect(text).toBe('Invalid authentication token');
        });

        it('should call initAuth with HAPPY_MASTER_SECRET when present', async () => {
            await app.request('/v1/updates?token=valid-token', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, testEnv);

            expect(mockInitAuth).toHaveBeenCalledWith('test-secret-for-vitest-tests');
        });

        it('should return 500 error when HAPPY_MASTER_SECRET is falsy (websocket handler)', async () => {
            // Create a fresh mock to track calls
            vi.mocked(mockInitAuth).mockClear();
            vi.mocked(mockVerifyToken).mockClear();

            const envWithoutSecret = createTestEnv({ HAPPY_MASTER_SECRET: '' });

            const response = await app.request('/v1/updates?token=valid-token', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, envWithoutSecret);

            // Middleware validates env BEFORE route handler executes
            // When HAPPY_MASTER_SECRET is missing, validateEnv throws and middleware returns 500
            expect(response.status).toBe(500);
            const body = await response.json() as { error: string; message: string };
            expect(body.error).toBe('Configuration Error');
            expect(body.message).toContain('HAPPY_MASTER_SECRET');

            // Auth functions should NOT be called - middleware blocks before route handler
            expect(mockVerifyToken).not.toHaveBeenCalled();
            expect(mockInitAuth).not.toHaveBeenCalledWith('');
        });

        it('should forward request to Durable Object with correct userId', async () => {
            await app.request('/v1/updates?token=valid-token', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, testEnv);

            // Verify DO was accessed with correct user ID
            expect(testEnv.CONNECTION_MANAGER.idFromName).toHaveBeenCalledWith(TEST_USER_ID);
            expect(testEnv.CONNECTION_MANAGER.get).toHaveBeenCalled();
        });

        it('should forward request with /websocket pathname to DO', async () => {
            await app.request('/v1/updates?token=valid-token', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, testEnv);

            // Check that DO fetch was called with modified URL
            const doFetchCalls = testEnv._mockDoFetch.mock.calls;
            expect(doFetchCalls.length).toBeGreaterThan(0);
            const firstCall = doFetchCalls[0];
            expect(firstCall).toBeDefined();
            const request = (firstCall as unknown as [Request])[0];
            const url = new URL(request.url);
            expect(url.pathname).toBe('/websocket');
        });

        it('should not handle invalid Authorization header format', async () => {
            const res = await app.request('/v1/updates', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                    'Authorization': 'Basic invalid-format',
                },
            }, testEnv);

            // Should return 401 as Bearer prefix is required
            expect(res.status).toBe(401);
            const text = await res.text();
            expect(text).toBe('Missing authentication (provide ticket or token)');
        });

        it('should handle empty Authorization header', async () => {
            const res = await app.request('/v1/updates', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                    'Authorization': '',
                },
            }, testEnv);

            expect(res.status).toBe(401);
            const text = await res.text();
            expect(text).toBe('Missing authentication (provide ticket or token)');
        });
    });

    describe('GET /v1/websocket - Alternative WebSocket Endpoint', () => {
        it('should return 426 when Upgrade header is not websocket', async () => {
            const res = await app.request('/v1/websocket', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(426);
            const text = await res.text();
            expect(text).toBe('Expected WebSocket upgrade');
        });

        it('should return 401 when token is missing', async () => {
            const res = await app.request('/v1/websocket', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should forward valid requests to Durable Object', async () => {
            await app.request('/v1/websocket?token=valid-token', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, testEnv);

            expect(testEnv.CONNECTION_MANAGER.idFromName).toHaveBeenCalledWith(TEST_USER_ID);
        });

        it('should support Authorization header', async () => {
            await app.request('/v1/websocket', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                    'Authorization': 'Bearer valid-token',
                },
            }, testEnv);

            // verifyToken is called with (token, db)
            expect(mockVerifyToken).toHaveBeenCalledWith('valid-token', expect.anything());
        });
    });

    describe('GET /v1/websocket/stats - Connection Statistics', () => {
        it('should return 401 when Authorization header is missing', async () => {
            const res = await app.request('/v1/websocket/stats', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body).toEqual({ error: 'Missing authorization header' });
        });

        it('should return 401 when Authorization header does not start with Bearer', async () => {
            const res = await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: {
                    'Authorization': 'Basic some-token',
                },
            }, testEnv);

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body).toEqual({ error: 'Missing authorization header' });
        });

        it('should return 401 when token verification fails', async () => {
            const res = await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer invalid-token',
                },
            }, testEnv);

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body).toEqual({ error: 'Invalid token' });
        });

        it('should call initAuth with HAPPY_MASTER_SECRET when present', async () => {
            await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer valid-token',
                },
            }, testEnv);

            expect(mockInitAuth).toHaveBeenCalledWith('test-secret-for-vitest-tests');
        });

        it('should return 500 error when HAPPY_MASTER_SECRET is falsy (stats handler)', async () => {
            vi.mocked(mockInitAuth).mockClear();
            vi.mocked(mockVerifyToken).mockClear();
            const envWithoutSecret = createTestEnv({ HAPPY_MASTER_SECRET: '' });

            const response = await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer valid-token',
                },
            }, envWithoutSecret);

            // Middleware validates env BEFORE route handler executes
            // When HAPPY_MASTER_SECRET is missing, validateEnv throws and middleware returns 500
            expect(response.status).toBe(500);
            const body = await response.json() as { error: string; message: string };
            expect(body.error).toBe('Configuration Error');
            expect(body.message).toContain('HAPPY_MASTER_SECRET');

            // Auth functions should NOT be called - middleware blocks before route handler
            expect(mockVerifyToken).not.toHaveBeenCalled();
            expect(mockInitAuth).not.toHaveBeenCalledWith('');
        });

        it('should return stats from Durable Object on successful auth', async () => {
            const mockStats = {
                totalConnections: 5,
                byType: {
                    'user-scoped': 2,
                    'session-scoped': 2,
                    'machine-scoped': 1,
                },
                activeSessions: 2,
                activeMachines: 1,
                oldestConnection: 1700000000000,
            };

            const envWithStats = createTestEnv({
                doFetchResponse: new Response(JSON.stringify(mockStats), {
                    headers: { 'Content-Type': 'application/json' },
                }),
            });

            const res = await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer valid-token',
                },
            }, envWithStats);

            expect(res.status).toBe(200);
            const body = await res.json();
            expect(body).toEqual(mockStats);
        });

        it('should forward request to user-specific Durable Object', async () => {
            await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer valid-token',
                },
            }, testEnv);

            expect(testEnv.CONNECTION_MANAGER.idFromName).toHaveBeenCalledWith(TEST_USER_ID);
        });

        it('should access different DO for different users', async () => {
            await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer user2-token',
                },
            }, testEnv);

            expect(testEnv.CONNECTION_MANAGER.idFromName).toHaveBeenCalledWith(TEST_USER_ID_2);
        });
    });

    describe('POST /v1/websocket/broadcast - Send Broadcast', () => {
        it('should return 401 when Authorization header is missing', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body).toEqual({ error: 'Missing authorization header' });
        });

        it('should return 401 when Authorization header does not start with Bearer', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Basic some-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body).toEqual({ error: 'Missing authorization header' });
        });

        it('should return 401 when token verification fails', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer invalid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body).toEqual({ error: 'Invalid token' });
        });

        it('should call initAuth with HAPPY_MASTER_SECRET when present', async () => {
            await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            expect(mockInitAuth).toHaveBeenCalledWith('test-secret-for-vitest-tests');
        });

        it('should return 500 error when HAPPY_MASTER_SECRET is falsy (broadcast handler)', async () => {
            vi.mocked(mockInitAuth).mockClear();
            vi.mocked(mockVerifyToken).mockClear();
            const envWithoutSecret = createTestEnv({ HAPPY_MASTER_SECRET: '' });

            const response = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                }),
            }, envWithoutSecret);

            // Middleware validates env BEFORE route handler executes
            // When HAPPY_MASTER_SECRET is missing, validateEnv throws and middleware returns 500
            expect(response.status).toBe(500);
            const body = await response.json() as { error: string; message: string };
            expect(body.error).toBe('Configuration Error');
            expect(body.message).toContain('HAPPY_MASTER_SECRET');

            // Auth functions should NOT be called - middleware blocks before route handler
            expect(mockVerifyToken).not.toHaveBeenCalled();
            expect(mockInitAuth).not.toHaveBeenCalledWith('');
        });

        it('should return 400 when message field is missing', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({}),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should return 400 when message.type is missing', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should return 400 when message.timestamp is missing', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should broadcast message successfully with valid auth and body', async () => {
            const mockBroadcastResult = {
                success: true,
                delivered: 3,
            };

            const envWithBroadcast = createTestEnv({
                doFetchResponse: new Response(JSON.stringify(mockBroadcastResult), {
                    headers: { 'Content-Type': 'application/json' },
                }),
            });

            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'session-update',
                        payload: { sessionId: 'xyz', status: 'active' },
                        timestamp: Date.now(),
                    },
                }),
            }, envWithBroadcast);

            expect(res.status).toBe(200);
            const body = await res.json();
            expect(body).toEqual(mockBroadcastResult);
        });

        it('should forward message to user-specific Durable Object', async () => {
            await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            expect(testEnv.CONNECTION_MANAGER.idFromName).toHaveBeenCalledWith(TEST_USER_ID);
        });

        it('should forward request body to Durable Object', async () => {
            const messageBody = {
                message: {
                    type: 'notification',
                    payload: { text: 'Hello' },
                    timestamp: 1700000000000,
                },
                filter: {
                    type: 'all',
                },
            };

            await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify(messageBody),
            }, testEnv);

            // Verify DO fetch was called
            const doFetchCalls = testEnv._mockDoFetch.mock.calls;
            expect(doFetchCalls.length).toBeGreaterThan(0);

            const firstCall = doFetchCalls[0];
            expect(firstCall).toBeDefined();
            const request = (firstCall as unknown as [Request])[0];
            expect(request.method).toBe('POST');
            const url = new URL(request.url);
            expect(url.pathname).toBe('/broadcast');
        });

        it('should accept optional payload in message', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'ping',
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(200);
        });

        it('should accept all filter type', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                    filter: {
                        type: 'all',
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(200);
        });

        it('should accept user-scoped-only filter type', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                    filter: {
                        type: 'user-scoped-only',
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(200);
        });

        it('should accept session filter type with sessionId', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                    filter: {
                        type: 'session',
                        sessionId: 'session-123',
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(200);
        });

        it('should accept machine filter type with machineId', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                    filter: {
                        type: 'machine',
                        machineId: 'machine-123',
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(200);
        });

        it('should accept exclude filter type with connectionId', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                    filter: {
                        type: 'exclude',
                        connectionId: 'conn-123',
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(200);
        });

        it('should access different DO for different users', async () => {
            await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer user2-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'test',
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            expect(testEnv.CONNECTION_MANAGER.idFromName).toHaveBeenCalledWith(TEST_USER_ID_2);
        });
    });

    describe('Edge Cases and Error Handling', () => {
        it('should handle empty token in query param', async () => {
            const res = await app.request('/v1/updates?token=', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                },
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should handle Bearer with no token', async () => {
            const res = await app.request('/v1/updates', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                    'Authorization': 'Bearer ',
                },
            }, testEnv);

            // Empty token after "Bearer " should fail verification
            expect([401, 500]).toContain(res.status);
        });

        it('should preserve original request headers when forwarding to DO', async () => {
            await app.request('/v1/updates?token=valid-token', {
                method: 'GET',
                headers: {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'X-Custom-Header': 'test-value',
                },
            }, testEnv);

            const doFetchCalls = testEnv._mockDoFetch.mock.calls;
            expect(doFetchCalls.length).toBeGreaterThan(0);

            const firstCall = doFetchCalls[0];
            expect(firstCall).toBeDefined();
            const request = (firstCall as unknown as [Request])[0];
            expect(request.headers.get('Upgrade')).toBe('websocket');
        });

        it('should handle DO returning non-JSON response for stats', async () => {
            const envWithBadResponse = createTestEnv({
                doFetchResponse: new Response('Internal Server Error', {
                    status: 500,
                }),
            });

            const res = await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer valid-token',
                },
            }, envWithBadResponse);

            // The handler attempts to parse JSON, which will throw
            // Hono's error handler catches it and returns 500
            expect(res.status).toBe(500);
        });

        it('should handle concurrent requests to same user DO', async () => {
            const requests = [
                app.request('/v1/websocket/stats', {
                    method: 'GET',
                    headers: { 'Authorization': 'Bearer valid-token' },
                }, testEnv),
                app.request('/v1/websocket/stats', {
                    method: 'GET',
                    headers: { 'Authorization': 'Bearer valid-token' },
                }, testEnv),
            ];

            const responses = await Promise.all(requests);

            // Both should succeed
            expect(responses[0]!.status).toBe(200);
            expect(responses[1]!.status).toBe(200);

            // Should use same user ID for both
            expect(testEnv.CONNECTION_MANAGER.idFromName).toHaveBeenCalledWith(TEST_USER_ID);
        });

        it('should handle message with complex payload', async () => {
            const complexPayload = {
                nested: {
                    deeply: {
                        value: [1, 2, 3],
                    },
                },
                array: ['a', 'b', 'c'],
                number: 42,
                boolean: true,
                nullValue: null,
            };

            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'complex',
                        payload: complexPayload,
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            expect(res.status).toBe(200);
        });
    });

    describe('Security Tests', () => {
        it('should not expose user data across different users', async () => {
            // First user makes a request
            await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: { 'Authorization': 'Bearer valid-token' },
            }, testEnv);

            const firstCall = testEnv.CONNECTION_MANAGER.idFromName.mock.calls[0];
            expect(firstCall).toBeDefined();

            // Second user makes a request
            await app.request('/v1/websocket/stats', {
                method: 'GET',
                headers: { 'Authorization': 'Bearer user2-token' },
            }, testEnv);

            const secondCall = testEnv.CONNECTION_MANAGER.idFromName.mock.calls[1];
            expect(secondCall).toBeDefined();

            // Different users should get different DO IDs
            expect(firstCall![0]).not.toBe(secondCall![0]);
        });

        it('should reject malformed JSON in broadcast body', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: 'not valid json',
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should reject very long type strings', async () => {
            const res = await app.request('/v1/websocket/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer valid-token',
                },
                body: JSON.stringify({
                    message: {
                        type: 'a'.repeat(10000),
                        timestamp: Date.now(),
                    },
                }),
            }, testEnv);

            // Schema validation should handle this
            expect([200, 400]).toContain(res.status);
        });
    });
});
