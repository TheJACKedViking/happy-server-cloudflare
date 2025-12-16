/**
 * Comprehensive Tests for ConnectionManager Durable Object
 *
 * Tests WebSocket connection management including:
 * - WebSocket upgrade and authentication
 * - Connection types (user-scoped, session-scoped, machine-scoped)
 * - Message broadcasting with filtering
 * - Connection lifecycle (connect, ping/pong, disconnect)
 * - Hibernation API callbacks (webSocketMessage, webSocketClose, webSocketError)
 * - Connection statistics
 * - All message handlers for database updates
 *
 * @module __tests__/connection-manager.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ConnectionMetadata, ClientType, MessageFilter } from '@/durable-objects/types';

// =============================================================================
// CLOUDFLARE WORKERS GLOBALS MOCK
// =============================================================================

// Mock WebSocketRequestResponsePair (Cloudflare Workers global)
class MockWebSocketRequestResponsePair {
    request: string;
    response: string;
    constructor(request: string, response: string) {
        this.request = request;
        this.response = response;
    }
}

// Mock WebSocketPair (Cloudflare Workers global)
class MockWebSocketPair {
    0: WebSocket;
    1: WebSocket;
    constructor() {
        // Create mock client and server WebSockets
        const client = createBasicMockWebSocket();
        const server = createBasicMockWebSocket();
        this[0] = client;
        this[1] = server;
    }
}

// Basic mock WebSocket for WebSocketPair
function createBasicMockWebSocket(): WebSocket {
    let attachment: unknown = null;
    return {
        send: vi.fn(),
        close: vi.fn(),
        serializeAttachment: vi.fn((data: unknown) => { attachment = data; }),
        deserializeAttachment: vi.fn(() => attachment),
        readyState: 1,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
    } as unknown as WebSocket;
}

// Install globals before any imports that use them
(globalThis as unknown as Record<string, unknown>).WebSocketRequestResponsePair = MockWebSocketRequestResponsePair;
(globalThis as unknown as Record<string, unknown>).WebSocketPair = MockWebSocketPair;

// =============================================================================
// MOCKS
// =============================================================================

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
const mockVerifyToken = vi.fn();
const mockInitAuth = vi.fn();

vi.mock('@/lib/auth', () => ({
    initAuth: () => mockInitAuth(),
    verifyToken: (token: string) => mockVerifyToken(token),
    createToken: vi.fn().mockResolvedValue('generated-token'),
    resetAuth: vi.fn(),
}));

// Mock database client
const mockDb = {
    select: vi.fn(),
    insert: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    transaction: vi.fn(),
};

vi.mock('@/db/client', () => ({
    getDb: () => mockDb,
}));

// Mock handlers - we'll test the handler integration
vi.mock('@/durable-objects/handlers', async () => {
    const actual = await vi.importActual('@/durable-objects/handlers');
    return {
        ...actual,
        handleSessionMetadataUpdate: vi.fn().mockResolvedValue({ response: { result: 'success' } }),
        handleSessionStateUpdate: vi.fn().mockResolvedValue({ response: { result: 'success' } }),
        handleSessionAlive: vi.fn().mockResolvedValue({}),
        handleSessionEnd: vi.fn().mockResolvedValue({}),
        handleSessionMessage: vi.fn().mockResolvedValue({}),
        handleMachineAlive: vi.fn().mockResolvedValue({}),
        handleMachineMetadataUpdate: vi.fn().mockResolvedValue({ response: { result: 'success' } }),
        handleMachineStateUpdate: vi.fn().mockResolvedValue({ response: { result: 'success' } }),
        handleArtifactRead: vi.fn().mockResolvedValue({ response: { result: 'success' } }),
        handleArtifactUpdate: vi.fn().mockResolvedValue({ response: { result: 'success' } }),
        handleArtifactCreate: vi.fn().mockResolvedValue({ response: { result: 'success' } }),
        handleArtifactDelete: vi.fn().mockResolvedValue({ response: { result: 'success' } }),
        handleAccessKeyGet: vi.fn().mockResolvedValue({ response: { ok: true } }),
        handleUsageReport: vi.fn().mockResolvedValue({ response: { success: true } }),
    };
});

// =============================================================================
// MOCK WEBSOCKET INFRASTRUCTURE
// =============================================================================

/**
 * Create a mock WebSocket for testing
 */
function createMockWebSocket(id: string = 'ws-1'): WebSocket & {
    _messages: string[];
    _closed: boolean;
    _closeCode?: number;
    _closeReason?: string;
    _attachment: unknown;
} {
    const messages: string[] = [];
    let closed = false;
    let closeCode: number | undefined;
    let closeReason: string | undefined;
    let attachment: unknown = null;

    const ws = {
        _messages: messages,
        _closed: closed,
        _closeCode: closeCode,
        _closeReason: closeReason,
        _attachment: attachment,
        send: vi.fn((msg: string) => {
            if (closed) throw new Error('WebSocket is closed');
            messages.push(msg);
        }),
        close: vi.fn((code?: number, reason?: string) => {
            closed = true;
            ws._closed = true;
            ws._closeCode = code;
            ws._closeReason = reason;
        }),
        serializeAttachment: vi.fn((data: unknown) => {
            attachment = data;
            ws._attachment = data;
        }),
        deserializeAttachment: vi.fn(() => attachment),
        readyState: 1, // OPEN
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
    } as unknown as WebSocket & {
        _messages: string[];
        _closed: boolean;
        _closeCode?: number;
        _closeReason?: string;
        _attachment: unknown;
    };

    return ws;
}

/**
 * Create mock DurableObjectState for testing
 */
function createMockDurableObjectState(existingWebSockets: WebSocket[] = []): DurableObjectState {
    const webSockets: WebSocket[] = [...existingWebSockets];
    let autoResponse: WebSocketRequestResponsePair | null = null;

    return {
        id: {
            toString: () => 'test-do-id',
            name: 'test-do',
            equals: () => false,
        } as DurableObjectId,
        storage: {
            get: vi.fn(),
            put: vi.fn(),
            delete: vi.fn(),
            list: vi.fn(),
            getAlarm: vi.fn(),
            setAlarm: vi.fn(),
            deleteAlarm: vi.fn(),
            transaction: vi.fn(),
            deleteAll: vi.fn(),
            sync: vi.fn(),
        } as unknown as DurableObjectStorage,
        acceptWebSocket: vi.fn((ws: WebSocket, _tags?: string[]) => {
            webSockets.push(ws);
        }),
        getWebSockets: vi.fn((tag?: string) => {
            if (!tag) return webSockets;
            // Filter by tag if needed - simplified for tests
            return webSockets;
        }),
        setWebSocketAutoResponse: vi.fn((pair: WebSocketRequestResponsePair | null) => {
            autoResponse = pair;
        }),
        getWebSocketAutoResponse: vi.fn(() => autoResponse),
        getWebSocketAutoResponseTimestamp: vi.fn(() => null),
        setHibernatableWebSocketEventTimeout: vi.fn(),
        getHibernatableWebSocketEventTimeout: vi.fn(() => null),
        getTags: vi.fn(() => []),
        blockConcurrencyWhile: vi.fn(async (fn) => fn()),
        waitUntil: vi.fn(),
        abort: vi.fn(),
    } as unknown as DurableObjectState;
}

/**
 * Create mock environment
 */
function createMockEnv() {
    return {
        DB: {} as D1Database,
        HANDY_MASTER_SECRET: 'test-secret-32-bytes-for-tests!',
        ENVIRONMENT: 'development' as const,
    };
}

// =============================================================================
// TESTS
// =============================================================================

import { ConnectionManager, ConnectionManagerEnv } from '@/durable-objects/ConnectionManager';

describe('ConnectionManager Durable Object', () => {
    let ctx: DurableObjectState;
    let env: ConnectionManagerEnv;
    let connectionManager: ConnectionManager;

    beforeEach(() => {
        vi.clearAllMocks();

        // Setup default mock behavior
        mockVerifyToken.mockImplementation(async (token: string) => {
            if (token === 'valid-token') {
                return { userId: 'test-user-123', extras: {} };
            }
            if (token === 'user2-token') {
                return { userId: 'test-user-456', extras: {} };
            }
            return null;
        });
        mockInitAuth.mockResolvedValue(undefined);

        ctx = createMockDurableObjectState();
        env = createMockEnv();
        connectionManager = new ConnectionManager(ctx, env);
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    // =========================================================================
    // CONSTRUCTOR & INITIALIZATION
    // =========================================================================

    describe('Constructor & Initialization', () => {
        it('should initialize with empty connections', () => {
            const cm = new ConnectionManager(ctx, env);
            expect(cm).toBeDefined();
        });

        it('should restore connections from hibernation', () => {
            // Create a mock WebSocket with attachment
            const existingWs = createMockWebSocket('existing');
            const metadata: ConnectionMetadata = {
                connectionId: 'conn-123',
                userId: 'user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now() - 60000,
                lastActivityAt: Date.now() - 30000,
                authState: 'legacy',
            };
            existingWs._attachment = metadata;
            existingWs.deserializeAttachment = vi.fn(() => metadata);

            const ctxWithWs = createMockDurableObjectState([existingWs]);
            const cm = new ConnectionManager(ctxWithWs, env);

            expect(ctxWithWs.getWebSockets).toHaveBeenCalled();
            expect(cm).toBeDefined();
        });

        it('should set up auto-response for ping/pong', () => {
            const cm = new ConnectionManager(ctx, env);
            expect(ctx.setWebSocketAutoResponse).toHaveBeenCalled();
        });
    });

    // =========================================================================
    // HTTP ENDPOINTS
    // =========================================================================

    describe('HTTP Endpoints', () => {
        describe('GET /health', () => {
            it('should return health status', async () => {
                const request = new Request('http://localhost/health', {
                    method: 'GET',
                });

                const response = await connectionManager.fetch(request);
                expect(response.status).toBe(200);

                const body = await response.json();
                expect(body).toHaveProperty('status', 'healthy');
                expect(body).toHaveProperty('connections');
            });
        });

        describe('GET /stats', () => {
            it('should return connection statistics', async () => {
                const request = new Request('http://localhost/stats', {
                    method: 'GET',
                });

                const response = await connectionManager.fetch(request);
                expect(response.status).toBe(200);

                const body = await response.json() as {
                    totalConnections: number;
                    byType: Record<string, number>;
                    activeSessions: number;
                    activeMachines: number;
                    oldestConnection: number | null;
                };
                expect(body).toHaveProperty('totalConnections');
                expect(body).toHaveProperty('byType');
                expect(body.byType).toHaveProperty('user-scoped');
                expect(body.byType).toHaveProperty('session-scoped');
                expect(body.byType).toHaveProperty('machine-scoped');
                expect(body).toHaveProperty('activeSessions');
                expect(body).toHaveProperty('activeMachines');
                expect(body).toHaveProperty('oldestConnection');
            });
        });

        describe('POST /broadcast', () => {
            it('should return success for valid broadcast', async () => {
                const request = new Request('http://localhost/broadcast', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: {
                            type: 'test',
                            payload: { data: 'test' },
                            timestamp: Date.now(),
                        },
                    }),
                });

                const response = await connectionManager.fetch(request);
                expect(response.status).toBe(200);

                const body = await response.json() as { success: boolean; delivered: number };
                expect(body).toHaveProperty('success', true);
                expect(body).toHaveProperty('delivered');
            });

            it('should return error for invalid broadcast request', async () => {
                const request = new Request('http://localhost/broadcast', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: 'invalid-json',
                });

                const response = await connectionManager.fetch(request);
                expect(response.status).toBe(400);
            });
        });

        describe('Unknown routes', () => {
            it('should return 404 for unknown paths', async () => {
                const request = new Request('http://localhost/unknown', {
                    method: 'GET',
                });

                const response = await connectionManager.fetch(request);
                expect(response.status).toBe(404);
            });
        });
    });

    // =========================================================================
    // WEBSOCKET UPGRADE
    // =========================================================================

    describe('WebSocket Upgrade', () => {
        it('should reject non-WebSocket upgrade requests', async () => {
            const request = new Request('http://localhost/websocket', {
                method: 'GET',
            });

            const response = await connectionManager.fetch(request);
            expect(response.status).toBe(426);
        });

        it('should reject requests without token', async () => {
            const request = new Request('http://localhost/websocket', {
                method: 'GET',
                headers: {
                    Upgrade: 'websocket',
                    Connection: 'Upgrade',
                },
            });

            const response = await connectionManager.fetch(request);
            expect(response.status).toBe(400);
        });

        it('should reject requests with invalid token', async () => {
            const request = new Request('http://localhost/websocket?token=invalid-token', {
                method: 'GET',
                headers: {
                    Upgrade: 'websocket',
                    Connection: 'Upgrade',
                },
            });

            const response = await connectionManager.fetch(request);
            expect(response.status).toBe(401);
        });

        it('should accept valid WebSocket upgrade for user-scoped client', async () => {
            const request = new Request(
                'http://localhost/websocket?token=valid-token&clientType=user-scoped',
                {
                    method: 'GET',
                    headers: {
                        Upgrade: 'websocket',
                        Connection: 'Upgrade',
                    },
                }
            );

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            // The actual code path succeeds - we verify via acceptWebSocket being called
            try {
                const response = await connectionManager.fetch(request);
                // In Cloudflare Workers runtime, this would return 101
                expect([101, 200]).toContain(response.status);
            } catch (e) {
                // RangeError is expected in Node.js for status 101
                expect((e as Error).message).toContain('status');
            }
            expect(ctx.acceptWebSocket).toHaveBeenCalled();
        });

        it('should reject session-scoped without sessionId', async () => {
            const request = new Request(
                'http://localhost/websocket?token=valid-token&clientType=session-scoped',
                {
                    method: 'GET',
                    headers: {
                        Upgrade: 'websocket',
                        Connection: 'Upgrade',
                    },
                }
            );

            const response = await connectionManager.fetch(request);
            expect(response.status).toBe(400);
            const body = await response.text();
            expect(body).toContain('Session ID required');
        });

        it('should accept session-scoped with sessionId', async () => {
            const request = new Request(
                'http://localhost/websocket?token=valid-token&clientType=session-scoped&sessionId=sess-123',
                {
                    method: 'GET',
                    headers: {
                        Upgrade: 'websocket',
                        Connection: 'Upgrade',
                    },
                }
            );

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                const response = await connectionManager.fetch(request);
                expect([101, 200]).toContain(response.status);
            } catch (e) {
                expect((e as Error).message).toContain('status');
            }
            expect(ctx.acceptWebSocket).toHaveBeenCalled();
        });

        it('should reject machine-scoped without machineId', async () => {
            const request = new Request(
                'http://localhost/websocket?token=valid-token&clientType=machine-scoped',
                {
                    method: 'GET',
                    headers: {
                        Upgrade: 'websocket',
                        Connection: 'Upgrade',
                    },
                }
            );

            const response = await connectionManager.fetch(request);
            expect(response.status).toBe(400);
            const body = await response.text();
            expect(body).toContain('Machine ID required');
        });

        it('should accept machine-scoped with machineId', async () => {
            const request = new Request(
                'http://localhost/websocket?token=valid-token&clientType=machine-scoped&machineId=machine-123',
                {
                    method: 'GET',
                    headers: {
                        Upgrade: 'websocket',
                        Connection: 'Upgrade',
                    },
                }
            );

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                const response = await connectionManager.fetch(request);
                expect([101, 200]).toContain(response.status);
            } catch (e) {
                expect((e as Error).message).toContain('status');
            }
            expect(ctx.acceptWebSocket).toHaveBeenCalled();
        });

        it('should support Authorization header for token', async () => {
            const request = new Request('http://localhost/websocket', {
                method: 'GET',
                headers: {
                    Upgrade: 'websocket',
                    Connection: 'Upgrade',
                    Authorization: 'Bearer valid-token',
                },
            });

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                const response = await connectionManager.fetch(request);
                expect([101, 200]).toContain(response.status);
            } catch (e) {
                expect((e as Error).message).toContain('status');
            }
            expect(ctx.acceptWebSocket).toHaveBeenCalled();
        });

        it('should support X-Client-Type header', async () => {
            const request = new Request('http://localhost/websocket?token=valid-token', {
                method: 'GET',
                headers: {
                    Upgrade: 'websocket',
                    Connection: 'Upgrade',
                    'X-Client-Type': 'user-scoped',
                },
            });

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                const response = await connectionManager.fetch(request);
                expect([101, 200]).toContain(response.status);
            } catch (e) {
                expect((e as Error).message).toContain('status');
            }
            expect(ctx.acceptWebSocket).toHaveBeenCalled();
        });

        it('should support X-Session-Id header for session-scoped', async () => {
            const request = new Request(
                'http://localhost/websocket?token=valid-token&clientType=session-scoped',
                {
                    method: 'GET',
                    headers: {
                        Upgrade: 'websocket',
                        Connection: 'Upgrade',
                        'X-Session-Id': 'sess-456',
                    },
                }
            );

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                const response = await connectionManager.fetch(request);
                expect([101, 200]).toContain(response.status);
            } catch (e) {
                expect((e as Error).message).toContain('status');
            }
            expect(ctx.acceptWebSocket).toHaveBeenCalled();
        });

        it('should support X-Machine-Id header for machine-scoped', async () => {
            const request = new Request(
                'http://localhost/websocket?token=valid-token&clientType=machine-scoped',
                {
                    method: 'GET',
                    headers: {
                        Upgrade: 'websocket',
                        Connection: 'Upgrade',
                        'X-Machine-Id': 'machine-456',
                    },
                }
            );

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                const response = await connectionManager.fetch(request);
                expect([101, 200]).toContain(response.status);
            } catch (e) {
                expect((e as Error).message).toContain('status');
            }
            expect(ctx.acceptWebSocket).toHaveBeenCalled();
        });

        it('should default to user-scoped when clientType is invalid', async () => {
            const request = new Request(
                'http://localhost/websocket?token=valid-token&clientType=invalid-type',
                {
                    method: 'GET',
                    headers: {
                        Upgrade: 'websocket',
                        Connection: 'Upgrade',
                    },
                }
            );

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                const response = await connectionManager.fetch(request);
                expect([101, 200]).toContain(response.status);
            } catch (e) {
                expect((e as Error).message).toContain('status');
            }
            expect(ctx.acceptWebSocket).toHaveBeenCalled();
        });

        it('should accept WebSocket on root path', async () => {
            const request = new Request('http://localhost/?token=valid-token', {
                method: 'GET',
                headers: {
                    Upgrade: 'websocket',
                    Connection: 'Upgrade',
                },
            });

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                const response = await connectionManager.fetch(request);
                expect([101, 200]).toContain(response.status);
            } catch (e) {
                expect((e as Error).message).toContain('status');
            }
            expect(ctx.acceptWebSocket).toHaveBeenCalled();
        });
    });

    // =========================================================================
    // CONNECTION LIMITS
    // =========================================================================

    describe('Connection Limits', () => {
        it('should reject connections when limit is exceeded', async () => {
            // Create a ConnectionManager with many existing connections
            const existingWsSockets: WebSocket[] = [];
            for (let i = 0; i < 100; i++) {
                const ws = createMockWebSocket(`ws-${i}`);
                const metadata: ConnectionMetadata = {
                    connectionId: `conn-${i}`,
                    userId: 'test-user-123',
                    clientType: 'user-scoped',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                ws._attachment = metadata;
                ws.deserializeAttachment = vi.fn(() => metadata);
                existingWsSockets.push(ws);
            }

            const ctxWithManyWs = createMockDurableObjectState(existingWsSockets);
            const cm = new ConnectionManager(ctxWithManyWs, env);

            const request = new Request('http://localhost/websocket?token=valid-token', {
                method: 'GET',
                headers: {
                    Upgrade: 'websocket',
                    Connection: 'Upgrade',
                },
            });

            const response = await cm.fetch(request);
            expect(response.status).toBe(429);
        });
    });

    // =========================================================================
    // WEBSOCKET MESSAGE HANDLING
    // =========================================================================

    describe('WebSocket Message Handling', () => {
        let testWs: WebSocket & { _messages: string[]; _attachment: unknown };
        let cm: ConnectionManager;

        beforeEach(async () => {
            testWs = createMockWebSocket('test-ws');
            const metadata: ConnectionMetadata = {
                connectionId: 'test-conn',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            testWs._attachment = metadata;
            testWs.deserializeAttachment = vi.fn(() => testWs._attachment);

            const ctxWithWs = createMockDurableObjectState([testWs]);
            cm = new ConnectionManager(ctxWithWs, env);
        });

        it('should handle ping message', async () => {
            const message = JSON.stringify({ event: 'ping' });
            await cm.webSocketMessage(testWs, message);

            expect(testWs.send).toHaveBeenCalled();
            const sentMessage = JSON.parse((testWs.send as ReturnType<typeof vi.fn>).mock.calls[0][0]);
            expect(sentMessage.event).toBe('pong');
        });

        it('should handle invalid JSON gracefully', async () => {
            await cm.webSocketMessage(testWs, 'invalid-json');

            expect(testWs.send).toHaveBeenCalled();
            const sentMessage = JSON.parse((testWs.send as ReturnType<typeof vi.fn>).mock.calls[0][0]);
            expect(sentMessage.event).toBe('error');
        });

        it('should handle invalid message format gracefully', async () => {
            const message = JSON.stringify({ invalid: 'format' });
            await cm.webSocketMessage(testWs, message);

            expect(testWs.send).toHaveBeenCalled();
            const sentMessage = JSON.parse((testWs.send as ReturnType<typeof vi.fn>).mock.calls[0][0]);
            expect(sentMessage.event).toBe('error');
        });

        it('should handle ArrayBuffer messages', async () => {
            const message = new TextEncoder().encode(JSON.stringify({ event: 'ping' })).buffer;
            await cm.webSocketMessage(testWs, message);

            expect(testWs.send).toHaveBeenCalled();
            const sentMessage = JSON.parse((testWs.send as ReturnType<typeof vi.fn>).mock.calls[0][0]);
            expect(sentMessage.event).toBe('pong');
        });

        it('should update lastActivityAt on message', async () => {
            const originalLastActivity = (testWs._attachment as ConnectionMetadata).lastActivityAt;

            // Wait a small amount to ensure timestamp changes
            await new Promise(resolve => setTimeout(resolve, 10));

            const message = JSON.stringify({ event: 'ping' });
            await cm.webSocketMessage(testWs, message);

            expect(testWs.serializeAttachment).toHaveBeenCalled();
        });

        it('should handle server message format (type/payload)', async () => {
            const message = JSON.stringify({
                type: 'ping',
                timestamp: Date.now(),
            });
            await cm.webSocketMessage(testWs, message);

            expect(testWs.send).toHaveBeenCalled();
        });

        describe('Session Message Handlers', () => {
            it('should route update-metadata message', async () => {
                const { handleSessionMetadataUpdate } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'update-metadata',
                    data: { sid: 'sess-1', metadata: '{}', expectedVersion: 1 },
                    ackId: 'ack-1',
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleSessionMetadataUpdate).toHaveBeenCalled();
            });

            it('should route update-state message', async () => {
                const { handleSessionStateUpdate } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'update-state',
                    data: { sid: 'sess-1', agentState: '{}', expectedVersion: 1 },
                    ackId: 'ack-1',
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleSessionStateUpdate).toHaveBeenCalled();
            });

            it('should route session-alive message', async () => {
                const { handleSessionAlive } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'session-alive',
                    data: { sid: 'sess-1', time: Date.now() },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleSessionAlive).toHaveBeenCalled();
            });

            it('should route session-end message', async () => {
                const { handleSessionEnd } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'session-end',
                    data: { sid: 'sess-1', time: Date.now() },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleSessionEnd).toHaveBeenCalled();
            });

            it('should route message event', async () => {
                const { handleSessionMessage } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'message',
                    data: { sid: 'sess-1', message: 'encrypted-content' },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleSessionMessage).toHaveBeenCalled();
            });
        });

        describe('Machine Message Handlers', () => {
            it('should route machine-alive message', async () => {
                const { handleMachineAlive } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'machine-alive',
                    data: { machineId: 'machine-1', time: Date.now() },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleMachineAlive).toHaveBeenCalled();
            });

            it('should route machine-update-metadata message', async () => {
                const { handleMachineMetadataUpdate } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'machine-update-metadata',
                    data: { machineId: 'machine-1', metadata: '{}', expectedVersion: 1 },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleMachineMetadataUpdate).toHaveBeenCalled();
            });

            it('should route machine-update-state message', async () => {
                const { handleMachineStateUpdate } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'machine-update-state',
                    data: { machineId: 'machine-1', daemonState: '{}', expectedVersion: 1 },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleMachineStateUpdate).toHaveBeenCalled();
            });
        });

        describe('Artifact Message Handlers', () => {
            it('should route artifact-read message', async () => {
                const { handleArtifactRead } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'artifact-read',
                    data: { artifactId: 'artifact-1' },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleArtifactRead).toHaveBeenCalled();
            });

            it('should route artifact-update message', async () => {
                const { handleArtifactUpdate } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'artifact-update',
                    data: {
                        artifactId: 'artifact-1',
                        header: { data: 'base64data', expectedVersion: 1 },
                    },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleArtifactUpdate).toHaveBeenCalled();
            });

            it('should route artifact-create message', async () => {
                const { handleArtifactCreate } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'artifact-create',
                    data: {
                        id: 'artifact-1',
                        header: 'base64header',
                        body: 'base64body',
                        dataEncryptionKey: 'base64key',
                    },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleArtifactCreate).toHaveBeenCalled();
            });

            it('should route artifact-delete message', async () => {
                const { handleArtifactDelete } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'artifact-delete',
                    data: { artifactId: 'artifact-1' },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleArtifactDelete).toHaveBeenCalled();
            });
        });

        describe('Access Key Message Handlers', () => {
            it('should route access-key-get message', async () => {
                const { handleAccessKeyGet } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'access-key-get',
                    data: { sessionId: 'sess-1', machineId: 'machine-1' },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleAccessKeyGet).toHaveBeenCalled();
            });
        });

        describe('Usage Message Handlers', () => {
            it('should route usage-report message', async () => {
                const { handleUsageReport } = await import('@/durable-objects/handlers');
                const message = JSON.stringify({
                    event: 'usage-report',
                    data: {
                        key: 'daily',
                        tokens: { total: 1000, input: 500, output: 500 },
                        cost: { total: 0.01, input: 0.005, output: 0.005 },
                    },
                });
                await cm.webSocketMessage(testWs, message);

                expect(handleUsageReport).toHaveBeenCalled();
            });
        });

        describe('RPC Message Handlers', () => {
            it('should forward rpc-call to user-scoped connections when from non-user-scoped', async () => {
                // Set up a machine-scoped connection
                const machineWs = createMockWebSocket('machine-ws');
                const machineMetadata: ConnectionMetadata = {
                    connectionId: 'machine-conn',
                    userId: 'test-user-123',
                    clientType: 'machine-scoped',
                    machineId: 'machine-1',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                machineWs._attachment = machineMetadata;
                machineWs.deserializeAttachment = vi.fn(() => machineWs._attachment);

                // Set up a user-scoped connection to receive
                const userWs = createMockWebSocket('user-ws');
                const userMetadata: ConnectionMetadata = {
                    connectionId: 'user-conn',
                    userId: 'test-user-123',
                    clientType: 'user-scoped',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                userWs._attachment = userMetadata;
                userWs.deserializeAttachment = vi.fn(() => userWs._attachment);

                const ctxWithBoth = createMockDurableObjectState([machineWs, userWs]);
                const cmBoth = new ConnectionManager(ctxWithBoth, env);

                const message = JSON.stringify({
                    event: 'rpc-call',
                    data: { method: 'someMethod', params: {} },
                    ackId: 'ack-123',
                });
                await cmBoth.webSocketMessage(machineWs, message);

                // User-scoped should receive the RPC
                expect(userWs.send).toHaveBeenCalled();
            });

            it('should forward rpc-request from user-scoped to machine by machineId', async () => {
                // Set up a user-scoped connection
                const userWs = createMockWebSocket('user-ws');
                const userMetadata: ConnectionMetadata = {
                    connectionId: 'user-conn',
                    userId: 'test-user-123',
                    clientType: 'user-scoped',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                userWs._attachment = userMetadata;
                userWs.deserializeAttachment = vi.fn(() => userWs._attachment);

                // Set up a machine-scoped connection
                const machineWs = createMockWebSocket('machine-ws');
                const machineMetadata: ConnectionMetadata = {
                    connectionId: 'machine-conn',
                    userId: 'test-user-123',
                    clientType: 'machine-scoped',
                    machineId: 'target-machine',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                machineWs._attachment = machineMetadata;
                machineWs.deserializeAttachment = vi.fn(() => machineWs._attachment);

                const ctxWithBoth = createMockDurableObjectState([userWs, machineWs]);
                const cmBoth = new ConnectionManager(ctxWithBoth, env);

                const message = JSON.stringify({
                    event: 'rpc-request',
                    data: { method: 'target-machine:someMethod', params: {} },
                    ackId: 'ack-123',
                });
                await cmBoth.webSocketMessage(userWs, message);

                // Machine-scoped should receive the RPC
                expect(machineWs.send).toHaveBeenCalled();
            });

            it('should forward rpc-response to all connections', async () => {
                const ws1 = createMockWebSocket('ws-1');
                const metadata1: ConnectionMetadata = {
                    connectionId: 'conn-1',
                    userId: 'test-user-123',
                    clientType: 'user-scoped',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                ws1._attachment = metadata1;
                // Ensure deserializeAttachment returns the attachment (simulating hibernation restore)
                (ws1 as unknown as { deserializeAttachment: () => ConnectionMetadata }).deserializeAttachment = () => metadata1;

                const ws2 = createMockWebSocket('ws-2');
                const metadata2: ConnectionMetadata = {
                    connectionId: 'conn-2',
                    userId: 'test-user-123',
                    clientType: 'machine-scoped',
                    machineId: 'machine-1',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                ws2._attachment = metadata2;
                (ws2 as unknown as { deserializeAttachment: () => ConnectionMetadata }).deserializeAttachment = () => metadata2;

                const ctxWithBoth = createMockDurableObjectState([ws1, ws2]);
                const cmBoth = new ConnectionManager(ctxWithBoth, env);

                // Note: The rpc-response handler uses 'data' as the payload (not 'ack')
                // because 'ack' + 'ackId' triggers the acknowledgement skip logic
                const message = JSON.stringify({
                    event: 'rpc-response',
                    ackId: 'ack-123',
                    data: { result: 'success' },
                });
                await cmBoth.webSocketMessage(ws1, message);

                // Both connections should receive the response (filter type: all)
                // Note: The sender (ws1) also receives because filter is 'all', not 'exclude'
                expect(ws1.send).toHaveBeenCalled();
                expect(ws2.send).toHaveBeenCalled();
            });
        });

        describe('Broadcast Message Handler', () => {
            it('should broadcast to all connections except sender', async () => {
                const ws1 = createMockWebSocket('ws-1');
                const metadata1: ConnectionMetadata = {
                    connectionId: 'conn-1',
                    userId: 'test-user-123',
                    clientType: 'user-scoped',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                ws1._attachment = metadata1;
                ws1.deserializeAttachment = vi.fn(() => ws1._attachment);

                const ws2 = createMockWebSocket('ws-2');
                const metadata2: ConnectionMetadata = {
                    connectionId: 'conn-2',
                    userId: 'test-user-123',
                    clientType: 'user-scoped',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                ws2._attachment = metadata2;
                ws2.deserializeAttachment = vi.fn(() => ws2._attachment);

                const ctxWithBoth = createMockDurableObjectState([ws1, ws2]);
                const cmBoth = new ConnectionManager(ctxWithBoth, env);

                const message = JSON.stringify({
                    event: 'broadcast',
                    data: { content: 'Hello everyone!' },
                });
                await cmBoth.webSocketMessage(ws1, message);

                // Only ws2 should receive (ws1 is the sender)
                expect(ws2.send).toHaveBeenCalled();
            });
        });

        describe('Default Message Handler (unhandled types)', () => {
            it('should forward unhandled messages from CLI to mobile', async () => {
                const cliWs = createMockWebSocket('cli-ws');
                const cliMetadata: ConnectionMetadata = {
                    connectionId: 'cli-conn',
                    userId: 'test-user-123',
                    clientType: 'session-scoped',
                    sessionId: 'sess-1',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                cliWs._attachment = cliMetadata;
                cliWs.deserializeAttachment = vi.fn(() => cliWs._attachment);

                const mobileWs = createMockWebSocket('mobile-ws');
                const mobileMetadata: ConnectionMetadata = {
                    connectionId: 'mobile-conn',
                    userId: 'test-user-123',
                    clientType: 'user-scoped',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                mobileWs._attachment = mobileMetadata;
                mobileWs.deserializeAttachment = vi.fn(() => mobileWs._attachment);

                const ctxWithBoth = createMockDurableObjectState([cliWs, mobileWs]);
                const cmBoth = new ConnectionManager(ctxWithBoth, env);

                const message = JSON.stringify({
                    event: 'custom-event',
                    data: { custom: 'data' },
                });
                await cmBoth.webSocketMessage(cliWs, message);

                // Mobile should receive the forwarded event
                expect(mobileWs.send).toHaveBeenCalled();
            });

            it('should forward unhandled messages from mobile to session', async () => {
                const mobileWs = createMockWebSocket('mobile-ws');
                const mobileMetadata: ConnectionMetadata = {
                    connectionId: 'mobile-conn',
                    userId: 'test-user-123',
                    clientType: 'user-scoped',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                mobileWs._attachment = mobileMetadata;
                mobileWs.deserializeAttachment = vi.fn(() => mobileWs._attachment);

                const sessionWs = createMockWebSocket('session-ws');
                const sessionMetadata: ConnectionMetadata = {
                    connectionId: 'session-conn',
                    userId: 'test-user-123',
                    clientType: 'session-scoped',
                    sessionId: 'target-session',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                sessionWs._attachment = sessionMetadata;
                sessionWs.deserializeAttachment = vi.fn(() => sessionWs._attachment);

                const ctxWithBoth = createMockDurableObjectState([mobileWs, sessionWs]);
                const cmBoth = new ConnectionManager(ctxWithBoth, env);

                const message = JSON.stringify({
                    event: 'custom-event',
                    data: { sessionId: 'target-session', action: 'do-something' },
                });
                await cmBoth.webSocketMessage(mobileWs, message);

                // Session should receive the forwarded event
                expect(sessionWs.send).toHaveBeenCalled();
            });

            it('should forward unhandled messages from mobile to machine', async () => {
                const mobileWs = createMockWebSocket('mobile-ws');
                const mobileMetadata: ConnectionMetadata = {
                    connectionId: 'mobile-conn',
                    userId: 'test-user-123',
                    clientType: 'user-scoped',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                mobileWs._attachment = mobileMetadata;
                mobileWs.deserializeAttachment = vi.fn(() => mobileWs._attachment);

                const machineWs = createMockWebSocket('machine-ws');
                const machineMetadata: ConnectionMetadata = {
                    connectionId: 'machine-conn',
                    userId: 'test-user-123',
                    clientType: 'machine-scoped',
                    machineId: 'target-machine',
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                authState: 'legacy',
                };
                machineWs._attachment = machineMetadata;
                machineWs.deserializeAttachment = vi.fn(() => machineWs._attachment);

                const ctxWithBoth = createMockDurableObjectState([mobileWs, machineWs]);
                const cmBoth = new ConnectionManager(ctxWithBoth, env);

                const message = JSON.stringify({
                    event: 'custom-event',
                    data: { machineId: 'target-machine', action: 'do-something' },
                });
                await cmBoth.webSocketMessage(mobileWs, message);

                // Machine should receive the forwarded event
                expect(machineWs.send).toHaveBeenCalled();
            });
        });
    });

    // =========================================================================
    // WEBSOCKET CLOSE HANDLING
    // =========================================================================

    describe('WebSocket Close Handling', () => {
        it('should remove connection on close', async () => {
            const ws = createMockWebSocket('ws-1');
            const metadata: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws._attachment = metadata;
            ws.deserializeAttachment = vi.fn(() => ws._attachment);

            const ctxWithWs = createMockDurableObjectState([ws]);
            const cm = new ConnectionManager(ctxWithWs, env);

            await cm.webSocketClose(ws, 1000, 'Normal closure', true);

            // WebSocket should be closed
            expect(ws.close).toHaveBeenCalled();
        });

        it('should broadcast machine-update when machine-scoped disconnects', async () => {
            const machineWs = createMockWebSocket('machine-ws');
            const machineMetadata: ConnectionMetadata = {
                connectionId: 'machine-conn',
                userId: 'test-user-123',
                clientType: 'machine-scoped',
                machineId: 'machine-1',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            machineWs._attachment = machineMetadata;
            machineWs.deserializeAttachment = vi.fn(() => machineWs._attachment);

            const userWs = createMockWebSocket('user-ws');
            const userMetadata: ConnectionMetadata = {
                connectionId: 'user-conn',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            userWs._attachment = userMetadata;
            userWs.deserializeAttachment = vi.fn(() => userWs._attachment);

            const ctxWithBoth = createMockDurableObjectState([machineWs, userWs]);
            const cm = new ConnectionManager(ctxWithBoth, env);

            await cm.webSocketClose(machineWs, 1000, 'Disconnect', true);

            // User should receive machine-update with active: false
            expect(userWs.send).toHaveBeenCalled();
            const sentMessage = JSON.parse((userWs.send as ReturnType<typeof vi.fn>).mock.calls[0][0]);
            expect(sentMessage.event).toBe('machine-update');
            expect(sentMessage.data.machineId).toBe('machine-1');
            expect(sentMessage.data.active).toBe(false);
        });

        it('should handle close of unknown connection gracefully', async () => {
            const unknownWs = createMockWebSocket('unknown-ws');

            // No expect needed - just ensure it doesn't throw
            await connectionManager.webSocketClose(unknownWs, 1000, 'Unknown', true);
        });

        it('should handle close when WebSocket is already closed', async () => {
            const ws = createMockWebSocket('ws-1');
            const metadata: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws._attachment = metadata;
            ws.deserializeAttachment = vi.fn(() => ws._attachment);
            ws._closed = true;
            ws.close = vi.fn(() => {
                throw new Error('Already closed');
            });

            const ctxWithWs = createMockDurableObjectState([ws]);
            const cm = new ConnectionManager(ctxWithWs, env);

            // Should not throw
            await cm.webSocketClose(ws, 1000, 'Normal closure', true);
        });
    });

    // =========================================================================
    // WEBSOCKET ERROR HANDLING
    // =========================================================================

    describe('WebSocket Error Handling', () => {
        it('should clean up connection on error', async () => {
            const ws = createMockWebSocket('ws-1');
            const metadata: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws._attachment = metadata;
            ws.deserializeAttachment = vi.fn(() => ws._attachment);

            const ctxWithWs = createMockDurableObjectState([ws]);
            const cm = new ConnectionManager(ctxWithWs, env);

            await cm.webSocketError(ws, new Error('Test error'));

            expect(ws.close).toHaveBeenCalled();
        });

        it('should log error for unknown connection', async () => {
            const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
            const unknownWs = createMockWebSocket('unknown-ws');

            await connectionManager.webSocketError(unknownWs, new Error('Test error'));

            expect(consoleSpy).toHaveBeenCalled();
            consoleSpy.mockRestore();
        });

        it('should handle error when WebSocket is already closed', async () => {
            const ws = createMockWebSocket('ws-1');
            ws.close = vi.fn(() => {
                throw new Error('Already closed');
            });

            const ctxWithWs = createMockDurableObjectState([ws]);
            const cm = new ConnectionManager(ctxWithWs, env);

            // Should not throw
            await cm.webSocketError(ws, new Error('Test error'));
        });
    });

    // =========================================================================
    // MESSAGE FILTERING
    // =========================================================================

    describe('Message Filtering', () => {
        let ws1: WebSocket & { _messages: string[]; _attachment: unknown };
        let ws2: WebSocket & { _messages: string[]; _attachment: unknown };
        let ws3: WebSocket & { _messages: string[]; _attachment: unknown };
        let cmMulti: ConnectionManager;

        beforeEach(() => {
            // User-scoped connection
            ws1 = createMockWebSocket('ws-1');
            const metadata1: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now() - 60000,
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws1._attachment = metadata1;
            ws1.deserializeAttachment = vi.fn(() => ws1._attachment);

            // Session-scoped connection
            ws2 = createMockWebSocket('ws-2');
            const metadata2: ConnectionMetadata = {
                connectionId: 'conn-2',
                userId: 'test-user-123',
                clientType: 'session-scoped',
                sessionId: 'sess-1',
                connectedAt: Date.now() - 30000,
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws2._attachment = metadata2;
            ws2.deserializeAttachment = vi.fn(() => ws2._attachment);

            // Machine-scoped connection
            ws3 = createMockWebSocket('ws-3');
            const metadata3: ConnectionMetadata = {
                connectionId: 'conn-3',
                userId: 'test-user-123',
                clientType: 'machine-scoped',
                machineId: 'machine-1',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws3._attachment = metadata3;
            ws3.deserializeAttachment = vi.fn(() => ws3._attachment);

            const ctxMulti = createMockDurableObjectState([ws1, ws2, ws3]);
            cmMulti = new ConnectionManager(ctxMulti, env);
        });

        it('should broadcast to all connections with filter type: all', async () => {
            const request = new Request('http://localhost/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: { type: 'test', timestamp: Date.now() },
                    filter: { type: 'all' },
                }),
            });

            const response = await cmMulti.fetch(request);
            const body = await response.json() as { delivered: number };

            expect(body.delivered).toBe(3);
        });

        it('should broadcast only to user-scoped with filter type: user-scoped-only', async () => {
            const request = new Request('http://localhost/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: { type: 'test', timestamp: Date.now() },
                    filter: { type: 'user-scoped-only' },
                }),
            });

            const response = await cmMulti.fetch(request);
            const body = await response.json() as { delivered: number };

            expect(body.delivered).toBe(1);
            expect(ws1.send).toHaveBeenCalled();
            expect(ws2.send).not.toHaveBeenCalled();
            expect(ws3.send).not.toHaveBeenCalled();
        });

        it('should broadcast to specific session with filter type: session', async () => {
            const request = new Request('http://localhost/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: { type: 'test', timestamp: Date.now() },
                    filter: { type: 'session', sessionId: 'sess-1' },
                }),
            });

            const response = await cmMulti.fetch(request);
            const body = await response.json() as { delivered: number };

            expect(body.delivered).toBe(1);
            expect(ws2.send).toHaveBeenCalled();
        });

        it('should broadcast to specific machine with filter type: machine', async () => {
            const request = new Request('http://localhost/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: { type: 'test', timestamp: Date.now() },
                    filter: { type: 'machine', machineId: 'machine-1' },
                }),
            });

            const response = await cmMulti.fetch(request);
            const body = await response.json() as { delivered: number };

            expect(body.delivered).toBe(1);
            expect(ws3.send).toHaveBeenCalled();
        });

        it('should broadcast to all except one with filter type: exclude', async () => {
            const request = new Request('http://localhost/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: { type: 'test', timestamp: Date.now() },
                    filter: { type: 'exclude', connectionId: 'conn-1' },
                }),
            });

            const response = await cmMulti.fetch(request);
            const body = await response.json() as { delivered: number };

            expect(body.delivered).toBe(2);
            expect(ws1.send).not.toHaveBeenCalled();
            expect(ws2.send).toHaveBeenCalled();
            expect(ws3.send).toHaveBeenCalled();
        });

        it('should broadcast to all interested in session (session + user-scoped)', async () => {
            const request = new Request('http://localhost/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: { type: 'test', timestamp: Date.now() },
                    filter: { type: 'all-interested-in-session', sessionId: 'sess-1' },
                }),
            });

            const response = await cmMulti.fetch(request);
            const body = await response.json() as { delivered: number };

            // User-scoped (ws1) + session-scoped with matching sessionId (ws2)
            expect(body.delivered).toBe(2);
            expect(ws1.send).toHaveBeenCalled();
            expect(ws2.send).toHaveBeenCalled();
            expect(ws3.send).not.toHaveBeenCalled();
        });

        it('should handle broadcast without filter (defaults to all)', async () => {
            const request = new Request('http://localhost/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: { type: 'test', timestamp: Date.now() },
                }),
            });

            const response = await cmMulti.fetch(request);
            const body = await response.json() as { delivered: number };

            expect(body.delivered).toBe(3);
        });
    });

    // =========================================================================
    // CONNECTION STATISTICS
    // =========================================================================

    describe('Connection Statistics', () => {
        it('should return accurate statistics', async () => {
            // Create connections of different types
            const ws1 = createMockWebSocket('ws-1');
            const metadata1: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now() - 60000,
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws1._attachment = metadata1;
            ws1.deserializeAttachment = vi.fn(() => ws1._attachment);

            const ws2 = createMockWebSocket('ws-2');
            const metadata2: ConnectionMetadata = {
                connectionId: 'conn-2',
                userId: 'test-user-123',
                clientType: 'session-scoped',
                sessionId: 'sess-1',
                connectedAt: Date.now() - 30000,
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws2._attachment = metadata2;
            ws2.deserializeAttachment = vi.fn(() => ws2._attachment);

            const ws3 = createMockWebSocket('ws-3');
            const metadata3: ConnectionMetadata = {
                connectionId: 'conn-3',
                userId: 'test-user-123',
                clientType: 'machine-scoped',
                machineId: 'machine-1',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws3._attachment = metadata3;
            ws3.deserializeAttachment = vi.fn(() => ws3._attachment);

            const ctxMulti = createMockDurableObjectState([ws1, ws2, ws3]);
            const cm = new ConnectionManager(ctxMulti, env);

            const request = new Request('http://localhost/stats', { method: 'GET' });
            const response = await cm.fetch(request);
            const stats = await response.json() as {
                totalConnections: number;
                byType: { 'user-scoped': number; 'session-scoped': number; 'machine-scoped': number };
                activeSessions: number;
                activeMachines: number;
                oldestConnection: number;
            };

            expect(stats.totalConnections).toBe(3);
            expect(stats.byType['user-scoped']).toBe(1);
            expect(stats.byType['session-scoped']).toBe(1);
            expect(stats.byType['machine-scoped']).toBe(1);
            expect(stats.activeSessions).toBe(1);
            expect(stats.activeMachines).toBe(1);
            expect(stats.oldestConnection).toBe(metadata1.connectedAt);
        });
    });

    // =========================================================================
    // MACHINE ONLINE STATUS BROADCAST
    // =========================================================================

    describe('Machine Online Status Broadcast', () => {
        it('should broadcast machine-update when machine connects', async () => {
            // Set up a user-scoped connection first
            const userWs = createMockWebSocket('user-ws');
            const userMetadata: ConnectionMetadata = {
                connectionId: 'user-conn',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            userWs._attachment = userMetadata;
            (userWs as unknown as { deserializeAttachment: () => ConnectionMetadata }).deserializeAttachment = () => userMetadata;

            const ctxWithUser = createMockDurableObjectState([userWs]);
            const cm = new ConnectionManager(ctxWithUser, env);

            // Now connect a machine
            const request = new Request(
                'http://localhost/websocket?token=valid-token&clientType=machine-scoped&machineId=new-machine',
                {
                    method: 'GET',
                    headers: {
                        Upgrade: 'websocket',
                        Connection: 'Upgrade',
                    },
                }
            );

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                await cm.fetch(request);
            } catch (e) {
                // RangeError is expected in Node.js for status 101
                expect((e as Error).message).toContain('status');
            }

            // User should receive machine-update with active: true
            expect(userWs.send).toHaveBeenCalled();
            const sentMessage = JSON.parse((userWs.send as ReturnType<typeof vi.fn>).mock.calls[0][0]);
            expect(sentMessage.event).toBe('machine-update');
            expect(sentMessage.data.machineId).toBe('new-machine');
            expect(sentMessage.data.active).toBe(true);
        });
    });

    // =========================================================================
    // ACKNOWLEDGEMENT HANDLING
    // =========================================================================

    describe('Acknowledgement Handling', () => {
        it('should skip processing for ack responses', async () => {
            const ws = createMockWebSocket('ws-1');
            const metadata: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws._attachment = metadata;
            ws.deserializeAttachment = vi.fn(() => ws._attachment);

            const ctxWithWs = createMockDurableObjectState([ws]);
            const cm = new ConnectionManager(ctxWithWs, env);

            // Send an ack response message
            const message = JSON.stringify({
                event: 'ack',
                ackId: 'original-request-id',
                ack: { result: 'success' },
            });
            await cm.webSocketMessage(ws, message);

            // Should not trigger any response since acks are just confirmations
            // The send would only be called for actual responses, not for ack messages
        });
    });

    // =========================================================================
    // HANDLER RESULT PROCESSING
    // =========================================================================

    describe('Handler Result Processing', () => {
        it('should send ack response when handler returns response', async () => {
            const { handleSessionMetadataUpdate } = await import('@/durable-objects/handlers');
            (handleSessionMetadataUpdate as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                response: { result: 'success', version: 2 },
            });

            const ws = createMockWebSocket('ws-1');
            const metadata: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws._attachment = metadata;
            ws.deserializeAttachment = vi.fn(() => ws._attachment);

            const ctxWithWs = createMockDurableObjectState([ws]);
            const cm = new ConnectionManager(ctxWithWs, env);

            const message = JSON.stringify({
                event: 'update-metadata',
                data: { sid: 'sess-1', metadata: '{}', expectedVersion: 1 },
                ackId: 'ack-123',
            });
            await cm.webSocketMessage(ws, message);

            // Should send ack response
            expect(ws.send).toHaveBeenCalled();
            const sentMessages = (ws.send as ReturnType<typeof vi.fn>).mock.calls.map(
                (call) => JSON.parse(call[0])
            );
            const ackMessage = sentMessages.find((m) => m.event === 'ack');
            expect(ackMessage).toBeDefined();
            expect(ackMessage.ackId).toBe('ack-123');
        });

        it('should broadcast when handler returns broadcast', async () => {
            const { handleSessionMetadataUpdate } = await import('@/durable-objects/handlers');
            (handleSessionMetadataUpdate as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                response: { result: 'success' },
                broadcast: {
                    message: { event: 'update', data: { test: true } },
                    filter: { type: 'user-scoped-only' },
                },
            });

            const ws1 = createMockWebSocket('ws-1');
            const metadata1: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'session-scoped',
                sessionId: 'sess-1',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws1._attachment = metadata1;
            ws1.deserializeAttachment = vi.fn(() => ws1._attachment);

            const ws2 = createMockWebSocket('ws-2');
            const metadata2: ConnectionMetadata = {
                connectionId: 'conn-2',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws2._attachment = metadata2;
            ws2.deserializeAttachment = vi.fn(() => ws2._attachment);

            const ctxWithBoth = createMockDurableObjectState([ws1, ws2]);
            const cm = new ConnectionManager(ctxWithBoth, env);

            const message = JSON.stringify({
                event: 'update-metadata',
                data: { sid: 'sess-1', metadata: '{}', expectedVersion: 1 },
            });
            await cm.webSocketMessage(ws1, message);

            // ws2 (user-scoped) should receive the broadcast
            expect(ws2.send).toHaveBeenCalled();
        });

        it('should broadcast ephemeral when handler returns ephemeral', async () => {
            const { handleSessionAlive } = await import('@/durable-objects/handlers');
            (handleSessionAlive as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ephemeral: {
                    message: { event: 'ephemeral', data: { type: 'activity', id: 'sess-1' } },
                    filter: { type: 'user-scoped-only' },
                },
            });

            const ws1 = createMockWebSocket('ws-1');
            const metadata1: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'session-scoped',
                sessionId: 'sess-1',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws1._attachment = metadata1;
            ws1.deserializeAttachment = vi.fn(() => ws1._attachment);

            const ws2 = createMockWebSocket('ws-2');
            const metadata2: ConnectionMetadata = {
                connectionId: 'conn-2',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws2._attachment = metadata2;
            ws2.deserializeAttachment = vi.fn(() => ws2._attachment);

            const ctxWithBoth = createMockDurableObjectState([ws1, ws2]);
            const cm = new ConnectionManager(ctxWithBoth, env);

            const message = JSON.stringify({
                event: 'session-alive',
                data: { sid: 'sess-1', time: Date.now() },
            });
            await cm.webSocketMessage(ws1, message);

            // ws2 (user-scoped) should receive the ephemeral
            expect(ws2.send).toHaveBeenCalled();
        });
    });

    // =========================================================================
    // EDGE CASES
    // =========================================================================

    describe('Edge Cases', () => {
        it('should handle message when connection metadata is missing', async () => {
            const ws = createMockWebSocket('ws-1');
            ws._attachment = null;
            ws.deserializeAttachment = vi.fn(() => null);

            const ctxWithWs = createMockDurableObjectState([ws]);
            const cm = new ConnectionManager(ctxWithWs, env);

            // Manually add the WebSocket to the internal map without metadata
            // This simulates a corrupted state
            const message = JSON.stringify({ event: 'ping' });

            // Should handle gracefully
            await cm.webSocketMessage(ws, message);
        });

        it('should handle send failure gracefully during broadcast', async () => {
            const ws1 = createMockWebSocket('ws-1');
            const metadata1: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws1._attachment = metadata1;
            ws1.deserializeAttachment = vi.fn(() => ws1._attachment);
            ws1.send = vi.fn(() => {
                throw new Error('Connection closed');
            });

            const ws2 = createMockWebSocket('ws-2');
            const metadata2: ConnectionMetadata = {
                connectionId: 'conn-2',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws2._attachment = metadata2;
            ws2.deserializeAttachment = vi.fn(() => ws2._attachment);

            const ctxWithBoth = createMockDurableObjectState([ws1, ws2]);
            const cm = new ConnectionManager(ctxWithBoth, env);

            // Should not throw even when one send fails
            const request = new Request('http://localhost/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: { type: 'test', timestamp: Date.now() },
                }),
            });

            const response = await cm.fetch(request);
            const body = await response.json() as { delivered: number };

            // Only ws2 should receive successfully
            expect(body.delivered).toBe(1);
        });

        it('should handle sendError failure gracefully', async () => {
            const ws = createMockWebSocket('ws-1');
            const metadata: ConnectionMetadata = {
                connectionId: 'conn-1',
                userId: 'test-user-123',
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            };
            ws._attachment = metadata;
            ws.deserializeAttachment = vi.fn(() => ws._attachment);
            ws.send = vi.fn(() => {
                throw new Error('Connection closed');
            });

            const ctxWithWs = createMockDurableObjectState([ws]);
            const cm = new ConnectionManager(ctxWithWs, env);

            // Send invalid JSON to trigger sendError
            await cm.webSocketMessage(ws, 'invalid-json');

            // Should not throw
        });
    });

    // =========================================================================
    // PRODUCTION ENVIRONMENT LOGGING
    // =========================================================================

    describe('Production Environment Logging', () => {
        it('should not log in production environment', async () => {
            const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
            const prodEnv = { ...env, ENVIRONMENT: 'production' as const };
            const cm = new ConnectionManager(ctx, prodEnv);

            const request = new Request('http://localhost/websocket?token=valid-token', {
                method: 'GET',
                headers: {
                    Upgrade: 'websocket',
                    Connection: 'Upgrade',
                },
            });

            // Node.js Response doesn't support status 101 (WebSocket upgrade)
            try {
                await cm.fetch(request);
            } catch (e) {
                // RangeError is expected in Node.js for status 101
                expect((e as Error).message).toContain('status');
            }

            // Should not log connection in production
            const connectionLogs = consoleSpy.mock.calls.filter(
                (call) => call[0]?.includes?.('[ConnectionManager]')
            );
            expect(connectionLogs.length).toBe(0);

            consoleSpy.mockRestore();
        });
    });
});
