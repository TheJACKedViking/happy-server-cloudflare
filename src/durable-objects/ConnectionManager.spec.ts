/**
 * Integration Tests for ConnectionManager Durable Object
 *
 * Tests the WebSocket connection lifecycle including:
 * - WebSocket upgrade and authentication
 * - Client type routing (user/session/machine-scoped)
 * - Connection metadata storage
 * - Disconnect handling
 * - Broadcasting to filtered connections
 *
 * @module durable-objects/ConnectionManager.spec
 */

import { describe, it, expect, vi } from 'vitest';

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

// Mock auth module to avoid Ed25519 crypto operations unsupported in Node.js
// The real implementation uses Web Crypto Ed25519 which only works in Cloudflare Workers
vi.mock('@/lib/auth', () => ({
    initAuth: vi.fn().mockResolvedValue(undefined),
    verifyToken: vi.fn().mockImplementation(async (token: string) => {
        // Return null for invalid/test tokens, simulating auth failure
        if (token === 'invalid-token' || token === 'test') {
            return null;
        }
        // Return valid result for "valid-token"
        if (token === 'valid-token') {
            return { userId: 'test-user-123', extras: {} };
        }
        return null;
    }),
    resetAuth: vi.fn(),
}));

import { ConnectionManager } from './ConnectionManager';
import type {
    ConnectionMetadata,
    WebSocketMessage,
    ConnectedMessage,
    ConnectionStats,
} from './types';
import { CloseCode } from './types';

// Mock D1Database
const mockD1Database = {
    prepare: vi.fn().mockReturnThis(),
    bind: vi.fn().mockReturnThis(),
    first: vi.fn().mockResolvedValue(null),
    all: vi.fn().mockResolvedValue({ results: [] }),
    run: vi.fn().mockResolvedValue({ success: true }),
    batch: vi.fn().mockResolvedValue([]),
    dump: vi.fn().mockResolvedValue(new ArrayBuffer(0)),
    exec: vi.fn().mockResolvedValue({ count: 0, duration: 0 }),
} as unknown as D1Database;

// Mock environment
const mockEnv = {
    HANDY_MASTER_SECRET: 'test-secret-for-vitest-tests',
    ENVIRONMENT: 'development' as const,
    DB: mockD1Database,
};

// Mock DurableObjectState
function createMockState() {
    const webSockets = new Map<WebSocket, ConnectionMetadata>();

    return {
        id: { toString: () => 'test-do-id' },
        storage: {
            get: vi.fn(),
            put: vi.fn(),
            delete: vi.fn(),
            list: vi.fn(),
        },
        getWebSockets: vi.fn(() => Array.from(webSockets.keys())),
        acceptWebSocket: vi.fn(),
        setWebSocketAutoResponse: vi.fn(),
        blockConcurrencyWhile: vi.fn(async (fn: () => Promise<void>) => fn()),
    };
}

// Mock WebSocket
function createMockWebSocket() {
    const messages: string[] = [];
    let closed = false;
    let closeCode: number | undefined;
    let closeReason: string | undefined;
    let attachment: unknown = null;

    return {
        send: vi.fn((msg: string) => {
            if (closed) throw new Error('WebSocket is closed');
            messages.push(msg);
        }),
        close: vi.fn((code?: number, reason?: string) => {
            closed = true;
            closeCode = code;
            closeReason = reason;
        }),
        serializeAttachment: vi.fn((data: unknown) => {
            attachment = data;
        }),
        deserializeAttachment: vi.fn(() => attachment),
        readyState: 1 as const,

        // Test helpers
        _getMessages: () => messages,
        _isClosed: () => closed,
        _getCloseCode: () => closeCode,
        _getCloseReason: () => closeReason,
    };
}

// Mock WebSocketPair
class MockWebSocketPair {
    0: ReturnType<typeof createMockWebSocket>;
    1: ReturnType<typeof createMockWebSocket>;

    constructor() {
        this[0] = createMockWebSocket();
        this[1] = createMockWebSocket();
    }
}

// Set up global mocks
vi.stubGlobal('WebSocketPair', MockWebSocketPair);
vi.stubGlobal('WebSocketRequestResponsePair', class WebSocketRequestResponsePairMock {});

describe('ConnectionManager', () => {
    describe('fetch - Health and Stats endpoints', () => {
        it('should return healthy status on GET /health', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            const request = new Request('https://do/health', { method: 'GET' });
            const response = await cm.fetch(request);

            expect(response.status).toBe(200);
            const body = await response.json();
            expect(body).toMatchObject({
                status: 'healthy',
                connections: 0,
            });
        });

        it('should return stats on GET /stats', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            const request = new Request('https://do/stats', { method: 'GET' });
            const response = await cm.fetch(request);

            expect(response.status).toBe(200);
            const stats = (await response.json()) as ConnectionStats;
            expect(stats).toMatchObject({
                totalConnections: 0,
                byType: {
                    'user-scoped': 0,
                    'session-scoped': 0,
                    'machine-scoped': 0,
                },
                activeSessions: 0,
                activeMachines: 0,
            });
        });
    });

    describe('fetch - WebSocket upgrade', () => {
        it('should reject non-WebSocket requests to /websocket', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            const request = new Request('https://do/websocket', {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
            });
            const response = await cm.fetch(request);

            expect(response.status).toBe(426);
            const text = await response.text();
            expect(text).toContain('WebSocket');
        });

        it('should reject WebSocket requests without token', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            const request = new Request('https://do/websocket', {
                method: 'GET',
                headers: { Upgrade: 'websocket' },
            });
            const response = await cm.fetch(request);

            expect(response.status).toBe(400);
        });

        it('should reject WebSocket requests with invalid token', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            const request = new Request('https://do/websocket?token=invalid-token', {
                method: 'GET',
                headers: { Upgrade: 'websocket' },
            });
            const response = await cm.fetch(request);

            expect(response.status).toBe(401);
        });

        it('should reject session-scoped connections without sessionId', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            // Use valid-token to pass auth, then test sessionId validation
            const request = new Request(
                'https://do/websocket?token=valid-token&clientType=session-scoped',
                {
                    method: 'GET',
                    headers: { Upgrade: 'websocket' },
                }
            );
            const response = await cm.fetch(request);

            // Should fail at validation since sessionId is missing
            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('Session ID');
        });

        it('should reject machine-scoped connections without machineId', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            // Use valid-token to pass auth, then test machineId validation
            const request = new Request(
                'https://do/websocket?token=valid-token&clientType=machine-scoped',
                {
                    method: 'GET',
                    headers: { Upgrade: 'websocket' },
                }
            );
            const response = await cm.fetch(request);

            // Should fail at validation since machineId is missing
            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('Machine ID');
        });
    });

    describe('fetch - Broadcast endpoint', () => {
        it('should accept valid broadcast requests', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            const message: WebSocketMessage = {
                type: 'broadcast',
                payload: { test: 'data' },
                timestamp: Date.now(),
            };

            const request = new Request('https://do/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message }),
            });
            const response = await cm.fetch(request);

            expect(response.status).toBe(200);
            const body = (await response.json()) as { success: boolean; delivered: number };
            expect(body).toMatchObject({
                success: true,
                delivered: 0, // No connections yet
            });
        });

        it('should reject invalid broadcast requests', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            const request = new Request('https://do/broadcast', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: 'invalid json',
            });
            const response = await cm.fetch(request);

            expect(response.status).toBe(400);
        });
    });

    describe('fetch - 404 handling', () => {
        it('should return 404 for unknown paths', async () => {
            const state = createMockState();
            const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);

            const request = new Request('https://do/unknown-path', { method: 'GET' });
            const response = await cm.fetch(request);

            expect(response.status).toBe(404);
        });
    });
});

describe('ConnectionMetadata types', () => {
    it('should correctly type user-scoped connection metadata', () => {
        const metadata: ConnectionMetadata = {
            connectionId: 'conn-123',
            userId: 'user-456',
            clientType: 'user-scoped',
            connectedAt: Date.now(),
            lastActivityAt: Date.now(),
            authState: 'legacy',
        };

        expect(metadata.clientType).toBe('user-scoped');
        expect(metadata.sessionId).toBeUndefined();
        expect(metadata.machineId).toBeUndefined();
    });

    it('should correctly type session-scoped connection metadata', () => {
        const metadata: ConnectionMetadata = {
            connectionId: 'conn-123',
            userId: 'user-456',
            clientType: 'session-scoped',
            sessionId: 'session-789',
            connectedAt: Date.now(),
            lastActivityAt: Date.now(),
            authState: 'legacy',
        };

        expect(metadata.clientType).toBe('session-scoped');
        expect(metadata.sessionId).toBe('session-789');
    });

    it('should correctly type machine-scoped connection metadata', () => {
        const metadata: ConnectionMetadata = {
            connectionId: 'conn-123',
            userId: 'user-456',
            clientType: 'machine-scoped',
            machineId: 'machine-abc',
            connectedAt: Date.now(),
            lastActivityAt: Date.now(),
            authState: 'legacy',
        };

        expect(metadata.clientType).toBe('machine-scoped');
        expect(metadata.machineId).toBe('machine-abc');
    });
});

describe('CloseCode constants', () => {
    it('should have correct standard WebSocket close codes', () => {
        expect(CloseCode.NORMAL).toBe(1000);
        expect(CloseCode.GOING_AWAY).toBe(1001);
        expect(CloseCode.PROTOCOL_ERROR).toBe(1002);
    });

    it('should have correct custom close codes in 4000 range', () => {
        expect(CloseCode.AUTH_FAILED).toBe(4001);
        expect(CloseCode.INVALID_HANDSHAKE).toBe(4002);
        expect(CloseCode.MISSING_SESSION_ID).toBe(4003);
        expect(CloseCode.MISSING_MACHINE_ID).toBe(4004);
        expect(CloseCode.CONNECTION_LIMIT_EXCEEDED).toBe(4005);
    });
});

describe('WebSocketMessage types', () => {
    it('should correctly type ConnectedMessage', () => {
        const msg: ConnectedMessage = {
            type: 'connected',
            payload: {
                connectionId: 'conn-123',
                userId: 'user-456',
                clientType: 'user-scoped',
            },
            timestamp: Date.now(),
        };

        expect(msg.type).toBe('connected');
        expect(msg.payload.connectionId).toBe('conn-123');
    });

    it('should correctly type broadcast messages', () => {
        const msg: WebSocketMessage = {
            type: 'broadcast',
            payload: { event: 'session-update', data: {} },
            timestamp: Date.now(),
        };

        expect(msg.type).toBe('broadcast');
    });
});

/**
 * RPC Routing Tests (HAP-296)
 *
 * Tests the RPC routing logic in ConnectionManager.handleClientMessage()
 * which was fixed to correctly route:
 * - Machine-targeted RPCs → { type: 'machine', machineId }
 * - Session-targeted RPCs → { type: 'all-interested-in-session', sessionId }
 */
describe('ConnectionManager - RPC Routing', () => {
    /**
     * Helper to access private members of ConnectionManager for testing.
     * This is necessary because the connections map and broadcastClientMessage are private.
     */
    interface ConnectionManagerTestAccess {
        connections: Map<WebSocket, ConnectionMetadata>;
        broadcastClientMessage: (message: unknown, filter?: unknown) => number;
    }

    /**
     * Creates a ConnectionManager instance with test access to private members
     */
    function createTestableConnectionManager() {
        const state = createMockState();
        const cm = new ConnectionManager(state as unknown as DurableObjectState, mockEnv);
        // Access private members for testing
        const testAccess = cm as unknown as ConnectionManagerTestAccess;
        return { cm, state, testAccess };
    }

    /**
     * Creates a mock authenticated WebSocket with attached metadata
     */
    function createAuthenticatedWebSocket(metadata: ConnectionMetadata) {
        const ws = createMockWebSocket();
        ws.serializeAttachment(metadata);
        return ws;
    }

    describe('RPC routing to machine-scoped connections', () => {
        it('should route RPC to machine-scoped connection when targetId matches machineId', async () => {
            const { cm, testAccess } = createTestableConnectionManager();

            const machineId = 'machine-abc-123';
            const userId = 'user-456';

            // Create a user-scoped WebSocket (the sender)
            const userWs = createAuthenticatedWebSocket({
                connectionId: 'conn-user-1',
                userId,
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Create a machine-scoped WebSocket (the target)
            const machineWs = createAuthenticatedWebSocket({
                connectionId: 'conn-machine-1',
                userId,
                clientType: 'machine-scoped',
                machineId,
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Register both connections in the manager
            testAccess.connections.set(userWs as unknown as WebSocket, userWs.deserializeAttachment() as ConnectionMetadata);
            testAccess.connections.set(machineWs as unknown as WebSocket, machineWs.deserializeAttachment() as ConnectionMetadata);

            // Spy on broadcastClientMessage to capture the filter used
            const broadcastSpy = vi.spyOn(testAccess, 'broadcastClientMessage');

            // Send RPC-call from user-scoped client targeting the machine
            const rpcMessage = JSON.stringify({
                event: 'rpc-call',
                data: { method: `${machineId}:getStatus`, params: {} },
                ackId: 'ack-123',
            });

            await cm.webSocketMessage(userWs as unknown as WebSocket, rpcMessage);

            // Verify broadcastClientMessage was called with machine filter
            expect(broadcastSpy).toHaveBeenCalled();
            const callArgs = broadcastSpy.mock.calls.find(
                (call) => (call[1] as { type: string })?.type === 'machine'
            );
            expect(callArgs).toBeDefined();
            expect(callArgs![1]).toEqual({
                type: 'machine',
                machineId,
            });
        });

        it('should route RPC to correct machine when multiple machines are connected', async () => {
            const { cm, testAccess } = createTestableConnectionManager();

            const machineId1 = 'machine-first';
            const machineId2 = 'machine-second';
            const userId = 'user-789';

            // Create user-scoped WebSocket (sender)
            const userWs = createAuthenticatedWebSocket({
                connectionId: 'conn-user-1',
                userId,
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Create two machine-scoped WebSockets
            const machineWs1 = createAuthenticatedWebSocket({
                connectionId: 'conn-machine-1',
                userId,
                clientType: 'machine-scoped',
                machineId: machineId1,
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            const machineWs2 = createAuthenticatedWebSocket({
                connectionId: 'conn-machine-2',
                userId,
                clientType: 'machine-scoped',
                machineId: machineId2,
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Register all connections
            testAccess.connections.set(userWs as unknown as WebSocket, userWs.deserializeAttachment() as ConnectionMetadata);
            testAccess.connections.set(machineWs1 as unknown as WebSocket, machineWs1.deserializeAttachment() as ConnectionMetadata);
            testAccess.connections.set(machineWs2 as unknown as WebSocket, machineWs2.deserializeAttachment() as ConnectionMetadata);

            // Spy on broadcastClientMessage
            const broadcastSpy = vi.spyOn(testAccess, 'broadcastClientMessage');

            // Send RPC targeting the second machine
            const rpcMessage = JSON.stringify({
                event: 'rpc-call',
                data: { method: `${machineId2}:executeCommand`, params: { cmd: 'ls' } },
                ackId: 'ack-456',
            });

            await cm.webSocketMessage(userWs as unknown as WebSocket, rpcMessage);

            // Verify it routes to machineId2, not machineId1
            const machineFilterCall = broadcastSpy.mock.calls.find(
                (call) => (call[1] as { type: string })?.type === 'machine'
            );
            expect(machineFilterCall).toBeDefined();
            expect(machineFilterCall![1]).toEqual({
                type: 'machine',
                machineId: machineId2,
            });
        });
    });

    describe('RPC routing to session-scoped connections', () => {
        it('should route RPC to session when targetId does not match any machineId', async () => {
            const { cm, testAccess } = createTestableConnectionManager();

            const sessionId = 'session-xyz-789';
            const userId = 'user-123';

            // Create user-scoped WebSocket (sender)
            const userWs = createAuthenticatedWebSocket({
                connectionId: 'conn-user-1',
                userId,
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Create session-scoped WebSocket (target)
            const sessionWs = createAuthenticatedWebSocket({
                connectionId: 'conn-session-1',
                userId,
                clientType: 'session-scoped',
                sessionId,
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Register connections
            testAccess.connections.set(userWs as unknown as WebSocket, userWs.deserializeAttachment() as ConnectionMetadata);
            testAccess.connections.set(sessionWs as unknown as WebSocket, sessionWs.deserializeAttachment() as ConnectionMetadata);

            // Spy on broadcastClientMessage
            const broadcastSpy = vi.spyOn(testAccess, 'broadcastClientMessage');

            // Send RPC targeting the session (no machine with this ID exists)
            const rpcMessage = JSON.stringify({
                event: 'rpc-call',
                data: { method: `${sessionId}:getSessionState`, params: {} },
                ackId: 'ack-789',
            });

            await cm.webSocketMessage(userWs as unknown as WebSocket, rpcMessage);

            // Verify it routes using all-interested-in-session filter
            const sessionFilterCall = broadcastSpy.mock.calls.find(
                (call) => (call[1] as { type: string })?.type === 'all-interested-in-session'
            );
            expect(sessionFilterCall).toBeDefined();
            expect(sessionFilterCall![1]).toEqual({
                type: 'all-interested-in-session',
                sessionId,
            });
        });

        it('should route to session when machines exist but targetId does not match', async () => {
            const { cm, testAccess } = createTestableConnectionManager();

            const machineId = 'machine-different';
            const sessionId = 'session-target';
            const userId = 'user-456';

            // Create user-scoped WebSocket (sender)
            const userWs = createAuthenticatedWebSocket({
                connectionId: 'conn-user-1',
                userId,
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Create a machine-scoped connection with a DIFFERENT ID
            const machineWs = createAuthenticatedWebSocket({
                connectionId: 'conn-machine-1',
                userId,
                clientType: 'machine-scoped',
                machineId, // This is 'machine-different', not 'session-target'
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Register connections
            testAccess.connections.set(userWs as unknown as WebSocket, userWs.deserializeAttachment() as ConnectionMetadata);
            testAccess.connections.set(machineWs as unknown as WebSocket, machineWs.deserializeAttachment() as ConnectionMetadata);

            // Spy on broadcastClientMessage
            const broadcastSpy = vi.spyOn(testAccess, 'broadcastClientMessage');

            // Send RPC targeting 'session-target' - should NOT match the machine
            const rpcMessage = JSON.stringify({
                event: 'rpc-call',
                data: { method: `${sessionId}:getData`, params: {} },
                ackId: 'ack-abc',
            });

            await cm.webSocketMessage(userWs as unknown as WebSocket, rpcMessage);

            // Verify it routes as session, not machine
            const sessionFilterCall = broadcastSpy.mock.calls.find(
                (call) => (call[1] as { type: string })?.type === 'all-interested-in-session'
            );
            expect(sessionFilterCall).toBeDefined();
            expect(sessionFilterCall![1]).toEqual({
                type: 'all-interested-in-session',
                sessionId,
            });

            // Verify it did NOT use machine filter
            const machineFilterCall = broadcastSpy.mock.calls.find(
                (call) => (call[1] as { type: string })?.type === 'machine'
            );
            expect(machineFilterCall).toBeUndefined();
        });
    });

    describe('RPC routing edge cases', () => {
        it('should handle RPC with no matching connections gracefully', async () => {
            const { cm, testAccess } = createTestableConnectionManager();

            const userId = 'user-lonely';
            const nonExistentTargetId = 'no-one-here';

            // Create only a user-scoped WebSocket (sender)
            const userWs = createAuthenticatedWebSocket({
                connectionId: 'conn-user-1',
                userId,
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Register only the sender
            testAccess.connections.set(userWs as unknown as WebSocket, userWs.deserializeAttachment() as ConnectionMetadata);

            // Spy on broadcastClientMessage
            const broadcastSpy = vi.spyOn(testAccess, 'broadcastClientMessage');

            // Send RPC targeting non-existent ID
            const rpcMessage = JSON.stringify({
                event: 'rpc-call',
                data: { method: `${nonExistentTargetId}:someMethod`, params: {} },
                ackId: 'ack-lonely',
            });

            // Should not throw
            await expect(
                cm.webSocketMessage(userWs as unknown as WebSocket, rpcMessage)
            ).resolves.not.toThrow();

            // Should still broadcast (to session filter since no machine matches)
            const sessionFilterCall = broadcastSpy.mock.calls.find(
                (call) => (call[1] as { type: string })?.type === 'all-interested-in-session'
            );
            expect(sessionFilterCall).toBeDefined();
            expect(sessionFilterCall![1]).toEqual({
                type: 'all-interested-in-session',
                sessionId: nonExistentTargetId,
            });
        });

        it('should route to user-scoped connections when RPC comes from machine', async () => {
            const { cm, testAccess } = createTestableConnectionManager();

            const machineId = 'machine-sender';
            const userId = 'user-789';

            // Create machine-scoped WebSocket (sender)
            const machineWs = createAuthenticatedWebSocket({
                connectionId: 'conn-machine-1',
                userId,
                clientType: 'machine-scoped',
                machineId,
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Create user-scoped WebSocket (target for machine RPCs)
            const userWs = createAuthenticatedWebSocket({
                connectionId: 'conn-user-1',
                userId,
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Register connections
            testAccess.connections.set(machineWs as unknown as WebSocket, machineWs.deserializeAttachment() as ConnectionMetadata);
            testAccess.connections.set(userWs as unknown as WebSocket, userWs.deserializeAttachment() as ConnectionMetadata);

            // Spy on broadcastClientMessage
            const broadcastSpy = vi.spyOn(testAccess, 'broadcastClientMessage');

            // Send RPC from machine-scoped client
            const rpcMessage = JSON.stringify({
                event: 'rpc-call',
                data: { method: 'someMethod', params: { result: 'data' } },
                ackId: 'ack-machine',
            });

            await cm.webSocketMessage(machineWs as unknown as WebSocket, rpcMessage);

            // When RPC comes from non-user-scoped, it should go to user-scoped-only
            const userScopedFilterCall = broadcastSpy.mock.calls.find(
                (call) => (call[1] as { type: string })?.type === 'user-scoped-only'
            );
            expect(userScopedFilterCall).toBeDefined();
            expect(userScopedFilterCall![1]).toEqual({
                type: 'user-scoped-only',
            });
        });

        it('should handle rpc-request type the same as rpc-call', async () => {
            const { cm, testAccess } = createTestableConnectionManager();

            const machineId = 'machine-for-request';
            const userId = 'user-request';

            // Create user-scoped WebSocket (sender)
            const userWs = createAuthenticatedWebSocket({
                connectionId: 'conn-user-1',
                userId,
                clientType: 'user-scoped',
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Create machine-scoped WebSocket (target)
            const machineWs = createAuthenticatedWebSocket({
                connectionId: 'conn-machine-1',
                userId,
                clientType: 'machine-scoped',
                machineId,
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
                authState: 'legacy',
            });

            // Register connections
            testAccess.connections.set(userWs as unknown as WebSocket, userWs.deserializeAttachment() as ConnectionMetadata);
            testAccess.connections.set(machineWs as unknown as WebSocket, machineWs.deserializeAttachment() as ConnectionMetadata);

            // Spy on broadcastClientMessage
            const broadcastSpy = vi.spyOn(testAccess, 'broadcastClientMessage');

            // Send rpc-request (alternative event name) targeting the machine
            const rpcMessage = JSON.stringify({
                event: 'rpc-request', // Using rpc-request instead of rpc-call
                data: { method: `${machineId}:getInfo`, params: {} },
                ackId: 'ack-request',
            });

            await cm.webSocketMessage(userWs as unknown as WebSocket, rpcMessage);

            // Should route to machine just like rpc-call
            const machineFilterCall = broadcastSpy.mock.calls.find(
                (call) => (call[1] as { type: string })?.type === 'machine'
            );
            expect(machineFilterCall).toBeDefined();
            expect(machineFilterCall![1]).toEqual({
                type: 'machine',
                machineId,
            });
        });
    });
});
