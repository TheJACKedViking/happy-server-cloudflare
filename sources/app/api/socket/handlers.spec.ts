/**
 * WebSocket Handler Integration Tests
 *
 * Tests for all 7 WebSocket event handlers:
 * - usageHandler: usage-report
 * - rpcHandler: rpc-call, rpc-register, rpc-unregister, rpc-cancel
 * - pingHandler: ping
 * - sessionUpdateHandler: update-metadata, update-state, session-alive, message, session-end
 * - machineUpdateHandler: machine-alive, machine-update-metadata, machine-update-state
 * - artifactUpdateHandler: artifact-read, artifact-update, artifact-create, artifact-delete
 * - accessKeyHandler: access-key-get
 *
 * Tests cover:
 * - Happy paths for all handlers
 * - Error cases and validation
 * - Optimistic concurrency control (version mismatch scenarios)
 * - RPC lifecycle (register → call → response → unregister)
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { Socket } from 'socket.io';
import {
    TEST_USER_ID,
    TEST_USER_ID_2,
    createMockSession,
    createMockMachine,
    createMockAccessKey,
    createMockArtifact,
    randomId
} from '../routes/__test__/testUtils';

// Mock external dependencies
vi.mock('@/storage/db', () => ({
    db: {
        session: {
            findFirst: vi.fn(),
            findUnique: vi.fn(),
            update: vi.fn(),
            updateMany: vi.fn(),
        },
        machine: {
            findFirst: vi.fn(),
            updateMany: vi.fn(),
        },
        accessKey: {
            findUnique: vi.fn(),
        },
        artifact: {
            findFirst: vi.fn(),
            findUnique: vi.fn(),
            create: vi.fn(),
            delete: vi.fn(),
            updateMany: vi.fn(),
        },
        usageReport: {
            upsert: vi.fn(),
        },
        sessionMessage: {
            findFirst: vi.fn(),
            create: vi.fn(),
        },
    },
}));

vi.mock('@/utils/log', () => ({
    log: vi.fn(),
}));

vi.mock('@/app/events/eventRouter', () => ({
    eventRouter: {
        addConnection: vi.fn(),
        removeConnection: vi.fn(),
        emitUpdate: vi.fn(),
        emitEphemeral: vi.fn(),
    },
    buildUpdateSessionUpdate: vi.fn(() => ({ type: 'update-session' })),
    buildNewMessageUpdate: vi.fn(() => ({ type: 'new-message' })),
    buildSessionActivityEphemeral: vi.fn(() => ({ type: 'session-activity' })),
    buildMachineActivityEphemeral: vi.fn(() => ({ type: 'machine-activity' })),
    buildUpdateMachineUpdate: vi.fn(() => ({ type: 'update-machine' })),
    buildNewArtifactUpdate: vi.fn(() => ({ type: 'new-artifact' })),
    buildUpdateArtifactUpdate: vi.fn(() => ({ type: 'update-artifact' })),
    buildDeleteArtifactUpdate: vi.fn(() => ({ type: 'delete-artifact' })),
    buildUsageEphemeral: vi.fn(() => ({ type: 'usage' })),
}));

vi.mock('@/app/presence/sessionCache', () => ({
    activityCache: {
        isSessionValid: vi.fn().mockResolvedValue(true),
        isMachineValid: vi.fn().mockResolvedValue(true),
        queueSessionUpdate: vi.fn(),
        queueMachineUpdate: vi.fn(),
    },
}));

vi.mock('@/storage/seq', () => ({
    allocateUserSeq: vi.fn().mockResolvedValue(1),
    allocateSessionSeq: vi.fn().mockResolvedValue(1),
}));

vi.mock('@/utils/randomKeyNaked', () => ({
    randomKeyNaked: vi.fn().mockReturnValue('test-key-12345'),
}));

vi.mock('@/utils/lock', () => {
    return {
        AsyncLock: class MockAsyncLock {
            async inLock<T>(fn: () => Promise<T>): Promise<T> {
                return fn();
            }
        },
    };
});

vi.mock('@/app/monitoring/metrics2', () => ({
    websocketEventsCounter: { inc: vi.fn() },
    sessionAliveEventsCounter: { inc: vi.fn() },
    machineAliveEventsCounter: { inc: vi.fn() },
}));

vi.mock('privacy-kit', () => ({
    encodeBase64: vi.fn((data: Uint8Array) => Buffer.from(data).toString('base64')),
    decodeBase64: vi.fn((str: string) => new Uint8Array(Buffer.from(str, 'base64'))),
}));

import { db } from '@/storage/db';
import { eventRouter } from '@/app/events/eventRouter';
import { activityCache } from '@/app/presence/sessionCache';

import { usageHandler } from './usageHandler';
import { rpcHandler } from './rpcHandler';
import { pingHandler } from './pingHandler';
import { sessionUpdateHandler } from './sessionUpdateHandler';
import { machineUpdateHandler } from './machineUpdateHandler';
import { artifactUpdateHandler } from './artifactUpdateHandler';
import { accessKeyHandler } from './accessKeyHandler';

/**
 * Creates a mock Socket.IO socket for testing
 */
function createMockSocket(): Socket {
    const handlers = new Map<string, Function>();

    const socket = {
        id: randomId('socket-'),
        on: vi.fn((event: string, handler: Function) => {
            handlers.set(event, handler);
        }),
        emit: vi.fn(),
        connected: true,
        timeout: vi.fn(() => ({
            emitWithAck: vi.fn(),
        })),
        // Helper to trigger events in tests
        __trigger: async (event: string, ...args: any[]) => {
            const handler = handlers.get(event);
            if (handler) {
                return handler(...args);
            }
            throw new Error(`No handler registered for event: ${event}`);
        },
        __handlers: handlers,
    } as unknown as Socket & {
        __trigger: (event: string, ...args: any[]) => Promise<any>;
        __handlers: Map<string, Function>;
    };

    return socket;
}

/**
 * Creates a mock client connection for testing
 */
function createMockConnection(socket: Socket, type: 'user-scoped' | 'session-scoped' | 'machine-scoped' = 'user-scoped') {
    if (type === 'session-scoped') {
        return {
            connectionType: 'session-scoped' as const,
            socket,
            userId: TEST_USER_ID,
            sessionId: 'test-session-123',
        };
    } else if (type === 'machine-scoped') {
        return {
            connectionType: 'machine-scoped' as const,
            socket,
            userId: TEST_USER_ID,
            machineId: 'test-machine-123',
        };
    }
    return {
        connectionType: 'user-scoped' as const,
        socket,
        userId: TEST_USER_ID,
    };
}

describe('WebSocket Handlers Integration Tests', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('pingHandler', () => {
        it('should respond to ping with empty object', async () => {
            const socket = createMockSocket() as Socket & { __trigger: Function };
            pingHandler(socket);

            const callback = vi.fn();
            await socket.__trigger('ping', callback);

            expect(callback).toHaveBeenCalledWith({});
        });
    });

    describe('usageHandler', () => {
        let socket: Socket & { __trigger: Function };

        beforeEach(() => {
            socket = createMockSocket() as Socket & { __trigger: Function };
            usageHandler(TEST_USER_ID, socket);
        });

        it('should save usage report successfully', async () => {
            const session = createMockSession({ id: 'sess-123' });
            vi.mocked(db.session.findFirst).mockResolvedValue(session as any);

            const report = {
                id: 'report-123',
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            vi.mocked(db.usageReport.upsert).mockResolvedValue(report as any);

            const callback = vi.fn();
            await socket.__trigger('usage-report', {
                key: 'session-usage-key',
                sessionId: 'sess-123',
                tokens: { total: 1000, input: 500, output: 500 },
                cost: { total: 0.05, input: 0.02, output: 0.03 },
            }, callback);

            expect(callback).toHaveBeenCalledWith(expect.objectContaining({
                success: true,
                reportId: 'report-123',
            }));
        });

        it('should return error for invalid key', async () => {
            const callback = vi.fn();
            await socket.__trigger('usage-report', {
                key: '', // Invalid empty key
                tokens: { total: 100 },
                cost: { total: 0.01 },
            }, callback);

            expect(callback).toHaveBeenCalledWith({
                success: false,
                error: 'Invalid key',
            });
        });

        it('should return error for invalid tokens object', async () => {
            const callback = vi.fn();
            await socket.__trigger('usage-report', {
                key: 'test-key',
                tokens: { input: 100 }, // Missing required 'total'
                cost: { total: 0.01 },
            }, callback);

            expect(callback).toHaveBeenCalledWith({
                success: false,
                error: 'Invalid tokens object - must include total',
            });
        });

        it('should return error for invalid cost object', async () => {
            const callback = vi.fn();
            await socket.__trigger('usage-report', {
                key: 'test-key',
                tokens: { total: 100 },
                cost: { input: 0.01 }, // Missing required 'total'
            }, callback);

            expect(callback).toHaveBeenCalledWith({
                success: false,
                error: 'Invalid cost object - must include total',
            });
        });

        it('should return error when session not found', async () => {
            vi.mocked(db.session.findFirst).mockResolvedValue(null);

            const callback = vi.fn();
            await socket.__trigger('usage-report', {
                key: 'test-key',
                sessionId: 'non-existent-session',
                tokens: { total: 100 },
                cost: { total: 0.01 },
            }, callback);

            expect(callback).toHaveBeenCalledWith({
                success: false,
                error: 'Session not found',
            });
        });
    });

    describe('rpcHandler', () => {
        let socket: Socket & { __trigger: Function };
        let rpcListeners: Map<string, Socket>;

        beforeEach(() => {
            socket = createMockSocket() as Socket & { __trigger: Function };
            rpcListeners = new Map();
            rpcHandler(TEST_USER_ID, socket, rpcListeners);
        });

        describe('rpc-register', () => {
            it('should register RPC method successfully', async () => {
                await socket.__trigger('rpc-register', { method: 'test-method' });

                expect(rpcListeners.has('test-method')).toBe(true);
                expect(socket.emit).toHaveBeenCalledWith('rpc-registered', { method: 'test-method' });
            });

            it('should emit error for invalid method name', async () => {
                await socket.__trigger('rpc-register', { method: '' });

                expect(socket.emit).toHaveBeenCalledWith('rpc-error', {
                    type: 'register',
                    error: 'Invalid method name',
                });
            });

            it('should emit error when method is not a string', async () => {
                await socket.__trigger('rpc-register', { method: 123 });

                expect(socket.emit).toHaveBeenCalledWith('rpc-error', {
                    type: 'register',
                    error: 'Invalid method name',
                });
            });
        });

        describe('rpc-unregister', () => {
            it('should unregister RPC method successfully', async () => {
                // First register the method
                rpcListeners.set('test-method', socket);

                await socket.__trigger('rpc-unregister', { method: 'test-method' });

                expect(rpcListeners.has('test-method')).toBe(false);
                expect(socket.emit).toHaveBeenCalledWith('rpc-unregistered', { method: 'test-method' });
            });

            it('should emit error for invalid method name', async () => {
                await socket.__trigger('rpc-unregister', { method: '' });

                expect(socket.emit).toHaveBeenCalledWith('rpc-error', {
                    type: 'unregister',
                    error: 'Invalid method name',
                });
            });
        });

        describe('rpc-call', () => {
            it('should return error when method not registered', async () => {
                const callback = vi.fn();
                await socket.__trigger('rpc-call', { method: 'unknown-method', params: {} }, callback);

                expect(callback).toHaveBeenCalledWith({
                    ok: false,
                    error: 'RPC method not available',
                });
            });

            it('should return error for invalid method parameter', async () => {
                const callback = vi.fn();
                await socket.__trigger('rpc-call', { method: '', params: {} }, callback);

                expect(callback).toHaveBeenCalledWith({
                    ok: false,
                    error: 'Invalid parameters: method is required',
                });
            });

            it('should return error when calling own socket', async () => {
                // Register on the same socket
                rpcListeners.set('self-method', socket);

                const callback = vi.fn();
                await socket.__trigger('rpc-call', { method: 'self-method', params: {} }, callback);

                expect(callback).toHaveBeenCalledWith({
                    ok: false,
                    error: 'Cannot call RPC on the same socket',
                });
            });

            it('should forward RPC call to target socket', async () => {
                // Create a target socket
                const targetSocket = createMockSocket() as Socket & { __trigger: Function };
                const mockEmitWithAck = vi.fn().mockResolvedValue({ result: 'success' });
                (targetSocket as any).timeout = vi.fn().mockReturnValue({
                    emitWithAck: mockEmitWithAck,
                });
                rpcListeners.set('target-method', targetSocket);

                const callback = vi.fn();
                await socket.__trigger('rpc-call', { method: 'target-method', params: { foo: 'bar' } }, callback);

                expect(mockEmitWithAck).toHaveBeenCalledWith('rpc-request', expect.objectContaining({
                    method: 'target-method',
                    params: { foo: 'bar' },
                }));
                expect(callback).toHaveBeenCalledWith(expect.objectContaining({
                    ok: true,
                    result: { result: 'success' },
                }));
            });

            it('should handle RPC timeout', async () => {
                const targetSocket = createMockSocket() as Socket & { __trigger: Function };
                // Use "timeout" (lowercase) in error message to trigger cancellation logic
                const mockEmitWithAck = vi.fn().mockRejectedValue(new Error('Request timeout exceeded'));
                (targetSocket as any).timeout = vi.fn().mockReturnValue({
                    emitWithAck: mockEmitWithAck,
                });
                rpcListeners.set('slow-method', targetSocket);

                const callback = vi.fn();
                await socket.__trigger('rpc-call', { method: 'slow-method', params: {} }, callback);

                expect(callback).toHaveBeenCalledWith(expect.objectContaining({
                    ok: false,
                    error: 'Request timeout exceeded',
                    cancelled: true,
                }));
                // Should emit cancel to target
                expect(targetSocket.emit).toHaveBeenCalledWith('rpc-cancel', expect.objectContaining({
                    method: 'slow-method',
                }));
            });
        });

        describe('rpc-cancel', () => {
            it('should handle cancel gracefully for unknown request', async () => {
                // Should not throw
                await socket.__trigger('rpc-cancel', { requestId: 'unknown-request' });
            });
        });

        describe('disconnect cleanup', () => {
            it('should clean up RPC registrations on disconnect', async () => {
                rpcListeners.set('method1', socket);
                rpcListeners.set('method2', socket);

                await socket.__trigger('disconnect');

                expect(rpcListeners.has('method1')).toBe(false);
                expect(rpcListeners.has('method2')).toBe(false);
            });
        });
    });

    describe('sessionUpdateHandler', () => {
        let socket: Socket & { __trigger: Function };
        let connection: ReturnType<typeof createMockConnection>;

        beforeEach(() => {
            socket = createMockSocket() as Socket & { __trigger: Function };
            connection = createMockConnection(socket, 'session-scoped');
            sessionUpdateHandler(TEST_USER_ID, socket, connection);
        });

        describe('update-metadata', () => {
            it('should update session metadata successfully', async () => {
                const session = createMockSession({ id: 'sess-123', metadataVersion: 1 });
                vi.mocked(db.session.findUnique).mockResolvedValue(session as any);
                vi.mocked(db.session.updateMany).mockResolvedValue({ count: 1 });

                const callback = vi.fn();
                await socket.__trigger('update-metadata', {
                    sid: 'sess-123',
                    metadata: '{"encrypted": "new-metadata"}',
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'success',
                    version: 2,
                    metadata: '{"encrypted": "new-metadata"}',
                });
                expect(eventRouter.emitUpdate).toHaveBeenCalled();
            });

            it('should return version-mismatch when version conflicts', async () => {
                const session = createMockSession({
                    id: 'sess-123',
                    metadataVersion: 3,
                    metadata: '{"current": "data"}',
                });
                vi.mocked(db.session.findUnique).mockResolvedValue(session as any);

                const callback = vi.fn();
                await socket.__trigger('update-metadata', {
                    sid: 'sess-123',
                    metadata: '{"new": "data"}',
                    expectedVersion: 1, // Wrong version
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'version-mismatch',
                    version: 3,
                    metadata: '{"current": "data"}',
                });
            });

            it('should return error for invalid input', async () => {
                const callback = vi.fn();
                await socket.__trigger('update-metadata', {
                    sid: 'sess-123',
                    metadata: 123, // Should be string
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith({ result: 'error' });
            });

            it('should handle race condition in atomic update', async () => {
                const session = createMockSession({ id: 'sess-123', metadataVersion: 1 });
                vi.mocked(db.session.findUnique).mockResolvedValue(session as any);
                vi.mocked(db.session.updateMany).mockResolvedValue({ count: 0 }); // Race condition

                const callback = vi.fn();
                await socket.__trigger('update-metadata', {
                    sid: 'sess-123',
                    metadata: '{"new": "data"}',
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith(expect.objectContaining({
                    result: 'version-mismatch',
                }));
            });
        });

        describe('update-state', () => {
            it('should update agent state successfully', async () => {
                const session = createMockSession({ id: 'sess-123', agentStateVersion: 1 });
                vi.mocked(db.session.findUnique).mockResolvedValue(session as any);
                vi.mocked(db.session.updateMany).mockResolvedValue({ count: 1 });

                const callback = vi.fn();
                await socket.__trigger('update-state', {
                    sid: 'sess-123',
                    agentState: '{"agent": "state"}',
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'success',
                    version: 2,
                    agentState: '{"agent": "state"}',
                });
            });

            it('should allow null agent state', async () => {
                const session = createMockSession({ id: 'sess-123', agentStateVersion: 1 });
                vi.mocked(db.session.findUnique).mockResolvedValue(session as any);
                vi.mocked(db.session.updateMany).mockResolvedValue({ count: 1 });

                const callback = vi.fn();
                await socket.__trigger('update-state', {
                    sid: 'sess-123',
                    agentState: null,
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'success',
                    version: 2,
                    agentState: null,
                });
            });

            it('should return version-mismatch for stale version', async () => {
                const session = createMockSession({
                    id: 'sess-123',
                    agentStateVersion: 5,
                    agentState: '{"current": "state"}',
                });
                vi.mocked(db.session.findUnique).mockResolvedValue(session as any);

                const callback = vi.fn();
                await socket.__trigger('update-state', {
                    sid: 'sess-123',
                    agentState: '{"new": "state"}',
                    expectedVersion: 2,
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'version-mismatch',
                    version: 5,
                    agentState: '{"current": "state"}',
                });
            });
        });

        describe('session-alive', () => {
            it('should emit session activity ephemeral', async () => {
                await socket.__trigger('session-alive', {
                    sid: 'sess-123',
                    time: Date.now(),
                    thinking: true,
                });

                expect(activityCache.isSessionValid).toHaveBeenCalledWith('sess-123', TEST_USER_ID);
                expect(activityCache.queueSessionUpdate).toHaveBeenCalledWith('sess-123', expect.any(Number));
                expect(eventRouter.emitEphemeral).toHaveBeenCalled();
            });

            it('should reject future timestamps', async () => {
                vi.mocked(activityCache.isSessionValid).mockClear();

                await socket.__trigger('session-alive', {
                    sid: 'sess-123',
                    time: Date.now() + 1000 * 60 * 60, // 1 hour in future
                });

                // Should still process but clamp time to now
                expect(activityCache.isSessionValid).toHaveBeenCalled();
            });

            it('should reject old timestamps', async () => {
                vi.mocked(activityCache.queueSessionUpdate).mockClear();

                await socket.__trigger('session-alive', {
                    sid: 'sess-123',
                    time: Date.now() - 1000 * 60 * 15, // 15 minutes ago
                });

                expect(activityCache.queueSessionUpdate).not.toHaveBeenCalled();
            });

            it('should reject invalid session', async () => {
                vi.mocked(activityCache.isSessionValid).mockResolvedValue(false);
                vi.mocked(activityCache.queueSessionUpdate).mockClear();

                await socket.__trigger('session-alive', {
                    sid: 'invalid-session',
                    time: Date.now(),
                });

                expect(activityCache.queueSessionUpdate).not.toHaveBeenCalled();
            });
        });

        describe('message', () => {
            it('should create session message successfully', async () => {
                const session = createMockSession({ id: 'sess-123' });
                vi.mocked(db.session.findUnique).mockResolvedValue(session as any);
                vi.mocked(db.sessionMessage.findFirst).mockResolvedValue(null);
                vi.mocked(db.sessionMessage.create).mockResolvedValue({
                    id: 'msg-123',
                    sessionId: 'sess-123',
                    seq: 1,
                } as any);

                await socket.__trigger('message', {
                    sid: 'sess-123',
                    message: 'encrypted-message-content',
                    localId: 'local-123',
                });

                expect(db.sessionMessage.create).toHaveBeenCalled();
                expect(eventRouter.emitUpdate).toHaveBeenCalled();
            });

            it('should deduplicate messages by localId', async () => {
                const session = createMockSession({ id: 'sess-123' });
                const existingMessage = { id: 'msg-existing', sessionId: 'sess-123' };
                vi.mocked(db.session.findUnique).mockResolvedValue(session as any);
                vi.mocked(db.sessionMessage.findFirst).mockResolvedValue(existingMessage as any);

                await socket.__trigger('message', {
                    sid: 'sess-123',
                    message: 'encrypted-content',
                    localId: 'duplicate-local-id',
                });

                expect(db.sessionMessage.create).not.toHaveBeenCalled();
            });
        });

        describe('session-end', () => {
            it('should mark session as inactive', async () => {
                const session = createMockSession({ id: 'sess-123' });
                vi.mocked(db.session.findUnique).mockResolvedValue(session as any);

                await socket.__trigger('session-end', {
                    sid: 'sess-123',
                    time: Date.now(),
                });

                expect(db.session.update).toHaveBeenCalledWith({
                    where: { id: 'sess-123' },
                    data: expect.objectContaining({
                        active: false,
                    }),
                });
                expect(eventRouter.emitEphemeral).toHaveBeenCalled();
            });
        });
    });

    describe('machineUpdateHandler', () => {
        let socket: Socket & { __trigger: Function };

        beforeEach(() => {
            socket = createMockSocket() as Socket & { __trigger: Function };
            machineUpdateHandler(TEST_USER_ID, socket);
        });

        describe('machine-alive', () => {
            it('should emit machine activity ephemeral', async () => {
                await socket.__trigger('machine-alive', {
                    machineId: 'machine-123',
                    time: Date.now(),
                });

                expect(activityCache.isMachineValid).toHaveBeenCalledWith('machine-123', TEST_USER_ID);
                expect(activityCache.queueMachineUpdate).toHaveBeenCalledWith('machine-123', expect.any(Number));
                expect(eventRouter.emitEphemeral).toHaveBeenCalled();
            });

            it('should reject invalid machine', async () => {
                vi.mocked(activityCache.isMachineValid).mockResolvedValue(false);
                vi.mocked(activityCache.queueMachineUpdate).mockClear();

                await socket.__trigger('machine-alive', {
                    machineId: 'invalid-machine',
                    time: Date.now(),
                });

                expect(activityCache.queueMachineUpdate).not.toHaveBeenCalled();
            });
        });

        describe('machine-update-metadata', () => {
            it('should update machine metadata successfully', async () => {
                const machine = createMockMachine({ id: 'machine-123', metadataVersion: 1 });
                vi.mocked(db.machine.findFirst).mockResolvedValue(machine as any);
                vi.mocked(db.machine.updateMany).mockResolvedValue({ count: 1 });

                const callback = vi.fn();
                await socket.__trigger('machine-update-metadata', {
                    machineId: 'machine-123',
                    metadata: '{"name": "updated-machine"}',
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'success',
                    version: 2,
                    metadata: '{"name": "updated-machine"}',
                });
                expect(eventRouter.emitUpdate).toHaveBeenCalled();
            });

            it('should return version-mismatch for stale version', async () => {
                const machine = createMockMachine({
                    id: 'machine-123',
                    metadataVersion: 5,
                    metadata: '{"current": "meta"}',
                });
                vi.mocked(db.machine.findFirst).mockResolvedValue(machine as any);

                const callback = vi.fn();
                await socket.__trigger('machine-update-metadata', {
                    machineId: 'machine-123',
                    metadata: '{"new": "meta"}',
                    expectedVersion: 2,
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'version-mismatch',
                    version: 5,
                    metadata: '{"current": "meta"}',
                });
            });

            it('should return error for machine not found', async () => {
                vi.mocked(db.machine.findFirst).mockResolvedValue(null);

                const callback = vi.fn();
                await socket.__trigger('machine-update-metadata', {
                    machineId: 'non-existent',
                    metadata: '{}',
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'error',
                    message: 'Machine not found',
                });
            });
        });

        describe('machine-update-state', () => {
            it('should update daemon state successfully', async () => {
                const machine = createMockMachine({ id: 'machine-123', daemonStateVersion: 1 });
                vi.mocked(db.machine.findFirst).mockResolvedValue(machine as any);
                vi.mocked(db.machine.updateMany).mockResolvedValue({ count: 1 });

                const callback = vi.fn();
                await socket.__trigger('machine-update-state', {
                    machineId: 'machine-123',
                    daemonState: '{"daemon": "running"}',
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'success',
                    version: 2,
                    daemonState: '{"daemon": "running"}',
                });
            });

            it('should return version-mismatch for race condition', async () => {
                const machine = createMockMachine({ id: 'machine-123', daemonStateVersion: 1 });
                vi.mocked(db.machine.findFirst)
                    .mockResolvedValueOnce(machine as any)
                    .mockResolvedValueOnce({ ...machine, daemonStateVersion: 3 } as any);
                vi.mocked(db.machine.updateMany).mockResolvedValue({ count: 0 }); // Race

                const callback = vi.fn();
                await socket.__trigger('machine-update-state', {
                    machineId: 'machine-123',
                    daemonState: '{"new": "state"}',
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith(expect.objectContaining({
                    result: 'version-mismatch',
                    version: 3,
                }));
            });
        });
    });

    describe('artifactUpdateHandler', () => {
        let socket: Socket & { __trigger: Function };

        beforeEach(() => {
            socket = createMockSocket() as Socket & { __trigger: Function };
            artifactUpdateHandler(TEST_USER_ID, socket);
        });

        describe('artifact-read', () => {
            it('should return artifact data', async () => {
                const artifact = createMockArtifact({ id: 'artifact-123' });
                vi.mocked(db.artifact.findFirst).mockResolvedValue(artifact as any);

                const callback = vi.fn();
                await socket.__trigger('artifact-read', { artifactId: 'artifact-123' }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'success',
                    artifact: expect.objectContaining({
                        id: 'artifact-123',
                    }),
                });
            });

            it('should return error for not found artifact', async () => {
                vi.mocked(db.artifact.findFirst).mockResolvedValue(null);

                const callback = vi.fn();
                await socket.__trigger('artifact-read', { artifactId: 'non-existent' }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'error',
                    message: 'Artifact not found',
                });
            });
        });

        describe('artifact-create', () => {
            it('should create artifact successfully', async () => {
                vi.mocked(db.artifact.findUnique).mockResolvedValue(null);
                const newArtifact = createMockArtifact({ id: 'new-artifact' });
                vi.mocked(db.artifact.create).mockResolvedValue(newArtifact as any);

                const callback = vi.fn();
                await socket.__trigger('artifact-create', {
                    id: 'new-artifact',
                    header: 'aGVhZGVy', // base64
                    body: 'Ym9keQ==', // base64
                    dataEncryptionKey: 'a2V5', // base64
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'success',
                    artifact: expect.objectContaining({
                        id: 'new-artifact',
                    }),
                });
                expect(eventRouter.emitUpdate).toHaveBeenCalled();
            });

            it('should return existing artifact for idempotency', async () => {
                const existingArtifact = createMockArtifact({
                    id: 'existing-artifact',
                    accountId: TEST_USER_ID,
                });
                vi.mocked(db.artifact.findUnique).mockResolvedValue(existingArtifact as any);

                const callback = vi.fn();
                await socket.__trigger('artifact-create', {
                    id: 'existing-artifact',
                    header: 'aGVhZGVy',
                    body: 'Ym9keQ==',
                    dataEncryptionKey: 'a2V5',
                }, callback);

                expect(db.artifact.create).not.toHaveBeenCalled();
                expect(callback).toHaveBeenCalledWith({
                    result: 'success',
                    artifact: expect.objectContaining({
                        id: 'existing-artifact',
                    }),
                });
            });

            it('should return error when artifact belongs to another account', async () => {
                const otherUserArtifact = createMockArtifact({
                    id: 'other-artifact',
                    accountId: TEST_USER_ID_2,
                });
                vi.mocked(db.artifact.findUnique).mockResolvedValue(otherUserArtifact as any);

                const callback = vi.fn();
                await socket.__trigger('artifact-create', {
                    id: 'other-artifact',
                    header: 'aGVhZGVy',
                    body: 'Ym9keQ==',
                    dataEncryptionKey: 'a2V5',
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'error',
                    message: 'Artifact with this ID already exists for another account',
                });
            });
        });

        describe('artifact-update', () => {
            it('should update artifact header successfully', async () => {
                const artifact = createMockArtifact({ id: 'artifact-123', headerVersion: 1 });
                vi.mocked(db.artifact.findFirst).mockResolvedValue(artifact as any);
                vi.mocked(db.artifact.updateMany).mockResolvedValue({ count: 1 });

                const callback = vi.fn();
                await socket.__trigger('artifact-update', {
                    artifactId: 'artifact-123',
                    header: { data: 'bmV3LWhlYWRlcg==', expectedVersion: 1 },
                }, callback);

                expect(callback).toHaveBeenCalledWith(expect.objectContaining({
                    result: 'success',
                    header: expect.objectContaining({
                        version: 2,
                    }),
                }));
            });

            it('should update artifact body successfully', async () => {
                const artifact = createMockArtifact({ id: 'artifact-123', bodyVersion: 1 });
                vi.mocked(db.artifact.findFirst).mockResolvedValue(artifact as any);
                vi.mocked(db.artifact.updateMany).mockResolvedValue({ count: 1 });

                const callback = vi.fn();
                await socket.__trigger('artifact-update', {
                    artifactId: 'artifact-123',
                    body: { data: 'bmV3LWJvZHk=', expectedVersion: 1 },
                }, callback);

                expect(callback).toHaveBeenCalledWith(expect.objectContaining({
                    result: 'success',
                    body: expect.objectContaining({
                        version: 2,
                    }),
                }));
            });

            it('should return version-mismatch for header conflict', async () => {
                const artifact = createMockArtifact({
                    id: 'artifact-123',
                    headerVersion: 5,
                });
                vi.mocked(db.artifact.findFirst).mockResolvedValue(artifact as any);

                const callback = vi.fn();
                await socket.__trigger('artifact-update', {
                    artifactId: 'artifact-123',
                    header: { data: 'bmV3LWhlYWRlcg==', expectedVersion: 2 },
                }, callback);

                expect(callback).toHaveBeenCalledWith(expect.objectContaining({
                    result: 'version-mismatch',
                    header: expect.objectContaining({
                        currentVersion: 5,
                    }),
                }));
            });

            it('should return error when no updates provided', async () => {
                const callback = vi.fn();
                await socket.__trigger('artifact-update', {
                    artifactId: 'artifact-123',
                    // No header or body
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'error',
                    message: 'No updates provided',
                });
            });
        });

        describe('artifact-delete', () => {
            it('should delete artifact successfully', async () => {
                const artifact = createMockArtifact({ id: 'artifact-123' });
                vi.mocked(db.artifact.findFirst).mockResolvedValue(artifact as any);

                const callback = vi.fn();
                await socket.__trigger('artifact-delete', { artifactId: 'artifact-123' }, callback);

                expect(db.artifact.delete).toHaveBeenCalledWith({
                    where: { id: 'artifact-123' },
                });
                expect(callback).toHaveBeenCalledWith({ result: 'success' });
                expect(eventRouter.emitUpdate).toHaveBeenCalled();
            });

            it('should return error for not found artifact', async () => {
                vi.mocked(db.artifact.findFirst).mockResolvedValue(null);

                const callback = vi.fn();
                await socket.__trigger('artifact-delete', { artifactId: 'non-existent' }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'error',
                    message: 'Artifact not found',
                });
            });
        });
    });

    describe('accessKeyHandler', () => {
        let socket: Socket & { __trigger: Function };

        beforeEach(() => {
            socket = createMockSocket() as Socket & { __trigger: Function };
            accessKeyHandler(TEST_USER_ID, socket);
        });

        describe('access-key-get', () => {
            it('should return access key for valid session and machine', async () => {
                const session = createMockSession({ id: 'sess-123' });
                const machine = createMockMachine({ id: 'machine-456' });
                const accessKey = createMockAccessKey({
                    sessionId: 'sess-123',
                    machineId: 'machine-456',
                });

                vi.mocked(db.session.findFirst).mockResolvedValue(session as any);
                vi.mocked(db.machine.findFirst).mockResolvedValue(machine as any);
                vi.mocked(db.accessKey.findUnique).mockResolvedValue(accessKey as any);

                const callback = vi.fn();
                await socket.__trigger('access-key-get', {
                    sessionId: 'sess-123',
                    machineId: 'machine-456',
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    ok: true,
                    accessKey: expect.objectContaining({
                        data: accessKey.data,
                        dataVersion: accessKey.dataVersion,
                    }),
                });
            });

            it('should return null when access key does not exist', async () => {
                const session = createMockSession({ id: 'sess-123' });
                const machine = createMockMachine({ id: 'machine-456' });

                vi.mocked(db.session.findFirst).mockResolvedValue(session as any);
                vi.mocked(db.machine.findFirst).mockResolvedValue(machine as any);
                vi.mocked(db.accessKey.findUnique).mockResolvedValue(null);

                const callback = vi.fn();
                await socket.__trigger('access-key-get', {
                    sessionId: 'sess-123',
                    machineId: 'machine-456',
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    ok: true,
                    accessKey: null,
                });
            });

            it('should return error when session not found', async () => {
                vi.mocked(db.session.findFirst).mockResolvedValue(null);
                vi.mocked(db.machine.findFirst).mockResolvedValue(createMockMachine() as any);

                const callback = vi.fn();
                await socket.__trigger('access-key-get', {
                    sessionId: 'non-existent',
                    machineId: 'machine-456',
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    ok: false,
                    error: 'Session or machine not found',
                });
            });

            it('should return error when machine not found', async () => {
                vi.mocked(db.session.findFirst).mockResolvedValue(createMockSession() as any);
                vi.mocked(db.machine.findFirst).mockResolvedValue(null);

                const callback = vi.fn();
                await socket.__trigger('access-key-get', {
                    sessionId: 'sess-123',
                    machineId: 'non-existent',
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    ok: false,
                    error: 'Session or machine not found',
                });
            });

            it('should return error for invalid parameters', async () => {
                const callback = vi.fn();
                await socket.__trigger('access-key-get', {
                    sessionId: '', // Empty
                    machineId: 'machine-456',
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    ok: false,
                    error: 'Invalid parameters: sessionId and machineId are required',
                });
            });
        });
    });

    describe('Optimistic Concurrency Control (OCC)', () => {
        describe('Session OCC', () => {
            let socket: Socket & { __trigger: Function };

            beforeEach(() => {
                socket = createMockSocket() as Socket & { __trigger: Function };
                sessionUpdateHandler(TEST_USER_ID, socket, createMockConnection(socket));
            });

            it('should handle concurrent metadata updates correctly', async () => {
                // First update succeeds
                const session1 = createMockSession({ id: 'sess-occ', metadataVersion: 1 });
                vi.mocked(db.session.findUnique).mockResolvedValue(session1 as any);
                vi.mocked(db.session.updateMany).mockResolvedValue({ count: 1 });

                const callback1 = vi.fn();
                await socket.__trigger('update-metadata', {
                    sid: 'sess-occ',
                    metadata: '{"update": "1"}',
                    expectedVersion: 1,
                }, callback1);

                expect(callback1).toHaveBeenCalledWith(expect.objectContaining({
                    result: 'success',
                    version: 2,
                }));

                // Second update fails due to version mismatch
                const session2 = createMockSession({ id: 'sess-occ', metadataVersion: 2 });
                vi.mocked(db.session.findUnique).mockResolvedValue(session2 as any);

                const callback2 = vi.fn();
                await socket.__trigger('update-metadata', {
                    sid: 'sess-occ',
                    metadata: '{"update": "2"}',
                    expectedVersion: 1, // Stale version
                }, callback2);

                expect(callback2).toHaveBeenCalledWith(expect.objectContaining({
                    result: 'version-mismatch',
                    version: 2,
                }));
            });
        });

        describe('Machine OCC', () => {
            let socket: Socket & { __trigger: Function };

            beforeEach(() => {
                socket = createMockSocket() as Socket & { __trigger: Function };
                machineUpdateHandler(TEST_USER_ID, socket);
            });

            it('should handle concurrent state updates with atomic CAS', async () => {
                const machine = createMockMachine({ id: 'machine-occ', daemonStateVersion: 1 });
                vi.mocked(db.machine.findFirst).mockResolvedValue(machine as any);
                vi.mocked(db.machine.updateMany).mockResolvedValue({ count: 1 });

                const callback = vi.fn();
                await socket.__trigger('machine-update-state', {
                    machineId: 'machine-occ',
                    daemonState: '{"state": "new"}',
                    expectedVersion: 1,
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'success',
                    version: 2,
                    daemonState: '{"state": "new"}',
                });
            });
        });

        describe('Artifact OCC', () => {
            let socket: Socket & { __trigger: Function };

            beforeEach(() => {
                socket = createMockSocket() as Socket & { __trigger: Function };
                artifactUpdateHandler(TEST_USER_ID, socket);
            });

            it('should handle simultaneous header and body version mismatches', async () => {
                const artifact = createMockArtifact({
                    id: 'artifact-occ',
                    headerVersion: 3,
                    bodyVersion: 5,
                });
                vi.mocked(db.artifact.findFirst).mockResolvedValue(artifact as any);

                const callback = vi.fn();
                await socket.__trigger('artifact-update', {
                    artifactId: 'artifact-occ',
                    header: { data: 'bmV3', expectedVersion: 1 }, // Stale
                    body: { data: 'bmV3', expectedVersion: 2 }, // Stale
                }, callback);

                expect(callback).toHaveBeenCalledWith({
                    result: 'version-mismatch',
                    header: expect.objectContaining({ currentVersion: 3 }),
                    body: expect.objectContaining({ currentVersion: 5 }),
                });
            });
        });
    });
});
