/**
 * Tests for WebSocket Message Handlers
 *
 * Tests all handler functions that process incoming WebSocket messages
 * and perform database operations with optimistic concurrency control.
 *
 * @module durable-objects/handlers.spec
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi } from 'vitest';
import type { HandlerContext } from './handlers';
import {
    handleSessionMetadataUpdate,
    handleSessionStateUpdate,
    handleSessionAlive,
    handleSessionEnd,
    handleSessionMessage,
    handleMachineAlive,
    handleMachineMetadataUpdate,
    handleMachineStateUpdate,
    handleArtifactRead,
    handleArtifactUpdate,
    handleArtifactCreate,
    handleArtifactDelete,
    handleAccessKeyGet,
    handleUsageReport,
} from './handlers';

// =============================================================================
// MOCK HELPERS
// =============================================================================

interface MockDbSelectResult {
    from: ReturnType<typeof vi.fn>;
}

interface MockDbUpdateResult {
    set: ReturnType<typeof vi.fn>;
}

interface MockDbInsertResult {
    values: ReturnType<typeof vi.fn>;
}

interface MockDbDeleteResult {
    where: ReturnType<typeof vi.fn>;
}

/**
 * Create a mock database client that mimics Drizzle ORM behavior
 */
function createMockDb() {
    let selectResults: unknown[] = [];
    let updateResults: unknown[] = [];
    let insertResults: unknown[] = [];
    let selectCallIndex = 0;
    let updateCallIndex = 0;
    let insertCallIndex = 0;
    const selectResultsQueue: unknown[][] = [];
    const updateResultsQueue: unknown[][] = [];
    const insertResultsQueue: unknown[][] = [];

    const mockWhere = vi.fn(() => ({
        returning: vi.fn(async () => updateResults),
    }));

    const mockSet = vi.fn(() => ({
        where: vi.fn(() => ({
            returning: vi.fn(async () => {
                if (updateResultsQueue.length > 0 && updateCallIndex < updateResultsQueue.length) {
                    return updateResultsQueue[updateCallIndex++];
                }
                return updateResults;
            }),
        })),
    }));

    const mockFrom = vi.fn(() => ({
        where: vi.fn(async () => {
            if (selectResultsQueue.length > 0 && selectCallIndex < selectResultsQueue.length) {
                return selectResultsQueue[selectCallIndex++];
            }
            return selectResults;
        }),
    }));

    const mockValues = vi.fn(() => ({
        returning: vi.fn(async () => {
            if (insertResultsQueue.length > 0 && insertCallIndex < insertResultsQueue.length) {
                return insertResultsQueue[insertCallIndex++];
            }
            return insertResults;
        }),
    }));

    const db = {
        select: vi.fn((): MockDbSelectResult => ({
            from: mockFrom,
        })),
        update: vi.fn((): MockDbUpdateResult => ({
            set: mockSet,
        })),
        insert: vi.fn((): MockDbInsertResult => ({
            values: mockValues,
        })),
        delete: vi.fn((): MockDbDeleteResult => ({
            where: mockWhere,
        })),
        // Test helpers
        _setSelectResults: (results: unknown[]) => {
            selectResults = results;
        },
        _setUpdateResults: (results: unknown[]) => {
            updateResults = results;
        },
        _setInsertResults: (results: unknown[]) => {
            insertResults = results;
        },
        // Queue-based helpers for multiple sequential calls
        _queueSelectResults: (resultsArray: unknown[][]) => {
            selectResultsQueue.length = 0;
            selectCallIndex = 0;
            resultsArray.forEach(r => selectResultsQueue.push(r));
        },
        _queueUpdateResults: (resultsArray: unknown[][]) => {
            updateResultsQueue.length = 0;
            updateCallIndex = 0;
            resultsArray.forEach(r => updateResultsQueue.push(r));
        },
        _queueInsertResults: (resultsArray: unknown[][]) => {
            insertResultsQueue.length = 0;
            insertCallIndex = 0;
            resultsArray.forEach(r => insertResultsQueue.push(r));
        },
        _mockFrom: mockFrom,
        _mockSet: mockSet,
        _mockWhere: mockWhere,
        _mockValues: mockValues,
    };

    return db;
}

/**
 * Create a basic handler context for testing
 */
function createContext(overrides: Partial<HandlerContext> = {}): HandlerContext {
    return {
        userId: 'test-user-123',
        db: createMockDb() as unknown as HandlerContext['db'],
        ...overrides,
    };
}

/**
 * Helper type to access response properties in tests
 */
type _TestResult = {
    response?: Record<string, any>;
    broadcast?: Record<string, any>;
    ephemeral?: Record<string, any>;
};

// =============================================================================
// SESSION HANDLER TESTS
// =============================================================================

describe('Session Handlers', () => {
    describe('handleSessionMetadataUpdate', () => {
        it('should return error for invalid parameters', async () => {
            const ctx = createContext();

            // Missing sid
            let result = await handleSessionMetadataUpdate(ctx, {
                sid: '',
                metadata: '{}',
                expectedVersion: 1,
            });
            expect(result.response?.result).toBe('error');

            // Invalid metadata type
            result = await handleSessionMetadataUpdate(ctx, {
                sid: 'session-1',
                metadata: 123 as unknown as string,
                expectedVersion: 1,
            });
            expect(result.response?.result).toBe('error');

            // Invalid expectedVersion type
            result = await handleSessionMetadataUpdate(ctx, {
                sid: 'session-1',
                metadata: '{}',
                expectedVersion: '1' as unknown as number,
            });
            expect(result.response?.result).toBe('error');
        });

        it('should return error if session not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionMetadataUpdate(ctx, {
                sid: 'nonexistent-session',
                metadata: '{}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('Session not found');
        });

        it('should return version-mismatch if version differs', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'session-1',
                accountId: 'test-user-123',
                metadataVersion: 5,
                metadata: '{"old":"data"}',
            }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionMetadataUpdate(ctx, {
                sid: 'session-1',
                metadata: '{"new":"data"}',
                expectedVersion: 3, // Mismatch!
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.version).toBe(5);
            expect(result.response?.metadata).toBe('{"old":"data"}');
        });

        it('should successfully update metadata', async () => {
            const mockDb = createMockDb();
            // First select returns current session
            mockDb._setSelectResults([{
                id: 'session-1',
                accountId: 'test-user-123',
                metadataVersion: 1,
                metadata: '{"old":"data"}',
            }]);
            // Update returns updated row
            mockDb._setUpdateResults([{
                id: 'session-1',
                metadataVersion: 2,
                metadata: '{"new":"data"}',
            }]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionMetadataUpdate(ctx, {
                sid: 'session-1',
                metadata: '{"new":"data"}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('success');
            expect(result.response?.version).toBe(2);
            expect(result.broadcast).toBeDefined();
            expect(result.broadcast?.message.event).toBe('update');
        });
    });

    describe('handleSessionStateUpdate', () => {
        it('should return error for invalid parameters', async () => {
            const ctx = createContext();

            // Missing sid
            let result = await handleSessionStateUpdate(ctx, {
                sid: '',
                agentState: '{}',
                expectedVersion: 1,
            });
            expect(result.response?.result).toBe('error');

            // Invalid agentState type (not string or null)
            result = await handleSessionStateUpdate(ctx, {
                sid: 'session-1',
                agentState: 123 as unknown as string,
                expectedVersion: 1,
            });
            expect(result.response?.result).toBe('error');
        });

        it('should return error if session not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionStateUpdate(ctx, {
                sid: 'nonexistent',
                agentState: '{}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('Session not found');
        });

        it('should handle null agentState', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'session-1',
                accountId: 'test-user-123',
                agentStateVersion: 1,
                agentState: '{}',
            }]);
            mockDb._setUpdateResults([{
                id: 'session-1',
                agentStateVersion: 2,
                agentState: null,
            }]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionStateUpdate(ctx, {
                sid: 'session-1',
                agentState: null,
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('success');
        });
    });

    describe('handleSessionAlive', () => {
        it('should return empty for invalid parameters', async () => {
            const ctx = createContext();

            // Missing sid
            let result = await handleSessionAlive(ctx, {
                sid: '',
                time: Date.now(),
            });
            expect(Object.keys(result)).toHaveLength(0);

            // Invalid time
            result = await handleSessionAlive(ctx, {
                sid: 'session-1',
                time: 'invalid' as unknown as number,
            });
            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should ignore timestamps older than 10 minutes', async () => {
            const mockDb = createMockDb();
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const oldTime = Date.now() - 15 * 60 * 1000; // 15 minutes ago
            const result = await handleSessionAlive(ctx, {
                sid: 'session-1',
                time: oldTime,
            });

            expect(Object.keys(result)).toHaveLength(0);
            expect(mockDb.select).not.toHaveBeenCalled();
        });

        it('should clamp future timestamps to now', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{ id: 'session-1' }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const futureTime = Date.now() + 60000; // 1 minute in future
            const result = await handleSessionAlive(ctx, {
                sid: 'session-1',
                time: futureTime,
            });

            // Should still process (clamped to now)
            expect(result.ephemeral).toBeDefined();
        });

        it('should return empty if session not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionAlive(ctx, {
                sid: 'nonexistent',
                time: Date.now(),
            });

            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should emit ephemeral event on success', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{ id: 'session-1' }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionAlive(ctx, {
                sid: 'session-1',
                time: Date.now(),
                thinking: true,
            });

            expect(result.ephemeral).toBeDefined();
            expect(result.ephemeral?.message.event).toBe('ephemeral');
            expect(result.ephemeral?.message.data.type).toBe('activity');
            expect(result.ephemeral?.message.data.thinking).toBe(true);
        });
    });

    describe('handleSessionEnd', () => {
        it('should return empty for invalid parameters', async () => {
            const ctx = createContext();

            const result = await handleSessionEnd(ctx, {
                sid: '',
                time: Date.now(),
            });
            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should ignore old timestamps', async () => {
            const mockDb = createMockDb();
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionEnd(ctx, {
                sid: 'session-1',
                time: Date.now() - 15 * 60 * 1000,
            });

            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should emit inactive ephemeral event', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{ id: 'session-1' }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionEnd(ctx, {
                sid: 'session-1',
                time: Date.now(),
            });

            expect(result.ephemeral?.message.data.active).toBe(false);
            expect(result.ephemeral?.message.data.thinking).toBe(false);
        });
    });

    describe('handleSessionMessage', () => {
        it('should return empty for invalid parameters', async () => {
            const ctx = createContext();

            let result = await handleSessionMessage(ctx, {
                sid: '',
                message: '{}',
            });
            expect(Object.keys(result)).toHaveLength(0);

            result = await handleSessionMessage(ctx, {
                sid: 'session-1',
                message: 123 as unknown as string,
            });
            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should return empty if session not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionMessage(ctx, {
                sid: 'nonexistent',
                message: '{}',
            });

            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should deduplicate by localId', async () => {
            const mockDb = createMockDb();
            // Session found
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{ id: 'session-1', seq: 0 }]),
            }));
            // Existing message with same localId
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{ id: 'existing-msg' }]),
            }));

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionMessage(ctx, {
                sid: 'session-1',
                message: '{"text":"duplicate"}',
                localId: 'local-123',
            });

            // Should return empty (idempotent)
            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should create message and broadcast', async () => {
            const mockDb = createMockDb();
            // Session found
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{ id: 'session-1', seq: 5 }]),
            }));
            // No existing message with localId (returns null)
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => []),
            }));
            // Updated session seq
            mockDb._setUpdateResults([{ seq: 6 }]);
            // Account seq update
            mockDb._mockSet.mockImplementationOnce(() => ({
                where: vi.fn(() => ({
                    returning: vi.fn(async () => [{ seq: 10 }]),
                })),
            }));

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionMessage(ctx, {
                sid: 'session-1',
                message: '{"text":"hello"}',
            });

            expect(result.broadcast).toBeDefined();
            expect(result.broadcast?.message.data.body.t).toBe('new-message');
        });
    });
});

// =============================================================================
// MACHINE HANDLER TESTS
// =============================================================================

describe('Machine Handlers', () => {
    describe('handleMachineAlive', () => {
        it('should return empty for invalid parameters', async () => {
            const ctx = createContext();

            let result = await handleMachineAlive(ctx, {
                machineId: '',
                time: Date.now(),
            });
            expect(Object.keys(result)).toHaveLength(0);

            result = await handleMachineAlive(ctx, {
                machineId: 'machine-1',
                time: 'invalid' as unknown as number,
            });
            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should ignore old timestamps', async () => {
            const mockDb = createMockDb();
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineAlive(ctx, {
                machineId: 'machine-1',
                time: Date.now() - 15 * 60 * 1000,
            });

            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should return empty if machine not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineAlive(ctx, {
                machineId: 'nonexistent',
                time: Date.now(),
            });

            expect(Object.keys(result)).toHaveLength(0);
        });

        it('should emit machine activity ephemeral', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{ id: 'machine-1' }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineAlive(ctx, {
                machineId: 'machine-1',
                time: Date.now(),
            });

            expect(result.ephemeral).toBeDefined();
            expect(result.ephemeral?.message.data.type).toBe('machine-activity');
            expect(result.ephemeral?.message.data.active).toBe(true);
        });
    });

    describe('handleMachineMetadataUpdate', () => {
        it('should return error for invalid parameters', async () => {
            const ctx = createContext();

            const result = await handleMachineMetadataUpdate(ctx, {
                machineId: '',
                metadata: '{}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('error');
        });

        it('should return error if machine not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineMetadataUpdate(ctx, {
                machineId: 'nonexistent',
                metadata: '{}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('Machine not found');
        });

        it('should return version-mismatch if version differs', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'machine-1',
                metadataVersion: 5,
                metadata: '{"old":"data"}',
            }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineMetadataUpdate(ctx, {
                machineId: 'machine-1',
                metadata: '{}',
                expectedVersion: 3,
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.version).toBe(5);
        });

        it('should successfully update and broadcast', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'machine-1',
                metadataVersion: 1,
                metadata: '{}',
            }]);
            mockDb._setUpdateResults([{ id: 'machine-1' }]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineMetadataUpdate(ctx, {
                machineId: 'machine-1',
                metadata: '{"hostname":"new-name"}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('success');
            expect(result.broadcast).toBeDefined();
        });
    });

    describe('handleMachineStateUpdate', () => {
        it('should return error for invalid parameters', async () => {
            const ctx = createContext();

            const result = await handleMachineStateUpdate(ctx, {
                machineId: '',
                daemonState: '{}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('error');
        });

        it('should return error if machine not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineStateUpdate(ctx, {
                machineId: 'nonexistent',
                daemonState: '{}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('error');
        });

        it('should return version-mismatch if version differs', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'machine-1',
                daemonStateVersion: 5,
                daemonState: '{}',
            }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineStateUpdate(ctx, {
                machineId: 'machine-1',
                daemonState: '{}',
                expectedVersion: 3,
            });

            expect(result.response?.result).toBe('version-mismatch');
        });
    });
});

// =============================================================================
// ARTIFACT HANDLER TESTS
// =============================================================================

describe('Artifact Handlers', () => {
    describe('handleArtifactRead', () => {
        it('should return error for missing artifactId', async () => {
            const ctx = createContext();

            const result = await handleArtifactRead(ctx, { artifactId: '' });

            expect(result.response?.result).toBe('error');
        });

        it('should return error if artifact not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactRead(ctx, { artifactId: 'nonexistent' });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('Artifact not found');
        });

        it('should return artifact data as base64', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'artifact-1',
                header: new Uint8Array([1, 2, 3]),
                headerVersion: 1,
                body: new Uint8Array([4, 5, 6]),
                bodyVersion: 1,
                seq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactRead(ctx, { artifactId: 'artifact-1' });

            expect(result.response?.result).toBe('success');
            expect(result.response?.artifact.id).toBe('artifact-1');
            expect(typeof result.response?.artifact.header).toBe('string');
            expect(typeof result.response?.artifact.body).toBe('string');
        });
    });

    describe('handleArtifactUpdate', () => {
        it('should return error for missing artifactId', async () => {
            const ctx = createContext();

            const result = await handleArtifactUpdate(ctx, { artifactId: '' });

            expect(result.response?.result).toBe('error');
        });

        it('should return error if no updates provided', async () => {
            const ctx = createContext();

            const result = await handleArtifactUpdate(ctx, { artifactId: 'artifact-1' });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('No updates provided');
        });

        it('should return error for invalid header parameters', async () => {
            const ctx = createContext();

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                header: { data: 123 as unknown as string, expectedVersion: 1 },
            });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('Invalid header parameters');
        });

        it('should return error for invalid body parameters', async () => {
            const ctx = createContext();

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                body: { data: 'valid', expectedVersion: '1' as unknown as number },
            });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('Invalid body parameters');
        });

        it('should return error if artifact not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'nonexistent',
                header: { data: 'base64data', expectedVersion: 1 },
            });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('Artifact not found');
        });

        it('should return version-mismatch for header version conflict', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'artifact-1',
                header: new Uint8Array([1, 2, 3]),
                headerVersion: 5,
                body: new Uint8Array([4, 5, 6]),
                bodyVersion: 1,
            }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                header: { data: 'base64data', expectedVersion: 3 },
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.header).toBeDefined();
        });

        it('should return version-mismatch for body version conflict', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'artifact-1',
                header: new Uint8Array([1, 2, 3]),
                headerVersion: 1,
                body: new Uint8Array([4, 5, 6]),
                bodyVersion: 5,
            }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                body: { data: 'base64data', expectedVersion: 3 },
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.body).toBeDefined();
        });
    });

    describe('handleArtifactCreate', () => {
        it('should return error for invalid parameters', async () => {
            const ctx = createContext();

            // Missing id
            let result = await handleArtifactCreate(ctx, {
                id: '',
                header: 'base64',
                body: 'base64',
                dataEncryptionKey: 'base64',
            });
            expect(result.response?.result).toBe('error');

            // Invalid header type
            result = await handleArtifactCreate(ctx, {
                id: 'artifact-1',
                header: 123 as unknown as string,
                body: 'base64',
                dataEncryptionKey: 'base64',
            });
            expect(result.response?.result).toBe('error');
        });

        it('should return error if artifact exists for different user', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'artifact-1',
                accountId: 'other-user', // Different user
            }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactCreate(ctx, {
                id: 'artifact-1',
                header: 'base64',
                body: 'base64',
                dataEncryptionKey: 'base64',
            });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toContain('another account');
        });

        it('should return existing artifact (idempotent) for same user', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{
                id: 'artifact-1',
                accountId: 'test-user-123', // Same user
                header: new Uint8Array([1, 2, 3]),
                headerVersion: 1,
                body: new Uint8Array([4, 5, 6]),
                bodyVersion: 1,
                seq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            }]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactCreate(ctx, {
                id: 'artifact-1',
                header: 'base64',
                body: 'base64',
                dataEncryptionKey: 'base64',
            });

            expect(result.response?.result).toBe('success');
            expect(result.response?.artifact.id).toBe('artifact-1');
        });

        it('should create new artifact', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]); // No existing
            mockDb._setInsertResults([{
                id: 'artifact-1',
                header: new Uint8Array([1, 2, 3]),
                headerVersion: 1,
                body: new Uint8Array([4, 5, 6]),
                bodyVersion: 1,
                seq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            }]);
            mockDb._setUpdateResults([{ seq: 1 }]); // Account seq update

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactCreate(ctx, {
                id: 'artifact-1',
                header: 'SGVhZGVy',
                body: 'Qm9keQ==',
                dataEncryptionKey: 'S2V5',
            });

            expect(result.response?.result).toBe('success');
            expect(result.broadcast).toBeDefined();
        });
    });

    describe('handleArtifactDelete', () => {
        it('should return error for missing artifactId', async () => {
            const ctx = createContext();

            const result = await handleArtifactDelete(ctx, { artifactId: '' });

            expect(result.response?.result).toBe('error');
        });

        it('should return error if artifact not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactDelete(ctx, { artifactId: 'nonexistent' });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('Artifact not found');
        });

        it('should delete artifact and broadcast', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([{ id: 'artifact-1' }]);
            mockDb._setUpdateResults([{ seq: 1 }]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactDelete(ctx, { artifactId: 'artifact-1' });

            expect(result.response?.result).toBe('success');
            expect(result.broadcast).toBeDefined();
            expect(result.broadcast?.message.data.body.t).toBe('delete-artifact');
        });
    });
});

// =============================================================================
// ACCESS KEY HANDLER TESTS
// =============================================================================

describe('Access Key Handlers', () => {
    describe('handleAccessKeyGet', () => {
        it('should return error for missing parameters', async () => {
            const ctx = createContext();

            let result = await handleAccessKeyGet(ctx, {
                sessionId: '',
                machineId: 'machine-1',
            });
            expect(result.response?.ok).toBe(false);

            result = await handleAccessKeyGet(ctx, {
                sessionId: 'session-1',
                machineId: '',
            });
            expect(result.response?.ok).toBe(false);
        });

        it('should return error if session or machine not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]); // Nothing found
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleAccessKeyGet(ctx, {
                sessionId: 'session-1',
                machineId: 'machine-1',
            });

            expect(result.response?.ok).toBe(false);
            expect(result.response?.error).toContain('not found');
        });

        it('should return null accessKey if not found', async () => {
            const mockDb = createMockDb();
            // Session found, machine found, but no access key
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{ id: 'session-1' }]),
            }));
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{ id: 'machine-1' }]),
            }));
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => []), // No access key
            }));

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleAccessKeyGet(ctx, {
                sessionId: 'session-1',
                machineId: 'machine-1',
            });

            expect(result.response?.ok).toBe(true);
            expect(result.response?.accessKey).toBeNull();
        });

        it('should return access key if found', async () => {
            const mockDb = createMockDb();
            const now = new Date();
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{ id: 'session-1' }]),
            }));
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{ id: 'machine-1' }]),
            }));
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{
                    data: 'encrypted-key-data',
                    dataVersion: 1,
                    createdAt: now,
                    updatedAt: now,
                }]),
            }));

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleAccessKeyGet(ctx, {
                sessionId: 'session-1',
                machineId: 'machine-1',
            });

            expect(result.response?.ok).toBe(true);
            expect(result.response?.accessKey.data).toBe('encrypted-key-data');
        });
    });
});

// =============================================================================
// USAGE HANDLER TESTS
// =============================================================================

describe('Usage Handlers', () => {
    describe('handleUsageReport', () => {
        it('should return error for missing key', async () => {
            const ctx = createContext();

            const result = await handleUsageReport(ctx, {
                key: '',
                tokens: { total: 100 },
                cost: { total: 0.01 },
            });

            expect(result.response?.success).toBe(false);
            expect(result.response?.error).toContain('Invalid key');
        });

        it('should return error for invalid tokens object', async () => {
            const ctx = createContext();

            let result = await handleUsageReport(ctx, {
                key: 'claude-3-sonnet',
                tokens: null as unknown as { total: number },
                cost: { total: 0.01 },
            });
            expect(result.response?.success).toBe(false);

            result = await handleUsageReport(ctx, {
                key: 'claude-3-sonnet',
                tokens: { notTotal: 100 } as unknown as { total: number },
                cost: { total: 0.01 },
            });
            expect(result.response?.success).toBe(false);
        });

        it('should return error for invalid cost object', async () => {
            const ctx = createContext();

            const result = await handleUsageReport(ctx, {
                key: 'claude-3-sonnet',
                tokens: { total: 100 },
                cost: { notTotal: 0.01 } as unknown as { total: number },
            });

            expect(result.response?.success).toBe(false);
        });

        it('should return error for invalid sessionId type', async () => {
            const ctx = createContext();

            const result = await handleUsageReport(ctx, {
                key: 'claude-3-sonnet',
                sessionId: 123 as unknown as string,
                tokens: { total: 100 },
                cost: { total: 0.01 },
            });

            expect(result.response?.success).toBe(false);
        });

        it('should return error if session not found', async () => {
            const mockDb = createMockDb();
            mockDb._setSelectResults([]);
            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleUsageReport(ctx, {
                key: 'claude-3-sonnet',
                sessionId: 'nonexistent',
                tokens: { total: 100 },
                cost: { total: 0.01 },
            });

            expect(result.response?.success).toBe(false);
            expect(result.response?.error).toBe('Session not found');
        });

        it('should update existing usage report', async () => {
            const mockDb = createMockDb();
            const now = new Date();
            // Session found
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{ id: 'session-1' }]),
            }));
            // Existing report found
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{
                    id: 'report-1',
                    createdAt: now,
                    updatedAt: now,
                }]),
            }));
            // Update returns updated report
            mockDb._setUpdateResults([{
                id: 'report-1',
                createdAt: now,
                updatedAt: new Date(),
            }]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleUsageReport(ctx, {
                key: 'claude-3-sonnet',
                sessionId: 'session-1',
                tokens: { total: 100, input: 80, output: 20 },
                cost: { total: 0.01 },
            });

            expect(result.response?.success).toBe(true);
            expect(result.ephemeral).toBeDefined();
            expect(result.ephemeral?.message.data.type).toBe('usage');
        });

        it('should create new usage report', async () => {
            const mockDb = createMockDb();
            const now = new Date();
            // No session check (no sessionId provided)
            // No existing report
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => []),
            }));
            // Insert returns new report
            mockDb._setInsertResults([{
                id: 'report-1',
                createdAt: now,
                updatedAt: now,
            }]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleUsageReport(ctx, {
                key: 'claude-3-sonnet',
                tokens: { total: 100 },
                cost: { total: 0.01 },
            });

            expect(result.response?.success).toBe(true);
            expect(result.response?.reportId).toBe('report-1');
            // No ephemeral since no sessionId
            expect(result.ephemeral).toBeUndefined();
        });

        it('should return error if save fails (insert returns empty)', async () => {
            const mockDb = createMockDb();
            // No existing report
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => []),
            }));
            // Insert fails - returns empty array
            mockDb._setInsertResults([]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleUsageReport(ctx, {
                key: 'claude-3-sonnet',
                tokens: { total: 100 },
                cost: { total: 0.01 },
            });

            expect(result.response?.success).toBe(false);
            expect(result.response?.error).toBe('Failed to save usage report');
        });

        it('should return error if update fails (update returns empty)', async () => {
            const mockDb = createMockDb();
            const now = new Date();
            // Existing report found
            mockDb._mockFrom.mockImplementationOnce(() => ({
                where: vi.fn(async () => [{
                    id: 'report-1',
                    createdAt: now,
                    updatedAt: now,
                }]),
            }));
            // Update fails - returns empty array (simulating failed update)
            mockDb._setUpdateResults([]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleUsageReport(ctx, {
                key: 'claude-3-sonnet',
                tokens: { total: 100 },
                cost: { total: 0.01 },
            });

            expect(result.response?.success).toBe(false);
            expect(result.response?.error).toBe('Failed to save usage report');
        });
    });
});

// =============================================================================
// ADDITIONAL COVERAGE TESTS
// =============================================================================

describe('Additional Coverage Tests', () => {
    describe('handleArtifactUpdate - Success Cases', () => {
        it('should successfully update header only', async () => {
            const mockDb = createMockDb();
            const now = new Date();
            // First select: artifact found
            mockDb._queueSelectResults([
                [{
                    id: 'artifact-1',
                    accountId: 'test-user-123',
                    header: new Uint8Array([1, 2, 3]),
                    headerVersion: 1,
                    body: new Uint8Array([4, 5, 6]),
                    bodyVersion: 1,
                    seq: 5,
                }],
            ]);
            // Update returns updated row
            mockDb._queueUpdateResults([
                [{
                    id: 'artifact-1',
                    headerVersion: 2,
                    seq: 6,
                }],
                [{ seq: 10 }], // Account seq update
            ]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                header: { data: 'bmV3LWhlYWRlcg==', expectedVersion: 1 },
            });

            expect(result.response?.result).toBe('success');
            expect(result.response?.header).toBeDefined();
            expect(result.response?.header?.version).toBe(2);
            expect(result.response?.body).toBeUndefined();
            expect(result.broadcast).toBeDefined();
            expect(result.broadcast?.message.event).toBe('update');
            expect(result.broadcast?.message.data.body.t).toBe('update-artifact');
        });

        it('should successfully update body only', async () => {
            const mockDb = createMockDb();
            // First select: artifact found
            mockDb._queueSelectResults([
                [{
                    id: 'artifact-1',
                    accountId: 'test-user-123',
                    header: new Uint8Array([1, 2, 3]),
                    headerVersion: 1,
                    body: new Uint8Array([4, 5, 6]),
                    bodyVersion: 1,
                    seq: 5,
                }],
            ]);
            // Update returns updated row
            mockDb._queueUpdateResults([
                [{
                    id: 'artifact-1',
                    bodyVersion: 2,
                    seq: 6,
                }],
                [{ seq: 10 }], // Account seq update
            ]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                body: { data: 'bmV3LWJvZHk=', expectedVersion: 1 },
            });

            expect(result.response?.result).toBe('success');
            expect(result.response?.header).toBeUndefined();
            expect(result.response?.body).toBeDefined();
            expect(result.response?.body?.version).toBe(2);
            expect(result.broadcast).toBeDefined();
        });

        it('should successfully update both header and body', async () => {
            const mockDb = createMockDb();
            // First select: artifact found
            mockDb._queueSelectResults([
                [{
                    id: 'artifact-1',
                    accountId: 'test-user-123',
                    header: new Uint8Array([1, 2, 3]),
                    headerVersion: 1,
                    body: new Uint8Array([4, 5, 6]),
                    bodyVersion: 1,
                    seq: 5,
                }],
            ]);
            // Update returns updated row
            mockDb._queueUpdateResults([
                [{
                    id: 'artifact-1',
                    headerVersion: 2,
                    bodyVersion: 2,
                    seq: 6,
                }],
                [{ seq: 10 }], // Account seq update
            ]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                header: { data: 'bmV3LWhlYWRlcg==', expectedVersion: 1 },
                body: { data: 'bmV3LWJvZHk=', expectedVersion: 1 },
            });

            expect(result.response?.result).toBe('success');
            expect(result.response?.header).toBeDefined();
            expect(result.response?.body).toBeDefined();
            expect(result.broadcast).toBeDefined();
        });

        it('should return version-mismatch on race condition during update', async () => {
            const mockDb = createMockDb();
            // First select: artifact found with matching version
            mockDb._queueSelectResults([
                [{
                    id: 'artifact-1',
                    accountId: 'test-user-123',
                    header: new Uint8Array([1, 2, 3]),
                    headerVersion: 1,
                    body: new Uint8Array([4, 5, 6]),
                    bodyVersion: 1,
                    seq: 5,
                }],
                // Re-fetch after failed update
                [{
                    id: 'artifact-1',
                    accountId: 'test-user-123',
                    header: new Uint8Array([7, 8, 9]),
                    headerVersion: 3, // Changed by another process
                    body: new Uint8Array([10, 11, 12]),
                    bodyVersion: 2,
                    seq: 7,
                }],
            ]);
            // Update returns empty (version mismatch during atomic update)
            mockDb._queueUpdateResults([[]]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                header: { data: 'bmV3LWhlYWRlcg==', expectedVersion: 1 },
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.header).toBeDefined();
            expect(result.response?.header?.currentVersion).toBe(3);
        });

        it('should return version-mismatch on race condition with body update', async () => {
            const mockDb = createMockDb();
            // First select: artifact found with matching version
            mockDb._queueSelectResults([
                [{
                    id: 'artifact-1',
                    accountId: 'test-user-123',
                    header: new Uint8Array([1, 2, 3]),
                    headerVersion: 1,
                    body: new Uint8Array([4, 5, 6]),
                    bodyVersion: 1,
                    seq: 5,
                }],
                // Re-fetch after failed update
                [{
                    id: 'artifact-1',
                    accountId: 'test-user-123',
                    header: new Uint8Array([7, 8, 9]),
                    headerVersion: 2,
                    body: new Uint8Array([10, 11, 12]),
                    bodyVersion: 5, // Changed by another process
                    seq: 7,
                }],
            ]);
            // Update returns empty (version mismatch during atomic update)
            mockDb._queueUpdateResults([[]]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                body: { data: 'bmV3LWJvZHk=', expectedVersion: 1 },
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.body).toBeDefined();
            expect(result.response?.body?.currentVersion).toBe(5);
        });

        it('should return version-mismatch for both header and body on early check', async () => {
            const mockDb = createMockDb();
            // Artifact found with both versions mismatched
            mockDb._queueSelectResults([
                [{
                    id: 'artifact-1',
                    accountId: 'test-user-123',
                    header: new Uint8Array([1, 2, 3]),
                    headerVersion: 5, // Mismatch
                    body: new Uint8Array([4, 5, 6]),
                    bodyVersion: 7, // Mismatch
                    seq: 10,
                }],
            ]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactUpdate(ctx, {
                artifactId: 'artifact-1',
                header: { data: 'bmV3LWhlYWRlcg==', expectedVersion: 1 },
                body: { data: 'bmV3LWJvZHk=', expectedVersion: 1 },
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.header).toBeDefined();
            expect(result.response?.header?.currentVersion).toBe(5);
            expect(result.response?.body).toBeDefined();
            expect(result.response?.body?.currentVersion).toBe(7);
        });
    });

    describe('handleArtifactCreate - Failure Cases', () => {
        it('should return error if insert returns empty', async () => {
            const mockDb = createMockDb();
            // No existing artifact
            mockDb._queueSelectResults([[]]);
            // Insert fails - returns empty array
            mockDb._queueInsertResults([[]]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleArtifactCreate(ctx, {
                id: 'artifact-1',
                header: 'SGVhZGVy',
                body: 'Qm9keQ==',
                dataEncryptionKey: 'S2V5',
            });

            expect(result.response?.result).toBe('error');
            expect(result.response?.message).toBe('Failed to create artifact');
        });
    });

    describe('handleSessionMetadataUpdate - Race Condition', () => {
        it('should return version-mismatch on race condition during atomic update', async () => {
            const mockDb = createMockDb();
            // First select: session found with matching version
            mockDb._queueSelectResults([
                [{
                    id: 'session-1',
                    accountId: 'test-user-123',
                    metadataVersion: 1,
                    metadata: '{"old":"data"}',
                }],
                // Re-fetch after failed update
                [{
                    id: 'session-1',
                    accountId: 'test-user-123',
                    metadataVersion: 3, // Changed by another process
                    metadata: '{"concurrent":"update"}',
                }],
            ]);
            // Update returns empty (version mismatch during atomic update)
            mockDb._queueUpdateResults([[]]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionMetadataUpdate(ctx, {
                sid: 'session-1',
                metadata: '{"new":"data"}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.version).toBe(3);
            expect(result.response?.metadata).toBe('{"concurrent":"update"}');
        });

        it('should handle missing current session on re-fetch', async () => {
            const mockDb = createMockDb();
            // First select: session found with matching version
            mockDb._queueSelectResults([
                [{
                    id: 'session-1',
                    accountId: 'test-user-123',
                    metadataVersion: 1,
                    metadata: '{"old":"data"}',
                }],
                // Re-fetch returns nothing (session deleted)
                [],
            ]);
            // Update returns empty (version mismatch or deleted)
            mockDb._queueUpdateResults([[]]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionMetadataUpdate(ctx, {
                sid: 'session-1',
                metadata: '{"new":"data"}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.version).toBe(0);
            expect(result.response?.metadata).toBeUndefined();
        });
    });

    describe('handleSessionStateUpdate - Race Condition', () => {
        it('should return version-mismatch on race condition during atomic update', async () => {
            const mockDb = createMockDb();
            // First select: session found with matching version
            mockDb._queueSelectResults([
                [{
                    id: 'session-1',
                    accountId: 'test-user-123',
                    agentStateVersion: 1,
                    agentState: '{"old":"state"}',
                }],
                // Re-fetch after failed update
                [{
                    id: 'session-1',
                    accountId: 'test-user-123',
                    agentStateVersion: 5, // Changed by another process
                    agentState: '{"concurrent":"state"}',
                }],
            ]);
            // Update returns empty (version mismatch during atomic update)
            mockDb._queueUpdateResults([[]]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleSessionStateUpdate(ctx, {
                sid: 'session-1',
                agentState: '{"new":"state"}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.version).toBe(5);
            expect(result.response?.agentState).toBe('{"concurrent":"state"}');
        });
    });

    describe('handleMachineMetadataUpdate - Race Condition', () => {
        it('should return version-mismatch on race condition during atomic update', async () => {
            const mockDb = createMockDb();
            // First select: machine found with matching version
            mockDb._queueSelectResults([
                [{
                    id: 'machine-1',
                    accountId: 'test-user-123',
                    metadataVersion: 1,
                    metadata: '{"old":"metadata"}',
                }],
                // Re-fetch after failed update
                [{
                    id: 'machine-1',
                    accountId: 'test-user-123',
                    metadataVersion: 4, // Changed by another process
                    metadata: '{"concurrent":"metadata"}',
                }],
            ]);
            // Update returns empty (version mismatch during atomic update)
            mockDb._queueUpdateResults([[]]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineMetadataUpdate(ctx, {
                machineId: 'machine-1',
                metadata: '{"new":"metadata"}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.version).toBe(4);
            expect(result.response?.metadata).toBe('{"concurrent":"metadata"}');
        });
    });

    describe('handleMachineStateUpdate - Race Condition', () => {
        it('should return version-mismatch on race condition during atomic update', async () => {
            const mockDb = createMockDb();
            // First select: machine found with matching version
            mockDb._queueSelectResults([
                [{
                    id: 'machine-1',
                    accountId: 'test-user-123',
                    daemonStateVersion: 1,
                    daemonState: '{"old":"state"}',
                }],
                // Re-fetch after failed update
                [{
                    id: 'machine-1',
                    accountId: 'test-user-123',
                    daemonStateVersion: 6, // Changed by another process
                    daemonState: '{"concurrent":"state"}',
                }],
            ]);
            // Update returns empty (version mismatch during atomic update)
            mockDb._queueUpdateResults([[]]);

            const ctx = createContext({ db: mockDb as unknown as HandlerContext['db'] });

            const result = await handleMachineStateUpdate(ctx, {
                machineId: 'machine-1',
                daemonState: '{"new":"state"}',
                expectedVersion: 1,
            });

            expect(result.response?.result).toBe('version-mismatch');
            expect(result.response?.version).toBe(6);
            expect(result.response?.daemonState).toBe('{"concurrent":"state"}');
        });
    });
});
