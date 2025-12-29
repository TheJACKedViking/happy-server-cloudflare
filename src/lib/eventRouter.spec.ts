/**
 * Tests for Event Router and Event Builder Functions
 *
 * Tests the EventRouter class and all event builder functions used for
 * broadcasting real-time updates to connected WebSocket clients.
 *
 * @module lib/eventRouter.spec
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    EventRouter,
    getEventRouter,
    buildNewSessionUpdate,
    buildNewMessageUpdate,
    buildUpdateSessionUpdate,
    buildDeleteSessionUpdate,
    buildUpdateAccountUpdate,
    buildNewMachineUpdate,
    buildUpdateMachineUpdate,
    buildNewArtifactUpdate,
    buildUpdateArtifactUpdate,
    buildDeleteArtifactUpdate,
    buildRelationshipUpdatedEvent,
    buildNewFeedPostUpdate,
    buildKVBatchUpdateUpdate,
    buildSessionActivityEphemeral,
    buildMachineActivityEphemeral,
    buildUsageEphemeral,
    buildMachineStatusEphemeral,
    bufferToBase64,
} from './eventRouter';

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function createMockDurableObjectNamespace() {
    const mockStub = {
        fetch: vi.fn().mockResolvedValue(
            new Response(JSON.stringify({ success: true, delivered: 5 }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            })
        ),
    };

    return {
        idFromName: vi.fn((name: string) => ({ toString: () => `do-id-${name}` })),
        get: vi.fn(() => mockStub),
        _mockStub: mockStub,
    };
}

// =============================================================================
// BUFFER TO BASE64 UTILITY TESTS
// =============================================================================

describe('bufferToBase64', () => {
    it('should convert empty buffer to empty base64', () => {
        const buffer = new Uint8Array([]);
        expect(bufferToBase64(buffer)).toBe('');
    });

    it('should convert simple buffer to base64', () => {
        const buffer = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
        expect(bufferToBase64(buffer)).toBe('SGVsbG8=');
    });

    it('should convert buffer with binary data', () => {
        const buffer = new Uint8Array([0, 1, 2, 255, 254, 253]);
        const result = bufferToBase64(buffer);
        expect(typeof result).toBe('string');
        expect(result.length).toBeGreaterThan(0);
    });

    it('should handle large buffers', () => {
        const buffer = new Uint8Array(1000).fill(65); // 1000 'A' characters
        const result = bufferToBase64(buffer);
        expect(result).toBeDefined();
        expect(result.length).toBeGreaterThan(1000);
    });
});

// =============================================================================
// EVENT ROUTER CLASS TESTS
// =============================================================================

describe('EventRouter', () => {
    let mockEnv: { CONNECTION_MANAGER: ReturnType<typeof createMockDurableObjectNamespace> };
    let router: EventRouter;

    beforeEach(() => {
        mockEnv = {
            CONNECTION_MANAGER: createMockDurableObjectNamespace(),
        };
        router = new EventRouter(mockEnv as unknown as { CONNECTION_MANAGER: DurableObjectNamespace });
    });

    describe('emitUpdate', () => {
        it('should broadcast update event successfully', async () => {
            const result = await router.emitUpdate({
                userId: 'user-123',
                payload: {
                    id: 'update-1',
                    seq: 1,
                    body: { t: 'new-session', id: 'session-1' },
                    createdAt: Date.now(),
                },
            });

            expect(result.success).toBe(true);
            expect(result.delivered).toBe(5);
            expect(mockEnv.CONNECTION_MANAGER.idFromName).toHaveBeenCalledWith('user-123');
            expect(mockEnv.CONNECTION_MANAGER.get).toHaveBeenCalled();
        });

        it('should include filter in broadcast request', async () => {
            await router.emitUpdate({
                userId: 'user-123',
                payload: {
                    id: 'update-1',
                    seq: 1,
                    body: { t: 'update-session', id: 'session-1' },
                    createdAt: Date.now(),
                },
                filter: { type: 'session', sessionId: 'session-1' },
            });

            const fetchCall = mockEnv.CONNECTION_MANAGER._mockStub.fetch.mock.calls[0] as any;
            const body = JSON.parse(fetchCall[1].body as string);
            expect(body.filter).toEqual({ type: 'session', sessionId: 'session-1' });
        });

        it('should handle DO error response', async () => {
            mockEnv.CONNECTION_MANAGER._mockStub.fetch.mockResolvedValueOnce(
                new Response('Internal error', { status: 500 })
            );

            const result = await router.emitUpdate({
                userId: 'user-123',
                payload: {
                    id: 'update-1',
                    seq: 1,
                    body: { t: 'new-session', id: 'session-1' },
                    createdAt: Date.now(),
                },
            });

            expect(result.success).toBe(false);
            expect(result.delivered).toBe(0);
            expect(result.error).toContain('500');
        });

        it('should handle network error', async () => {
            mockEnv.CONNECTION_MANAGER._mockStub.fetch.mockRejectedValueOnce(
                new Error('Network failure')
            );

            const result = await router.emitUpdate({
                userId: 'user-123',
                payload: {
                    id: 'update-1',
                    seq: 1,
                    body: { t: 'new-session', id: 'session-1' },
                    createdAt: Date.now(),
                },
            });

            expect(result.success).toBe(false);
            expect(result.delivered).toBe(0);
            expect(result.error).toBe('Network failure');
        });

        it('should handle non-Error thrown', async () => {
            mockEnv.CONNECTION_MANAGER._mockStub.fetch.mockRejectedValueOnce('string error');

            const result = await router.emitUpdate({
                userId: 'user-123',
                payload: {
                    id: 'update-1',
                    seq: 1,
                    body: { t: 'new-session', id: 'session-1' },
                    createdAt: Date.now(),
                },
            });

            expect(result.success).toBe(false);
            expect(result.error).toBe('Unknown error');
        });
    });

    describe('emitEphemeral', () => {
        it('should broadcast ephemeral event successfully', async () => {
            const result = await router.emitEphemeral({
                userId: 'user-123',
                payload: {
                    type: 'activity',
                    id: 'session-1',
                    active: true,
                    activeAt: Date.now(),
                },
            });

            expect(result.success).toBe(true);
            expect(result.delivered).toBe(5);
        });

        it('should include filter in ephemeral broadcast', async () => {
            await router.emitEphemeral({
                userId: 'user-123',
                payload: {
                    type: 'machine-activity',
                    id: 'machine-1',
                    active: true,
                    activeAt: Date.now(),
                },
                filter: { type: 'user-scoped-only' },
            });

            const fetchCall = mockEnv.CONNECTION_MANAGER._mockStub.fetch.mock.calls[0] as any;
            const body = JSON.parse(fetchCall[1].body as string);
            expect(body.filter).toEqual({ type: 'user-scoped-only' });
        });
    });
});

describe('getEventRouter', () => {
    it('should create EventRouter instance', () => {
        const mockEnv = {
            CONNECTION_MANAGER: createMockDurableObjectNamespace(),
        };
        const router = getEventRouter(mockEnv as unknown as { CONNECTION_MANAGER: DurableObjectNamespace });
        expect(router).toBeInstanceOf(EventRouter);
    });
});

// =============================================================================
// UPDATE EVENT BUILDER TESTS
// =============================================================================

describe('Update Event Builders', () => {
    describe('buildNewSessionUpdate', () => {
        it('should build new session update payload', () => {
            const now = new Date();
            const session = {
                id: 'session-123',
                seq: 5,
                metadata: '{"name":"Test"}',
                metadataVersion: 1,
                agentState: '{"state":"idle"}',
                agentStateVersion: 2,
                dataEncryptionKey: new Uint8Array([1, 2, 3, 4]),
                active: true,
                lastActiveAt: now,
                createdAt: now,
                updatedAt: now,
            };

            const payload = buildNewSessionUpdate(session, 10, 'update-1');

            expect(payload.id).toBe('update-1');
            expect(payload.seq).toBe(10);
            expect(payload.body.t).toBe('new-session');
            expect((payload.body as any).sid).toBe('session-123'); // HAP-654: Standardized to `sid`
            expect((payload.body as any).seq).toBe(5);
            expect((payload.body as any).metadata).toBe('{"name":"Test"}');
            expect(payload.body.active).toBe(true);
            expect(payload.body.dataEncryptionKey).toBeDefined();
            expect(typeof payload.createdAt).toBe('number');
        });

        it('should handle null dataEncryptionKey', () => {
            const now = new Date();
            const session = {
                id: 'session-123',
                seq: 0,
                metadata: '{}',
                metadataVersion: 1,
                agentState: null,
                agentStateVersion: 1,
                dataEncryptionKey: null,
                active: false,
                lastActiveAt: now,
                createdAt: now,
                updatedAt: now,
            };

            const payload = buildNewSessionUpdate(session, 1, 'update-1');
            expect(payload.body.dataEncryptionKey).toBeNull();
            expect(payload.body.agentState).toBeNull();
        });
    });

    describe('buildNewMessageUpdate', () => {
        it('should build new message update payload', () => {
            const now = new Date();
            const message = {
                id: 'msg-123',
                seq: 3,
                content: { type: 'user', text: 'Hello' },
                localId: 'local-456',
                createdAt: now,
                updatedAt: now,
            };

            const payload = buildNewMessageUpdate(message, 'session-123', 10, 'update-1');

            expect(payload.id).toBe('update-1');
            expect(payload.seq).toBe(10);
            expect(payload.body.t).toBe('new-message');
            expect(payload.body.sid).toBe('session-123');
            expect((payload.body as any).message.id).toBe('msg-123');
            expect((payload.body as any).message.seq).toBe(3);
            expect((payload.body as any).message.content).toEqual({ type: 'user', text: 'Hello' });
            expect((payload.body as any).message.localId).toBe('local-456');
        });

        it('should handle null localId', () => {
            const now = new Date();
            const message = {
                id: 'msg-123',
                seq: 1,
                content: { text: 'Test' },
                localId: null,
                createdAt: now,
                updatedAt: now,
            };

            const payload = buildNewMessageUpdate(message, 'session-1', 1, 'update-1');
            expect((payload.body as any).message.localId).toBeNull();
        });
    });

    describe('buildUpdateSessionUpdate', () => {
        it('should build update session payload with metadata', () => {
            const payload = buildUpdateSessionUpdate(
                'session-123',
                10,
                'update-1',
                { value: '{"name":"Updated"}', version: 2 }
            );

            expect(payload.body.t).toBe('update-session');
            expect((payload.body as any).sid).toBe('session-123'); // HAP-654: Standardized to `sid`
            expect(payload.body.metadata).toEqual({ value: '{"name":"Updated"}', version: 2 });
            expect(payload.body.agentState).toBeUndefined();
        });

        it('should build update session payload with agentState', () => {
            const payload = buildUpdateSessionUpdate(
                'session-123',
                10,
                'update-1',
                undefined,
                { value: '{"state":"thinking"}', version: 3 }
            );

            expect(payload.body.agentState).toEqual({ value: '{"state":"thinking"}', version: 3 });
            expect(payload.body.metadata).toBeUndefined();
        });

        it('should build update session payload with both', () => {
            const payload = buildUpdateSessionUpdate(
                'session-123',
                10,
                'update-1',
                { value: '{}', version: 1 },
                { value: '{}', version: 1 }
            );

            expect(payload.body.metadata).toBeDefined();
            expect(payload.body.agentState).toBeDefined();
        });
    });

    describe('buildDeleteSessionUpdate', () => {
        it('should build delete session payload', () => {
            const payload = buildDeleteSessionUpdate('session-123', 10, 'update-1');

            expect(payload.id).toBe('update-1');
            expect(payload.seq).toBe(10);
            expect(payload.body.t).toBe('delete-session');
            expect(payload.body.sid).toBe('session-123');
        });
    });

    describe('buildUpdateAccountUpdate', () => {
        it('should build update account payload', () => {
            const payload = buildUpdateAccountUpdate(
                'user-123',
                {
                    settings: '{"theme":"dark"}',
                    settingsVersion: 5,
                },
                10,
                'update-1'
            );

            expect(payload.body.t).toBe('update-account');
            expect(payload.body.id).toBe('user-123');
            expect(payload.body.settings).toBe('{"theme":"dark"}');
            expect(payload.body.settingsVersion).toBe(5);
        });

        it('should handle partial profile updates', () => {
            const payload = buildUpdateAccountUpdate(
                'user-123',
                { settings: null },
                1,
                'update-1'
            );

            expect(payload.body.settings).toBeNull();
        });

        it('should handle github profile', () => {
            const payload = buildUpdateAccountUpdate(
                'user-123',
                {
                    github: {
                        id: 123,
                        login: 'testuser',
                        name: 'Test User',
                        avatar_url: 'https://github.com/avatar.png',
                    },
                },
                1,
                'update-1'
            );

            expect(payload.body.github).toEqual({
                id: 123,
                login: 'testuser',
                name: 'Test User',
                avatar_url: 'https://github.com/avatar.png',
            });
        });
    });

    describe('buildNewMachineUpdate', () => {
        it('should build new machine update payload', () => {
            const now = new Date();
            const machine = {
                id: 'machine-123',
                seq: 0,
                metadata: '{"hostname":"dev-machine"}',
                metadataVersion: 1,
                daemonState: '{"status":"running"}',
                daemonStateVersion: 1,
                dataEncryptionKey: new Uint8Array([5, 6, 7, 8]),
                active: true,
                lastActiveAt: now,
                createdAt: now,
                updatedAt: now,
            };

            const payload = buildNewMachineUpdate(machine, 5, 'update-1');

            expect(payload.body.t).toBe('new-machine');
            expect(payload.body.machineId).toBe('machine-123');
            expect(payload.body.metadata).toBe('{"hostname":"dev-machine"}');
            expect(payload.body.dataEncryptionKey).toBeDefined();
        });

        it('should handle null fields', () => {
            const now = new Date();
            const machine = {
                id: 'machine-123',
                seq: 0,
                metadata: '{}',
                metadataVersion: 1,
                daemonState: null,
                daemonStateVersion: 1,
                dataEncryptionKey: null,
                active: false,
                lastActiveAt: now,
                createdAt: now,
                updatedAt: now,
            };

            const payload = buildNewMachineUpdate(machine, 1, 'update-1');
            expect(payload.body.daemonState).toBeNull();
            expect(payload.body.dataEncryptionKey).toBeNull();
        });
    });

    describe('buildUpdateMachineUpdate', () => {
        it('should build update machine payload with metadata', () => {
            const payload = buildUpdateMachineUpdate(
                'machine-123',
                10,
                'update-1',
                { value: '{"hostname":"new-name"}', version: 2 }
            );

            expect(payload.body.t).toBe('update-machine');
            expect(payload.body.machineId).toBe('machine-123');
            expect(payload.body.metadata).toEqual({ value: '{"hostname":"new-name"}', version: 2 });
        });

        it('should build update machine payload with daemonState', () => {
            const payload = buildUpdateMachineUpdate(
                'machine-123',
                10,
                'update-1',
                undefined,
                { value: '{"status":"stopped"}', version: 3 }
            );

            expect(payload.body.daemonState).toEqual({ value: '{"status":"stopped"}', version: 3 });
        });
    });

    describe('buildNewArtifactUpdate', () => {
        it('should build new artifact update payload', () => {
            const now = new Date();
            const artifact = {
                id: 'artifact-123',
                seq: 0,
                header: new Uint8Array([1, 2, 3]),
                headerVersion: 1,
                body: new Uint8Array([4, 5, 6]),
                bodyVersion: 1,
                dataEncryptionKey: new Uint8Array([7, 8, 9]),
                createdAt: now,
                updatedAt: now,
            };

            const payload = buildNewArtifactUpdate(artifact, 5, 'update-1');

            expect(payload.body.t).toBe('new-artifact');
            expect(payload.body.artifactId).toBe('artifact-123');
            expect(typeof payload.body.header).toBe('string'); // base64
            expect(typeof payload.body.body).toBe('string'); // base64
            expect(typeof payload.body.dataEncryptionKey).toBe('string'); // base64
        });
    });

    describe('buildUpdateArtifactUpdate', () => {
        it('should build update artifact payload with header', () => {
            const payload = buildUpdateArtifactUpdate(
                'artifact-123',
                10,
                'update-1',
                { value: 'bmV3LWhlYWRlcg==', version: 2 }
            );

            expect(payload.body.t).toBe('update-artifact');
            expect(payload.body.artifactId).toBe('artifact-123');
            expect(payload.body.header).toEqual({ value: 'bmV3LWhlYWRlcg==', version: 2 });
        });

        it('should build update artifact payload with body', () => {
            const payload = buildUpdateArtifactUpdate(
                'artifact-123',
                10,
                'update-1',
                undefined,
                { value: 'bmV3LWJvZHk=', version: 2 }
            );

            expect(payload.body.body).toEqual({ value: 'bmV3LWJvZHk=', version: 2 });
        });
    });

    describe('buildDeleteArtifactUpdate', () => {
        it('should build delete artifact payload', () => {
            const payload = buildDeleteArtifactUpdate('artifact-123', 10, 'update-1');

            expect(payload.body.t).toBe('delete-artifact');
            expect(payload.body.artifactId).toBe('artifact-123');
        });
    });

    describe('buildRelationshipUpdatedEvent', () => {
        it('should build relationship updated payload', () => {
            const payload = buildRelationshipUpdatedEvent(
                {
                    uid: 'user-456',
                    status: 'friend',
                    timestamp: 1234567890,
                },
                10,
                'update-1'
            );

            expect(payload.body.t).toBe('relationship-updated');
            expect(payload.body.uid).toBe('user-456');
            expect(payload.body.status).toBe('friend');
            expect(payload.body.timestamp).toBe(1234567890);
        });

        it('should handle all relationship statuses', () => {
            const statuses: Array<'none' | 'requested' | 'pending' | 'friend' | 'rejected'> = [
                'none',
                'requested',
                'pending',
                'friend',
                'rejected',
            ];

            for (const status of statuses) {
                const payload = buildRelationshipUpdatedEvent(
                    { uid: 'user-1', status, timestamp: Date.now() },
                    1,
                    'update-1'
                );
                expect(payload.body.status).toBe(status);
            }
        });
    });

    describe('buildNewFeedPostUpdate', () => {
        it('should build new feed post payload', () => {
            const payload = buildNewFeedPostUpdate(
                {
                    id: 'feed-123',
                    body: { type: 'session-created', sessionId: 'session-1' },
                    cursor: 'cursor_42',
                    createdAt: 1234567890,
                },
                10,
                'update-1'
            );

            expect(payload.body.t).toBe('new-feed-post');
            expect(payload.body.id).toBe('feed-123');
            expect(payload.body.body).toEqual({ type: 'session-created', sessionId: 'session-1' });
            expect(payload.body.cursor).toBe('cursor_42');
        });
    });

    describe('buildKVBatchUpdateUpdate', () => {
        it('should build KV batch update payload', () => {
            const changes = [
                { key: 'settings:theme', value: 'dark', version: 2 },
                { key: 'settings:lang', value: null, version: 3 },
            ];

            const payload = buildKVBatchUpdateUpdate(changes, 10, 'update-1');

            expect(payload.body.t).toBe('kv-batch-update');
            expect(payload.body.changes).toEqual(changes);
        });

        it('should handle empty changes array', () => {
            const payload = buildKVBatchUpdateUpdate([], 1, 'update-1');
            expect(payload.body.changes).toEqual([]);
        });
    });
});

// =============================================================================
// EPHEMERAL EVENT BUILDER TESTS
// =============================================================================

describe('Ephemeral Event Builders', () => {
    describe('buildSessionActivityEphemeral', () => {
        it('should build session activity payload', () => {
            const now = Date.now();
            const payload = buildSessionActivityEphemeral('session-123', true, now, true);

            expect(payload.type).toBe('activity');
            expect(payload.sid).toBe('session-123'); // HAP-654: Standardized to `sid`
            expect(payload.active).toBe(true);
            expect(payload.activeAt).toBe(now);
            expect(payload.thinking).toBe(true);
        });

        it('should default thinking to false', () => {
            const payload = buildSessionActivityEphemeral('session-123', false, Date.now());
            expect(payload.thinking).toBe(false);
        });

        it('should handle undefined thinking parameter', () => {
            const payload = buildSessionActivityEphemeral('session-123', true, Date.now(), undefined);
            expect(payload.thinking).toBe(false);
        });
    });

    describe('buildMachineActivityEphemeral', () => {
        it('should build machine activity payload', () => {
            const now = Date.now();
            const payload = buildMachineActivityEphemeral('machine-123', true, now);

            expect(payload.type).toBe('machine-activity');
            expect(payload.machineId).toBe('machine-123');
            expect(payload.active).toBe(true);
            expect(payload.activeAt).toBe(now);
        });

        it('should build inactive machine payload', () => {
            const payload = buildMachineActivityEphemeral('machine-123', false, Date.now());
            expect(payload.active).toBe(false);
        });
    });

    describe('buildUsageEphemeral', () => {
        it('should build usage ephemeral payload', () => {
            const tokens = { total: 1000, input: 800, output: 200 };
            const cost = { total: 0.05, input: 0.04, output: 0.01 };

            const payload = buildUsageEphemeral('session-123', 'claude-3-sonnet', tokens, cost);

            expect(payload.type).toBe('usage');
            expect(payload.sid).toBe('session-123'); // HAP-654: Standardized to `sid`
            expect(payload.key).toBe('claude-3-sonnet');
            expect(payload.tokens).toEqual(tokens);
            expect(payload.cost).toEqual(cost);
            expect(typeof payload.timestamp).toBe('number');
        });
    });

    describe('buildMachineStatusEphemeral', () => {
        it('should build machine online status payload', () => {
            const payload = buildMachineStatusEphemeral('machine-123', true);

            expect(payload.type).toBe('machine-status');
            expect(payload.machineId).toBe('machine-123');
            expect(payload.online).toBe(true);
            expect(typeof payload.timestamp).toBe('number');
        });

        it('should build machine offline status payload', () => {
            const payload = buildMachineStatusEphemeral('machine-123', false);
            expect(payload.online).toBe(false);
        });
    });
});
