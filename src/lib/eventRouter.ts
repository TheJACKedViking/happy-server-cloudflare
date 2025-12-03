/**
 * Event Broadcasting Infrastructure for Cloudflare Workers
 *
 * This module provides the EventRouter class and event builder functions for
 * broadcasting real-time updates to connected WebSocket clients via Durable Objects.
 *
 * Architecture:
 * - Workers call EventRouter methods to broadcast events
 * - EventRouter routes to the appropriate ConnectionManager DO by userId
 * - ConnectionManager broadcasts to connected WebSocket clients with filtering
 *
 * Event Types:
 * - **Update events**: Persistent state changes (new session, message, etc.)
 * - **Ephemeral events**: Transient status (activity, presence, online status)
 *
 * @module lib/eventRouter
 */

import type {
    MessageFilter,
    UpdatePayload,
    EphemeralPayload,
    WebSocketMessage,
    GitHubProfile,
} from '@/durable-objects/types';

// =============================================================================
// TYPES
// =============================================================================

/**
 * Environment bindings required for EventRouter
 */
export interface EventRouterEnv {
    /** Durable Object namespace for ConnectionManager */
    CONNECTION_MANAGER: DurableObjectNamespace;
}

/**
 * Result of a broadcast operation
 */
export interface BroadcastResult {
    /** Whether the broadcast was successful */
    success: boolean;
    /** Number of connections the message was delivered to */
    delivered: number;
    /** Error message if broadcast failed */
    error?: string;
}

/**
 * Account profile data for update-account events
 */
export interface AccountProfile {
    settings?: string | null;
    settingsVersion?: number;
    github?: GitHubProfile | null;
    avatar?: {
        path: string;
        hash: string;
    } | null;
}

// =============================================================================
// EVENT ROUTER CLASS
// =============================================================================

/**
 * EventRouter handles broadcasting events to WebSocket clients via Durable Objects.
 *
 * This is the Workers-side counterpart to happy-server's eventRouter.ts.
 * Instead of maintaining connections in memory (impossible in serverless),
 * it routes broadcasts to the appropriate ConnectionManager DO.
 *
 * @example
 * ```typescript
 * const router = new EventRouter(env);
 *
 * // Broadcast a new session to all user connections
 * await router.emitUpdate({
 *     userId: 'user_123',
 *     payload: buildNewSessionUpdate(session, seq, updateId),
 * });
 *
 * // Broadcast machine online status
 * await router.emitEphemeral({
 *     userId: 'user_123',
 *     payload: buildMachineStatusEphemeral('machine_456', true),
 *     filter: { type: 'user-scoped-only' },
 * });
 * ```
 */
export class EventRouter {
    constructor(private env: EventRouterEnv) {}

    /**
     * Emit an update event to connected clients.
     *
     * Update events represent persistent state changes that should be synced.
     * They include a sequence number for ordered delivery.
     *
     * @param params - Broadcast parameters
     * @returns Result with delivery count
     */
    async emitUpdate(params: {
        userId: string;
        payload: UpdatePayload;
        filter?: MessageFilter;
    }): Promise<BroadcastResult> {
        const message: WebSocketMessage<UpdatePayload> = {
            type: 'update',
            payload: params.payload,
            timestamp: Date.now(),
        };

        return this.broadcast(params.userId, message, params.filter);
    }

    /**
     * Emit an ephemeral event to connected clients.
     *
     * Ephemeral events are transient status updates (activity, presence, etc.)
     * that don't need persistence or ordering guarantees.
     *
     * @param params - Broadcast parameters
     * @returns Result with delivery count
     */
    async emitEphemeral(params: {
        userId: string;
        payload: EphemeralPayload;
        filter?: MessageFilter;
    }): Promise<BroadcastResult> {
        const message: WebSocketMessage<EphemeralPayload> = {
            type: 'ephemeral',
            payload: params.payload,
            timestamp: Date.now(),
        };

        return this.broadcast(params.userId, message, params.filter);
    }

    /**
     * Get the ConnectionManager DO stub for a user.
     *
     * Each user has their own ConnectionManager DO instance,
     * identified by their userId.
     */
    private getStub(userId: string): DurableObjectStub {
        const id = this.env.CONNECTION_MANAGER.idFromName(userId);
        return this.env.CONNECTION_MANAGER.get(id);
    }

    /**
     * Broadcast a message to connected clients via the DO.
     */
    private async broadcast(
        userId: string,
        message: WebSocketMessage,
        filter?: MessageFilter
    ): Promise<BroadcastResult> {
        try {
            const stub = this.getStub(userId);
            const response = await stub.fetch('https://internal/broadcast', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message, filter }),
            });

            if (!response.ok) {
                const text = await response.text();
                return {
                    success: false,
                    delivered: 0,
                    error: `DO returned ${response.status}: ${text}`,
                };
            }

            const result = (await response.json()) as { success: boolean; delivered: number };
            return {
                success: result.success,
                delivered: result.delivered,
            };
        } catch (error) {
            return {
                success: false,
                delivered: 0,
                error: error instanceof Error ? error.message : 'Unknown error',
            };
        }
    }
}

/**
 * Create an EventRouter instance from environment bindings.
 *
 * @param env - Environment with CONNECTION_MANAGER binding
 * @returns Configured EventRouter
 */
export function getEventRouter(env: EventRouterEnv): EventRouter {
    return new EventRouter(env);
}

// =============================================================================
// UPDATE EVENT BUILDERS
// =============================================================================

/**
 * Build a 'new-session' update payload.
 *
 * Sent when a new Claude Code session is created.
 */
export function buildNewSessionUpdate(
    session: {
        id: string;
        seq: number;
        metadata: string;
        metadataVersion: number;
        agentState: string | null;
        agentStateVersion: number;
        dataEncryptionKey: Uint8Array | null;
        active: boolean;
        lastActiveAt: Date;
        createdAt: Date;
        updatedAt: Date;
    },
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'new-session',
            id: session.id,
            seq: session.seq,
            metadata: session.metadata,
            metadataVersion: session.metadataVersion,
            agentState: session.agentState,
            agentStateVersion: session.agentStateVersion,
            dataEncryptionKey: session.dataEncryptionKey
                ? bufferToBase64(session.dataEncryptionKey)
                : null,
            active: session.active,
            activeAt: session.lastActiveAt.getTime(),
            createdAt: session.createdAt.getTime(),
            updatedAt: session.updatedAt.getTime(),
        },
        createdAt: Date.now(),
    };
}

/**
 * Build a 'new-message' update payload.
 *
 * Sent when a new message is added to a session.
 */
export function buildNewMessageUpdate(
    message: {
        id: string;
        seq: number;
        content: unknown;
        localId: string | null;
        createdAt: Date;
        updatedAt: Date;
    },
    sessionId: string,
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'new-message',
            sid: sessionId,
            message: {
                id: message.id,
                seq: message.seq,
                content: message.content,
                localId: message.localId,
                createdAt: message.createdAt.getTime(),
                updatedAt: message.updatedAt.getTime(),
            },
        },
        createdAt: Date.now(),
    };
}

/**
 * Build an 'update-session' update payload.
 *
 * Sent when session metadata or agent state is updated.
 */
export function buildUpdateSessionUpdate(
    sessionId: string,
    updateSeq: number,
    updateId: string,
    metadata?: { value: string; version: number },
    agentState?: { value: string; version: number }
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'update-session',
            id: sessionId,
            metadata,
            agentState,
        },
        createdAt: Date.now(),
    };
}

/**
 * Build a 'delete-session' update payload.
 *
 * Sent when a session is deleted (soft delete).
 */
export function buildDeleteSessionUpdate(
    sessionId: string,
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'delete-session',
            sid: sessionId,
        },
        createdAt: Date.now(),
    };
}

/**
 * Build an 'update-account' update payload.
 *
 * Sent when user account settings or profile is updated.
 */
export function buildUpdateAccountUpdate(
    userId: string,
    profile: Partial<AccountProfile>,
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'update-account',
            id: userId,
            ...profile,
        },
        createdAt: Date.now(),
    };
}

/**
 * Build a 'new-machine' update payload.
 *
 * Sent when a new CLI machine is registered.
 */
export function buildNewMachineUpdate(
    machine: {
        id: string;
        seq: number;
        metadata: string;
        metadataVersion: number;
        daemonState: string | null;
        daemonStateVersion: number;
        dataEncryptionKey: Uint8Array | null;
        active: boolean;
        lastActiveAt: Date;
        createdAt: Date;
        updatedAt: Date;
    },
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'new-machine',
            machineId: machine.id,
            seq: machine.seq,
            metadata: machine.metadata,
            metadataVersion: machine.metadataVersion,
            daemonState: machine.daemonState,
            daemonStateVersion: machine.daemonStateVersion,
            dataEncryptionKey: machine.dataEncryptionKey
                ? bufferToBase64(machine.dataEncryptionKey)
                : null,
            active: machine.active,
            activeAt: machine.lastActiveAt.getTime(),
            createdAt: machine.createdAt.getTime(),
            updatedAt: machine.updatedAt.getTime(),
        },
        createdAt: Date.now(),
    };
}

/**
 * Build an 'update-machine' update payload.
 *
 * Sent when machine metadata or daemon state is updated.
 */
export function buildUpdateMachineUpdate(
    machineId: string,
    updateSeq: number,
    updateId: string,
    metadata?: { value: string; version: number },
    daemonState?: { value: string; version: number }
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'update-machine',
            machineId,
            metadata,
            daemonState,
        },
        createdAt: Date.now(),
    };
}

/**
 * Build a 'new-artifact' update payload.
 *
 * Sent when a new artifact is created.
 */
export function buildNewArtifactUpdate(
    artifact: {
        id: string;
        seq: number;
        header: Uint8Array;
        headerVersion: number;
        body: Uint8Array;
        bodyVersion: number;
        dataEncryptionKey: Uint8Array;
        createdAt: Date;
        updatedAt: Date;
    },
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'new-artifact',
            artifactId: artifact.id,
            seq: artifact.seq,
            header: bufferToBase64(artifact.header),
            headerVersion: artifact.headerVersion,
            body: bufferToBase64(artifact.body),
            bodyVersion: artifact.bodyVersion,
            dataEncryptionKey: bufferToBase64(artifact.dataEncryptionKey),
            createdAt: artifact.createdAt.getTime(),
            updatedAt: artifact.updatedAt.getTime(),
        },
        createdAt: Date.now(),
    };
}

/**
 * Build an 'update-artifact' update payload.
 *
 * Sent when artifact header or body is updated.
 */
export function buildUpdateArtifactUpdate(
    artifactId: string,
    updateSeq: number,
    updateId: string,
    header?: { value: string; version: number },
    body?: { value: string; version: number }
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'update-artifact',
            artifactId,
            header,
            body,
        },
        createdAt: Date.now(),
    };
}

/**
 * Build a 'delete-artifact' update payload.
 *
 * Sent when an artifact is deleted.
 */
export function buildDeleteArtifactUpdate(
    artifactId: string,
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'delete-artifact',
            artifactId,
        },
        createdAt: Date.now(),
    };
}

/**
 * Build a 'relationship-updated' update payload.
 *
 * Sent when a friend relationship status changes.
 */
export function buildRelationshipUpdatedEvent(
    data: {
        uid: string;
        status: 'none' | 'requested' | 'pending' | 'friend' | 'rejected';
        timestamp: number;
    },
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'relationship-updated',
            ...data,
        },
        createdAt: Date.now(),
    };
}

/**
 * Build a 'new-feed-post' update payload.
 *
 * Sent when a new feed post is created.
 */
export function buildNewFeedPostUpdate(
    feedItem: {
        id: string;
        body: unknown;
        cursor: string;
        createdAt: number;
    },
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'new-feed-post',
            id: feedItem.id,
            body: feedItem.body,
            cursor: feedItem.cursor,
            createdAt: feedItem.createdAt,
        },
        createdAt: Date.now(),
    };
}

/**
 * Build a 'kv-batch-update' update payload.
 *
 * Sent when key-value pairs are batch updated.
 */
export function buildKVBatchUpdateUpdate(
    changes: Array<{ key: string; value: string | null; version: number }>,
    updateSeq: number,
    updateId: string
): UpdatePayload {
    return {
        id: updateId,
        seq: updateSeq,
        body: {
            t: 'kv-batch-update',
            changes,
        },
        createdAt: Date.now(),
    };
}

// =============================================================================
// EPHEMERAL EVENT BUILDERS
// =============================================================================

/**
 * Build a session 'activity' ephemeral payload.
 *
 * Sent when a session's activity status changes (active/inactive, thinking).
 */
export function buildSessionActivityEphemeral(
    sessionId: string,
    active: boolean,
    activeAt: number,
    thinking?: boolean
): EphemeralPayload {
    return {
        type: 'activity',
        id: sessionId,
        active,
        activeAt,
        thinking: thinking ?? false,
    };
}

/**
 * Build a 'machine-activity' ephemeral payload.
 *
 * Sent when a machine's activity status changes.
 */
export function buildMachineActivityEphemeral(
    machineId: string,
    active: boolean,
    activeAt: number
): EphemeralPayload {
    return {
        type: 'machine-activity',
        id: machineId,
        active,
        activeAt,
    };
}

/**
 * Build a 'usage' ephemeral payload.
 *
 * Sent to report token/cost usage for a session.
 */
export function buildUsageEphemeral(
    sessionId: string,
    key: string,
    tokens: Record<string, number>,
    cost: Record<string, number>
): EphemeralPayload {
    return {
        type: 'usage',
        id: sessionId,
        key,
        tokens,
        cost,
        timestamp: Date.now(),
    };
}

/**
 * Build a 'machine-status' ephemeral payload.
 *
 * Sent when a machine comes online or goes offline.
 * This is the primary event for machine online/offline broadcasts.
 */
export function buildMachineStatusEphemeral(machineId: string, online: boolean): EphemeralPayload {
    return {
        type: 'machine-status',
        machineId,
        online,
        timestamp: Date.now(),
    };
}

// =============================================================================
// UTILITIES
// =============================================================================

/**
 * Convert Uint8Array to base64 string.
 *
 * Uses the native btoa function available in Workers runtime.
 */
function bufferToBase64(buffer: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < buffer.length; i++) {
        binary += String.fromCharCode(buffer[i]!);
    }
    return btoa(binary);
}
