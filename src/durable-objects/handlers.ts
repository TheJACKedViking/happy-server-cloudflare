/**
 * WebSocket Message Handlers for Database Updates
 *
 * Handles incoming WebSocket messages that require database persistence.
 * Mirrors the handlers from happy-server/sources/app/api/socket/*.ts
 *
 * @module durable-objects/handlers
 * @see HAP-283 - Implement WebSocket Message Handlers for Database Updates
 */

import { eq, and, sql } from 'drizzle-orm';
import type { DbClient } from '@/db/client';
import {
    sessions,
    machines,
    artifacts,
    accessKeys,
    usageReports,
    sessionMessages,
    accounts,
} from '@/db/schema';
import { createId } from '@/utils/id';
import type { ClientMessage, MessageFilter, UpdatePayload, EphemeralEvent } from './types';

/**
 * Handler result with optional response and broadcast
 */
export interface HandlerResult {
    /** Response to send back to the caller via ack */
    response?: unknown;
    /** Update event to broadcast to other connections */
    broadcast?: {
        message: ClientMessage;
        filter: MessageFilter;
    };
    /** Ephemeral event to broadcast (for activity updates) */
    ephemeral?: {
        message: ClientMessage;
        filter: MessageFilter;
    };
}

/**
 * Context passed to all handlers
 */
export interface HandlerContext {
    /** Authenticated user ID */
    userId: string;
    /** Database client */
    db: DbClient;
    /** Connection's machine ID (for machine-scoped connections) */
    machineId?: string;
    /** Connection's session ID (for session-scoped connections) */
    sessionId?: string;
}

// =============================================================================
// SESSION HANDLERS
// =============================================================================

/**
 * Handle session metadata update with optimistic concurrency control
 *
 * Event: 'update-metadata'
 * Data: { sid: string, metadata: string, expectedVersion: number }
 */
export async function handleSessionMetadataUpdate(
    ctx: HandlerContext,
    data: { sid: string; metadata: string; expectedVersion: number }
): Promise<HandlerResult> {
    const { sid, metadata, expectedVersion } = data;

    // Validate input
    if (!sid || typeof metadata !== 'string' || typeof expectedVersion !== 'number') {
        return { response: { result: 'error', message: 'Invalid parameters' } };
    }

    // Fetch current session
    const [session] = await ctx.db
        .select()
        .from(sessions)
        .where(and(eq(sessions.id, sid), eq(sessions.accountId, ctx.userId)));

    if (!session) {
        return { response: { result: 'error', message: 'Session not found' } };
    }

    // Check version
    if (session.metadataVersion !== expectedVersion) {
        return {
            response: {
                result: 'version-mismatch',
                version: session.metadataVersion,
                metadata: session.metadata,
            },
        };
    }

    // Atomic update with version check
    const result = await ctx.db
        .update(sessions)
        .set({
            metadata,
            metadataVersion: expectedVersion + 1,
            updatedAt: new Date(),
        })
        .where(
            and(
                eq(sessions.id, sid),
                eq(sessions.accountId, ctx.userId),
                eq(sessions.metadataVersion, expectedVersion)
            )
        )
        .returning();

    if (result.length === 0) {
        // Re-fetch to get current state
        const [current] = await ctx.db
            .select()
            .from(sessions)
            .where(and(eq(sessions.id, sid), eq(sessions.accountId, ctx.userId)));

        return {
            response: {
                result: 'version-mismatch',
                version: current?.metadataVersion ?? 0,
                metadata: current?.metadata,
            },
        };
    }

    // Allocate sequence number for the update
    const [account] = await ctx.db
        .update(accounts)
        .set({ seq: sql`${accounts.seq} + 1` })
        .where(eq(accounts.id, ctx.userId))
        .returning({ seq: accounts.seq });

    const updateId = createId();

    return {
        response: {
            result: 'success',
            version: expectedVersion + 1,
            metadata,
        },
        broadcast: {
            message: {
                event: 'update',
                data: {
                    id: updateId,
                    seq: account?.seq ?? 0,
                    body: {
                        t: 'update-session',
                        id: sid,
                        metadata: {
                            value: metadata,
                            version: expectedVersion + 1,
                        },
                    },
                    createdAt: Date.now(),
                } satisfies UpdatePayload,
            },
            filter: { type: 'all-interested-in-session', sessionId: sid },
        },
    };
}

/**
 * Handle session agent state update with optimistic concurrency control
 *
 * Event: 'update-state'
 * Data: { sid: string, agentState: string | null, expectedVersion: number }
 */
export async function handleSessionStateUpdate(
    ctx: HandlerContext,
    data: { sid: string; agentState: string | null; expectedVersion: number }
): Promise<HandlerResult> {
    const { sid, agentState, expectedVersion } = data;

    // Validate input
    if (
        !sid ||
        (typeof agentState !== 'string' && agentState !== null) ||
        typeof expectedVersion !== 'number'
    ) {
        return { response: { result: 'error', message: 'Invalid parameters' } };
    }

    // Fetch current session
    const [session] = await ctx.db
        .select()
        .from(sessions)
        .where(and(eq(sessions.id, sid), eq(sessions.accountId, ctx.userId)));

    if (!session) {
        return { response: { result: 'error', message: 'Session not found' } };
    }

    // Check version
    if (session.agentStateVersion !== expectedVersion) {
        return {
            response: {
                result: 'version-mismatch',
                version: session.agentStateVersion,
                agentState: session.agentState,
            },
        };
    }

    // Atomic update with version check
    const result = await ctx.db
        .update(sessions)
        .set({
            agentState,
            agentStateVersion: expectedVersion + 1,
            updatedAt: new Date(),
        })
        .where(
            and(
                eq(sessions.id, sid),
                eq(sessions.accountId, ctx.userId),
                eq(sessions.agentStateVersion, expectedVersion)
            )
        )
        .returning();

    if (result.length === 0) {
        const [current] = await ctx.db
            .select()
            .from(sessions)
            .where(and(eq(sessions.id, sid), eq(sessions.accountId, ctx.userId)));

        return {
            response: {
                result: 'version-mismatch',
                version: current?.agentStateVersion ?? 0,
                agentState: current?.agentState,
            },
        };
    }

    // Allocate sequence number
    const [account] = await ctx.db
        .update(accounts)
        .set({ seq: sql`${accounts.seq} + 1` })
        .where(eq(accounts.id, ctx.userId))
        .returning({ seq: accounts.seq });

    const updateId = createId();

    return {
        response: {
            result: 'success',
            version: expectedVersion + 1,
            agentState,
        },
        broadcast: {
            message: {
                event: 'update',
                data: {
                    id: updateId,
                    seq: account?.seq ?? 0,
                    body: {
                        t: 'update-session',
                        id: sid,
                        agentState: {
                            value: agentState,
                            version: expectedVersion + 1,
                        },
                    },
                    createdAt: Date.now(),
                } satisfies UpdatePayload,
            },
            filter: { type: 'all-interested-in-session', sessionId: sid },
        },
    };
}

/**
 * Handle session activity heartbeat
 *
 * Event: 'session-alive'
 * Data: { sid: string, time: number, thinking?: boolean }
 */
export async function handleSessionAlive(
    ctx: HandlerContext,
    data: { sid: string; time: number; thinking?: boolean }
): Promise<HandlerResult> {
    const { sid, thinking } = data;
    let { time } = data;

    // Validate input
    if (!sid || typeof time !== 'number') {
        return {};
    }

    // Clamp time to reasonable range
    const now = Date.now();
    if (time > now) {
        time = now;
    }
    if (time < now - 10 * 60 * 1000) {
        // Ignore if older than 10 minutes
        return {};
    }

    // Verify session exists and belongs to user
    const [session] = await ctx.db
        .select({ id: sessions.id })
        .from(sessions)
        .where(and(eq(sessions.id, sid), eq(sessions.accountId, ctx.userId)));

    if (!session) {
        return {};
    }

    // Update last active timestamp
    await ctx.db
        .update(sessions)
        .set({
            lastActiveAt: new Date(time),
            active: true,
        })
        .where(eq(sessions.id, sid));

    // Emit session activity ephemeral event
    return {
        ephemeral: {
            message: {
                event: 'ephemeral',
                data: {
                    type: 'activity',
                    sid, // HAP-654: Standardized to `sid`
                    active: true,
                    activeAt: time,
                    thinking: thinking || false,
                } satisfies EphemeralEvent,
            },
            filter: { type: 'user-scoped-only' },
        },
    };
}

/**
 * Handle session end notification
 *
 * Event: 'session-end'
 * Data: { sid: string, time: number }
 */
export async function handleSessionEnd(
    ctx: HandlerContext,
    data: { sid: string; time: number }
): Promise<HandlerResult> {
    const { sid } = data;
    let { time } = data;

    if (!sid || typeof time !== 'number') {
        return {};
    }

    // Clamp time
    const now = Date.now();
    if (time > now) {
        time = now;
    }
    if (time < now - 10 * 60 * 1000) {
        return {};
    }

    // Verify session exists
    const [session] = await ctx.db
        .select({ id: sessions.id })
        .from(sessions)
        .where(and(eq(sessions.id, sid), eq(sessions.accountId, ctx.userId)));

    if (!session) {
        return {};
    }

    // Mark session as inactive
    await ctx.db
        .update(sessions)
        .set({
            lastActiveAt: new Date(time),
            active: false,
        })
        .where(eq(sessions.id, sid));

    return {
        ephemeral: {
            message: {
                event: 'ephemeral',
                data: {
                    type: 'activity',
                    sid, // HAP-654: Standardized to `sid`
                    active: false,
                    activeAt: time,
                    thinking: false,
                } satisfies EphemeralEvent,
            },
            filter: { type: 'user-scoped-only' },
        },
    };
}

/**
 * Handle new session message
 *
 * Event: 'message'
 * Data: { sid: string, message: string, localId?: string }
 */
export async function handleSessionMessage(
    ctx: HandlerContext,
    data: { sid: string; message: string; localId?: string }
): Promise<HandlerResult> {
    const { sid, message, localId } = data;

    if (!sid || typeof message !== 'string') {
        return {};
    }

    // Verify session exists
    const [session] = await ctx.db
        .select({ id: sessions.id, seq: sessions.seq })
        .from(sessions)
        .where(and(eq(sessions.id, sid), eq(sessions.accountId, ctx.userId)));

    if (!session) {
        return {};
    }

    // Check for duplicate by localId
    const useLocalId = typeof localId === 'string' ? localId : null;
    if (useLocalId) {
        const [existing] = await ctx.db
            .select()
            .from(sessionMessages)
            .where(
                and(eq(sessionMessages.sessionId, sid), eq(sessionMessages.localId, useLocalId))
            );

        if (existing) {
            return {}; // Already exists, idempotent
        }
    }

    // Increment session seq
    const [updatedSession] = await ctx.db
        .update(sessions)
        .set({ seq: sql`${sessions.seq} + 1` })
        .where(eq(sessions.id, sid))
        .returning({ seq: sessions.seq });

    const msgSeq = updatedSession?.seq ?? session.seq + 1;

    // Create message
    const msgContent = {
        t: 'encrypted',
        c: message,
    };

    const msgId = createId();
    const now = Date.now();

    await ctx.db.insert(sessionMessages).values({
        id: msgId,
        sessionId: sid,
        seq: msgSeq,
        content: msgContent,
        localId: useLocalId,
        createdAt: new Date(now),
        updatedAt: new Date(now),
    });

    // Allocate user sequence for update
    const [account] = await ctx.db
        .update(accounts)
        .set({ seq: sql`${accounts.seq} + 1` })
        .where(eq(accounts.id, ctx.userId))
        .returning({ seq: accounts.seq });

    const updateId = createId();

    return {
        broadcast: {
            message: {
                event: 'update',
                data: {
                    id: updateId,
                    seq: account?.seq ?? 0,
                    body: {
                        t: 'new-message',
                        sid,
                        message: {
                            id: msgId,
                            seq: msgSeq,
                            content: msgContent,
                            localId: useLocalId,
                            createdAt: now,
                            updatedAt: now,
                        },
                    },
                    createdAt: now,
                } satisfies UpdatePayload,
            },
            filter: { type: 'all-interested-in-session', sessionId: sid },
        },
    };
}

// =============================================================================
// MACHINE HANDLERS
// =============================================================================

/**
 * Handle machine activity heartbeat
 *
 * Event: 'machine-alive'
 * Data: { machineId: string, time: number }
 */
export async function handleMachineAlive(
    ctx: HandlerContext,
    data: { machineId: string; time: number }
): Promise<HandlerResult> {
    const { machineId } = data;
    let { time } = data;

    if (!machineId || typeof time !== 'number') {
        return {};
    }

    // Clamp time
    const now = Date.now();
    if (time > now) {
        time = now;
    }
    if (time < now - 10 * 60 * 1000) {
        return {};
    }

    // Verify machine exists
    const [machine] = await ctx.db
        .select({ id: machines.id })
        .from(machines)
        .where(and(eq(machines.id, machineId), eq(machines.accountId, ctx.userId)));

    if (!machine) {
        return {};
    }

    // Update last active timestamp
    await ctx.db
        .update(machines)
        .set({
            lastActiveAt: new Date(time),
            active: true,
        })
        .where(and(eq(machines.id, machineId), eq(machines.accountId, ctx.userId)));

    return {
        ephemeral: {
            message: {
                event: 'ephemeral',
                data: {
                    type: 'machine-activity',
                    machineId, // HAP-655: Standardized to `machineId`
                    active: true,
                    activeAt: time,
                } satisfies EphemeralEvent,
            },
            filter: { type: 'user-scoped-only' },
        },
    };
}

/**
 * Handle machine metadata update with optimistic concurrency control
 *
 * Event: 'machine-update-metadata'
 * Data: { machineId: string, metadata: string, expectedVersion: number }
 */
export async function handleMachineMetadataUpdate(
    ctx: HandlerContext,
    data: { machineId: string; metadata: string; expectedVersion: number }
): Promise<HandlerResult> {
    const { machineId, metadata, expectedVersion } = data;

    if (!machineId || typeof metadata !== 'string' || typeof expectedVersion !== 'number') {
        return { response: { result: 'error', message: 'Invalid parameters' } };
    }

    // Fetch current machine
    const [machine] = await ctx.db
        .select()
        .from(machines)
        .where(and(eq(machines.id, machineId), eq(machines.accountId, ctx.userId)));

    if (!machine) {
        return { response: { result: 'error', message: 'Machine not found' } };
    }

    // Check version
    if (machine.metadataVersion !== expectedVersion) {
        return {
            response: {
                result: 'version-mismatch',
                version: machine.metadataVersion,
                metadata: machine.metadata,
            },
        };
    }

    // Atomic update
    const result = await ctx.db
        .update(machines)
        .set({
            metadata,
            metadataVersion: expectedVersion + 1,
            updatedAt: new Date(),
        })
        .where(
            and(
                eq(machines.id, machineId),
                eq(machines.accountId, ctx.userId),
                eq(machines.metadataVersion, expectedVersion)
            )
        )
        .returning();

    if (result.length === 0) {
        const [current] = await ctx.db
            .select()
            .from(machines)
            .where(and(eq(machines.id, machineId), eq(machines.accountId, ctx.userId)));

        return {
            response: {
                result: 'version-mismatch',
                version: current?.metadataVersion ?? 0,
                metadata: current?.metadata,
            },
        };
    }

    // Allocate sequence number
    const [account] = await ctx.db
        .update(accounts)
        .set({ seq: sql`${accounts.seq} + 1` })
        .where(eq(accounts.id, ctx.userId))
        .returning({ seq: accounts.seq });

    const updateId = createId();

    return {
        response: {
            result: 'success',
            version: expectedVersion + 1,
            metadata,
        },
        broadcast: {
            message: {
                event: 'update',
                data: {
                    id: updateId,
                    seq: account?.seq ?? 0,
                    body: {
                        t: 'update-machine',
                        machineId,
                        metadata: {
                            value: metadata,
                            version: expectedVersion + 1,
                        },
                    },
                    createdAt: Date.now(),
                } satisfies UpdatePayload,
            },
            filter: { type: 'machine-scoped-only', machineId },
        },
    };
}

/**
 * Handle machine daemon state update with optimistic concurrency control
 *
 * Event: 'machine-update-state'
 * Data: { machineId: string, daemonState: string, expectedVersion: number }
 */
export async function handleMachineStateUpdate(
    ctx: HandlerContext,
    data: { machineId: string; daemonState: string; expectedVersion: number }
): Promise<HandlerResult> {
    const { machineId, daemonState, expectedVersion } = data;

    if (!machineId || typeof daemonState !== 'string' || typeof expectedVersion !== 'number') {
        return { response: { result: 'error', message: 'Invalid parameters' } };
    }

    // Fetch current machine
    const [machine] = await ctx.db
        .select()
        .from(machines)
        .where(and(eq(machines.id, machineId), eq(machines.accountId, ctx.userId)));

    if (!machine) {
        return { response: { result: 'error', message: 'Machine not found' } };
    }

    // Check version
    if (machine.daemonStateVersion !== expectedVersion) {
        return {
            response: {
                result: 'version-mismatch',
                version: machine.daemonStateVersion,
                daemonState: machine.daemonState,
            },
        };
    }

    // Atomic update
    const result = await ctx.db
        .update(machines)
        .set({
            daemonState,
            daemonStateVersion: expectedVersion + 1,
            active: true,
            lastActiveAt: new Date(),
            updatedAt: new Date(),
        })
        .where(
            and(
                eq(machines.id, machineId),
                eq(machines.accountId, ctx.userId),
                eq(machines.daemonStateVersion, expectedVersion)
            )
        )
        .returning();

    if (result.length === 0) {
        const [current] = await ctx.db
            .select()
            .from(machines)
            .where(and(eq(machines.id, machineId), eq(machines.accountId, ctx.userId)));

        return {
            response: {
                result: 'version-mismatch',
                version: current?.daemonStateVersion ?? 0,
                daemonState: current?.daemonState,
            },
        };
    }

    // Allocate sequence number
    const [account] = await ctx.db
        .update(accounts)
        .set({ seq: sql`${accounts.seq} + 1` })
        .where(eq(accounts.id, ctx.userId))
        .returning({ seq: accounts.seq });

    const updateId = createId();

    return {
        response: {
            result: 'success',
            version: expectedVersion + 1,
            daemonState,
        },
        broadcast: {
            message: {
                event: 'update',
                data: {
                    id: updateId,
                    seq: account?.seq ?? 0,
                    body: {
                        t: 'update-machine',
                        machineId,
                        daemonState: {
                            value: daemonState,
                            version: expectedVersion + 1,
                        },
                        activeAt: Date.now(),
                    },
                    createdAt: Date.now(),
                } satisfies UpdatePayload,
            },
            filter: { type: 'machine-scoped-only', machineId },
        },
    };
}

// =============================================================================
// ARTIFACT HANDLERS
// =============================================================================

/**
 * Handle artifact read request
 *
 * Event: 'artifact-read'
 * Data: { artifactId: string }
 */
export async function handleArtifactRead(
    ctx: HandlerContext,
    data: { artifactId: string }
): Promise<HandlerResult> {
    const { artifactId } = data;

    if (!artifactId) {
        return { response: { result: 'error', message: 'Invalid parameters' } };
    }

    const [artifact] = await ctx.db
        .select()
        .from(artifacts)
        .where(and(eq(artifacts.id, artifactId), eq(artifacts.accountId, ctx.userId)));

    if (!artifact) {
        return { response: { result: 'error', message: 'Artifact not found' } };
    }

    // Convert Uint8Array to base64 string
    const headerBase64 = Buffer.from(artifact.header).toString('base64');
    const bodyBase64 = Buffer.from(artifact.body).toString('base64');

    return {
        response: {
            result: 'success',
            artifact: {
                id: artifact.id,
                header: headerBase64,
                headerVersion: artifact.headerVersion,
                body: bodyBase64,
                bodyVersion: artifact.bodyVersion,
                seq: artifact.seq,
                createdAt: artifact.createdAt.getTime(),
                updatedAt: artifact.updatedAt.getTime(),
            },
        },
    };
}

/**
 * Handle artifact update with optimistic concurrency control
 *
 * Event: 'artifact-update'
 * Data: {
 *   artifactId: string,
 *   header?: { data: string, expectedVersion: number },
 *   body?: { data: string, expectedVersion: number }
 * }
 */
export async function handleArtifactUpdate(
    ctx: HandlerContext,
    data: {
        artifactId: string;
        header?: { data: string; expectedVersion: number };
        body?: { data: string; expectedVersion: number };
    }
): Promise<HandlerResult> {
    const { artifactId, header, body } = data;

    if (!artifactId) {
        return { response: { result: 'error', message: 'Invalid parameters' } };
    }

    if (!header && !body) {
        return { response: { result: 'error', message: 'No updates provided' } };
    }

    // Validate structures
    if (header && (typeof header.data !== 'string' || typeof header.expectedVersion !== 'number')) {
        return { response: { result: 'error', message: 'Invalid header parameters' } };
    }
    if (body && (typeof body.data !== 'string' || typeof body.expectedVersion !== 'number')) {
        return { response: { result: 'error', message: 'Invalid body parameters' } };
    }

    // Fetch current artifact
    const [current] = await ctx.db
        .select()
        .from(artifacts)
        .where(and(eq(artifacts.id, artifactId), eq(artifacts.accountId, ctx.userId)));

    if (!current) {
        return { response: { result: 'error', message: 'Artifact not found' } };
    }

    // Check for version mismatches
    const headerMismatch = header && current.headerVersion !== header.expectedVersion;
    const bodyMismatch = body && current.bodyVersion !== body.expectedVersion;

    if (headerMismatch || bodyMismatch) {
        const response: Record<string, unknown> = { result: 'version-mismatch' };
        if (headerMismatch) {
            response.header = {
                currentVersion: current.headerVersion,
                currentData: Buffer.from(current.header).toString('base64'),
            };
        }
        if (bodyMismatch) {
            response.body = {
                currentVersion: current.bodyVersion,
                currentData: Buffer.from(current.body).toString('base64'),
            };
        }
        return { response };
    }

    // Build update data
    const updateData: Record<string, unknown> = {
        seq: current.seq + 1,
        updatedAt: new Date(),
    };

    let headerUpdate: { value: string; version: number } | undefined;
    let bodyUpdate: { value: string; version: number } | undefined;

    if (header) {
        updateData.header = Buffer.from(header.data, 'base64');
        updateData.headerVersion = header.expectedVersion + 1;
        headerUpdate = { value: header.data, version: header.expectedVersion + 1 };
    }

    if (body) {
        updateData.body = Buffer.from(body.data, 'base64');
        updateData.bodyVersion = body.expectedVersion + 1;
        bodyUpdate = { value: body.data, version: body.expectedVersion + 1 };
    }

    // Atomic update with version checks
    // Note: SQLite/D1 doesn't support multiple where conditions in the same way
    // We use a WHERE clause with all conditions
    const whereConditions = [
        eq(artifacts.id, artifactId),
        eq(artifacts.accountId, ctx.userId),
    ];
    if (header) {
        whereConditions.push(eq(artifacts.headerVersion, header.expectedVersion));
    }
    if (body) {
        whereConditions.push(eq(artifacts.bodyVersion, body.expectedVersion));
    }

    const result = await ctx.db
        .update(artifacts)
        .set(updateData)
        .where(and(...whereConditions))
        .returning();

    if (result.length === 0) {
        // Re-fetch to get current state
        const [refetched] = await ctx.db
            .select()
            .from(artifacts)
            .where(and(eq(artifacts.id, artifactId), eq(artifacts.accountId, ctx.userId)));

        const response: Record<string, unknown> = { result: 'version-mismatch' };
        if (header && refetched) {
            response.header = {
                currentVersion: refetched.headerVersion,
                currentData: Buffer.from(refetched.header).toString('base64'),
            };
        }
        if (body && refetched) {
            response.body = {
                currentVersion: refetched.bodyVersion,
                currentData: Buffer.from(refetched.body).toString('base64'),
            };
        }
        return { response };
    }

    // Allocate sequence number
    const [account] = await ctx.db
        .update(accounts)
        .set({ seq: sql`${accounts.seq} + 1` })
        .where(eq(accounts.id, ctx.userId))
        .returning({ seq: accounts.seq });

    const updateId = createId();

    // Build success response
    const response: Record<string, unknown> = { result: 'success' };
    if (headerUpdate) {
        response.header = { version: headerUpdate.version, data: header!.data };
    }
    if (bodyUpdate) {
        response.body = { version: bodyUpdate.version, data: body!.data };
    }

    return {
        response,
        broadcast: {
            message: {
                event: 'update',
                data: {
                    id: updateId,
                    seq: account?.seq ?? 0,
                    body: {
                        t: 'update-artifact',
                        artifactId,
                        ...(headerUpdate && { header: headerUpdate }),
                        ...(bodyUpdate && { body: bodyUpdate }),
                    },
                    createdAt: Date.now(),
                } satisfies UpdatePayload,
            },
            filter: { type: 'user-scoped-only' },
        },
    };
}

/**
 * Handle artifact creation
 *
 * Event: 'artifact-create'
 * Data: { id: string, header: string, body: string, dataEncryptionKey: string }
 */
export async function handleArtifactCreate(
    ctx: HandlerContext,
    data: { id: string; header: string; body: string; dataEncryptionKey: string }
): Promise<HandlerResult> {
    const { id, header, body, dataEncryptionKey } = data;

    if (
        !id ||
        typeof header !== 'string' ||
        typeof body !== 'string' ||
        typeof dataEncryptionKey !== 'string'
    ) {
        return { response: { result: 'error', message: 'Invalid parameters' } };
    }

    // Check if artifact exists
    const [existing] = await ctx.db.select().from(artifacts).where(eq(artifacts.id, id));

    if (existing) {
        if (existing.accountId !== ctx.userId) {
            return {
                response: {
                    result: 'error',
                    message: 'Artifact with this ID already exists for another account',
                },
            };
        }

        // Return existing (idempotent)
        return {
            response: {
                result: 'success',
                artifact: {
                    id: existing.id,
                    header: Buffer.from(existing.header).toString('base64'),
                    headerVersion: existing.headerVersion,
                    body: Buffer.from(existing.body).toString('base64'),
                    bodyVersion: existing.bodyVersion,
                    seq: existing.seq,
                    createdAt: existing.createdAt.getTime(),
                    updatedAt: existing.updatedAt.getTime(),
                },
            },
        };
    }

    // Create new artifact
    const now = Date.now();
    const insertResult = await ctx.db
        .insert(artifacts)
        .values({
            id,
            accountId: ctx.userId,
            header: Buffer.from(header, 'base64'),
            headerVersion: 1,
            body: Buffer.from(body, 'base64'),
            bodyVersion: 1,
            dataEncryptionKey: Buffer.from(dataEncryptionKey, 'base64'),
            seq: 0,
            createdAt: new Date(now),
            updatedAt: new Date(now),
        })
        .returning();

    const artifact = insertResult[0];
    if (!artifact) {
        return { response: { result: 'error', message: 'Failed to create artifact' } };
    }

    // Allocate sequence number
    const [account] = await ctx.db
        .update(accounts)
        .set({ seq: sql`${accounts.seq} + 1` })
        .where(eq(accounts.id, ctx.userId))
        .returning({ seq: accounts.seq });

    const updateId = createId();

    return {
        response: {
            result: 'success',
            artifact: {
                id: artifact.id,
                header: Buffer.from(artifact.header).toString('base64'),
                headerVersion: artifact.headerVersion,
                body: Buffer.from(artifact.body).toString('base64'),
                bodyVersion: artifact.bodyVersion,
                seq: artifact.seq,
                createdAt: artifact.createdAt.getTime(),
                updatedAt: artifact.updatedAt.getTime(),
            },
        },
        broadcast: {
            message: {
                event: 'update',
                data: {
                    id: updateId,
                    seq: account?.seq ?? 0,
                    body: {
                        t: 'new-artifact',
                        artifactId: artifact.id,
                        seq: artifact.seq,
                        header,
                        headerVersion: artifact.headerVersion,
                        body,
                        bodyVersion: artifact.bodyVersion,
                        dataEncryptionKey,
                        createdAt: artifact.createdAt.getTime(),
                        updatedAt: artifact.updatedAt.getTime(),
                    },
                    createdAt: now,
                } satisfies UpdatePayload,
            },
            filter: { type: 'user-scoped-only' },
        },
    };
}

/**
 * Handle artifact deletion
 *
 * Event: 'artifact-delete'
 * Data: { artifactId: string }
 */
export async function handleArtifactDelete(
    ctx: HandlerContext,
    data: { artifactId: string }
): Promise<HandlerResult> {
    const { artifactId } = data;

    if (!artifactId) {
        return { response: { result: 'error', message: 'Invalid parameters' } };
    }

    // Verify artifact exists and belongs to user
    const [artifact] = await ctx.db
        .select({ id: artifacts.id })
        .from(artifacts)
        .where(and(eq(artifacts.id, artifactId), eq(artifacts.accountId, ctx.userId)));

    if (!artifact) {
        return { response: { result: 'error', message: 'Artifact not found' } };
    }

    // Delete artifact
    await ctx.db.delete(artifacts).where(eq(artifacts.id, artifactId));

    // Allocate sequence number
    const [account] = await ctx.db
        .update(accounts)
        .set({ seq: sql`${accounts.seq} + 1` })
        .where(eq(accounts.id, ctx.userId))
        .returning({ seq: accounts.seq });

    const updateId = createId();

    return {
        response: { result: 'success' },
        broadcast: {
            message: {
                event: 'update',
                data: {
                    id: updateId,
                    seq: account?.seq ?? 0,
                    body: {
                        t: 'delete-artifact',
                        artifactId,
                    },
                    createdAt: Date.now(),
                } satisfies UpdatePayload,
            },
            filter: { type: 'user-scoped-only' },
        },
    };
}

// =============================================================================
// ACCESS KEY HANDLERS
// =============================================================================

/**
 * Handle access key retrieval
 *
 * Event: 'access-key-get'
 * Data: { sessionId: string, machineId: string }
 */
export async function handleAccessKeyGet(
    ctx: HandlerContext,
    data: { sessionId: string; machineId: string }
): Promise<HandlerResult> {
    const { sessionId, machineId } = data;

    if (!sessionId || !machineId) {
        return { response: { ok: false, error: 'Invalid parameters: sessionId and machineId are required' } };
    }

    // Verify session and machine belong to user
    const [session] = await ctx.db
        .select({ id: sessions.id })
        .from(sessions)
        .where(and(eq(sessions.id, sessionId), eq(sessions.accountId, ctx.userId)));

    const [machine] = await ctx.db
        .select({ id: machines.id })
        .from(machines)
        .where(and(eq(machines.id, machineId), eq(machines.accountId, ctx.userId)));

    if (!session || !machine) {
        return { response: { ok: false, error: 'Session or machine not found' } };
    }

    // Get access key
    const [accessKey] = await ctx.db
        .select()
        .from(accessKeys)
        .where(
            and(
                eq(accessKeys.accountId, ctx.userId),
                eq(accessKeys.machineId, machineId),
                eq(accessKeys.sessionId, sessionId)
            )
        );

    if (accessKey) {
        return {
            response: {
                ok: true,
                accessKey: {
                    data: accessKey.data,
                    dataVersion: accessKey.dataVersion,
                    createdAt: accessKey.createdAt.getTime(),
                    updatedAt: accessKey.updatedAt.getTime(),
                },
            },
        };
    }

    return { response: { ok: true, accessKey: null } };
}

// =============================================================================
// USAGE HANDLERS
// =============================================================================

/**
 * Handle usage report
 *
 * Event: 'usage-report'
 * Data: { key: string, sessionId?: string, tokens: { total: number, ... }, cost: { total: number, ... } }
 */
export async function handleUsageReport(
    ctx: HandlerContext,
    data: {
        key: string;
        sessionId?: string;
        tokens: { total: number; [key: string]: number };
        cost: { total: number; [key: string]: number };
    }
): Promise<HandlerResult> {
    const { key, sessionId, tokens, cost } = data;

    // Validate required fields
    if (!key || typeof key !== 'string') {
        return { response: { success: false, error: 'Invalid key' } };
    }

    if (!tokens || typeof tokens !== 'object' || typeof tokens.total !== 'number') {
        return { response: { success: false, error: 'Invalid tokens object - must include total' } };
    }

    if (!cost || typeof cost !== 'object' || typeof cost.total !== 'number') {
        return { response: { success: false, error: 'Invalid cost object - must include total' } };
    }

    if (sessionId && typeof sessionId !== 'string') {
        return { response: { success: false, error: 'Invalid sessionId' } };
    }

    // Verify session if provided
    if (sessionId) {
        const [session] = await ctx.db
            .select({ id: sessions.id })
            .from(sessions)
            .where(and(eq(sessions.id, sessionId), eq(sessions.accountId, ctx.userId)));

        if (!session) {
            return { response: { success: false, error: 'Session not found' } };
        }
    }

    // Prepare usage data
    const usageData = { tokens, cost };
    const now = Date.now();

    // Upsert the usage report
    // First try to find existing
    const [existing] = await ctx.db
        .select()
        .from(usageReports)
        .where(
            and(
                eq(usageReports.accountId, ctx.userId),
                sessionId ? eq(usageReports.sessionId, sessionId) : sql`${usageReports.sessionId} IS NULL`,
                eq(usageReports.key, key)
            )
        );

    let report: typeof existing;
    if (existing) {
        // Update existing
        const updateResult = await ctx.db
            .update(usageReports)
            .set({
                data: usageData,
                updatedAt: new Date(now),
            })
            .where(eq(usageReports.id, existing.id))
            .returning();
        report = updateResult[0];
    } else {
        // Create new
        const reportId = createId();
        const insertResult = await ctx.db
            .insert(usageReports)
            .values({
                id: reportId,
                accountId: ctx.userId,
                sessionId: sessionId || null,
                key,
                data: usageData,
                createdAt: new Date(now),
                updatedAt: new Date(now),
            })
            .returning();
        report = insertResult[0];
    }

    if (!report) {
        return { response: { success: false, error: 'Failed to save usage report' } };
    }

    // Build result
    const result: HandlerResult = {
        response: {
            success: true,
            reportId: report.id,
            createdAt: report.createdAt.getTime(),
            updatedAt: report.updatedAt.getTime(),
        },
    };

    // Emit usage ephemeral if sessionId provided
    // Note: tokens/cost are typed loosely to accept various CLI payload structures.
    // The protocol schema will validate at runtime if needed.
    if (sessionId) {
        result.ephemeral = {
            message: {
                event: 'ephemeral',
                data: {
                    type: 'usage',
                    sid: sessionId, // HAP-654: Standardized to `sid`
                    key,
                    tokens,
                    cost,
                    timestamp: now,
                } as EphemeralEvent,
            },
            filter: { type: 'user-scoped-only' },
        };
    }

    return result;
}

// =============================================================================
// DELTA SYNC HANDLERS (HAP-441)
// =============================================================================

/**
 * Handle delta sync request on reconnection.
 *
 * Event: 'request-updates-since'
 * Data: { sessions: number, machines: number, artifacts: number }
 *
 * Returns updates since the given seq numbers to minimize bandwidth
 * and prevent missed updates during disconnect.
 *
 * @see HAP-441 - WebSocket reconnection may miss updates during disconnect window
 */
export async function handleRequestUpdatesSince(
    ctx: HandlerContext,
    data: { sessions: number; machines: number; artifacts: number }
): Promise<HandlerResult> {
    const { sessions: sessionsSeq, machines: machinesSeq, artifacts: artifactsSeq } = data;

    // Validate input
    if (
        typeof sessionsSeq !== 'number' ||
        typeof machinesSeq !== 'number' ||
        typeof artifactsSeq !== 'number'
    ) {
        return { response: { success: false, error: 'Invalid parameters' } };
    }

    // Collect updates since the given seq numbers
    const updates: { type: string; data: unknown; seq: number; createdAt: number }[] = [];

    // Query sessions updated since sessionsSeq
    const sessionUpdates = await ctx.db
        .select()
        .from(sessions)
        .where(
            and(
                eq(sessions.accountId, ctx.userId),
                sql`${sessions.seq} > ${sessionsSeq}`,
                eq(sessions.active, true)
            )
        )
        .limit(100);

    for (const session of sessionUpdates) {
        updates.push({
            type: 'update-session',
            data: {
                t: 'update-session',
                id: session.id,
                metadata: session.metadata
                    ? { version: session.metadataVersion, value: session.metadata }
                    : undefined,
                agentState: session.agentState
                    ? { version: session.agentStateVersion, value: session.agentState }
                    : undefined,
            },
            seq: session.seq,
            createdAt: session.updatedAt.getTime(),
        });
    }

    // Query machines updated since machinesSeq
    const machineUpdates = await ctx.db
        .select()
        .from(machines)
        .where(
            and(eq(machines.accountId, ctx.userId), sql`${machines.seq} > ${machinesSeq}`)
        )
        .limit(50);

    for (const machine of machineUpdates) {
        updates.push({
            type: 'update-machine',
            data: {
                t: 'update-machine',
                machineId: machine.id,
                active: machine.active,
                activeAt: machine.lastActiveAt?.getTime() ?? machine.updatedAt.getTime(),
                metadata: machine.metadata
                    ? { version: machine.metadataVersion, value: machine.metadata }
                    : undefined,
                daemonState: machine.daemonState
                    ? { version: machine.daemonStateVersion, value: machine.daemonState }
                    : undefined,
            },
            seq: machine.seq,
            createdAt: machine.updatedAt.getTime(),
        });
    }

    // Query artifacts updated since artifactsSeq
    const artifactUpdates = await ctx.db
        .select()
        .from(artifacts)
        .where(
            and(eq(artifacts.accountId, ctx.userId), sql`${artifacts.seq} > ${artifactsSeq}`)
        )
        .limit(100);

    for (const artifact of artifactUpdates) {
        updates.push({
            type: 'update-artifact',
            data: {
                t: 'update-artifact',
                artifactId: artifact.id,
                header: artifact.header
                    ? { version: artifact.headerVersion, value: artifact.header }
                    : undefined,
                body: artifact.body
                    ? { version: artifact.bodyVersion, value: artifact.body }
                    : undefined,
            },
            seq: artifact.seq,
            createdAt: artifact.updatedAt.getTime(),
        });
    }

    return {
        response: {
            success: true,
            updates,
            counts: {
                sessions: sessionUpdates.length,
                machines: machineUpdates.length,
                artifacts: artifactUpdates.length,
            },
        },
    };
}

// =============================================================================
// HELPER TYPES
// =============================================================================
// NOTE: UpdatePayload is now imported from @happy/protocol via ./types
// This ensures consistent field names across the stack (HAP-387).
