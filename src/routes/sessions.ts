import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { createId } from '@/utils/id';
// Encoding utilities for base64/hex operations (Workers-compatible)
import * as privacyKit from '@/lib/privacy-kit-shim';
import { eq, desc, lt, gt, and, sql, count } from 'drizzle-orm';
import { getEventRouter, buildDeleteSessionUpdate, buildArchiveSessionUpdate } from '@/lib/eventRouter';
import {
    ListSessionsResponseSchema,
    PaginatedSessionsQuerySchema,
    PaginatedSessionsResponseSchema,
    ActiveSessionsQuerySchema,
    ActiveSessionsResponseSchema,
    CreateSessionRequestSchema,
    CreateSessionResponseSchema,
    SessionIdParamSchema,
    GetSessionResponseSchema,
    DeleteSessionResponseSchema,
    CreateSessionMessageRequestSchema,
    CreateSessionMessageResponseSchema,
    ListSessionMessagesResponseSchema,
    PaginatedMessagesQuerySchema,
    PaginatedMessagesResponseSchema,
    SessionStateResponseSchema,
    ArchiveSessionRequestSchema,
    ArchiveSessionResponseSchema,
    BadRequestErrorSchema,
    NotFoundErrorSchema,
    UnauthorizedErrorSchema,
} from '@/schemas/sessions';

/**
 * Environment bindings for session routes
 */
interface Env {
    DB: D1Database;
    CONNECTION_MANAGER?: DurableObjectNamespace;
}

/**
 * Session routes module
 *
 * Implements all session management endpoints:
 * - GET /v1/sessions - List sessions (legacy, no pagination)
 * - GET /v2/sessions - List sessions with cursor-based pagination
 * - GET /v2/sessions/active - List active sessions (last 15 minutes)
 * - POST /v1/sessions - Create session (tag-based deduplication)
 * - GET /v1/sessions/:id - Get single session
 * - DELETE /v1/sessions/:id - Delete session (hard delete, removes from database)
 * - POST /v1/sessions/:id/messages - Create message in session
 * - GET /v1/sessions/:id/messages - List messages in session (legacy, no pagination)
 * - GET /v2/sessions/:id/messages - List messages with cursor-based pagination
 *
 * All routes use OpenAPI schemas for automatic documentation and validation.
 */
const sessionRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all session routes
// HAP-938: Skip auth for /v1/sessions/shared/* paths (public shared session access)
// The sharing routes module handles its own auth for protected endpoints
const sessionsAuthMiddleware = authMiddleware();
sessionRoutes.use('/v1/sessions/*', async (c, next) => {
    if (c.req.path.startsWith('/v1/sessions/shared/')) {
        return next();
    }
    return sessionsAuthMiddleware(c as never, next);
});
sessionRoutes.use('/v2/sessions/*', authMiddleware());

// ============================================================================
// GET /v1/sessions - List Sessions (Legacy)
// ============================================================================

const listSessionsRoute = createRoute({
    method: 'get',
    path: '/v1/sessions',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ListSessionsResponseSchema,
                },
            },
            description: 'List of sessions (up to 150, ordered by most recent)',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'List user sessions (legacy)',
    description: 'Returns up to 150 sessions ordered by most recent. Use GET /v2/sessions for pagination.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(listSessionsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    const sessions = await db.query.sessions.findMany({
        where: (sessions, { eq }) => eq(sessions.accountId, userId),
        orderBy: (sessions, { desc }) => [desc(sessions.updatedAt)],
        limit: 150,
    });

    return c.json({
        sessions: sessions.map((s) => ({
            id: s.id,
            seq: s.seq,
            createdAt: s.createdAt.getTime(),
            updatedAt: s.updatedAt.getTime(),
            active: s.active,
            activeAt: s.lastActiveAt.getTime(),
            metadata: s.metadata,
            metadataVersion: s.metadataVersion,
            agentState: s.agentState,
            agentStateVersion: s.agentStateVersion,
            dataEncryptionKey: s.dataEncryptionKey
                ? privacyKit.encodeBase64(s.dataEncryptionKey)
                : null,
            lastMessage: null, // Legacy field, always null
        })),
    });
});

// ============================================================================
// GET /v2/sessions - List Sessions with Pagination
// ============================================================================

const paginatedSessionsRoute = createRoute({
    method: 'get',
    path: '/v2/sessions',
    request: {
        query: PaginatedSessionsQuerySchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: PaginatedSessionsResponseSchema,
                },
            },
            description: 'Paginated list of sessions',
        },
        400: {
            content: {
                'application/json': {
                    schema: BadRequestErrorSchema,
                },
            },
            description: 'Invalid cursor format',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'List user sessions with pagination',
    description: 'Cursor-based pagination with optional changedSince filter. Always sorted by ID descending.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(paginatedSessionsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { cursor, limit = 50, changedSince } = c.req.valid('query');
    const db = getDb(c.env.DB);

    // Decode cursor - simple ID-based cursor
    let cursorSessionId: string | undefined;
    if (cursor) {
        if (cursor.startsWith('cursor_v1_')) {
            cursorSessionId = cursor.substring(10);
        } else {
            return c.json({ error: 'Invalid cursor format' }, 400);
        }
    }

    // Build where conditions
    const conditions = [eq(schema.sessions.accountId, userId)];

    // Add changedSince filter
    if (changedSince) {
        conditions.push(gt(schema.sessions.updatedAt, new Date(changedSince)));
    }

    // Add cursor pagination
    if (cursorSessionId) {
        conditions.push(lt(schema.sessions.id, cursorSessionId));
    }

    // Fetch sessions with +1 to check for more
    const sessions = await db
        .select()
        .from(schema.sessions)
        .where(and(...conditions))
        .orderBy(desc(schema.sessions.id))
        .limit(limit + 1);

    // Check if there are more results
    const hasNext = sessions.length > limit;
    const resultSessions = hasNext ? sessions.slice(0, limit) : sessions;

    // Generate next cursor
    let nextCursor: string | null = null;
    const lastSession = resultSessions[resultSessions.length - 1];
    // Defensive check: ensures lastSession is not undefined when resultSessions is unexpectedly empty.
    // This prevents runtime errors when accessing lastSession.id.
    if (hasNext && lastSession) {
        nextCursor = `cursor_v1_${lastSession.id}`;
    }

    return c.json({
        sessions: resultSessions.map((s) => ({
            id: s.id,
            seq: s.seq,
            createdAt: s.createdAt.getTime(),
            updatedAt: s.updatedAt.getTime(),
            active: s.active,
            activeAt: s.lastActiveAt.getTime(),
            metadata: s.metadata,
            metadataVersion: s.metadataVersion,
            agentState: s.agentState,
            agentStateVersion: s.agentStateVersion,
            dataEncryptionKey: s.dataEncryptionKey
                ? privacyKit.encodeBase64(s.dataEncryptionKey)
                : null,
            lastMessage: null,
        })),
        nextCursor,
    });
});

// ============================================================================
// GET /v2/sessions/active - List Active Sessions
// ============================================================================

const activeSessionsRoute = createRoute({
    method: 'get',
    path: '/v2/sessions/active',
    request: {
        query: ActiveSessionsQuerySchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ActiveSessionsResponseSchema,
                },
            },
            description: 'List of active sessions',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'List active sessions',
    description: 'Returns sessions active in the last 15 minutes, ordered by most recent activity.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(activeSessionsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { limit = 150 } = c.req.valid('query');
    const db = getDb(c.env.DB);

    // Calculate 15 minutes ago
    const fifteenMinutesAgo = new Date(Date.now() - 1000 * 60 * 15);

    const sessions = await db.query.sessions.findMany({
        where: (sessions, { eq, gt, and }) =>
            and(
                eq(sessions.accountId, userId),
                eq(sessions.active, true),
                gt(sessions.lastActiveAt, fifteenMinutesAgo)
            ),
        orderBy: (sessions, { desc }) => [desc(sessions.lastActiveAt)],
        limit,
    });

    return c.json({
        sessions: sessions.map((s) => ({
            id: s.id,
            seq: s.seq,
            createdAt: s.createdAt.getTime(),
            updatedAt: s.updatedAt.getTime(),
            active: s.active,
            activeAt: s.lastActiveAt.getTime(),
            metadata: s.metadata,
            metadataVersion: s.metadataVersion,
            agentState: s.agentState,
            agentStateVersion: s.agentStateVersion,
            dataEncryptionKey: s.dataEncryptionKey
                ? privacyKit.encodeBase64(s.dataEncryptionKey)
                : null,
            lastMessage: null,
        })),
    });
});

// ============================================================================
// POST /v1/sessions - Create Session (Tag-Based Deduplication)
// ============================================================================

const createSessionRoute = createRoute({
    method: 'post',
    path: '/v1/sessions',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: CreateSessionRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: CreateSessionResponseSchema,
                },
            },
            description: 'Session created or existing session returned',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'Create session',
    description: 'Create a new session with tag-based deduplication. If a session with the same tag exists for the user, returns existing session.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(createSessionRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { tag, metadata, agentState, dataEncryptionKey } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Check if session with this tag already exists
    const existingSession = await db.query.sessions.findFirst({
        where: (sessions, { eq, and }) =>
            and(eq(sessions.accountId, userId), eq(sessions.tag, tag)),
    });

    if (existingSession) {
        // Return existing session
        return c.json({
            session: {
                id: existingSession.id,
                seq: existingSession.seq,
                createdAt: existingSession.createdAt.getTime(),
                updatedAt: existingSession.updatedAt.getTime(),
                active: existingSession.active,
                activeAt: existingSession.lastActiveAt.getTime(),
                metadata: existingSession.metadata,
                metadataVersion: existingSession.metadataVersion,
                agentState: existingSession.agentState,
                agentStateVersion: existingSession.agentStateVersion,
                dataEncryptionKey: existingSession.dataEncryptionKey
                    ? privacyKit.encodeBase64(existingSession.dataEncryptionKey)
                    : null,
                lastMessage: null,
            },
        });
    }

    // Create new session
    const newSessions = await db
        .insert(schema.sessions)
        .values({
            id: createId(),
            accountId: userId,
            tag,
            metadata,
            metadataVersion: 1,
            agentState: agentState || null,
            agentStateVersion: agentState ? 1 : 0,
            dataEncryptionKey: dataEncryptionKey
                ? Buffer.from(privacyKit.decodeBase64(dataEncryptionKey))
                : null,
            seq: 0,
            active: true,
            lastActiveAt: new Date(),
        })
        .returning();

    const session = newSessions[0];
    if (!session) {
        return c.json({ error: 'Failed to create session' }, 500);
    }

    return c.json({
        session: {
            id: session.id,
            seq: session.seq,
            createdAt: session.createdAt.getTime(),
            updatedAt: session.updatedAt.getTime(),
            active: session.active,
            activeAt: session.lastActiveAt.getTime(),
            metadata: session.metadata,
            metadataVersion: session.metadataVersion,
            agentState: session.agentState,
            agentStateVersion: session.agentStateVersion,
            dataEncryptionKey: session.dataEncryptionKey
                ? privacyKit.encodeBase64(session.dataEncryptionKey)
                : null,
            lastMessage: null,
        },
    });
});

// ============================================================================
// GET /v1/sessions/:id - Get Session
// ============================================================================

const getSessionRoute = createRoute({
    method: 'get',
    path: '/v1/sessions/:id',
    request: {
        params: SessionIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetSessionResponseSchema,
                },
            },
            description: 'Session details',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'Get session',
    description: 'Get a single session by ID. User must own the session.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(getSessionRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);

    const session = await db.query.sessions.findFirst({
        where: (sessions, { eq, and }) =>
            and(eq(sessions.id, id), eq(sessions.accountId, userId)),
    });

    if (!session) {
        return c.json({ error: 'Session not found' }, 404);
    }

    return c.json({
        session: {
            id: session.id,
            seq: session.seq,
            createdAt: session.createdAt.getTime(),
            updatedAt: session.updatedAt.getTime(),
            active: session.active,
            activeAt: session.lastActiveAt.getTime(),
            metadata: session.metadata,
            metadataVersion: session.metadataVersion,
            agentState: session.agentState,
            agentStateVersion: session.agentStateVersion,
            dataEncryptionKey: session.dataEncryptionKey
                ? privacyKit.encodeBase64(session.dataEncryptionKey)
                : null,
            lastMessage: null,
        },
    });
});

// ============================================================================
// DELETE /v1/sessions/:id - Delete Session (Hard Delete)
// ============================================================================

const deleteSessionRoute = createRoute({
    method: 'delete',
    path: '/v1/sessions/:id',
    request: {
        params: SessionIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: DeleteSessionResponseSchema,
                },
            },
            description: 'Session deleted',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'Delete session',
    description: 'Permanently delete a session and all its related data. User must own the session.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(deleteSessionRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);

    // Verify session exists and belongs to user
    const session = await db.query.sessions.findFirst({
        where: (sessions, { eq, and }) =>
            and(eq(sessions.id, id), eq(sessions.accountId, userId)),
    });

    if (!session) {
        return c.json({ error: 'Session not found' }, 404);
    }

    // Hard delete: Remove session and all related data
    // Order matters due to foreign key constraints

    // 1. Delete all session messages
    await db
        .delete(schema.sessionMessages)
        .where(eq(schema.sessionMessages.sessionId, id));

    // 2. Delete all usage reports for this session
    await db
        .delete(schema.usageReports)
        .where(eq(schema.usageReports.sessionId, id));

    // 3. Delete all access keys for this session
    await db
        .delete(schema.accessKeys)
        .where(eq(schema.accessKeys.sessionId, id));

    // 4. Delete the session itself
    await db
        .delete(schema.sessions)
        .where(eq(schema.sessions.id, id));

    // 5. Allocate sequence number for the update event
    const [account] = await db
        .update(schema.accounts)
        .set({ seq: sql`${schema.accounts.seq} + 1` })
        .where(eq(schema.accounts.id, userId))
        .returning({ seq: schema.accounts.seq });

    // 6. Emit delete-session event to connected clients
    const connectionManager = c.env.CONNECTION_MANAGER;
    if (connectionManager) {
        const updateId = createId();
        const eventRouter = getEventRouter({ CONNECTION_MANAGER: connectionManager });
        await eventRouter.emitUpdate({
            userId,
            payload: buildDeleteSessionUpdate(id, account?.seq ?? 0, updateId),
        });
    }

    return c.json({ success: true });
});

// ============================================================================
// GET /v1/sessions/:id/state - Get Session State (HAP-734)
// ============================================================================

const getSessionStateRoute = createRoute({
    method: 'get',
    path: '/v1/sessions/:id/state',
    request: {
        params: SessionIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: SessionStateResponseSchema,
                },
            },
            description: 'Session state information',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'Get session state',
    description: 'Returns the current state of a session (active, stopped, or archived) for revival flow coordination.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(getSessionStateRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);

    const session = await db.query.sessions.findFirst({
        where: (sessions, { eq, and }) =>
            and(eq(sessions.id, id), eq(sessions.accountId, userId)),
    });

    if (!session) {
        return c.json({ error: 'Session not found' }, 404);
    }

    // Derive state from database fields
    // Priority: archived > stopped > active
    let state: 'active' | 'stopped' | 'archived';
    if (session.archivedAt) {
        state = 'archived';
    } else if (!session.active || session.stoppedAt) {
        state = 'stopped';
    } else {
        state = 'active';
    }

    return c.json({
        sessionId: session.id,
        state,
        stoppedAt: session.stoppedAt ? session.stoppedAt.toISOString() : null,
        stoppedReason: session.stoppedReason || null,
        lastActivity: session.lastActiveAt ? session.lastActiveAt.toISOString() : null,
    });
});

// ============================================================================
// POST /v1/sessions/:id/archive - Archive Session (HAP-734)
// ============================================================================

const archiveSessionRoute = createRoute({
    method: 'post',
    path: '/v1/sessions/:id/archive',
    request: {
        params: SessionIdParamSchema,
        body: {
            content: {
                'application/json': {
                    schema: ArchiveSessionRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ArchiveSessionResponseSchema,
                },
            },
            description: 'Session archived successfully',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session not found',
        },
        400: {
            content: {
                'application/json': {
                    schema: BadRequestErrorSchema,
                },
            },
            description: 'Session already archived',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'Archive session',
    description: 'Archives a session that failed revival attempts. Archived sessions are excluded from active session lists.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(archiveSessionRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const { reason, originalError } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Verify session exists and belongs to user
    const session = await db.query.sessions.findFirst({
        where: (sessions, { eq, and }) =>
            and(eq(sessions.id, id), eq(sessions.accountId, userId)),
    });

    if (!session) {
        return c.json({ error: 'Session not found' }, 404);
    }

    // Check if already archived
    if (session.archivedAt) {
        return c.json({ error: 'Session already archived' }, 400);
    }

    // Check if session has any messages
    const [messageCount] = await db
        .select({ count: count() })
        .from(schema.sessionMessages)
        .where(eq(schema.sessionMessages.sessionId, id));

    const hasMessages = (messageCount?.count ?? 0) > 0;

    // Allocate sequence number for the update event
    const [account] = await db
        .update(schema.accounts)
        .set({ seq: sql`${schema.accounts.seq} + 1` })
        .where(eq(schema.accounts.id, userId))
        .returning({ seq: schema.accounts.seq });

    const connectionManager = c.env.CONNECTION_MANAGER;
    const updateId = createId();

    if (!hasMessages) {
        // Session has no messages - delete it entirely (consistency with handleSessionEnd)
        // Delete related data first (usage reports, access keys)
        await db.delete(schema.usageReports).where(eq(schema.usageReports.sessionId, id));
        await db.delete(schema.accessKeys).where(eq(schema.accessKeys.sessionId, id));
        // Delete the session (no messages to delete since count is 0)
        await db.delete(schema.sessions).where(eq(schema.sessions.id, id));

        // Emit delete-session event to connected clients
        if (connectionManager) {
            const eventRouter = getEventRouter({ CONNECTION_MANAGER: connectionManager });
            await eventRouter.emitUpdate({
                userId,
                payload: buildDeleteSessionUpdate(id, account?.seq ?? 0, updateId),
            });
        }

        return c.json({
            success: true,
            sessionId: id,
            deleted: true,
        });
    }

    // Session has messages - archive it normally
    const now = new Date();

    await db
        .update(schema.sessions)
        .set({
            active: false,
            archivedAt: now,
            archiveReason: reason,
            archiveError: originalError || null,
        })
        .where(eq(schema.sessions.id, id));

    // Emit archive-session event to connected clients
    if (connectionManager) {
        const eventRouter = getEventRouter({ CONNECTION_MANAGER: connectionManager });
        await eventRouter.emitUpdate({
            userId,
            payload: buildArchiveSessionUpdate(
                id,
                now.getTime(),
                reason,
                account?.seq ?? 0,
                updateId
            ),
        });
    }

    return c.json({
        success: true,
        sessionId: id,
        archivedAt: now.toISOString(),
    });
});

// ============================================================================
// POST /v1/sessions/:id/messages - Create Session Message
// ============================================================================

const createSessionMessageRoute = createRoute({
    method: 'post',
    path: '/v1/sessions/:id/messages',
    request: {
        params: SessionIdParamSchema,
        body: {
            content: {
                'application/json': {
                    schema: CreateSessionMessageRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: CreateSessionMessageResponseSchema,
                },
            },
            description: 'Message created',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'Create session message',
    description: 'Create a new message in a session. User must own the session.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(createSessionMessageRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId } = c.req.valid('param');
    const { localId, content } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Verify session exists and belongs to user
    const session = await db.query.sessions.findFirst({
        where: (sessions, { eq, and }) =>
            and(eq(sessions.id, sessionId), eq(sessions.accountId, userId)),
    });

    if (!session) {
        return c.json({ error: 'Session not found' }, 404);
    }

    // Get next sequence number (count existing messages + 1)
    const existingMessages = await db
        .select()
        .from(schema.sessionMessages)
        .where(eq(schema.sessionMessages.sessionId, sessionId));
    const nextSeq = existingMessages.length;

    // Create message
    const newMessages = await db
        .insert(schema.sessionMessages)
        .values({
            id: createId(),
            sessionId,
            localId: localId || null,
            seq: nextSeq,
            content: JSON.stringify(content),
        })
        .returning();

    const message = newMessages[0];
    if (!message) {
        return c.json({ error: 'Failed to create message' }, 500);
    }

    return c.json({
        message: {
            id: message.id,
            sessionId: message.sessionId,
            localId: message.localId,
            seq: message.seq,
            content: JSON.parse(message.content as string),
            createdAt: message.createdAt.getTime(),
            updatedAt: message.updatedAt.getTime(),
        },
    });
});

// ============================================================================
// GET /v1/sessions/:id/messages - List Session Messages
// ============================================================================

const listSessionMessagesRoute = createRoute({
    method: 'get',
    path: '/v1/sessions/:id/messages',
    request: {
        params: SessionIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ListSessionMessagesResponseSchema,
                },
            },
            description: 'List of session messages',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'List session messages',
    description: 'Get all messages for a session. Returns up to 150 messages ordered by most recent. User must own the session.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(listSessionMessagesRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId } = c.req.valid('param');
    const db = getDb(c.env.DB);

    // Verify session exists and belongs to user
    const session = await db.query.sessions.findFirst({
        where: (sessions, { eq, and }) =>
            and(eq(sessions.id, sessionId), eq(sessions.accountId, userId)),
    });

    if (!session) {
        return c.json({ error: 'Session not found' }, 404);
    }

    // Fetch messages ordered by createdAt descending (most recent first)
    const messages = await db.query.sessionMessages.findMany({
        where: (sessionMessages, { eq }) => eq(sessionMessages.sessionId, sessionId),
        orderBy: (sessionMessages, { desc }) => [desc(sessionMessages.createdAt)],
        limit: 150,
    });

    return c.json({
        messages: messages.map((m) => ({
            id: m.id,
            sessionId: m.sessionId,
            localId: m.localId,
            seq: m.seq,
            content: m.content,
            createdAt: m.createdAt.getTime(),
            updatedAt: m.updatedAt.getTime(),
        })),
    });
});

// ============================================================================
// GET /v2/sessions/:id/messages - List Session Messages with Pagination
// ============================================================================

const paginatedMessagesRoute = createRoute({
    method: 'get',
    path: '/v2/sessions/:id/messages',
    request: {
        params: SessionIdParamSchema,
        query: PaginatedMessagesQuerySchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: PaginatedMessagesResponseSchema,
                },
            },
            description: 'Paginated list of session messages',
        },
        400: {
            content: {
                'application/json': {
                    schema: BadRequestErrorSchema,
                },
            },
            description: 'Invalid cursor format',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Sessions'],
    summary: 'List session messages with pagination',
    description: 'Cursor-based pagination for session messages. Always sorted by ID descending (most recent first).',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sessionRoutes.openapi(paginatedMessagesRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId } = c.req.valid('param');
    const { cursor, limit = 50 } = c.req.valid('query');
    const db = getDb(c.env.DB);

    // Verify session exists and belongs to user
    const session = await db.query.sessions.findFirst({
        where: (sessions, { eq, and }) =>
            and(eq(sessions.id, sessionId), eq(sessions.accountId, userId)),
    });

    if (!session) {
        return c.json({ error: 'Session not found' }, 404);
    }

    // Decode cursor - simple ID-based cursor
    let cursorMessageId: string | undefined;
    if (cursor) {
        if (cursor.startsWith('cursor_v1_')) {
            cursorMessageId = cursor.substring(10);
        } else {
            return c.json({ error: 'Invalid cursor format' }, 400);
        }
    }

    // Build where conditions
    const conditions = [eq(schema.sessionMessages.sessionId, sessionId)];

    // Add cursor pagination
    if (cursorMessageId) {
        conditions.push(lt(schema.sessionMessages.id, cursorMessageId));
    }

    // Fetch messages with +1 to check for more
    const messages = await db
        .select()
        .from(schema.sessionMessages)
        .where(and(...conditions))
        .orderBy(desc(schema.sessionMessages.id))
        .limit(limit + 1);

    // Check if there are more results
    const hasNext = messages.length > limit;
    const resultMessages = hasNext ? messages.slice(0, limit) : messages;

    // Generate next cursor
    let nextCursor: string | null = null;
    const lastMessage = resultMessages[resultMessages.length - 1];
    if (hasNext && lastMessage) {
        nextCursor = `cursor_v1_${lastMessage.id}`;
    }

    return c.json({
        messages: resultMessages.map((m) => ({
            id: m.id,
            sessionId: m.sessionId,
            localId: m.localId,
            seq: m.seq,
            content: m.content,
            createdAt: m.createdAt.getTime(),
            updatedAt: m.updatedAt.getTime(),
        })),
        nextCursor,
    });
});

export default sessionRoutes;
