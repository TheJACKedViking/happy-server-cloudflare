import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { createId } from '@/utils/id';
// TODO: HAP-264 - Replace with jose-based implementation
// privacy-kit fails in Workers due to createRequire(import.meta.url)
import * as privacyKit from '@/lib/privacy-kit-shim';
import { eq, desc, lt, gt, and } from 'drizzle-orm';
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
    BadRequestErrorSchema,
    NotFoundErrorSchema,
    UnauthorizedErrorSchema,
} from '@/schemas/sessions';

/**
 * Environment bindings for session routes
 */
interface Env {
    DB: D1Database;
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
 * - DELETE /v1/sessions/:id - Delete session (soft delete, sets active=false)
 * - POST /v1/sessions/:id/messages - Create message in session
 * - GET /v1/sessions/:id/messages - List messages in session
 *
 * All routes use OpenAPI schemas for automatic documentation and validation.
 */
const sessionRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all session routes
sessionRoutes.use('/v1/sessions/*', authMiddleware());
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
// DELETE /v1/sessions/:id - Delete Session (Soft Delete)
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
    description: 'Soft delete a session (sets active=false). User must own the session.',
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

    // Soft delete: set active=false
    await db
        .update(schema.sessions)
        .set({
            active: false,
            updatedAt: new Date(),
        })
        .where(eq(schema.sessions.id, id));

    return c.json({ success: true });
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

export default sessionRoutes;
