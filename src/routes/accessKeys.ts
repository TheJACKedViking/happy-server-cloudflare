import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { createId } from '@/utils/id';
import { eq, and } from 'drizzle-orm';
import {
    AccessKeyParamsSchema,
    GetAccessKeyResponseSchema,
    CreateAccessKeyRequestSchema,
    CreateAccessKeyResponseSchema,
    UpdateAccessKeyRequestSchema,
    UpdateAccessKeyResponseSchema,
    NotFoundErrorSchema,
    ConflictErrorSchema,
    UnauthorizedErrorSchema,
} from '@/schemas/accessKeys';

/**
 * Environment bindings for access key routes
 */
interface Env {
    DB: D1Database;
}

/**
 * Access Key routes module
 *
 * Implements all access key management endpoints:
 * - GET /v1/access-keys/:sessionId/:machineId - Get access key
 * - POST /v1/access-keys/:sessionId/:machineId - Create access key
 * - PUT /v1/access-keys/:sessionId/:machineId - Update access key
 *
 * Access keys use composite unique key: (accountId + machineId + sessionId)
 *
 * All routes use OpenAPI schemas for automatic documentation and validation.
 */
const accessKeyRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all access key routes
accessKeyRoutes.use('/v1/access-keys/*', authMiddleware());

// ============================================================================
// GET /v1/access-keys/:sessionId/:machineId - Get Access Key
// ============================================================================

const getAccessKeyRoute = createRoute({
    method: 'get',
    path: '/v1/access-keys/:sessionId/:machineId',
    request: {
        params: AccessKeyParamsSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetAccessKeyResponseSchema,
                },
            },
            description: 'Access key or null if not found',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session or machine not found',
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
    tags: ['Access Keys'],
    summary: 'Get access key',
    description: 'Get an access key by session and machine ID. Returns null if not found.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accessKeyRoutes.openapi(getAccessKeyRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { sessionId, machineId } = c.req.valid('param');
    const db = getDb(c.env.DB);

    // Verify session and machine belong to user
    const [session, machine] = await Promise.all([
        db.query.sessions.findFirst({
            where: (sessions, { eq, and }) =>
                and(eq(sessions.id, sessionId), eq(sessions.accountId, userId)),
        }),
        db.query.machines.findFirst({
            where: (machines, { eq, and }) =>
                and(eq(machines.id, machineId), eq(machines.accountId, userId)),
        }),
    ]);

    if (!session || !machine) {
        return c.json({ error: 'Session or machine not found' }, 404);
    }

    // Get access key
    const accessKey = await db.query.accessKeys.findFirst({
        where: (accessKeys, { eq, and }) =>
            and(
                eq(accessKeys.accountId, userId),
                eq(accessKeys.machineId, machineId),
                eq(accessKeys.sessionId, sessionId)
            ),
    });

    if (!accessKey) {
        return c.json({ accessKey: null });
    }

    return c.json({
        accessKey: {
            data: accessKey.data,
            dataVersion: accessKey.dataVersion,
            createdAt: accessKey.createdAt.getTime(),
            updatedAt: accessKey.updatedAt.getTime(),
        },
    });
});

// ============================================================================
// POST /v1/access-keys/:sessionId/:machineId - Create Access Key
// ============================================================================

const createAccessKeyRoute = createRoute({
    method: 'post',
    path: '/v1/access-keys/:sessionId/:machineId',
    request: {
        params: AccessKeyParamsSchema,
        body: {
            content: {
                'application/json': {
                    schema: CreateAccessKeyRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: CreateAccessKeyResponseSchema,
                },
            },
            description: 'Access key created',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session or machine not found',
        },
        409: {
            content: {
                'application/json': {
                    schema: ConflictErrorSchema,
                },
            },
            description: 'Access key already exists',
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
    tags: ['Access Keys'],
    summary: 'Create access key',
    description: 'Create a new access key for a session-machine pair. Fails if already exists.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accessKeyRoutes.openapi(createAccessKeyRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { sessionId, machineId } = c.req.valid('param');
    const { data } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Verify session and machine belong to user
    const [session, machine] = await Promise.all([
        db.query.sessions.findFirst({
            where: (sessions, { eq, and }) =>
                and(eq(sessions.id, sessionId), eq(sessions.accountId, userId)),
        }),
        db.query.machines.findFirst({
            where: (machines, { eq, and }) =>
                and(eq(machines.id, machineId), eq(machines.accountId, userId)),
        }),
    ]);

    if (!session || !machine) {
        return c.json({ error: 'Session or machine not found' }, 404);
    }

    // Check if access key already exists
    const existing = await db.query.accessKeys.findFirst({
        where: (accessKeys, { eq, and }) =>
            and(
                eq(accessKeys.accountId, userId),
                eq(accessKeys.machineId, machineId),
                eq(accessKeys.sessionId, sessionId)
            ),
    });

    if (existing) {
        return c.json({ error: 'Access key already exists' }, 409);
    }

    // Create access key
    const newAccessKeys = await db
        .insert(schema.accessKeys)
        .values({
            id: createId(),
            accountId: userId,
            machineId,
            sessionId,
            data,
            dataVersion: 1,
        })
        .returning();

    const accessKey = newAccessKeys[0];
    if (!accessKey) {
        return c.json(
            { error: `Database insert operation returned no rows when creating access key for session ${sessionId} and machine ${machineId}` },
            500
        );
    }

    return c.json({
        success: true,
        accessKey: {
            data: accessKey.data,
            dataVersion: accessKey.dataVersion,
            createdAt: accessKey.createdAt.getTime(),
            updatedAt: accessKey.updatedAt.getTime(),
        },
    });
});

// ============================================================================
// PUT /v1/access-keys/:sessionId/:machineId - Update Access Key
// ============================================================================

const updateAccessKeyRoute = createRoute({
    method: 'put',
    path: '/v1/access-keys/:sessionId/:machineId',
    request: {
        params: AccessKeyParamsSchema,
        body: {
            content: {
                'application/json': {
                    schema: UpdateAccessKeyRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UpdateAccessKeyResponseSchema,
                },
            },
            description: 'Access key updated or version mismatch',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Access key not found',
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
    tags: ['Access Keys'],
    summary: 'Update access key',
    description: 'Update an access key with optimistic locking. Returns version-mismatch on conflict.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accessKeyRoutes.openapi(updateAccessKeyRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { sessionId, machineId } = c.req.valid('param');
    const { data, expectedVersion } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Get current access key for version check
    const currentAccessKey = await db.query.accessKeys.findFirst({
        where: (accessKeys, { eq, and }) =>
            and(
                eq(accessKeys.accountId, userId),
                eq(accessKeys.machineId, machineId),
                eq(accessKeys.sessionId, sessionId)
            ),
    });

    if (!currentAccessKey) {
        return c.json({ error: 'Access key not found' }, 404);
    }

    // Check version
    if (currentAccessKey.dataVersion !== expectedVersion) {
        return c.json({
            success: false,
            error: 'version-mismatch',
            currentVersion: currentAccessKey.dataVersion,
            currentData: currentAccessKey.data,
        });
    }

    // Update with version increment
    const updatedAccessKeys = await db
        .update(schema.accessKeys)
        .set({
            data,
            dataVersion: expectedVersion + 1,
            updatedAt: new Date(),
        })
        .where(
            and(
                eq(schema.accessKeys.accountId, userId),
                eq(schema.accessKeys.machineId, machineId),
                eq(schema.accessKeys.sessionId, sessionId),
                eq(schema.accessKeys.dataVersion, expectedVersion)
            )
        )
        .returning();

    // Check if update actually happened (version could have changed between checks)
    if (updatedAccessKeys.length === 0) {
        // Re-fetch to get current version
        const accessKey = await db.query.accessKeys.findFirst({
            where: (accessKeys, { eq, and }) =>
                and(
                    eq(accessKeys.accountId, userId),
                    eq(accessKeys.machineId, machineId),
                    eq(accessKeys.sessionId, sessionId)
                ),
        });

        return c.json({
            success: false,
            error: 'version-mismatch',
            currentVersion: accessKey?.dataVersion || 0,
            currentData: accessKey?.data || '',
        });
    }

    return c.json({
        success: true,
        version: expectedVersion + 1,
    });
});

export default accessKeyRoutes;
