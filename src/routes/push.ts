import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { createId } from '@/utils/id';
import { eq, and, desc } from 'drizzle-orm';
import {
    RegisterPushTokenRequestSchema,
    PushTokenSuccessSchema,
    PushTokenParamSchema,
    ListPushTokensResponseSchema,
    PushTokenErrorSchema,
    UnauthorizedErrorSchema,
} from '@/schemas/push';

/**
 * Environment bindings for push routes
 */
interface Env {
    DB: D1Database;
}

/**
 * Push routes module
 *
 * Implements push notification token management:
 * - POST /v1/push-tokens - Register a push token
 * - DELETE /v1/push-tokens/:token - Delete a push token
 * - GET /v1/push-tokens - List all push tokens for user
 *
 * All routes require authentication and are scoped to the authenticated user.
 */
const pushRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all push routes
pushRoutes.use('/v1/push-tokens/*', authMiddleware());
pushRoutes.use('/v1/push-tokens', authMiddleware());

// ============================================================================
// POST /v1/push-tokens - Register Push Token
// ============================================================================

const registerPushTokenRoute = createRoute({
    method: 'post',
    path: '/v1/push-tokens',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: RegisterPushTokenRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: PushTokenSuccessSchema,
                },
            },
            description: 'Push token registered successfully',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        500: {
            content: {
                'application/json': {
                    schema: PushTokenErrorSchema,
                },
            },
            description: 'Failed to register push token',
        },
    },
    tags: ['Push Notifications'],
    summary: 'Register push token',
    description:
        'Register a push notification token. If the token already exists for the user, updates the timestamp. Idempotent operation.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
pushRoutes.openapi(registerPushTokenRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { token } = c.req.valid('json');
    const db = getDb(c.env.DB);

    try {
        // Check if token already exists for this user
        const existing = await db.query.accountPushTokens.findFirst({
            where: (tokens, { eq, and }) =>
                and(eq(tokens.accountId, userId), eq(tokens.token, token)),
        });

        if (existing) {
            // Update timestamp only
            await db
                .update(schema.accountPushTokens)
                .set({
                    updatedAt: new Date(),
                })
                .where(eq(schema.accountPushTokens.id, existing.id));
        } else {
            // Create new token record
            await db.insert(schema.accountPushTokens).values({
                id: createId(),
                accountId: userId,
                token,
            });
        }

        return c.json({ success: true as const });
    } catch (error) {
        console.error(`Failed to register push token: ${error}`);
        return c.json({ error: 'Failed to register push token' }, 500);
    }
});

// ============================================================================
// DELETE /v1/push-tokens/:token - Delete Push Token
// ============================================================================

const deletePushTokenRoute = createRoute({
    method: 'delete',
    path: '/v1/push-tokens/:token',
    request: {
        params: PushTokenParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: PushTokenSuccessSchema,
                },
            },
            description: 'Push token deleted successfully',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        500: {
            content: {
                'application/json': {
                    schema: PushTokenErrorSchema,
                },
            },
            description: 'Failed to delete push token',
        },
    },
    tags: ['Push Notifications'],
    summary: 'Delete push token',
    description: 'Delete a push notification token. User must own the token.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
pushRoutes.openapi(deletePushTokenRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { token } = c.req.valid('param');
    const db = getDb(c.env.DB);

    try {
        // Delete token(s) matching user and token value
        await db
            .delete(schema.accountPushTokens)
            .where(
                and(
                    eq(schema.accountPushTokens.accountId, userId),
                    eq(schema.accountPushTokens.token, token)
                )
            );

        return c.json({ success: true as const });
    } catch (error) {
        console.error(`Failed to delete push token: ${error}`);
        return c.json({ error: 'Failed to delete push token' }, 500);
    }
});

// ============================================================================
// GET /v1/push-tokens - List Push Tokens
// ============================================================================

const listPushTokensRoute = createRoute({
    method: 'get',
    path: '/v1/push-tokens',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ListPushTokensResponseSchema,
                },
            },
            description: 'List of push tokens',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        500: {
            content: {
                'application/json': {
                    schema: PushTokenErrorSchema,
                },
            },
            description: 'Failed to get push tokens',
        },
    },
    tags: ['Push Notifications'],
    summary: 'List push tokens',
    description:
        'List all push notification tokens for the authenticated user.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
pushRoutes.openapi(listPushTokensRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const db = getDb(c.env.DB);

    try {
        const tokens = await db
            .select()
            .from(schema.accountPushTokens)
            .where(eq(schema.accountPushTokens.accountId, userId))
            .orderBy(desc(schema.accountPushTokens.createdAt));

        return c.json({
            tokens: tokens.map((t) => ({
                id: t.id,
                token: t.token,
                createdAt: t.createdAt.getTime(),
                updatedAt: t.updatedAt.getTime(),
            })),
        });
    } catch (error) {
        console.error(`Failed to get push tokens: ${error}`);
        return c.json({ error: 'Failed to get push tokens' }, 500);
    }
});

export default pushRoutes;
