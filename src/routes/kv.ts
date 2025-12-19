import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { createId } from '@/utils/id';
// Encoding utilities for base64/hex operations (Workers-compatible)
import * as privacyKit from '@/lib/privacy-kit-shim';
import { eq, and, like } from 'drizzle-orm';
import {
    KVKeyParamSchema,
    KVGetResponseSchema,
    KVListQuerySchema,
    KVListResponseSchema,
    KVBulkGetRequestSchema,
    KVBulkGetResponseSchema,
    KVMutateRequestSchema,
    KVMutateSuccessSchema,
    KVMutateConflictSchema,
    KVNotFoundSchema,
    KVInternalErrorSchema,
    UnauthorizedErrorSchema,
} from '@/schemas/kv';

/**
 * Environment bindings for KV routes
 */
interface Env {
    DB: D1Database;
}

/**
 * KV routes module
 *
 * Implements key-value storage endpoints:
 * - GET /v1/kv/:key - Get single value
 * - GET /v1/kv - List key-value pairs with optional prefix filter
 * - POST /v1/kv/bulk - Bulk get values
 * - POST /v1/kv - Atomic batch mutation (create/update/delete)
 *
 * All routes require authentication and are scoped to the authenticated user.
 * Values are stored encrypted (encryption is handled client-side).
 */
const kvRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all KV routes
kvRoutes.use('/v1/kv/*', authMiddleware());
kvRoutes.use('/v1/kv', authMiddleware());

// ============================================================================
// GET /v1/kv/:key - Get Single Value
// ============================================================================

const getKVRoute = createRoute({
    method: 'get',
    path: '/v1/kv/:key',
    request: {
        params: KVKeyParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: KVGetResponseSchema,
                },
            },
            description: 'Key-value pair',
        },
        404: {
            content: {
                'application/json': {
                    schema: KVNotFoundSchema,
                },
            },
            description: 'Key not found',
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
                    schema: KVInternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Key-Value Storage'],
    summary: 'Get single value',
    description: 'Get a single key-value pair by key. User must own the key.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
kvRoutes.openapi(getKVRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { key } = c.req.valid('param');
    const db = getDb(c.env.DB);

    try {
        const result = await db.query.userKVStores.findFirst({
            where: (kv, { eq, and }) =>
                and(eq(kv.accountId, userId), eq(kv.key, key)),
        });

        if (!result || !result.value) {
            return c.json({ error: 'Key not found' as const }, 404);
        }

        return c.json({
            key: result.key,
            value: privacyKit.encodeBase64(result.value),
            version: result.version,
        });
    } catch (error) {
        console.error(`Failed to get KV value: ${error}`);
        return c.json({ error: 'Failed to get value' }, 500);
    }
});

// ============================================================================
// GET /v1/kv - List Key-Value Pairs
// ============================================================================

const listKVRoute = createRoute({
    method: 'get',
    path: '/v1/kv',
    request: {
        query: KVListQuerySchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: KVListResponseSchema,
                },
            },
            description: 'List of key-value pairs',
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
                    schema: KVInternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Key-Value Storage'],
    summary: 'List key-value pairs',
    description:
        'List key-value pairs with optional prefix filter. User sees only their own keys.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
kvRoutes.openapi(listKVRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { prefix, limit } = c.req.valid('query');
    const db = getDb(c.env.DB);

    try {
        const conditions = [eq(schema.userKVStores.accountId, userId)];

        if (prefix) {
            conditions.push(like(schema.userKVStores.key, `${prefix}%`));
        }

        const results = await db
            .select()
            .from(schema.userKVStores)
            .where(and(...conditions))
            .limit(limit);

        const items = results
            .filter((item) => item.value !== null)
            .map((item) => ({
                key: item.key,
                value: item.value ? privacyKit.encodeBase64(item.value) : '',
                version: item.version,
            }));

        return c.json({ items });
    } catch (error) {
        console.error(`Failed to list KV items: ${error}`);
        return c.json({ error: 'Failed to list items' }, 500);
    }
});

// ============================================================================
// POST /v1/kv/bulk - Bulk Get Values
// ============================================================================

const bulkGetKVRoute = createRoute({
    method: 'post',
    path: '/v1/kv/bulk',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: KVBulkGetRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: KVBulkGetResponseSchema,
                },
            },
            description: 'Bulk retrieved values',
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
                    schema: KVInternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Key-Value Storage'],
    summary: 'Bulk get values',
    description:
        'Get multiple key-value pairs by keys. Returns only existing keys.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
kvRoutes.openapi(bulkGetKVRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { keys } = c.req.valid('json');
    const db = getDb(c.env.DB);

    try {
        // Fetch all items for the user and filter to requested keys
        // Note: D1/SQLite doesn't support IN with dynamic arrays well, so we fetch all user's keys
        // and filter in memory for small key sets, or use individual queries for larger sets
        const results = await db.query.userKVStores.findMany({
            where: (kv, { eq }) => eq(kv.accountId, userId),
        });

        const keySet = new Set(keys);
        const values = results
            .filter((item) => keySet.has(item.key) && item.value !== null)
            .map((item) => ({
                key: item.key,
                value: item.value ? privacyKit.encodeBase64(item.value) : '',
                version: item.version,
            }));

        return c.json({ values });
    } catch (error) {
        console.error(`Failed to bulk get KV values: ${error}`);
        return c.json({ error: 'Failed to get values' }, 500);
    }
});

// ============================================================================
// POST /v1/kv - Atomic Batch Mutation
// ============================================================================

const mutateKVRoute = createRoute({
    method: 'post',
    path: '/v1/kv',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: KVMutateRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: KVMutateSuccessSchema,
                },
            },
            description: 'Mutation successful',
        },
        409: {
            content: {
                'application/json': {
                    schema: KVMutateConflictSchema,
                },
            },
            description: 'Version mismatch conflict',
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
                    schema: KVInternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Key-Value Storage'],
    summary: 'Atomic batch mutation',
    description:
        'Atomically create, update, or delete multiple key-value pairs. Uses optimistic locking with version numbers. Version -1 indicates a new key.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
kvRoutes.openapi(mutateKVRoute, async (c) => {
    const userId = (
        c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>
    ).get('userId');
    const { mutations } = c.req.valid('json');
    const db = getDb(c.env.DB);

    try {
        // Fetch current state of all keys
        const existingItems = await db.query.userKVStores.findMany({
            where: (kv, { eq }) => eq(kv.accountId, userId),
        });

        const existingByKey = new Map(
            existingItems.map((item) => [item.key, item])
        );

        // Validate versions
        const conflicts: Array<{
            key: string;
            error: 'version-mismatch';
            version: number;
            value: string | null;
        }> = [];

        for (const mutation of mutations) {
            const existing = existingByKey.get(mutation.key);

            if (mutation.version === -1) {
                // Creating new key - should not exist
                if (existing && existing.value !== null) {
                    conflicts.push({
                        key: mutation.key,
                        error: 'version-mismatch',
                        version: existing.version,
                        value: existing.value
                            ? privacyKit.encodeBase64(existing.value)
                            : null,
                    });
                }
            } else {
                // Updating/deleting - version must match
                const currentVersion = existing?.version ?? 0;
                if (currentVersion !== mutation.version) {
                    conflicts.push({
                        key: mutation.key,
                        error: 'version-mismatch',
                        version: currentVersion,
                        value: existing?.value
                            ? privacyKit.encodeBase64(existing.value)
                            : null,
                    });
                }
            }
        }

        if (conflicts.length > 0) {
            return c.json(
                {
                    success: false as const,
                    errors: conflicts,
                },
                409
            );
        }

        // Apply mutations
        const results: Array<{ key: string; version: number }> = [];

        for (const mutation of mutations) {
            const existing = existingByKey.get(mutation.key);
            const newVersion =
                mutation.version === -1 ? 1 : mutation.version + 1;

            if (mutation.value === null) {
                // Delete - set value to null (soft delete)
                if (existing) {
                    await db
                        .update(schema.userKVStores)
                        .set({
                            value: null,
                            version: newVersion,
                            updatedAt: new Date(),
                        })
                        .where(eq(schema.userKVStores.id, existing.id));
                }
                results.push({ key: mutation.key, version: newVersion });
            } else if (existing) {
                // Update existing
                await db
                    .update(schema.userKVStores)
                    .set({
                        value: Buffer.from(
                            privacyKit.decodeBase64(mutation.value)
                        ),
                        version: newVersion,
                        updatedAt: new Date(),
                    })
                    .where(eq(schema.userKVStores.id, existing.id));
                results.push({ key: mutation.key, version: newVersion });
            } else {
                // Create new
                await db.insert(schema.userKVStores).values({
                    id: createId(),
                    accountId: userId,
                    key: mutation.key,
                    value: Buffer.from(privacyKit.decodeBase64(mutation.value)),
                    version: 1,
                });
                results.push({ key: mutation.key, version: 1 });
            }
        }

        return c.json({
            success: true as const,
            results,
        });
    } catch (error) {
        console.error(`Failed to mutate KV values: ${error}`);
        return c.json({ error: 'Failed to mutate values' }, 500);
    }
});

export default kvRoutes;
