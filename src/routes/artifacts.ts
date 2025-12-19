import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
// Encoding utilities for base64/hex operations (Workers-compatible)
import * as privacyKit from '@/lib/privacy-kit-shim';
import { eq, desc, and } from 'drizzle-orm';
import {
    ListArtifactsResponseSchema,
    ArtifactIdParamSchema,
    GetArtifactResponseSchema,
    CreateArtifactRequestSchema,
    CreateArtifactResponseSchema,
    UpdateArtifactRequestSchema,
    UpdateArtifactResponseSchema,
    DeleteArtifactResponseSchema,
    NotFoundErrorSchema,
    ConflictErrorSchema,
    UnauthorizedErrorSchema,
} from '@/schemas/artifacts';

/**
 * Environment bindings for artifact routes
 */
interface Env {
    DB: D1Database;
}

/**
 * Artifact routes module
 *
 * Implements all artifact management endpoints:
 * - GET /v1/artifacts - List artifacts (headers only)
 * - GET /v1/artifacts/:id - Get artifact with full body
 * - POST /v1/artifacts - Create artifact (idempotent by ID)
 * - POST /v1/artifacts/:id - Update artifact with version control
 * - DELETE /v1/artifacts/:id - Delete artifact
 *
 * All routes use OpenAPI schemas for automatic documentation and validation.
 */
const artifactRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all artifact routes
artifactRoutes.use('/v1/artifacts/*', authMiddleware());

// ============================================================================
// GET /v1/artifacts - List Artifacts
// ============================================================================

const listArtifactsRoute = createRoute({
    method: 'get',
    path: '/v1/artifacts',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ListArtifactsResponseSchema,
                },
            },
            description: 'List of artifacts (headers only, no body)',
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
    tags: ['Artifacts'],
    summary: 'List user artifacts',
    description: 'Returns artifact headers without body content, ordered by most recent.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
artifactRoutes.openapi(listArtifactsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    const artifacts = await db
        .select({
            id: schema.artifacts.id,
            header: schema.artifacts.header,
            headerVersion: schema.artifacts.headerVersion,
            dataEncryptionKey: schema.artifacts.dataEncryptionKey,
            seq: schema.artifacts.seq,
            createdAt: schema.artifacts.createdAt,
            updatedAt: schema.artifacts.updatedAt,
        })
        .from(schema.artifacts)
        .where(eq(schema.artifacts.accountId, userId))
        .orderBy(desc(schema.artifacts.updatedAt));

    return c.json({
        artifacts: artifacts.map((a) => ({
            id: a.id,
            header: privacyKit.encodeBase64(a.header),
            headerVersion: a.headerVersion,
            dataEncryptionKey: privacyKit.encodeBase64(a.dataEncryptionKey),
            seq: a.seq,
            createdAt: a.createdAt.getTime(),
            updatedAt: a.updatedAt.getTime(),
        })),
    });
});

// ============================================================================
// GET /v1/artifacts/:id - Get Artifact
// ============================================================================

const getArtifactRoute = createRoute({
    method: 'get',
    path: '/v1/artifacts/:id',
    request: {
        params: ArtifactIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetArtifactResponseSchema,
                },
            },
            description: 'Artifact with full body',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Artifact not found',
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
    tags: ['Artifacts'],
    summary: 'Get artifact',
    description: 'Get a single artifact with full body content. User must own the artifact.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
artifactRoutes.openapi(getArtifactRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);

    const artifact = await db.query.artifacts.findFirst({
        where: (artifacts, { eq, and }) =>
            and(eq(artifacts.id, id), eq(artifacts.accountId, userId)),
    });

    if (!artifact) {
        return c.json({ error: 'Artifact not found' }, 404);
    }

    return c.json({
        artifact: {
            id: artifact.id,
            header: privacyKit.encodeBase64(artifact.header),
            headerVersion: artifact.headerVersion,
            body: privacyKit.encodeBase64(artifact.body),
            bodyVersion: artifact.bodyVersion,
            dataEncryptionKey: privacyKit.encodeBase64(artifact.dataEncryptionKey),
            seq: artifact.seq,
            createdAt: artifact.createdAt.getTime(),
            updatedAt: artifact.updatedAt.getTime(),
        },
    });
});

// ============================================================================
// POST /v1/artifacts - Create Artifact
// ============================================================================

const createArtifactRoute = createRoute({
    method: 'post',
    path: '/v1/artifacts',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: CreateArtifactRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: CreateArtifactResponseSchema,
                },
            },
            description: 'Artifact created or existing artifact returned (idempotent)',
        },
        409: {
            content: {
                'application/json': {
                    schema: ConflictErrorSchema,
                },
            },
            description: 'Artifact ID already exists for another account',
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
    tags: ['Artifacts'],
    summary: 'Create artifact',
    description: 'Create a new artifact. Idempotent by ID - returns existing artifact if ID matches.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
artifactRoutes.openapi(createArtifactRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id, header, body, dataEncryptionKey } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Check if artifact already exists
    const existingArtifact = await db.query.artifacts.findFirst({
        where: (artifacts, { eq }) => eq(artifacts.id, id),
    });

    if (existingArtifact) {
        // If exists for another account, return conflict
        if (existingArtifact.accountId !== userId) {
            return c.json(
                {
                    error: 'Artifact with this ID already exists for another account',
                },
                409
            );
        }

        // If exists for same account, return existing (idempotent)
        return c.json({
            artifact: {
                id: existingArtifact.id,
                header: privacyKit.encodeBase64(existingArtifact.header),
                headerVersion: existingArtifact.headerVersion,
                body: privacyKit.encodeBase64(existingArtifact.body),
                bodyVersion: existingArtifact.bodyVersion,
                dataEncryptionKey: privacyKit.encodeBase64(existingArtifact.dataEncryptionKey),
                seq: existingArtifact.seq,
                createdAt: existingArtifact.createdAt.getTime(),
                updatedAt: existingArtifact.updatedAt.getTime(),
            },
        });
    }

    // Create new artifact
    const newArtifacts = await db
        .insert(schema.artifacts)
        .values({
            id,
            accountId: userId,
            header: Buffer.from(privacyKit.decodeBase64(header)),
            headerVersion: 1,
            body: Buffer.from(privacyKit.decodeBase64(body)),
            bodyVersion: 1,
            dataEncryptionKey: Buffer.from(privacyKit.decodeBase64(dataEncryptionKey)),
            seq: 0,
        })
        .returning();

    const artifact = newArtifacts[0];
    if (!artifact) {
        // Log detailed error server-side for debugging
        console.error(`Database insert operation returned no rows when creating artifact with id: ${id}`);
        return c.json(
            { error: 'Failed to create artifact due to a server error.' },
            500
        );
    }

    return c.json({
        artifact: {
            id: artifact.id,
            header: privacyKit.encodeBase64(artifact.header),
            headerVersion: artifact.headerVersion,
            body: privacyKit.encodeBase64(artifact.body),
            bodyVersion: artifact.bodyVersion,
            dataEncryptionKey: privacyKit.encodeBase64(artifact.dataEncryptionKey),
            seq: artifact.seq,
            createdAt: artifact.createdAt.getTime(),
            updatedAt: artifact.updatedAt.getTime(),
        },
    });
});

// ============================================================================
// POST /v1/artifacts/:id - Update Artifact
// ============================================================================

const updateArtifactRoute = createRoute({
    method: 'post',
    path: '/v1/artifacts/:id',
    request: {
        params: ArtifactIdParamSchema,
        body: {
            content: {
                'application/json': {
                    schema: UpdateArtifactRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UpdateArtifactResponseSchema,
                },
            },
            description: 'Artifact updated or version mismatch',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Artifact not found',
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
    tags: ['Artifacts'],
    summary: 'Update artifact',
    description: 'Update artifact header and/or body with optimistic locking. Returns version-mismatch on conflict.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
artifactRoutes.openapi(updateArtifactRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const { header, expectedHeaderVersion, body, expectedBodyVersion } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Get current artifact for version check
    const currentArtifact = await db.query.artifacts.findFirst({
        where: (artifacts, { eq, and }) =>
            and(eq(artifacts.id, id), eq(artifacts.accountId, userId)),
    });

    if (!currentArtifact) {
        return c.json({ error: 'Artifact not found' }, 404);
    }

    // Check version mismatches
    const headerMismatch =
        header !== undefined &&
        expectedHeaderVersion !== undefined &&
        currentArtifact.headerVersion !== expectedHeaderVersion;

    const bodyMismatch =
        body !== undefined &&
        expectedBodyVersion !== undefined &&
        currentArtifact.bodyVersion !== expectedBodyVersion;

    if (headerMismatch || bodyMismatch) {
        return c.json({
            success: false,
            error: 'version-mismatch',
            ...(headerMismatch && {
                currentHeaderVersion: currentArtifact.headerVersion,
                currentHeader: privacyKit.encodeBase64(currentArtifact.header),
            }),
            ...(bodyMismatch && {
                currentBodyVersion: currentArtifact.bodyVersion,
                currentBody: privacyKit.encodeBase64(currentArtifact.body),
            }),
        });
    }

    // Build update data
    const updates: {
        updatedAt: Date;
        seq: number;
        header?: Uint8Array;
        headerVersion?: number;
        body?: Uint8Array;
        bodyVersion?: number;
    } = {
        updatedAt: new Date(),
        seq: currentArtifact.seq + 1,
    };

    let newHeaderVersion: number | undefined;
    let newBodyVersion: number | undefined;

    if (header !== undefined && expectedHeaderVersion !== undefined) {
        updates.header = privacyKit.decodeBase64(header);
        updates.headerVersion = expectedHeaderVersion + 1;
        newHeaderVersion = expectedHeaderVersion + 1;
    }

    if (body !== undefined && expectedBodyVersion !== undefined) {
        updates.body = privacyKit.decodeBase64(body);
        updates.bodyVersion = expectedBodyVersion + 1;
        newBodyVersion = expectedBodyVersion + 1;
    }

    // Convert Uint8Array to Buffer for Drizzle blob columns
    const drizzleUpdates: {
        updatedAt: Date;
        seq: number;
        header?: Buffer;
        headerVersion?: number;
        body?: Buffer;
        bodyVersion?: number;
    } = {
        updatedAt: updates.updatedAt,
        seq: updates.seq,
        ...(updates.headerVersion !== undefined && {
            header: Buffer.from(updates.header!),
            headerVersion: updates.headerVersion,
        }),
        ...(updates.bodyVersion !== undefined && {
            body: Buffer.from(updates.body!),
            bodyVersion: updates.bodyVersion,
        }),
    };

    // Update artifact
    await db
        .update(schema.artifacts)
        .set(drizzleUpdates)
        .where(and(eq(schema.artifacts.id, id), eq(schema.artifacts.accountId, userId)));

    return c.json({
        success: true,
        ...(newHeaderVersion && { headerVersion: newHeaderVersion }),
        ...(newBodyVersion && { bodyVersion: newBodyVersion }),
    });
});

// ============================================================================
// DELETE /v1/artifacts/:id - Delete Artifact
// ============================================================================

const deleteArtifactRoute = createRoute({
    method: 'delete',
    path: '/v1/artifacts/:id',
    request: {
        params: ArtifactIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: DeleteArtifactResponseSchema,
                },
            },
            description: 'Artifact deleted',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Artifact not found',
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
    tags: ['Artifacts'],
    summary: 'Delete artifact',
    description: 'Delete an artifact. User must own the artifact.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
artifactRoutes.openapi(deleteArtifactRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);

    // Verify artifact exists and belongs to user
    const artifact = await db.query.artifacts.findFirst({
        where: (artifacts, { eq, and }) =>
            and(eq(artifacts.id, id), eq(artifacts.accountId, userId)),
    });

    if (!artifact) {
        return c.json({ error: 'Artifact not found' }, 404);
    }

    // Delete artifact
    await db.delete(schema.artifacts).where(eq(schema.artifacts.id, id));

    return c.json({ success: true });
});

export default artifactRoutes;
