import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
// Encoding utilities for base64/hex operations (Workers-compatible)
import * as privacyKit from '@/lib/privacy-kit-shim';
import { eq, desc, and } from 'drizzle-orm';
import type { Context } from 'hono';
import {
    RegisterMachineRequestSchema,
    RegisterMachineResponseSchema,
    ListMachinesQuerySchema,
    ListMachinesResponseSchema,
    MachineIdParamSchema,
    GetMachineResponseSchema,
    UpdateMachineStatusRequestSchema,
    UpdateMachineStatusResponseSchema,
    NotFoundErrorSchema,
    UnauthorizedErrorSchema,
} from '@/schemas/machines';

/**
 * Environment bindings for machine routes
 */
interface Env {
    DB: D1Database;
}

/**
 * Machine routes module
 *
 * Implements all machine management endpoints:
 * - POST /v1/machines - Register machine (upsert by accountId+id)
 * - GET /v1/machines - List machines
 * - GET /v1/machines/:id - Get single machine
 * - PUT /v1/machines/:id/status - Update machine status
 *
 * All routes use OpenAPI schemas for automatic documentation and validation.
 */
const machineRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all machine routes
machineRoutes.use('/v1/machines/*', authMiddleware());

// ============================================================================
// POST /v1/machines - Register Machine (Upsert)
// ============================================================================

const registerMachineRoute = createRoute({
    method: 'post',
    path: '/v1/machines',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: RegisterMachineRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: RegisterMachineResponseSchema,
                },
            },
            description: 'Machine registered or existing machine returned',
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
    tags: ['Machines'],
    summary: 'Register machine',
    description: 'Register a new machine or return existing machine with same ID. Composite key: (accountId + id).',
});

// @ts-expect-error - OpenAPI handler type inference doesn't account for auth middleware Variables
machineRoutes.openapi(registerMachineRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id, metadata, daemonState, dataEncryptionKey } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Check if machine already exists for this user
    const existingMachine = await db.query.machines.findFirst({
        where: (machines, { eq, and }) =>
            and(eq(machines.accountId, userId), eq(machines.id, id)),
    });

    if (existingMachine) {
        // Return existing machine
        return c.json({
            machine: {
                id: existingMachine.id,
                accountId: existingMachine.accountId,
                metadata: existingMachine.metadata,
                metadataVersion: existingMachine.metadataVersion,
                daemonState: existingMachine.daemonState,
                daemonStateVersion: existingMachine.daemonStateVersion,
                dataEncryptionKey: existingMachine.dataEncryptionKey
                    ? privacyKit.encodeBase64(existingMachine.dataEncryptionKey)
                    : null,
                seq: existingMachine.seq,
                active: existingMachine.active,
                activeAt: existingMachine.lastActiveAt.getTime(),
                createdAt: existingMachine.createdAt.getTime(),
                updatedAt: existingMachine.updatedAt.getTime(),
            },
        });
    }

    // Create new machine (default to inactive)
    const newMachines = await db
        .insert(schema.machines)
        .values({
            id,
            accountId: userId,
            metadata,
            metadataVersion: 1,
            daemonState: daemonState || null,
            daemonStateVersion: daemonState ? 1 : 0,
            dataEncryptionKey: dataEncryptionKey
                ? Buffer.from(privacyKit.decodeBase64(dataEncryptionKey))
                : null,
            seq: 0,
            active: false, // Default to offline until status update
            lastActiveAt: new Date(),
        })
        .returning();

    const machine = newMachines[0];
    if (!machine) {
        return c.json({ error: 'Failed to register machine' }, 500);
    }

    return c.json({
        machine: {
            id: machine.id,
            accountId: machine.accountId,
            metadata: machine.metadata,
            metadataVersion: machine.metadataVersion,
            daemonState: machine.daemonState,
            daemonStateVersion: machine.daemonStateVersion,
            dataEncryptionKey: machine.dataEncryptionKey
                ? privacyKit.encodeBase64(machine.dataEncryptionKey)
                : null,
            seq: machine.seq,
            active: machine.active,
            activeAt: machine.lastActiveAt.getTime(),
            createdAt: machine.createdAt.getTime(),
            updatedAt: machine.updatedAt.getTime(),
        },
    });
});

// ============================================================================
// GET /v1/machines - List Machines
// ============================================================================

const listMachinesRoute = createRoute({
    method: 'get',
    path: '/v1/machines',
    request: {
        query: ListMachinesQuerySchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ListMachinesResponseSchema,
                },
            },
            description: 'List of machines',
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
    tags: ['Machines'],
    summary: 'List user machines',
    description: 'Returns machines ordered by most recently active. Optional activeOnly filter.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't account for auth middleware Variables
machineRoutes.openapi(listMachinesRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { limit = 50, activeOnly = false } = c.req.valid('query');
    const db = getDb(c.env.DB);

    // Build where conditions
    const conditions = [eq(schema.machines.accountId, userId)];
    if (activeOnly) {
        conditions.push(eq(schema.machines.active, true));
    }

    const machines = await db
        .select()
        .from(schema.machines)
        .where(and(...conditions))
        .orderBy(desc(schema.machines.lastActiveAt))
        .limit(limit);

    return c.json({
        machines: machines.map((m) => ({
            id: m.id,
            accountId: m.accountId,
            metadata: m.metadata,
            metadataVersion: m.metadataVersion,
            daemonState: m.daemonState,
            daemonStateVersion: m.daemonStateVersion,
            dataEncryptionKey: m.dataEncryptionKey
                ? privacyKit.encodeBase64(m.dataEncryptionKey)
                : null,
            seq: m.seq,
            active: m.active,
            activeAt: m.lastActiveAt.getTime(),
            createdAt: m.createdAt.getTime(),
            updatedAt: m.updatedAt.getTime(),
        })),
    });
});

// ============================================================================
// GET /v1/machines/:id - Get Machine
// ============================================================================

const getMachineRoute = createRoute({
    method: 'get',
    path: '/v1/machines/:id',
    request: {
        params: MachineIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetMachineResponseSchema,
                },
            },
            description: 'Machine details',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Machine not found',
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
    tags: ['Machines'],
    summary: 'Get machine',
    description: 'Get a single machine by ID. User must own the machine.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't account for auth middleware Variables
machineRoutes.openapi(getMachineRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);

    const machine = await db.query.machines.findFirst({
        where: (machines, { eq, and }) =>
            and(eq(machines.id, id), eq(machines.accountId, userId)),
    });

    if (!machine) {
        return c.json({ error: 'Machine not found' }, 404);
    }

    return c.json({
        machine: {
            id: machine.id,
            accountId: machine.accountId,
            metadata: machine.metadata,
            metadataVersion: machine.metadataVersion,
            daemonState: machine.daemonState,
            daemonStateVersion: machine.daemonStateVersion,
            dataEncryptionKey: machine.dataEncryptionKey
                ? privacyKit.encodeBase64(machine.dataEncryptionKey)
                : null,
            seq: machine.seq,
            active: machine.active,
            activeAt: machine.lastActiveAt.getTime(),
            createdAt: machine.createdAt.getTime(),
            updatedAt: machine.updatedAt.getTime(),
        },
    });
});

// ============================================================================
// PUT /v1/machines/:id/status - Update Machine Status
// ============================================================================

const updateMachineStatusRoute = createRoute({
    method: 'put',
    path: '/v1/machines/:id/status',
    request: {
        params: MachineIdParamSchema,
        body: {
            content: {
                'application/json': {
                    schema: UpdateMachineStatusRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UpdateMachineStatusResponseSchema,
                },
            },
            description: 'Machine status updated',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Machine not found',
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
    tags: ['Machines'],
    summary: 'Update machine status',
    description: 'Update machine active status, metadata, or daemon state. User must own the machine.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't account for auth middleware Variables
machineRoutes.openapi(updateMachineStatusRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const { active, metadata, daemonState } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Verify machine exists and belongs to user
    const machine = await db.query.machines.findFirst({
        where: (machines, { eq, and }) =>
            and(eq(machines.id, id), eq(machines.accountId, userId)),
    });

    if (!machine) {
        return c.json({ error: 'Machine not found' }, 404);
    }

    // Build update object
    const updates: {
        updatedAt: Date;
        lastActiveAt: Date;
        active?: boolean;
        metadata?: string;
        metadataVersion?: number;
        daemonState?: string | null;
        daemonStateVersion?: number;
    } = {
        updatedAt: new Date(),
        lastActiveAt: new Date(), // Always update lastActiveAt
    };

    if (active !== undefined) {
        updates.active = active;
    }

    if (metadata !== undefined) {
        updates.metadata = metadata;
        updates.metadataVersion = machine.metadataVersion + 1;
    }

    if (daemonState !== undefined) {
        updates.daemonState = daemonState;
        updates.daemonStateVersion = machine.daemonStateVersion + 1;
    }

    // Update machine
    const updatedMachines = await db
        .update(schema.machines)
        .set(updates)
        .where(and(eq(schema.machines.id, id), eq(schema.machines.accountId, userId)))
        .returning();

    const updatedMachine = updatedMachines[0];
    if (!updatedMachine) {
        return c.json({ error: 'Failed to update machine' }, 500);
    }

    return c.json({
        machine: {
            id: updatedMachine.id,
            accountId: updatedMachine.accountId,
            metadata: updatedMachine.metadata,
            metadataVersion: updatedMachine.metadataVersion,
            daemonState: updatedMachine.daemonState,
            daemonStateVersion: updatedMachine.daemonStateVersion,
            dataEncryptionKey: updatedMachine.dataEncryptionKey
                ? privacyKit.encodeBase64(updatedMachine.dataEncryptionKey)
                : null,
            seq: updatedMachine.seq,
            active: updatedMachine.active,
            activeAt: updatedMachine.lastActiveAt.getTime(),
            createdAt: updatedMachine.createdAt.getTime(),
            updatedAt: updatedMachine.updatedAt.getTime(),
        },
    });
});

export default machineRoutes;
