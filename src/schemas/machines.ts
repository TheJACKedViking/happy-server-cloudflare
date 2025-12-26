import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for machine management endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for all machine routes.
 * Machines represent devices (CLI instances) that connect to the Happy ecosystem.
 */

// ============================================================================
// Common Schemas
// ============================================================================

/**
 * Schema for machine object returned in API responses
 * @internal Used for composing response schemas
 */
const MachineSchema = z
    .object({
        id: z.string().openapi({
            description: 'Unique machine identifier',
            example: 'machine_abc123',
        }),
        accountId: z.string().openapi({
            description: 'Owner account identifier',
            example: 'user_xyz789',
        }),
        metadata: z.string().openapi({
            description: 'Encrypted machine metadata (JSON string)',
            example: '{"hostname":"macbook-pro","os":"darwin"}',
        }),
        metadataVersion: z.number().int().openapi({
            description: 'Metadata version for conflict resolution',
            example: 2,
        }),
        daemonState: z.string().nullable().openapi({
            description: 'Encrypted daemon state (JSON string) or null',
            example: '{"status":"running","pid":1234}',
        }),
        daemonStateVersion: z.number().int().openapi({
            description: 'Daemon state version for conflict resolution',
            example: 1,
        }),
        dataEncryptionKey: z.string().nullable().openapi({
            description: 'Base64-encoded data encryption key or null',
            example: 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
        }),
        seq: z.number().int().openapi({
            description: 'Sequence number for optimistic concurrency control',
            example: 3,
        }),
        active: z.boolean().openapi({
            description: 'Whether the machine is currently active',
            example: true,
        }),
        activeAt: z.number().int().openapi({
            description: 'Last active timestamp (Unix milliseconds)',
            example: 1705014000000,
        }),
        createdAt: z.number().int().openapi({
            description: 'Machine creation timestamp (Unix milliseconds)',
            example: 1705010400000,
        }),
        updatedAt: z.number().int().openapi({
            description: 'Machine last update timestamp (Unix milliseconds)',
            example: 1705014000000,
        }),
    })
    .openapi('Machine');

// ============================================================================
// POST /v1/machines - Register Machine
// ============================================================================

/**
 * Schema for machine registration request
 */
export const RegisterMachineRequestSchema = z
    .object({
        id: z.string().min(1).openapi({
            description: 'Client-provided machine identifier (usually hostname-based)',
            example: 'machine_abc123',
        }),
        metadata: z.string().openapi({
            description: 'Encrypted machine metadata (JSON string)',
            example: '{"hostname":"macbook-pro","os":"darwin"}',
        }),
        daemonState: z.string().optional().openapi({
            description: 'Encrypted daemon state (JSON string)',
            example: '{"status":"running","pid":1234}',
        }),
        dataEncryptionKey: z.string().optional().openapi({
            description: 'Base64-encoded data encryption key',
            example: 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
        }),
    })
    .openapi('RegisterMachineRequest');

/**
 * Schema for successful machine registration
 */
export const RegisterMachineResponseSchema = z
    .object({
        machine: MachineSchema.openapi({
            description: 'Registered machine',
        }),
    })
    .openapi('RegisterMachineResponse');

// ============================================================================
// GET /v1/machines - List Machines
// ============================================================================

/**
 * Schema for list machines query parameters
 */
export const ListMachinesQuerySchema = z.object({
    limit: z
        .string()
        .default('50')
        .transform((v) => parseInt(v, 10))
        .pipe(z.number().int().min(1).max(200))
        .openapi({
            param: {
                name: 'limit',
                in: 'query',
            },
            description: 'Maximum number of machines to return (1-200, default 50)',
            example: '50',
        }),
    activeOnly: z
        .string()
        .transform((v) => v === 'true')
        .pipe(z.boolean())
        .optional()
        .openapi({
            param: {
                name: 'activeOnly',
                in: 'query',
            },
            description: 'Only return active machines (default false)',
            example: 'true',
        }),
});

/**
 * Schema for list machines response
 */
export const ListMachinesResponseSchema = z
    .object({
        machines: z.array(MachineSchema).openapi({
            description: 'Array of user machines ordered by most recent',
        }),
    })
    .openapi('ListMachinesResponse');

// ============================================================================
// GET /v1/machines/:id - Get Machine
// ============================================================================

/**
 * Schema for machine ID path parameter
 */
export const MachineIdParamSchema = z.object({
    id: z.string().openapi({
        param: {
            name: 'id',
            in: 'path',
        },
        description: 'Machine identifier',
        example: 'machine_abc123',
    }),
});

/**
 * Schema for get machine response
 */
export const GetMachineResponseSchema = z
    .object({
        machine: MachineSchema.openapi({
            description: 'Requested machine',
        }),
    })
    .openapi('GetMachineResponse');

// ============================================================================
// PUT /v1/machines/:id/status - Update Machine Status
// ============================================================================

/**
 * Schema for machine status update request
 */
export const UpdateMachineStatusRequestSchema = z
    .object({
        active: z.boolean().optional().openapi({
            description: 'Set machine active status',
            example: true,
        }),
        metadata: z.string().optional().openapi({
            description: 'Updated encrypted machine metadata (JSON string)',
            example: '{"hostname":"macbook-pro","os":"darwin"}',
        }),
        daemonState: z.string().optional().openapi({
            description: 'Updated encrypted daemon state (JSON string)',
            example: '{"status":"running","pid":1234}',
        }),
    })
    .openapi('UpdateMachineStatusRequest');

/**
 * Schema for successful status update
 */
export const UpdateMachineStatusResponseSchema = z
    .object({
        machine: MachineSchema.openapi({
            description: 'Updated machine',
        }),
    })
    .openapi('UpdateMachineStatusResponse');

// ============================================================================
// Error Responses
// ============================================================================

/**
 * Schema for 404 Not Found error
 */
export const NotFoundErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Machine not found',
        }),
    })
    .openapi('NotFoundError');

/**
 * Schema for 401 Unauthorized error
 */
export const UnauthorizedErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Unauthorized',
        }),
    })
    .openapi('UnauthorizedError');

