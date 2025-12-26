import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for session management endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for all session routes.
 * They provide both runtime validation (via Zod) and automatic OpenAPI
 * documentation generation (via .openapi() extensions).
 */

// ============================================================================
// Common Schemas
// ============================================================================

/**
 * Schema for session object returned in API responses
 * @internal Used for composing response schemas
 */
const SessionSchema = z
    .object({
        id: z.string().openapi({
            description: 'Unique session identifier',
            example: 'cmed556s4002bvb2020igg8jf',
        }),
        seq: z.number().int().openapi({
            description: 'Sequence number for optimistic concurrency control',
            example: 5,
        }),
        createdAt: z.number().int().openapi({
            description: 'Session creation timestamp (Unix milliseconds)',
            example: 1705010400000,
        }),
        updatedAt: z.number().int().openapi({
            description: 'Session last update timestamp (Unix milliseconds)',
            example: 1705014000000,
        }),
        active: z.boolean().openapi({
            description: 'Whether the session is currently active',
            example: true,
        }),
        activeAt: z.number().int().openapi({
            description: 'Last active timestamp (Unix milliseconds)',
            example: 1705014000000,
        }),
        metadata: z.string().openapi({
            description: 'Encrypted session metadata (JSON string)',
            example: '{"device":"macOS","version":"1.0.0"}',
        }),
        metadataVersion: z.number().int().openapi({
            description: 'Metadata version for conflict resolution',
            example: 3,
        }),
        agentState: z.string().nullable().openapi({
            description: 'Encrypted agent state (JSON string) or null',
            example: '{"context":"working"}',
        }),
        agentStateVersion: z.number().int().openapi({
            description: 'Agent state version for conflict resolution',
            example: 1,
        }),
        dataEncryptionKey: z.string().nullable().openapi({
            description: 'Base64-encoded data encryption key or null',
            example: 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
        }),
        lastMessage: z.unknown().nullable().openapi({
            description: 'Last message in session (legacy, always null)',
            example: null,
        }),
    })
    .openapi('Session');

/**
 * Schema for session message object
 * @internal Used for composing response schemas
 */
const SessionMessageSchema = z
    .object({
        id: z.string().openapi({
            description: 'Unique message identifier',
            example: 'msg_abc123',
        }),
        sessionId: z.string().openapi({
            description: 'Parent session identifier',
            example: 'cmed556s4002bvb2020igg8jf',
        }),
        localId: z.string().nullable().openapi({
            description: 'Client-side local identifier for deduplication',
            example: 'local_msg_001',
        }),
        seq: z.number().int().openapi({
            description: 'Message sequence number within session',
            example: 42,
        }),
        content: z.unknown().openapi({
            description: 'Message content (JSON object)',
            example: { type: 'text', text: 'Hello world' },
        }),
        createdAt: z.number().int().openapi({
            description: 'Message creation timestamp (Unix milliseconds)',
            example: 1705014000000,
        }),
        updatedAt: z.number().int().openapi({
            description: 'Message last update timestamp (Unix milliseconds)',
            example: 1705014000000,
        }),
    })
    .openapi('SessionMessage');

// ============================================================================
// GET /v1/sessions - List Sessions
// ============================================================================

/**
 * Schema for listing sessions response
 */
export const ListSessionsResponseSchema = z
    .object({
        sessions: z.array(SessionSchema).openapi({
            description: 'Array of user sessions ordered by most recent',
        }),
    })
    .openapi('ListSessionsResponse');

// ============================================================================
// GET /v2/sessions - List Sessions with Pagination
// ============================================================================

/**
 * Schema for paginated session list query parameters
 */
export const PaginatedSessionsQuerySchema = z.object({
    cursor: z.string().optional().openapi({
        param: {
            name: 'cursor',
            in: 'query',
        },
        description: 'Cursor for pagination (format: cursor_v1_{sessionId})',
        example: 'cursor_v1_cmed556s4002bvb2020igg8jf',
    }),
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
            description: 'Maximum number of sessions to return (1-200, default 50)',
            example: '50',
        }),
    changedSince: z
        .string()
        .transform((v) => parseInt(v, 10))
        .pipe(z.number().int().positive())
        .optional()
        .openapi({
            param: {
                name: 'changedSince',
                in: 'query',
            },
            description: 'Only return sessions updated after this timestamp (Unix ms)',
            example: '1705010400000',
        }),
});

/**
 * Schema for paginated session list response
 */
export const PaginatedSessionsResponseSchema = z
    .object({
        sessions: z.array(SessionSchema).openapi({
            description: 'Array of sessions for current page',
        }),
        nextCursor: z.string().nullable().openapi({
            description: 'Cursor for next page, null if no more results',
            example: 'cursor_v1_cmed556s4002bvb2020igg8jf',
        }),
    })
    .openapi('PaginatedSessionsResponse');

// ============================================================================
// GET /v2/sessions/active - List Active Sessions
// ============================================================================

/**
 * Schema for active sessions query parameters
 */
export const ActiveSessionsQuerySchema = z.object({
    limit: z
        .string()
        .default('150')
        .transform((v) => parseInt(v, 10))
        .pipe(z.number().int().min(1).max(500))
        .openapi({
            param: {
                name: 'limit',
                in: 'query',
            },
            description: 'Maximum number of sessions to return (1-500, default 150)',
            example: '150',
        }),
});

/**
 * Schema for active sessions response
 */
export const ActiveSessionsResponseSchema = z
    .object({
        sessions: z.array(SessionSchema).openapi({
            description: 'Array of active sessions (last 15 minutes)',
        }),
    })
    .openapi('ActiveSessionsResponse');

// ============================================================================
// POST /v1/sessions - Create Session
// ============================================================================

/**
 * Schema for creating a session
 */
export const CreateSessionRequestSchema = z
    .object({
        tag: z.string().min(1).openapi({
            description: 'Session tag for identification (unique per user)',
            example: 'main',
        }),
        metadata: z.string().openapi({
            description: 'Encrypted session metadata (JSON string)',
            example: '{"device":"macOS","version":"1.0.0"}',
        }),
        agentState: z.string().optional().openapi({
            description: 'Encrypted agent state (JSON string)',
            example: '{"context":"working"}',
        }),
        dataEncryptionKey: z.string().optional().openapi({
            description: 'Base64-encoded data encryption key',
            example: 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
        }),
    })
    .openapi('CreateSessionRequest');

/**
 * Schema for successful session creation
 */
export const CreateSessionResponseSchema = z
    .object({
        session: SessionSchema.openapi({
            description: 'Newly created session',
        }),
    })
    .openapi('CreateSessionResponse');

// ============================================================================
// GET /v1/sessions/:id - Get Session
// ============================================================================

/**
 * Schema for session ID path parameter
 */
export const SessionIdParamSchema = z.object({
    id: z.string().openapi({
        param: {
            name: 'id',
            in: 'path',
        },
        description: 'Session identifier',
        example: 'cmed556s4002bvb2020igg8jf',
    }),
});

/**
 * Schema for get session response
 */
export const GetSessionResponseSchema = z
    .object({
        session: SessionSchema.openapi({
            description: 'Requested session',
        }),
    })
    .openapi('GetSessionResponse');

// ============================================================================
// DELETE /v1/sessions/:id - Delete Session
// ============================================================================

/**
 * Schema for successful session deletion
 */
export const DeleteSessionResponseSchema = z
    .object({
        success: z.boolean().openapi({
            description: 'Always true for successful deletion',
            example: true,
        }),
    })
    .openapi('DeleteSessionResponse');

// ============================================================================
// POST /v1/sessions/:id/messages - Create Session Message
// ============================================================================

/**
 * Schema for creating a session message
 */
export const CreateSessionMessageRequestSchema = z
    .object({
        localId: z.string().optional().openapi({
            description: 'Client-side local identifier for deduplication',
            example: 'local_msg_001',
        }),
        content: z.unknown().openapi({
            description: 'Message content (JSON object)',
            example: { type: 'text', text: 'Hello world' },
        }),
    })
    .openapi('CreateSessionMessageRequest');

/**
 * Schema for successful message creation
 */
export const CreateSessionMessageResponseSchema = z
    .object({
        message: SessionMessageSchema.openapi({
            description: 'Newly created message',
        }),
    })
    .openapi('CreateSessionMessageResponse');

// ============================================================================
// GET /v1/sessions/:id/messages - List Session Messages
// ============================================================================

/**
 * Schema for listing session messages response
 */
export const ListSessionMessagesResponseSchema = z
    .object({
        messages: z.array(SessionMessageSchema).openapi({
            description: 'Array of session messages ordered by most recent',
        }),
    })
    .openapi('ListSessionMessagesResponse');

// ============================================================================
// GET /v2/sessions/:id/messages - List Session Messages with Pagination
// ============================================================================

/**
 * Schema for paginated session messages query parameters
 */
export const PaginatedMessagesQuerySchema = z.object({
    cursor: z.string().optional().openapi({
        param: {
            name: 'cursor',
            in: 'query',
        },
        description: 'Cursor for pagination (format: cursor_v1_{messageId})',
        example: 'cursor_v1_msg_abc123',
    }),
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
            description: 'Maximum number of messages to return (1-200, default 50)',
            example: '50',
        }),
});

/**
 * Schema for paginated session messages response
 */
export const PaginatedMessagesResponseSchema = z
    .object({
        messages: z.array(SessionMessageSchema).openapi({
            description: 'Array of messages for current page',
        }),
        nextCursor: z.string().nullable().openapi({
            description: 'Cursor for next page, null if no more results',
            example: 'cursor_v1_msg_abc123',
        }),
    })
    .openapi('PaginatedMessagesResponse');

// ============================================================================
// Error Responses
// ============================================================================

/**
 * Schema for 400 Bad Request error
 */
export const BadRequestErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Invalid cursor format',
        }),
    })
    .openapi('BadRequestError');

/**
 * Schema for 404 Not Found error
 */
export const NotFoundErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Session not found',
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
