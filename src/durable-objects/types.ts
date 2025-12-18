/**
 * Durable Objects Types for WebSocket Connection Management
 *
 * These types define the structure for WebSocket connections in the Happy Server
 * Cloudflare Workers implementation. The architecture supports three client types:
 *
 * - **user-scoped**: Mobile apps that receive all user events
 * - **session-scoped**: Connections tied to a specific Claude Code session
 * - **machine-scoped**: CLI daemon connections for a specific machine
 *
 * @module durable-objects/types
 */

// =============================================================================
// SHARED PROTOCOL TYPES
// =============================================================================

/**
 * Import shared protocol types from @happy/protocol
 *
 * CRITICAL: These types use the correct field names (e.g., 'sid' not 'sessionId')
 * that clients expect. Using these ensures field name consistency across the stack.
 *
 * @see HAP-387 - Integrate @happy/protocol in happy-server-workers
 * @see HAP-383 - RFC for shared protocol types
 */
import {
    // Update event schemas and types
    ApiUpdateSchema,
    type ApiUpdate,
    type ApiUpdateType,
    // Ephemeral event schemas and types
    ApiEphemeralUpdateSchema,
    type ApiEphemeralUpdate,
    type ApiEphemeralUpdateType,
    // Payload container types
    UpdatePayloadSchema,
    type UpdatePayload,
    type EphemeralPayload,
    // Common types
    type GitHubProfile,
} from '@happy/protocol';

/**
 * Re-export shared types for backward compatibility
 *
 * Local code can continue using `UpdateEvent` and `EphemeralEvent` names.
 * These now point to the shared protocol types with correct field names.
 */
export type UpdateEvent = ApiUpdate;
export type EphemeralEvent = ApiEphemeralUpdate;

/**
 * Re-export schemas for runtime validation
 */
export { ApiUpdateSchema, ApiEphemeralUpdateSchema, UpdatePayloadSchema };
export type { ApiUpdate, ApiUpdateType, ApiEphemeralUpdate, ApiEphemeralUpdateType, UpdatePayload, EphemeralPayload, GitHubProfile };

/**
 * Client connection types supported by the WebSocket system
 *
 * @remarks
 * These mirror the client types from the original Socket.io implementation in happy-server:
 * - `user-scoped`: Receives broadcasts for all user activity (typically mobile app)
 * - `session-scoped`: Only receives events for a specific session (session viewers)
 * - `machine-scoped`: CLI daemons that manage a specific machine's sessions
 */
export type ClientType = 'user-scoped' | 'session-scoped' | 'machine-scoped';

/**
 * Authentication state for WebSocket connections (HAP-360)
 *
 * Connections can be in one of three states:
 * - pending-auth: Connection established, waiting for auth message
 * - authenticated: Auth message validated, ready for normal operation
 * - legacy: Authenticated via URL/header (backward compatibility with happy-cli)
 */
export type ConnectionAuthState = 'pending-auth' | 'authenticated' | 'legacy';

/**
 * Connection metadata stored with each WebSocket connection
 *
 * This is serialized via `WebSocket.serializeAttachment()` and restored on DO wake-up.
 * The metadata is used to route messages to appropriate connections and track state.
 */
export interface ConnectionMetadata {
    /** Unique connection ID (UUID) for tracking */
    connectionId: string;

    /** The authenticated user ID owning this connection */
    userId: string;

    /** The type of client connection */
    clientType: ClientType;

    /** Session ID for session-scoped connections */
    sessionId?: string;

    /** Machine ID for machine-scoped connections */
    machineId?: string;

    /** Timestamp when connection was established */
    connectedAt: number;

    /** Last activity timestamp (updated on each message) */
    lastActivityAt: number;

    /**
     * Authentication state (HAP-360)
     * - 'pending-auth': Waiting for auth message (new handshake flow)
     * - 'authenticated': Auth complete via message handshake
     * - 'legacy': Auth via URL/header (backward compatibility)
     */
    authState: ConnectionAuthState;
}

/**
 * Authentication handshake data sent by clients during WebSocket upgrade
 *
 * Clients must provide a valid auth token and their client type.
 * Session and machine-scoped clients must also provide their respective IDs.
 */
export interface WebSocketAuthHandshake {
    /** Authentication token from privacy-kit */
    token: string;

    /** Type of client connection */
    clientType: ClientType;

    /** Session ID (required for session-scoped connections) */
    sessionId?: string;

    /** Machine ID (required for machine-scoped connections) */
    machineId?: string;
}

/**
 * WebSocket close codes used by the connection manager
 *
 * Standard WebSocket close codes plus custom application codes.
 * @see https://www.rfc-editor.org/rfc/rfc6455.html#section-7.4
 */
export const CloseCode = {
    /** Normal closure - client requested disconnect */
    NORMAL: 1000,

    /** Server is going away (e.g., DO being evicted) */
    GOING_AWAY: 1001,

    /** Protocol error - invalid message format */
    PROTOCOL_ERROR: 1002,

    /** Unsupported data type received */
    UNSUPPORTED_DATA: 1003,

    /** Policy violation */
    POLICY_VIOLATION: 1008,

    /** Message too large */
    MESSAGE_TOO_BIG: 1009,

    /** Server error */
    INTERNAL_ERROR: 1011,

    // Custom application codes (4000-4999)

    /** Authentication failed - invalid or missing token */
    AUTH_FAILED: 4001,

    /** Missing required handshake data */
    INVALID_HANDSHAKE: 4002,

    /** Session ID required but not provided */
    MISSING_SESSION_ID: 4003,

    /** Machine ID required but not provided */
    MISSING_MACHINE_ID: 4004,

    /** Connection limit exceeded for user */
    CONNECTION_LIMIT_EXCEEDED: 4005,

    /** Duplicate connection detected */
    DUPLICATE_CONNECTION: 4006,

    /** Authentication timeout - client didn't send auth message in time (HAP-360) */
    AUTH_TIMEOUT: 4007,
} as const;

/**
 * Message types for internal WebSocket protocol
 *
 * These define the structure of messages exchanged between clients and the DO.
 * All messages are JSON-encoded with a `type` field for routing.
 */
export type WebSocketMessageType =
    | 'ping'
    | 'pong'
    | 'error'
    | 'connected'
    | 'disconnected'
    | 'broadcast'
    | 'update'
    | 'ephemeral'
    | 'session-update'
    | 'machine-update'
    | 'artifact-update'
    | 'access-key-update'
    | 'rpc-request'
    | 'rpc-response';

/**
 * Base structure for all WebSocket messages
 */
export interface WebSocketMessage<T = unknown> {
    /** Message type for routing */
    type: WebSocketMessageType;

    /** Message payload */
    payload?: T;

    /** Timestamp when message was created */
    timestamp: number;

    /** Optional message ID for request/response correlation */
    messageId?: string;
}


/**
 * Client message format (happy-cli and happy-app)
 *
 * This matches the format used by Socket.io-style clients:
 * - event: Event name (similar to type in server format)
 * - data: Payload data
 * - ackId: UUID for request-response correlation
 * - ack: Response data for acknowledgements
 *
 * @see HAP-271 - Protocol alignment between clients and Workers backend
 */
export interface ClientMessage {
    /** Event name (e.g., 'sessionUpdate', 'rpc-call', 'ping') */
    event: string;

    /** Event payload */
    data?: unknown;

    /** Acknowledgement ID for request-response pattern */
    ackId?: string;

    /** Response data (present in ack responses) */
    ack?: unknown;
}

/**
 * Unified message format that normalizes both client and server messages.
 *
 * The ConnectionManager accepts both formats:
 * - Server format: { type, payload, timestamp, messageId }
 * - Client format: { event, data, ackId, ack }
 *
 * This interface represents the parsed/normalized form used internally.
 */
export interface NormalizedMessage {
    /** Message type (from server `type` or client `event`) */
    type: string;

    /** Message payload (from server `payload` or client `data`) */
    payload?: unknown;

    /** Timestamp when message was created (server format only) */
    timestamp?: number;

    /** Message ID for correlation (server `messageId` or client `ackId`) */
    messageId?: string;

    /** Acknowledgement response data (client format only) */
    ack?: unknown;
}

/**
 * Type guard to check if a raw message is in client format
 */
export function isClientMessage(msg: unknown): msg is ClientMessage {
    return (
        typeof msg === 'object' &&
        msg !== null &&
        'event' in msg &&
        typeof (msg as ClientMessage).event === 'string'
    );
}

/**
 * Type guard to check if a raw message is in server format
 */
export function isServerMessage(msg: unknown): msg is WebSocketMessage {
    return (
        typeof msg === 'object' &&
        msg !== null &&
        'type' in msg &&
        typeof (msg as WebSocketMessage).type === 'string'
    );
}

/**
 * Normalize a message from either client or server format to unified format
 */
export function normalizeMessage(msg: unknown): NormalizedMessage | null {
    if (isClientMessage(msg)) {
        return {
            type: msg.event,
            payload: msg.data,
            messageId: msg.ackId,
            ack: msg.ack,
        };
    }

    if (isServerMessage(msg)) {
        return {
            type: msg.type,
            payload: msg.payload,
            timestamp: msg.timestamp,
            messageId: msg.messageId,
        };
    }

    return null;
}

/**
 * Error message sent to clients
 */
export interface ErrorMessage extends WebSocketMessage {
    type: 'error';
    payload: {
        code: number;
        message: string;
        details?: unknown;
    };
}

/**
 * Connection confirmation message sent after successful authentication
 */
export interface ConnectedMessage extends WebSocketMessage {
    type: 'connected';
    payload: {
        connectionId: string;
        userId: string;
        clientType: ClientType;
        sessionId?: string;
        machineId?: string;
    };
}

/**
 * Broadcast message filter for routing messages to specific connections
 */
export interface BroadcastFilter {
    /** Target all connections for a user */
    type: 'all';
}

export interface BroadcastFilterUserScoped {
    /** Target only user-scoped connections */
    type: 'user-scoped-only';
}

export interface BroadcastFilterSession {
    /** Target connections for a specific session */
    type: 'session';
    sessionId: string;
}

export interface BroadcastFilterMachine {
    /** Target connections for a specific machine */
    type: 'machine';
    machineId: string;
}

export interface BroadcastFilterMachineScoped {
    /** Target user-scoped connections + specific machine-scoped connection */
    type: 'machine-scoped-only';
    machineId: string;
}

export interface BroadcastFilterExclude {
    /** Target all except specific connection */
    type: 'exclude';
    connectionId: string;
}

export interface BroadcastFilterInterestedInSession {
    /** Target all connections interested in a session (session-scoped + user-scoped) */
    type: 'all-interested-in-session';
    sessionId: string;
}

export type MessageFilter =
    | BroadcastFilter
    | BroadcastFilterUserScoped
    | BroadcastFilterSession
    | BroadcastFilterMachine
    | BroadcastFilterMachineScoped
    | BroadcastFilterExclude
    | BroadcastFilterInterestedInSession;

/**
 * Connection statistics for monitoring
 */
export interface ConnectionStats {
    /** Total active connections */
    totalConnections: number;

    /** Connections by type */
    byType: {
        'user-scoped': number;
        'session-scoped': number;
        'machine-scoped': number;
    };

    /** Unique sessions with active connections */
    activeSessions: number;

    /** Unique machines with active connections */
    activeMachines: number;

    /** Oldest connection timestamp */
    oldestConnection: number | null;
}

/**
 * Configuration for the ConnectionManager Durable Object
 */
export interface ConnectionManagerConfig {
    /**
     * Maximum connections per user
     * @default 100
     */
    maxConnectionsPerUser: number;

    /**
     * Connection timeout in milliseconds (no activity)
     * @default 300000 (5 minutes)
     */
    connectionTimeoutMs: number;

    /**
     * Enable auto-response for ping/pong during hibernation
     * @default true
     */
    enableAutoResponse: boolean;

    /**
     * Maximum message size in bytes
     * @default 1048576 (1MB)
     */
    maxMessageSize: number;

    /**
     * Auth timeout in milliseconds (HAP-360)
     * How long to wait for auth message after connection before closing
     * @default 5000 (5 seconds)
     */
    authTimeoutMs: number;
}

/**
 * Default configuration values
 */
export const DEFAULT_CONFIG: ConnectionManagerConfig = {
    maxConnectionsPerUser: 100,
    connectionTimeoutMs: 5 * 60 * 1000, // 5 minutes
    enableAutoResponse: true,
    maxMessageSize: 1024 * 1024, // 1MB
    authTimeoutMs: 5000, // 5 seconds (HAP-360)
};

/**
 * Auth message payload from client (HAP-360)
 *
 * Sent as the first message after WebSocket connection to authenticate.
 * This replaces sending the token in URL query parameters.
 */
export interface AuthMessagePayload {
    /** Authentication token from privacy-kit */
    token: string;

    /** Type of client connection */
    clientType: ClientType;

    /** Session ID (required for session-scoped connections) */
    sessionId?: string;

    /** Machine ID (required for machine-scoped connections) */
    machineId?: string;
}

// =============================================================================
// EVENT BROADCASTING TYPES
// =============================================================================
// NOTE: UpdateEvent, EphemeralEvent, UpdatePayload, EphemeralPayload, and GitHubProfile
// are now imported from @happy/protocol (see top of file).
// This ensures consistent field names across the stack (HAP-387).
