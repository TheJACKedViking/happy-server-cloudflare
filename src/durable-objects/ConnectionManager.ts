/**
 * ConnectionManager Durable Object
 *
 * Manages WebSocket connections for a single user using the WebSocket Hibernation API.
 * Each user has their own ConnectionManager instance, identified by the user's ID.
 *
 * Key features:
 * - Supports three client types: user-scoped, session-scoped, machine-scoped
 * - Uses WebSocket Hibernation for cost optimization
 * - Maintains connection state across hibernation via serializeAttachment
 * - Provides filtered message broadcasting
 * - Handles authentication via privacy-kit tokens
 *
 * @module durable-objects/ConnectionManager
 */

import { DurableObject } from 'cloudflare:workers';
import * as Sentry from '@sentry/cloudflare';
import type {
    ConnectionMetadata,
    WebSocketAuthHandshake,
    ClientType,
    WebSocketMessage,
    MessageFilter,
    ConnectionStats,
    ConnectionManagerConfig,
    ClientMessage,
    AuthMessagePayload,
    AlarmRetryState,
    AlarmDeadLetterEntry,
} from './types';
import {
    CloseCode,
    DEFAULT_CONFIG,
    normalizeMessage,
    DEFAULT_ALARM_RETRY_CONFIG,
    calculateBackoffDelay,
} from './types';
import { verifyToken, initAuth } from '@/lib/auth';
import { getDb } from '@/db/client';
import { getMasterSecret } from '@/config/env';
import type { HandlerResult, HandlerContext } from './handlers';
import { buildSentryOptions, instrumentDurableObjectWithSentry } from '@/lib/sentry';
import {
    handleSessionMetadataUpdate,
    handleSessionStateUpdate,
    handleSessionAlive,
    handleSessionEnd,
    handleSessionMessage,
    handleMachineAlive,
    handleMachineMetadataUpdate,
    handleMachineStateUpdate,
    handleArtifactRead,
    handleArtifactUpdate,
    handleArtifactCreate,
    handleArtifactDelete,
    handleAccessKeyGet,
    handleUsageReport,
    handleRequestUpdatesSince,
} from './handlers';

/**
 * Environment bindings for the ConnectionManager Durable Object
 */
export interface ConnectionManagerEnv {
    /** D1 Database binding for database updates */
    DB: D1Database;

    /** Master secret for auth token verification (preferred) */
    HAPPY_MASTER_SECRET?: string;

    /** Master secret for auth token verification (deprecated) */
    HANDY_MASTER_SECRET?: string;

    /** Current environment */
    ENVIRONMENT?: 'development' | 'staging' | 'production';

    /**
     * Enable debug logging for RPC routing decisions (HAP-297)
     * Set to 'true' to enable verbose logging of RPC routing
     */
    DEBUG_RPC_ROUTING?: string;

    /** Sentry DSN for error monitoring */
    SENTRY_DSN?: string;

    /** Cloudflare version metadata for Sentry releases */
    CF_VERSION_METADATA?: { id: string };
}

/**
 * ConnectionManager Durable Object Class
 *
 * Implements WebSocket connection management with hibernation support.
 * One instance per user for isolation and efficient resource usage.
 *
 * Architecture:
 * ```
 * Worker (fetch) → DO.fetch() → WebSocket upgrade
 *                            ↓
 *                     acceptWebSocket() + tag
 *                            ↓
 *                     [hibernation if idle]
 *                            ↓
 *                     webSocketMessage() → broadcast/handle
 *                            ↓
 *                     webSocketClose() → cleanup
 * ```
 */
class ConnectionManagerBase extends DurableObject<ConnectionManagerEnv> {
    /**
     * Active connections map, keyed by WebSocket reference
     * Reconstructed from attachments on wake from hibernation
     */
    private connections: Map<WebSocket, ConnectionMetadata>;

    /**
     * Configuration for this DO instance
     */
    private config: ConnectionManagerConfig;

    /**
     * User ID this DO manages (extracted from first connection)
     */
    private userId: string | null = null;

    /**
     * Whether auth has been initialized for this instance
     */
    private authInitialized = false;


    /**
     * Auth timeout alarms for pending connections (HAP-360)
     * Maps connectionId to alarm timestamp
     * Used to close connections that don't authenticate in time
     */
    private pendingAuthAlarms: Map<string, number> = new Map();

    /**
     * Storage key for alarm retry state (HAP-479)
     */
    private static readonly ALARM_RETRY_STATE_KEY = 'alarm:retry:state';

    /**
     * Storage key prefix for dead letter entries (HAP-479)
     */
    private static readonly DEAD_LETTER_PREFIX = 'alarm:deadletter:';

    constructor(ctx: DurableObjectState, env: ConnectionManagerEnv) {
        super(ctx, env);
        this.connections = new Map();
        this.config = { ...DEFAULT_CONFIG };

        // Restore connections from hibernation
        // When the DO wakes up, WebSocket connections are still active
        // but our in-memory state is gone. Reconstruct from attachments.
        this.ctx.getWebSockets().forEach((ws) => {
            const attachment = ws.deserializeAttachment() as ConnectionMetadata | null;
            if (attachment) {
                // HAP-360: If connection was pending-auth when we hibernated, close it
                // The auth timeout would have expired during hibernation anyway
                if (attachment.authState === 'pending-auth') {
                    try {
                        ws.close(CloseCode.AUTH_TIMEOUT, 'Authentication timeout (hibernation recovery)');
                    } catch {
                        // Already closed
                    }
                    return; // Don't add to connections map
                }

                this.connections.set(ws, attachment);
                // Restore userId from first connection
                if (!this.userId) {
                    this.userId = attachment.userId;
                }
            }
        });

        // Set up auto-response for ping/pong during hibernation
        // This keeps connections alive without waking the DO
        // Uses client format {event, data} for compatibility with happy-cli and happy-app
        if (this.config.enableAutoResponse) {
            this.ctx.setWebSocketAutoResponse(
                new WebSocketRequestResponsePair(
                    JSON.stringify({ event: 'ping' }),
                    JSON.stringify({ event: 'pong', data: { timestamp: Date.now() } })
                )
            );
        }
    }

    /**
     * Initialize authentication module if not already done
     */
    private async ensureAuthInitialized(): Promise<void> {
        const secret = getMasterSecret(this.env);
        if (!this.authInitialized && secret) {
            await initAuth(secret);
            this.authInitialized = true;
        }
    }

    /**
     * Handle incoming HTTP requests to the Durable Object
     *
     * Supports:
     * - WebSocket upgrade requests (POST /websocket)
     * - Stats endpoint (GET /stats)
     * - Health check (GET /health)
     *
     * @param request - Incoming HTTP request
     * @returns HTTP Response or WebSocket upgrade response
     */
    override async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        const path = url.pathname;

        // Health check endpoint
        if (path === '/health' && request.method === 'GET') {
            return Response.json({
                status: 'healthy',
                connections: this.connections.size,
                userId: this.userId,
            });
        }

        // Stats endpoint
        if (path === '/stats' && request.method === 'GET') {
            return Response.json(this.getStats());
        }

        // Usage limits endpoint (HAP-731)
        // Returns cached plan limits from connected CLI sessions
        if (path === '/usage-limits' && request.method === 'GET') {
            return this.getUsageLimits();
        }

        // Broadcast endpoint (for sending messages from Workers to connected clients)
        if (path === '/broadcast' && request.method === 'POST') {
            try {
                const body = (await request.json()) as {
                    message: WebSocketMessage;
                    filter?: MessageFilter;
                };
                const count = this.broadcast(body.message, body.filter);
                return Response.json({ success: true, delivered: count });
            } catch {
                return Response.json({ error: 'Invalid broadcast request' }, { status: 400 });
            }
        }

        // WebSocket upgrade request
        if (path === '/websocket' || path === '/') {
            const upgradeHeader = request.headers.get('Upgrade');
            if (upgradeHeader !== 'websocket') {
                return new Response('Expected WebSocket upgrade', { status: 426 });
            }

            // Parse handshake data from query params or headers
            // HAP-360: Token may not be present (new auth flow uses message-based auth)
            const handshake = this.parseHandshake(url, request.headers);

            // Check connection limits
            if (this.connections.size >= this.config.maxConnectionsPerUser) {
                return new Response('Connection limit exceeded', { status: 429 });
            }

            await this.ensureAuthInitialized();

            // Create WebSocket pair
            const webSocketPair = new WebSocketPair();
            const client = webSocketPair[0];
            const server = webSocketPair[1];

            // Create connection metadata
            const connectionId = crypto.randomUUID();

            // Check for pre-validated user from route handler (HAP-375 ticket flow)
            // The route handler validates tickets and sets this header
            const preValidatedUserId = request.headers.get('X-Validated-User-Id');

            // HAP-375: Determine auth strategy based on authentication method
            // - Pre-validated userId: Route handler already validated (ticket flow)
            // - Token present: Validate immediately (legacy flow for happy-cli)
            // - No token: Accept in pending-auth state, wait for auth message (HAP-360)
            if (preValidatedUserId) {
                // =============================================
                // TICKET AUTH FLOW (HAP-375)
                // User already validated by route handler via ticket
                // Used by happy-app (browser/React Native)
                // =============================================

                // Get client type from query params (user-scoped is default for web)
                const clientType = (url.searchParams.get('clientType') as 'user-scoped' | 'session-scoped' | 'machine-scoped') || 'user-scoped';
                const sessionId = url.searchParams.get('sessionId') || undefined;
                const machineId = url.searchParams.get('machineId') || undefined;

                // Validate client type requirements
                if (clientType === 'session-scoped' && !sessionId) {
                    return new Response('Session ID required for session-scoped connections', { status: 400 });
                }
                if (clientType === 'machine-scoped' && !machineId) {
                    return new Response('Machine ID required for machine-scoped connections', { status: 400 });
                }

                // Create fully authenticated metadata
                const metadata: ConnectionMetadata = {
                    connectionId,
                    userId: preValidatedUserId,
                    clientType,
                    sessionId,
                    machineId,
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                    authState: 'authenticated',
                };

                // Build tags for efficient filtering
                const tags = this.buildConnectionTags(metadata);

                // Accept the WebSocket with hibernation support
                this.ctx.acceptWebSocket(server, tags);

                // Serialize metadata for hibernation recovery
                server.serializeAttachment(metadata);

                // Store in our local map
                this.connections.set(server, metadata);

                // Set userId if this is the first connection
                if (!this.userId) {
                    this.userId = preValidatedUserId;
                }

                // Send connected confirmation in client format
                const connectedMsg: ClientMessage = {
                    event: 'connected',
                    data: {
                        connectionId,
                        userId: preValidatedUserId,
                        clientType,
                        sessionId,
                        machineId,
                        timestamp: Date.now(),
                    },
                };

                // Queue the message to be sent after the connection is established
                server.send(JSON.stringify(connectedMsg));

                // Broadcast machine online status if applicable
                if (clientType === 'machine-scoped' && machineId) {
                    this.broadcastClientMessage(
                        {
                            event: 'machine-update',
                            data: {
                                machineId,
                                active: true,
                                timestamp: Date.now(),
                            },
                        },
                        { type: 'user-scoped-only' }
                    );
                }

                // Log connection
                if (this.env.ENVIRONMENT !== 'production') {
                    console.log(
                        `[ConnectionManager] New connection (ticket auth): ${connectionId}, type: ${clientType}, user: ${preValidatedUserId}`
                    );
                }
            } else if (handshake?.token) {
                // =============================================
                // LEGACY AUTH FLOW (token in URL/header)
                // Used by happy-cli which can send custom headers
                // =============================================

                const verified = await verifyToken(handshake.token, this.env.DB);
                if (!verified) {
                    return new Response('Authentication failed', { status: 401 });
                }

                // Validate client type requirements
                const validation = this.validateClientType(handshake);
                if (!validation.valid) {
                    return new Response(validation.error!, { status: 400 });
                }

                // Create fully authenticated metadata
                const metadata: ConnectionMetadata = {
                    connectionId,
                    userId: verified.userId,
                    clientType: handshake.clientType,
                    sessionId: handshake.sessionId,
                    machineId: handshake.machineId,
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                    authState: 'legacy',
                };

                // Build tags for efficient filtering
                const tags = this.buildConnectionTags(metadata);

                // Accept the WebSocket with hibernation support
                this.ctx.acceptWebSocket(server, tags);

                // Serialize metadata for hibernation recovery
                server.serializeAttachment(metadata);

                // Store in our local map
                this.connections.set(server, metadata);

                // Set userId if this is the first connection
                if (!this.userId) {
                    this.userId = verified.userId;
                }

                // Send connected confirmation in client format
                const connectedMsg: ClientMessage = {
                    event: 'connected',
                    data: {
                        connectionId,
                        userId: verified.userId,
                        clientType: handshake.clientType,
                        sessionId: handshake.sessionId,
                        machineId: handshake.machineId,
                        timestamp: Date.now(),
                    },
                };

                // Queue the message to be sent after the connection is established
                server.send(JSON.stringify(connectedMsg));

                // Broadcast machine online status to user-scoped connections
                if (handshake.clientType === 'machine-scoped' && handshake.machineId) {
                    this.broadcastClientMessage(
                        {
                            event: 'machine-update',
                            data: {
                                machineId: handshake.machineId,
                                active: true,
                                timestamp: Date.now(),
                            },
                        },
                        { type: 'user-scoped-only' }
                    );
                }

                // Log connection
                if (this.env.ENVIRONMENT !== 'production') {
                    console.log(
                        `[ConnectionManager] New connection (legacy auth): ${connectionId}, type: ${handshake.clientType}, user: ${verified.userId}`
                    );
                }
            } else {
                // =============================================
                // NEW AUTH FLOW (HAP-360)
                // Token sent via message after connection
                // Used by happy-app (browser/React Native can't send WS headers)
                // =============================================

                // Create pending-auth metadata (userId will be set after auth)
                const metadata: ConnectionMetadata = {
                    connectionId,
                    userId: '', // Will be set after auth message
                    clientType: 'user-scoped', // Will be updated after auth message
                    connectedAt: Date.now(),
                    lastActivityAt: Date.now(),
                    authState: 'pending-auth',
                };

                // Accept the WebSocket with minimal tags (no user-specific tags until auth)
                const tags = [`conn:${connectionId.slice(0, 8)}`, 'auth:pending'];

                this.ctx.acceptWebSocket(server, tags);

                // Serialize metadata for hibernation recovery
                server.serializeAttachment(metadata);

                // Store in our local map
                this.connections.set(server, metadata);

                // Set up auth timeout using Durable Object alarm
                // If client doesn't authenticate within timeout, close connection
                const authDeadline = Date.now() + this.config.authTimeoutMs;
                this.pendingAuthAlarms.set(connectionId, authDeadline);
                await this.scheduleAuthTimeout();

                // Log pending connection
                if (this.env.ENVIRONMENT !== 'production') {
                    console.log(
                        `[ConnectionManager] New connection (pending auth): ${connectionId}`
                    );
                }
            }

            return new Response(null, {
                status: 101,
                webSocket: client,
            });
        }

        return new Response('Not found', { status: 404 });
    }

    /**
     * Handle incoming WebSocket messages
     *
     * Called when a connected client sends a message.
     * The DO may wake from hibernation to process this message.
     *
     * Routes messages to appropriate handlers:
     * - Database update handlers (session, machine, artifact, usage)
     * - RPC forwarding
     * - Generic broadcast forwarding
     *
     * @param ws - The WebSocket that sent the message
     * @param message - The message content (string or binary)
     * @see HAP-283 - WebSocket message handlers for database updates
     */
    override async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string): Promise<void> {
        // Update last activity timestamp
        const metadata = this.connections.get(ws);
        if (metadata) {
            metadata.lastActivityAt = Date.now();
            ws.serializeAttachment(metadata);
        }

        // Parse the message - accept both client and server formats
        let raw: unknown;
        try {
            const messageStr = typeof message === 'string' ? message : new TextDecoder().decode(message);
            raw = JSON.parse(messageStr);
        } catch {
            this.sendError(ws, CloseCode.PROTOCOL_ERROR, 'Invalid JSON message');
            return;
        }

        // Normalize to unified format (supports both {event, data, ackId} and {type, payload, timestamp})
        const normalized = normalizeMessage(raw);
        if (!normalized) {
            this.sendError(ws, CloseCode.PROTOCOL_ERROR, 'Invalid message format');
            return;
        }

        // Handle acknowledgement responses from server-to-client (for emitWithAck pattern)
        // Client sends: { event, data, ackId }
        // Server responds: { event: 'ack', ackId, ack: responseData }
        // HAP-689: Don't skip rpc-response messages - they need to be forwarded to the requesting client
        // The CLI sends rpc-response with both ack (encrypted response) and ackId (correlation ID)
        if (normalized.ack !== undefined && normalized.messageId && normalized.type !== 'rpc-response') {
            // This is a simple acknowledgement - not an RPC response that needs forwarding
            return;
        }

        // =============================================
        // HAP-360: Handle auth message for pending-auth connections
        // =============================================
        if (metadata?.authState === 'pending-auth') {
            // Only allow 'auth' messages from pending-auth connections
            if (normalized.type === 'auth') {
                const payload = normalized.payload as AuthMessagePayload | undefined;
                if (!payload?.token) {
                    const errorMsg: ClientMessage = {
                        event: 'auth-error',
                        data: {
                            code: CloseCode.AUTH_FAILED,
                            message: 'Auth message must include token',
                            timestamp: Date.now(),
                        },
                    };
                    try {
                        ws.send(JSON.stringify(errorMsg));
                    } catch {
                        // Ignore
                    }
                    return;
                }

                // Process auth message
                const result = await this.handleAuthMessage(ws, metadata, payload);
                if (!result) {
                    // Auth failed - close connection
                    try {
                        ws.close(CloseCode.AUTH_FAILED, 'Authentication failed');
                    } catch {
                        // Already closed
                    }
                }
                return;
            } else {
                // Reject non-auth messages from pending-auth connections
                const errorMsg: ClientMessage = {
                    event: 'auth-error',
                    data: {
                        code: CloseCode.AUTH_FAILED,
                        message: 'Connection not authenticated - send auth message first',
                        timestamp: Date.now(),
                    },
                };
                try {
                    ws.send(JSON.stringify(errorMsg));
                } catch {
                    // Ignore
                }
                return;
            }
        }

        // Create handler context for database operations
        const handlerCtx: HandlerContext | null = this.userId
            ? {
                  userId: this.userId,
                  db: getDb(this.env.DB),
                  machineId: metadata?.machineId,
                  sessionId: metadata?.sessionId,
              }
            : null;

        // Handle message by type (normalized from either format)
        switch (normalized.type) {
            case 'ping':
                // Respond with pong in client-compatible format
                ws.send(JSON.stringify({
                    event: 'pong',
                    data: { timestamp: Date.now() },
                }));
                break;

            // =========================================================================
            // SESSION HANDLERS - Database update events
            // =========================================================================
            case 'update-metadata':
                if (handlerCtx) {
                    const result = await handleSessionMetadataUpdate(
                        handlerCtx,
                        normalized.payload as { sid: string; metadata: string; expectedVersion: number }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'update-state':
                if (handlerCtx) {
                    const result = await handleSessionStateUpdate(
                        handlerCtx,
                        normalized.payload as { sid: string; agentState: string | null; expectedVersion: number }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'session-alive':
                if (handlerCtx) {
                    const result = await handleSessionAlive(
                        handlerCtx,
                        normalized.payload as { sid: string; time: number; thinking?: boolean }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'session-end':
                if (handlerCtx) {
                    const result = await handleSessionEnd(
                        handlerCtx,
                        normalized.payload as { sid: string; time: number }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'message':
                if (handlerCtx) {
                    const result = await handleSessionMessage(
                        handlerCtx,
                        normalized.payload as { sid: string; message: string; localId?: string }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId, metadata?.connectionId);
                }
                break;

            // =========================================================================
            // MACHINE HANDLERS - Database update events
            // =========================================================================
            case 'machine-alive':
                if (handlerCtx) {
                    const result = await handleMachineAlive(
                        handlerCtx,
                        normalized.payload as { machineId: string; time: number }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'machine-update-metadata':
                if (handlerCtx) {
                    const result = await handleMachineMetadataUpdate(
                        handlerCtx,
                        normalized.payload as { machineId: string; metadata: string; expectedVersion: number }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'machine-update-state':
                if (handlerCtx) {
                    const result = await handleMachineStateUpdate(
                        handlerCtx,
                        normalized.payload as { machineId: string; daemonState: string; expectedVersion: number }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            // =========================================================================
            // ARTIFACT HANDLERS - Database update events
            // =========================================================================
            case 'artifact-read':
                if (handlerCtx) {
                    const result = await handleArtifactRead(
                        handlerCtx,
                        normalized.payload as { artifactId: string }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'artifact-update':
                if (handlerCtx) {
                    const result = await handleArtifactUpdate(
                        handlerCtx,
                        normalized.payload as {
                            artifactId: string;
                            header?: { data: string; expectedVersion: number };
                            body?: { data: string; expectedVersion: number };
                        }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'artifact-create':
                if (handlerCtx) {
                    const result = await handleArtifactCreate(
                        handlerCtx,
                        normalized.payload as { id: string; header: string; body: string; dataEncryptionKey: string }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'artifact-delete':
                if (handlerCtx) {
                    const result = await handleArtifactDelete(
                        handlerCtx,
                        normalized.payload as { artifactId: string }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            // =========================================================================
            // ACCESS KEY HANDLERS
            // =========================================================================
            case 'access-key-get':
                if (handlerCtx) {
                    const result = await handleAccessKeyGet(
                        handlerCtx,
                        normalized.payload as { sessionId: string; machineId: string }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            // =========================================================================
            // USAGE HANDLERS
            // =========================================================================
            case 'usage-report':
                if (handlerCtx) {
                    const result = await handleUsageReport(
                        handlerCtx,
                        normalized.payload as {
                            key: string;
                            sessionId?: string;
                            tokens: { total: number; [key: string]: number };
                            cost: { total: number; [key: string]: number };
                        }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            case 'update-usage-limits': {
                // HAP-751: Store usage limits from CLI in DO storage
                // This doesn't require database access - stores directly in DO storage
                const result = await this.handleUsageLimitsUpdate(
                    normalized.payload as {
                        sessionLimit?: {
                            id: string;
                            label: string;
                            percentageUsed: number;
                            resetsAt: number | null;
                            resetDisplayType: 'countdown' | 'datetime';
                            description?: string;
                        };
                        weeklyLimits: Array<{
                            id: string;
                            label: string;
                            percentageUsed: number;
                            resetsAt: number | null;
                            resetDisplayType: 'countdown' | 'datetime';
                            description?: string;
                        }>;
                        limitsAvailable: boolean;
                        provider?: string;
                    }
                );
                await this.processHandlerResult(ws, result, normalized.messageId);
                break;
            }

            // =========================================================================
            // DELTA SYNC HANDLERS (HAP-441)
            // =========================================================================
            case 'request-updates-since':
                // Handle delta sync request on reconnection
                if (handlerCtx) {
                    const result = await handleRequestUpdatesSince(
                        handlerCtx,
                        normalized.payload as { sessions: number; machines: number; artifacts: number }
                    );
                    await this.processHandlerResult(ws, result, normalized.messageId);
                }
                break;

            // =========================================================================
            // RPC HANDLERS - Message forwarding
            // =========================================================================
            case 'broadcast':
                // Client requests to broadcast a message to other connections
                // Note: Most broadcasts should come from the Worker via /broadcast endpoint
                if (metadata) {
                    this.broadcastClientMessage(
                        {
                            event: 'broadcast',
                            data: normalized.payload,
                        },
                        {
                            type: 'exclude',
                            connectionId: metadata.connectionId,
                        }
                    );
                }
                break;

            case 'rpc-call':
            case 'rpc-request': {
                // Forward RPC requests to the appropriate session/machine scoped connection
                // The RPC message should contain target info in payload
                const rpcPayload = normalized.payload as { method?: string } | undefined;

                // HAP-297: Log RPC request received
                this.logRpcRouting('RPC request received', {
                    type: normalized.type,
                    method: rpcPayload?.method,
                    senderClientType: metadata?.clientType,
                    ackId: normalized.messageId,
                });

                if (metadata?.clientType !== 'user-scoped') {
                    // Forward to user-scoped connections (mobile app handles RPC routing)
                    const filter = { type: 'user-scoped-only' as const };
                    const delivered = this.broadcastClientMessage(
                        {
                            event: normalized.type,
                            data: normalized.payload,
                            ackId: normalized.messageId,
                        },
                        filter
                    );

                    // HAP-297: Log broadcast filter selection
                    this.logRpcRouting('Broadcast filter: non-user-scoped → user-scoped', {
                        filterType: filter.type,
                        connectionsDelivered: delivered,
                    });
                } else {
                    // User-scoped client sending RPC - forward to session/machine scoped
                    if (rpcPayload?.method) {
                        // Extract target from method (format: "sessionId:methodName" or "machineId:methodName")
                        const parts = rpcPayload.method.split(':');
                        const targetId = parts[0];
                        if (targetId) {
                            // Check if the targetId matches a machine-scoped connection
                            // This determines whether to route to machine or session
                            let hasMachineConnection = false;
                            for (const connMetadata of this.connections.values()) {
                                if (
                                    connMetadata.clientType === 'machine-scoped' &&
                                    connMetadata.machineId === targetId
                                ) {
                                    hasMachineConnection = true;
                                    break;
                                }
                            }

                            // HAP-297: Log targetId extraction and machine connection lookup
                            this.logRpcRouting('Target extraction', {
                                targetId,
                                hasMachineConnection,
                                totalConnections: this.connections.size,
                            });

                            if (hasMachineConnection) {
                                // Target is a machine - route to machine-scoped connection
                                const filter = { type: 'machine' as const, machineId: targetId };
                                const delivered = this.broadcastClientMessage(
                                    {
                                        event: 'rpc-request',
                                        data: normalized.payload,
                                        ackId: normalized.messageId,
                                    },
                                    filter
                                );

                                // HAP-297: Log broadcast filter selection
                                this.logRpcRouting('Broadcast filter: machine', {
                                    filterType: filter.type,
                                    machineId: targetId,
                                    connectionsDelivered: delivered,
                                });
                            } else {
                                // Target is a session - route to session-scoped connections and user-scoped
                                const filter = { type: 'all-interested-in-session' as const, sessionId: targetId };
                                const delivered = this.broadcastClientMessage(
                                    {
                                        event: 'rpc-request',
                                        data: normalized.payload,
                                        ackId: normalized.messageId,
                                    },
                                    filter
                                );

                                // HAP-297: Log broadcast filter selection
                                this.logRpcRouting('Broadcast filter: all-interested-in-session', {
                                    filterType: filter.type,
                                    sessionId: targetId,
                                    connectionsDelivered: delivered,
                                });
                            }
                        }
                    }
                }
                break;
            }

            case 'rpc-response':
                // Forward RPC response back to the requesting client
                // The ackId identifies the original request
                if (normalized.messageId) {
                    // HAP-297: Log RPC response routing
                    this.logRpcRouting('RPC response routing', {
                        ackId: normalized.messageId,
                        senderClientType: metadata?.clientType,
                    });

                    // HAP-689: CRITICAL FIX - Two issues were causing RPC responses to fail:
                    //
                    // 1. Event name mismatch: The app's sessionRPC uses emitWithAck which
                    //    expects responses with event: 'ack', NOT event: 'rpc-response'.
                    //
                    // 2. Response format mismatch: The CLI sends just the encrypted response
                    //    string in the 'ack' field, but the app expects an object with format:
                    //    { ok: boolean, result: string, cancelled?: boolean, requestId?: string }
                    //
                    // The CLI sends: { event: 'rpc-response', ackId, ack: encryptedString }
                    // The app expects: { event: 'ack', ackId, ack: { ok: true, result: encryptedString } }
                    //
                    // Note: The app will decrypt the 'result' field and then check the decrypted
                    // content for errors like SESSION_NOT_ACTIVE.
                    const filter = { type: 'all' as const };
                    const delivered = this.broadcastClientMessage(
                        {
                            event: 'ack', // Fix #1: Changed from 'rpc-response' to 'ack'
                            ackId: normalized.messageId,
                            ack: { ok: true, result: normalized.ack }, // Fix #2: Wrap in expected format
                        },
                        filter
                    );

                    // HAP-297: Log broadcast result
                    this.logRpcRouting('RPC response broadcast complete', {
                        filterType: filter.type,
                        connectionsDelivered: delivered,
                    });
                }
                break;

            default:
                // Forward unhandled message types to appropriate connections
                // This allows the mobile app to receive events from CLI and vice versa
                if (metadata?.clientType !== 'user-scoped') {
                    // Non-user-scoped (CLI) → forward to user-scoped (mobile)
                    this.broadcastClientMessage(
                        {
                            event: normalized.type,
                            data: normalized.payload,
                            ackId: normalized.messageId,
                        },
                        { type: 'user-scoped-only' }
                    );
                } else {
                    // User-scoped (mobile) sending event → forward based on payload content
                    // Try to extract sessionId or machineId from payload for targeted delivery
                    const payload = normalized.payload as { sessionId?: string; machineId?: string } | undefined;
                    if (payload?.sessionId) {
                        this.broadcastClientMessage(
                            {
                                event: normalized.type,
                                data: normalized.payload,
                                ackId: normalized.messageId,
                            },
                            { type: 'session', sessionId: payload.sessionId }
                        );
                    } else if (payload?.machineId) {
                        this.broadcastClientMessage(
                            {
                                event: normalized.type,
                                data: normalized.payload,
                                ackId: normalized.messageId,
                            },
                            { type: 'machine', machineId: payload.machineId }
                        );
                    }
                }
                break;
        }
    }

    /**
     * Process handler result - send response and broadcast updates
     *
     * @param ws - WebSocket to send response to
     * @param result - Handler result with response and/or broadcast
     * @param ackId - Optional ack ID for request-response correlation
     * @param skipConnectionId - Optional connection ID to exclude from broadcast
     */
    private async processHandlerResult(
        ws: WebSocket,
        result: HandlerResult,
        ackId?: string,
        skipConnectionId?: string
    ): Promise<void> {
        // Send response if provided
        if (result.response !== undefined) {
            const responseMsg: ClientMessage = {
                event: 'ack',
                ackId,
                ack: result.response,
            };
            try {
                ws.send(JSON.stringify(responseMsg));
            } catch {
                // Connection may be closed
            }
        }

        // Broadcast update if provided
        if (result.broadcast) {
            // Add connection exclusion if requested (for message events to avoid echo)
            let filter = result.broadcast.filter;
            if (skipConnectionId) {
                // Wrap in exclude filter if not already excluding
                if (filter.type !== 'exclude') {
                    // For now, just use the original filter - true exclusion would need more complex logic
                }
            }
            this.broadcastClientMessage(result.broadcast.message, filter);
        }

        // Broadcast ephemeral event if provided
        if (result.ephemeral) {
            this.broadcastClientMessage(result.ephemeral.message, result.ephemeral.filter);
        }
    }

    /**
     * Handle WebSocket connection close
     *
     * Called when a client disconnects (cleanly or due to error).
     * Cleans up connection state and broadcasts disconnect notification.
     *
     * @param ws - The WebSocket that closed
     * @param code - Close code (standard or custom)
     * @param reason - Close reason string
     * @param wasClean - Whether the close was clean (client-initiated)
     */
    override async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
        const metadata = this.connections.get(ws);

        if (metadata) {
            // Log disconnection
            if (this.env.ENVIRONMENT !== 'production') {
                console.log(
                    `[ConnectionManager] Connection closed: ${metadata.connectionId}, type: ${metadata.clientType}, code: ${code}, clean: ${wasClean}`
                );
            }

            // Broadcast machine offline status if this was a machine-scoped connection
            if (metadata.clientType === 'machine-scoped' && metadata.machineId) {
                this.broadcastClientMessage(
                    {
                        event: 'machine-update',
                        data: {
                            machineId: metadata.machineId,
                            active: false,
                            timestamp: Date.now(),
                        },
                    },
                    { type: 'user-scoped-only' }
                );
            }

            // Remove from our map
            this.connections.delete(ws);
        }

        // Close the WebSocket if not already closed
        try {
            ws.close(code, reason || 'Connection closed');
        } catch {
            // Already closed, ignore
        }
    }

    /**
     * Handle WebSocket errors
     *
     * Called when a WebSocket encounters an error.
     * Logs the error, captures to Sentry (via instrumentDurableObjectWithSentry wrapper),
     * and closes the connection.
     *
     * @param ws - The WebSocket that errored
     * @param error - The error that occurred
     */
    override async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
        const metadata = this.connections.get(ws);
        const connectionId = metadata?.connectionId || 'unknown';

        console.error(
            `[ConnectionManager] WebSocket error for connection ${connectionId}:`,
            error
        );

        // Set Sentry context for this error
        // Note: Error capture is handled automatically by instrumentDurableObjectWithSentry
        Sentry.setContext('connection', {
            connectionId,
            clientType: metadata?.clientType,
            sessionId: metadata?.sessionId,
            machineId: metadata?.machineId,
            authState: metadata?.authState,
        });
        Sentry.setTag('operation', 'webSocketError');

        // Clean up the connection
        this.connections.delete(ws);

        try {
            ws.close(CloseCode.INTERNAL_ERROR, 'Internal error');
        } catch {
            // Already closed, ignore
        }

        // Re-throw error so instrumentDurableObjectWithSentry can capture it
        throw error;
    }

    /**
     * Parse authentication handshake from request
     *
     * Extracts token and client type from query params or headers.
     *
     * @param url - Request URL with query params
     * @param headers - Request headers
     * @returns Parsed handshake data or null if invalid
     */
    private parseHandshake(url: URL, headers: Headers): WebSocketAuthHandshake | null {
        // Try query params first (WebSocket clients often use this)
        let token = url.searchParams.get('token');
        let clientType = url.searchParams.get('clientType') as ClientType | null;
        let sessionId = url.searchParams.get('sessionId');
        let machineId = url.searchParams.get('machineId');

        // Fall back to headers
        if (!token) {
            const authHeader = headers.get('Authorization');
            if (authHeader?.startsWith('Bearer ')) {
                token = authHeader.slice(7);
            }
        }
        if (!clientType) {
            clientType = headers.get('X-Client-Type') as ClientType | null;
        }
        if (!sessionId) {
            sessionId = headers.get('X-Session-Id');
        }
        if (!machineId) {
            machineId = headers.get('X-Machine-Id');
        }

        // Token is required
        if (!token) {
            return null;
        }

        // Default to user-scoped if not specified
        if (!clientType || !['user-scoped', 'session-scoped', 'machine-scoped'].includes(clientType)) {
            clientType = 'user-scoped';
        }

        return {
            token,
            clientType,
            sessionId: sessionId || undefined,
            machineId: machineId || undefined,
        };
    }

    /**
     * Validate client type requirements
     *
     * Ensures session-scoped clients provide sessionId and
     * machine-scoped clients provide machineId.
     *
     * @param handshake - Parsed handshake data
     * @returns Validation result with error message if invalid
     */
    private validateClientType(handshake: WebSocketAuthHandshake): { valid: boolean; error?: string } {
        if (handshake.clientType === 'session-scoped' && !handshake.sessionId) {
            return { valid: false, error: 'Session ID required for session-scoped connections' };
        }
        if (handshake.clientType === 'machine-scoped' && !handshake.machineId) {
            return { valid: false, error: 'Machine ID required for machine-scoped connections' };
        }
        return { valid: true };
    }

    /**
     * Build tags for a connection
     *
     * Tags are used by getWebSockets() to filter connections efficiently.
     * Max 10 tags per connection, max 256 chars each.
     *
     * HAP-456: Added 'auth:yes' tag for authenticated connections to enable
     * O(1) broadcast filtering that excludes pending-auth connections.
     *
     * @param metadata - Connection metadata
     * @returns Array of tags for this connection
     */
    private buildConnectionTags(metadata: ConnectionMetadata): string[] {
        const tags: string[] = [
            `type:${metadata.clientType}`,
            `conn:${metadata.connectionId.slice(0, 8)}`, // Shortened for tag limit
        ];

        // HAP-456: Only authenticated connections get the auth tag
        // This enables O(1) filtering in broadcast methods
        if (metadata.authState !== 'pending-auth') {
            tags.push('auth:yes');
        }

        if (metadata.sessionId) {
            tags.push(`session:${metadata.sessionId.slice(0, 50)}`);
        }

        if (metadata.machineId) {
            tags.push(`machine:${metadata.machineId.slice(0, 50)}`);
        }

        return tags;
    }

    /**
     * Send a message to all WebSockets matching a tag (HAP-456)
     *
     * Uses ctx.getWebSockets(tag) for O(1) lookup instead of iterating all connections.
     * This is the core optimization for broadcast performance.
     *
     * @param tag - Tag to filter WebSockets by
     * @param messageStr - Pre-serialized message string
     * @returns Number of WebSockets the message was delivered to
     */
    private sendToTag(tag: string, messageStr: string): number {
        const sockets = this.ctx.getWebSockets(tag);
        let delivered = 0;

        for (const ws of sockets) {
            try {
                ws.send(messageStr);
                delivered++;
            } catch {
                // Connection may be dead, will be cleaned up on next close event
            }
        }

        return delivered;
    }

    /**
     * Send an error message to a specific WebSocket
     *
     * Uses client format {event, data} for compatibility with happy-cli and happy-app
     *
     * @param ws - Target WebSocket
     * @param code - Error code
     * @param message - Error message
     */
    private sendError(ws: WebSocket, code: number, message: string): void {
        const errorMsg: ClientMessage = {
            event: 'error',
            data: { code, message, timestamp: Date.now() },
        };
        try {
            ws.send(JSON.stringify(errorMsg));
        } catch {
            // Connection may be closed, ignore
        }
    }

    /**
     * Log RPC routing decisions when DEBUG_RPC_ROUTING is enabled (HAP-297)
     *
     * This helper provides conditional debug logging for RPC routing to help
     * diagnose issues with message delivery and broadcast filter selection.
     *
     * @param message - The log message
     * @param context - Optional context object with additional details
     */
    private logRpcRouting(message: string, context?: Record<string, unknown>): void {
        if (this.env.DEBUG_RPC_ROUTING !== 'true') {
            return;
        }
        if (context) {
            console.log(`[RPC-Routing] ${message}`, JSON.stringify(context));
        } else {
            console.log(`[RPC-Routing] ${message}`);
        }
    }

    /**
     * Broadcast a message to connections matching a filter
     *
     * HAP-456: Optimized to use tag-based O(1) lookups where possible.
     * Falls back to O(n) iteration only for complex hybrid filters.
     *
     * @param message - Message to broadcast
     * @param filter - Optional filter to select target connections
     * @returns Number of connections the message was delivered to
     */
    private broadcast(message: WebSocketMessage, filter?: MessageFilter): number {
        const messageStr = JSON.stringify(message);

        // HAP-456: Use tag-based O(1) lookups for simple filter types
        const tag = this.getTagForFilter(filter);
        if (tag) {
            return this.sendToTag(tag, messageStr);
        }

        // Fall back to O(n) iteration for complex hybrid filters
        return this.broadcastWithIteration(messageStr, filter);
    }

    /**
     * Get the tag to use for a simple filter type (HAP-456)
     *
     * Returns the tag for O(1) lookup, or null if the filter requires iteration.
     *
     * @param filter - Filter to convert to tag
     * @returns Tag string for simple filters, null for complex filters
     */
    private getTagForFilter(filter?: MessageFilter): string | null {
        if (!filter || filter.type === 'all') {
            // All authenticated connections
            return 'auth:yes';
        }

        switch (filter.type) {
            case 'user-scoped-only':
                return 'type:user-scoped';

            case 'session':
                return `session:${filter.sessionId.slice(0, 50)}`;

            case 'machine':
                return `machine:${filter.machineId.slice(0, 50)}`;

            // Complex filters that require iteration
            case 'machine-scoped-only':
            case 'exclude':
            case 'all-interested-in-session':
                return null;

            default:
                return null;
        }
    }

    /**
     * Broadcast using O(n) iteration for complex filters (HAP-456)
     *
     * Used as fallback for filters that can't be expressed as a single tag.
     *
     * @param messageStr - Pre-serialized message string
     * @param filter - Filter to apply
     * @returns Number of connections the message was delivered to
     */
    private broadcastWithIteration(messageStr: string, filter?: MessageFilter): number {
        let delivered = 0;

        for (const [ws, metadata] of this.connections.entries()) {
            if (this.matchesFilter(metadata, filter)) {
                try {
                    ws.send(messageStr);
                    delivered++;
                } catch {
                    // Connection may be dead, will be cleaned up on next close event
                }
            }
        }

        return delivered;
    }


    /**
     * Broadcast a client-format message to connections matching the filter
     *
     * This method sends messages in the client-compatible format:
     * { event, data, ackId?, ack? }
     *
     * Used for forwarding messages between clients (CLI ↔ Mobile) where
     * both sides expect the Socket.io-style format.
     *
     * HAP-456: Optimized to use tag-based O(1) lookups where possible.
     *
     * @param message Client-format message to broadcast
     * @param filter Optional filter to target specific connections
     * @returns Number of connections the message was delivered to
     *
     * @see HAP-271 - Protocol alignment between clients and Workers backend
     */
    private broadcastClientMessage(message: ClientMessage, filter?: MessageFilter): number {
        const messageStr = JSON.stringify(message);

        // HAP-456: Use tag-based O(1) lookups for simple filter types
        const tag = this.getTagForFilter(filter);
        if (tag) {
            return this.sendToTag(tag, messageStr);
        }

        // Fall back to O(n) iteration for complex hybrid filters
        return this.broadcastWithIteration(messageStr, filter);
    }

    /**
     * Check if a connection matches a broadcast filter
     *
     * @param metadata - Connection metadata
     * @param filter - Filter to check against
     * @returns True if connection matches filter
     */
    private matchesFilter(metadata: ConnectionMetadata, filter?: MessageFilter): boolean {
        // HAP-360: Never broadcast to pending-auth connections
        if (metadata.authState === 'pending-auth') {
            return false;
        }

        if (!filter || filter.type === 'all') {
            return true;
        }

        switch (filter.type) {
            case 'user-scoped-only':
                return metadata.clientType === 'user-scoped';

            case 'session':
                return metadata.sessionId === filter.sessionId;

            case 'machine':
                return metadata.machineId === filter.machineId;

            case 'machine-scoped-only':
                // Send to user-scoped connections + specific machine-scoped connection
                // This hybrid pattern notifies both mobile app (dashboard) and the CLI daemon
                if (metadata.clientType === 'user-scoped') {
                    return true;
                }
                if (metadata.clientType === 'machine-scoped') {
                    return metadata.machineId === filter.machineId;
                }
                return false;

            case 'exclude':
                return metadata.connectionId !== filter.connectionId;

            case 'all-interested-in-session':
                // Send to session-scoped connections with matching session + all user-scoped connections
                // Machine-scoped connections don't receive session updates
                if (metadata.clientType === 'session-scoped') {
                    return metadata.sessionId === filter.sessionId;
                }
                if (metadata.clientType === 'machine-scoped') {
                    return false;
                }
                // user-scoped connections always get session updates
                return true;

            default:
                return true;
        }
    }

    /**
     * Get connection statistics
     *
     * @returns Current connection statistics
     */
    private getStats(): ConnectionStats {
        const stats: ConnectionStats = {
            totalConnections: this.connections.size,
            byType: {
                'user-scoped': 0,
                'session-scoped': 0,
                'machine-scoped': 0,
            },
            activeSessions: 0,
            activeMachines: 0,
            oldestConnection: null,
        };

        const sessions = new Set<string>();
        const machines = new Set<string>();
        let oldest: number | null = null;

        for (const metadata of this.connections.values()) {
            stats.byType[metadata.clientType]++;

            if (metadata.sessionId) {
                sessions.add(metadata.sessionId);
            }

            if (metadata.machineId) {
                machines.add(metadata.machineId);
            }

            if (oldest === null || metadata.connectedAt < oldest) {
                oldest = metadata.connectedAt;
            }
        }

        stats.activeSessions = sessions.size;
        stats.activeMachines = machines.size;
        stats.oldestConnection = oldest;

        return stats;
    }

    /**
     * Get cached usage limits (HAP-731)
     *
     * Returns plan limits data cached from connected CLI sessions.
     * The CLI polls the AI provider for usage limits and sends updates via WebSocket.
     * This data is stored in the Durable Object's persistent storage.
     *
     * @returns Response with plan limits or unavailable status
     */
    private async getUsageLimits(): Promise<Response> {
        // Storage key for usage limits data
        const USAGE_LIMITS_KEY = 'usage:limits';

        try {
            // Read from persistent storage
            const cached = await this.ctx.storage.get<{
                sessionLimit?: {
                    id: string;
                    label: string;
                    percentageUsed: number;
                    resetsAt: number | null;
                    resetDisplayType: 'countdown' | 'datetime';
                    description?: string;
                };
                weeklyLimits: Array<{
                    id: string;
                    label: string;
                    percentageUsed: number;
                    resetsAt: number | null;
                    resetDisplayType: 'countdown' | 'datetime';
                    description?: string;
                }>;
                lastUpdatedAt: number;
                limitsAvailable: boolean;
                provider?: string;
            }>(USAGE_LIMITS_KEY);

            if (cached) {
                return Response.json(cached);
            }

            // No cached data available
            return Response.json({
                limitsAvailable: false,
                weeklyLimits: [],
                lastUpdatedAt: Date.now(),
            });
        } catch (error) {
            console.error('[ConnectionManager] Failed to get usage limits:', error);
            return Response.json({
                limitsAvailable: false,
                weeklyLimits: [],
                lastUpdatedAt: Date.now(),
            });
        }
    }

    /**
     * Handle usage limits update from CLI (HAP-751)
     *
     * Receives usage limits data from the CLI via WebSocket and stores it
     * in the Durable Object's persistent storage for later retrieval via
     * GET /v1/usage/limits endpoint.
     *
     * @param data - The usage limits data from the CLI
     * @returns HandlerResult with success status
     */
    private async handleUsageLimitsUpdate(data: {
        sessionLimit?: {
            id: string;
            label: string;
            percentageUsed: number;
            resetsAt: number | null;
            resetDisplayType: 'countdown' | 'datetime';
            description?: string;
        };
        weeklyLimits: Array<{
            id: string;
            label: string;
            percentageUsed: number;
            resetsAt: number | null;
            resetDisplayType: 'countdown' | 'datetime';
            description?: string;
        }>;
        limitsAvailable: boolean;
        provider?: string;
    }): Promise<HandlerResult> {
        const USAGE_LIMITS_KEY = 'usage:limits';

        try {
            // Validate required fields
            if (typeof data?.limitsAvailable !== 'boolean') {
                return {
                    response: { success: false, error: 'Invalid payload: limitsAvailable must be boolean' },
                };
            }

            if (!Array.isArray(data.weeklyLimits)) {
                return {
                    response: { success: false, error: 'Invalid payload: weeklyLimits must be array' },
                };
            }

            // Store in persistent storage with timestamp
            await this.ctx.storage.put(USAGE_LIMITS_KEY, {
                ...data,
                lastUpdatedAt: Date.now(),
            });

            return {
                response: { success: true },
            };
        } catch (error) {
            console.error('[ConnectionManager] Failed to store usage limits:', error);
            return {
                response: { success: false, error: 'Failed to store usage limits' },
            };
        }
    }

    // =========================================================================
    // HAP-360: MESSAGE-BASED AUTHENTICATION
    // =========================================================================

    /**
     * Schedule an alarm for the earliest auth timeout (HAP-360)
     *
     * Durable Objects can only have one alarm at a time, so we schedule
     * for the earliest deadline among all pending auth connections.
     */
    private async scheduleAuthTimeout(): Promise<void> {
        if (this.pendingAuthAlarms.size === 0) {
            return;
        }

        // Find the earliest deadline
        let earliestDeadline = Infinity;
        for (const deadline of this.pendingAuthAlarms.values()) {
            if (deadline < earliestDeadline) {
                earliestDeadline = deadline;
            }
        }

        // Schedule alarm (Durable Objects can only have one alarm)
        // This might overwrite an existing alarm, but we handle all expired
        // connections when the alarm fires
        if (earliestDeadline < Infinity) {
            await this.ctx.storage.setAlarm(earliestDeadline);
        }
    }

    /**
     * Durable Object alarm handler with retry logic (HAP-360, HAP-479)
     *
     * This method wraps the actual alarm processing with error recovery:
     * - Automatic retry with exponential backoff on failure
     * - Dead letter logging after max retries exhausted
     * - Persistent retry state across DO hibernation
     *
     * @see HAP-479 - Durable Object alarm scheduling lacks error recovery
     */
    override async alarm(): Promise<void> {
        // Check if this is a retry attempt
        const retryState = await this.ctx.storage.get<AlarmRetryState>(
            ConnectionManager.ALARM_RETRY_STATE_KEY
        );

        const currentAttempt = retryState?.attempt ?? 0;
        const context = retryState?.context ?? 'auth-timeout';
        const originalScheduledAt = retryState?.originalScheduledAt ?? Date.now();

        try {
            // Execute the actual alarm logic
            await this.executeAlarmLogic();

            // Success - clear retry state if it exists
            if (retryState) {
                await this.ctx.storage.delete(ConnectionManager.ALARM_RETRY_STATE_KEY);
            }
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            const errorStack = error instanceof Error ? error.stack : undefined;

            // Log the error
            console.error(
                `[ConnectionManager] Alarm failed (attempt ${currentAttempt + 1}/${DEFAULT_ALARM_RETRY_CONFIG.maxRetries}):`,
                errorMessage
            );

            // Check if we should retry
            if (currentAttempt < DEFAULT_ALARM_RETRY_CONFIG.maxRetries - 1) {
                // Schedule retry with exponential backoff
                const delay = calculateBackoffDelay(currentAttempt);
                const nextAlarmTime = Date.now() + delay;

                // Save retry state for next attempt
                const nextRetryState: AlarmRetryState = {
                    attempt: currentAttempt + 1,
                    originalScheduledAt,
                    lastError: errorMessage,
                    context,
                };
                await this.ctx.storage.put(
                    ConnectionManager.ALARM_RETRY_STATE_KEY,
                    nextRetryState
                );

                // Schedule the retry alarm
                await this.ctx.storage.setAlarm(nextAlarmTime);

                if (this.env.ENVIRONMENT !== 'production') {
                    console.log(
                        `[ConnectionManager] Scheduling alarm retry in ${delay}ms (attempt ${currentAttempt + 2})`
                    );
                }
            } else {
                // Max retries exhausted - dead letter
                await this.handleAlarmDeadLetter(
                    originalScheduledAt,
                    currentAttempt + 1,
                    errorMessage,
                    context,
                    errorStack
                );

                // Clear retry state
                await this.ctx.storage.delete(ConnectionManager.ALARM_RETRY_STATE_KEY);
            }
        }
    }

    /**
     * Execute the actual alarm processing logic
     *
     * Separated from the alarm() method to allow error wrapping.
     * This contains the original auth timeout handling.
     *
     * @throws Error if processing fails (will trigger retry)
     */
    private async executeAlarmLogic(): Promise<void> {
        const now = Date.now();

        // Find all expired auth deadlines
        const expiredConnectionIds: string[] = [];
        for (const [connectionId, deadline] of this.pendingAuthAlarms.entries()) {
            if (deadline <= now) {
                expiredConnectionIds.push(connectionId);
            }
        }

        // Close expired connections
        for (const connectionId of expiredConnectionIds) {
            this.pendingAuthAlarms.delete(connectionId);

            // Find the WebSocket with this connection ID
            for (const [ws, metadata] of this.connections.entries()) {
                if (metadata.connectionId === connectionId && metadata.authState === 'pending-auth') {
                    // Send auth timeout error
                    const errorMsg: ClientMessage = {
                        event: 'auth-error',
                        data: {
                            code: CloseCode.AUTH_TIMEOUT,
                            message: 'Authentication timeout - auth message not received in time',
                            timestamp: Date.now(),
                        },
                    };
                    try {
                        ws.send(JSON.stringify(errorMsg));
                    } catch {
                        // Ignore send errors
                    }

                    // Close the connection
                    this.connections.delete(ws);
                    try {
                        ws.close(CloseCode.AUTH_TIMEOUT, 'Authentication timeout');
                    } catch {
                        // Already closed
                    }

                    if (this.env.ENVIRONMENT !== 'production') {
                        console.log(`[ConnectionManager] Auth timeout: ${connectionId}`);
                    }
                    break;
                }
            }
        }

        // Reschedule for remaining pending auths
        await this.scheduleAuthTimeout();
    }

    /**
     * Handle a dead-lettered alarm (HAP-479)
     *
     * Called when an alarm has exhausted all retry attempts.
     * Logs the failure for debugging, captures to Sentry, and stores in DO storage.
     *
     * @param originalScheduledAt - When the alarm was originally scheduled
     * @param attempts - Number of retry attempts made
     * @param finalError - The error that caused the final failure
     * @param context - Context about what the alarm was trying to do
     * @param stack - Optional stack trace
     */
    private async handleAlarmDeadLetter(
        originalScheduledAt: number,
        attempts: number,
        finalError: string,
        context: string,
        stack?: string
    ): Promise<void> {
        const deadLetterEntry: AlarmDeadLetterEntry = {
            id: crypto.randomUUID(),
            originalScheduledAt,
            deadLetteredAt: Date.now(),
            attempts,
            finalError,
            context,
            stack,
        };

        // Log prominently for monitoring/alerting
        console.error('[ConnectionManager] ALARM DEAD LETTER:', JSON.stringify(deadLetterEntry));

        // Capture to Sentry as a critical error
        // Note: Sentry is initialized by instrumentDurableObjectWithSentry wrapper
        Sentry.setTag('alarm.context', context);
        Sentry.captureMessage('Alarm dead lettered after max retries', {
            level: 'fatal',
            extra: {
                deadLetterId: deadLetterEntry.id,
                originalScheduledAt: deadLetterEntry.originalScheduledAt,
                deadLetteredAt: deadLetterEntry.deadLetteredAt,
                attempts: deadLetterEntry.attempts,
                finalError: deadLetterEntry.finalError,
                context: deadLetterEntry.context,
            },
        });

        // Store in DO storage for later analysis
        // Use timestamp-based key for chronological ordering
        const storageKey = `${ConnectionManager.DEAD_LETTER_PREFIX}${deadLetterEntry.deadLetteredAt}:${deadLetterEntry.id}`;
        await this.ctx.storage.put(storageKey, deadLetterEntry);

        // Cleanup old dead letter entries (keep last 100)
        await this.cleanupDeadLetterEntries(100);
    }

    /**
     * Cleanup old dead letter entries to prevent unbounded storage growth (HAP-479)
     *
     * @param maxEntries - Maximum number of dead letter entries to keep
     */
    private async cleanupDeadLetterEntries(maxEntries: number): Promise<void> {
        // List all dead letter entries
        const entries = await this.ctx.storage.list<AlarmDeadLetterEntry>({
            prefix: ConnectionManager.DEAD_LETTER_PREFIX,
        });

        // If within limits, nothing to do
        if (entries.size <= maxEntries) {
            return;
        }

        // Sort by key (which includes timestamp) and delete oldest
        const sortedKeys = [...entries.keys()].sort();
        const keysToDelete = sortedKeys.slice(0, entries.size - maxEntries);

        for (const key of keysToDelete) {
            await this.ctx.storage.delete(key);
        }

        if (this.env.ENVIRONMENT !== 'production') {
            console.log(`[ConnectionManager] Cleaned up ${keysToDelete.length} old dead letter entries`);
        }
    }

    /**
     * Handle auth message from client (HAP-360)
     *
     * This is called when a client in pending-auth state sends an auth message.
     * Validates the token and transitions the connection to authenticated state.
     *
     * @param ws - The WebSocket that sent the auth message
     * @param metadata - Current connection metadata
     * @param payload - The auth message payload
     * @returns Updated metadata if auth succeeded, null if failed
     */
    private async handleAuthMessage(
        ws: WebSocket,
        metadata: ConnectionMetadata,
        payload: AuthMessagePayload
    ): Promise<ConnectionMetadata | null> {
        // Verify the token (with distributed blacklist check - HAP-507)
        const verified = await verifyToken(payload.token, this.env.DB);
        if (!verified) {
            const errorMsg: ClientMessage = {
                event: 'auth-error',
                data: {
                    code: CloseCode.AUTH_FAILED,
                    message: 'Invalid authentication token',
                    timestamp: Date.now(),
                },
            };
            try {
                ws.send(JSON.stringify(errorMsg));
            } catch {
                // Ignore
            }
            return null;
        }

        // Validate client type requirements
        const clientType = payload.clientType || 'user-scoped';
        if (clientType === 'session-scoped' && !payload.sessionId) {
            const errorMsg: ClientMessage = {
                event: 'auth-error',
                data: {
                    code: CloseCode.MISSING_SESSION_ID,
                    message: 'Session ID required for session-scoped connections',
                    timestamp: Date.now(),
                },
            };
            try {
                ws.send(JSON.stringify(errorMsg));
            } catch {
                // Ignore
            }
            return null;
        }
        if (clientType === 'machine-scoped' && !payload.machineId) {
            const errorMsg: ClientMessage = {
                event: 'auth-error',
                data: {
                    code: CloseCode.MISSING_MACHINE_ID,
                    message: 'Machine ID required for machine-scoped connections',
                    timestamp: Date.now(),
                },
            };
            try {
                ws.send(JSON.stringify(errorMsg));
            } catch {
                // Ignore
            }
            return null;
        }

        // Clear the auth timeout
        this.pendingAuthAlarms.delete(metadata.connectionId);

        // Update metadata with authenticated info
        const updatedMetadata: ConnectionMetadata = {
            ...metadata,
            userId: verified.userId,
            clientType: clientType,
            sessionId: payload.sessionId,
            machineId: payload.machineId,
            authState: 'authenticated',
            lastActivityAt: Date.now(),
        };

        // Update the attachment for hibernation recovery
        ws.serializeAttachment(updatedMetadata);

        // Update our map
        this.connections.set(ws, updatedMetadata);

        // Set userId if this is the first authenticated connection
        if (!this.userId) {
            this.userId = verified.userId;
        }

        // Send connected confirmation
        const connectedMsg: ClientMessage = {
            event: 'connected',
            data: {
                connectionId: metadata.connectionId,
                userId: verified.userId,
                clientType: clientType,
                sessionId: payload.sessionId,
                machineId: payload.machineId,
                timestamp: Date.now(),
            },
        };
        try {
            ws.send(JSON.stringify(connectedMsg));
        } catch {
            // Ignore
        }

        // Broadcast machine online status if applicable
        if (clientType === 'machine-scoped' && payload.machineId) {
            this.broadcastClientMessage(
                {
                    event: 'machine-update',
                    data: {
                        machineId: payload.machineId,
                        active: true,
                        timestamp: Date.now(),
                    },
                },
                { type: 'user-scoped-only' }
            );
        }

        if (this.env.ENVIRONMENT !== 'production') {
            console.log(
                `[ConnectionManager] Auth completed: ${metadata.connectionId}, type: ${clientType}, user: ${verified.userId}`
            );
        }

        return updatedMetadata;
    }
}

/**
 * ConnectionManager Durable Object with Sentry instrumentation
 *
 * This exports the ConnectionManagerBase class wrapped with Sentry's
 * instrumentDurableObjectWithSentry, which automatically:
 * - Captures exceptions from fetch, alarm, webSocketMessage, webSocketClose, webSocketError
 * - Adds performance tracing for all methods
 * - Handles event flushing via waitUntil
 *
 * @see https://docs.sentry.io/platforms/javascript/guides/cloudflare/
 */
export const ConnectionManager = instrumentDurableObjectWithSentry(
    (env: ConnectionManagerEnv) => buildSentryOptions(env),
    ConnectionManagerBase
);

/**
 * Type alias for ConnectionManager instances
 * Use this for type annotations instead of `ConnectionManager` which is now a value
 */
export type ConnectionManagerInstance = InstanceType<typeof ConnectionManager>;

/**
 * Export the base class for testing purposes
 * Tests may need to instantiate the class directly without Sentry instrumentation
 */
export { ConnectionManagerBase };
