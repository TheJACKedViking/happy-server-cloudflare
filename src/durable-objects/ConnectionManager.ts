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
import type {
    ConnectionMetadata,
    WebSocketAuthHandshake,
    ClientType,
    WebSocketMessage,
    MessageFilter,
    ConnectionStats,
    ConnectionManagerConfig,
    ClientMessage,
} from './types';
import { CloseCode, DEFAULT_CONFIG, normalizeMessage } from './types';
import { verifyToken, initAuth } from '@/lib/auth';
import { getDb } from '@/db/client';
import type { HandlerResult, HandlerContext } from './handlers';
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
} from './handlers';

/**
 * Environment bindings for the ConnectionManager Durable Object
 */
export interface ConnectionManagerEnv {
    /** D1 Database binding for database updates */
    DB: D1Database;

    /** Master secret for auth token verification */
    HANDY_MASTER_SECRET: string;

    /** Current environment */
    ENVIRONMENT?: 'development' | 'staging' | 'production';
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
export class ConnectionManager extends DurableObject<ConnectionManagerEnv> {
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
        if (!this.authInitialized && this.env.HANDY_MASTER_SECRET) {
            await initAuth(this.env.HANDY_MASTER_SECRET);
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
            const handshake = this.parseHandshake(url, request.headers);
            if (!handshake) {
                return new Response('Invalid handshake data', { status: 400 });
            }

            // Validate authentication
            await this.ensureAuthInitialized();
            const verified = await verifyToken(handshake.token);
            if (!verified) {
                return new Response('Authentication failed', { status: 401 });
            }

            // Validate client type requirements
            const validation = this.validateClientType(handshake);
            if (!validation.valid) {
                return new Response(validation.error!, { status: 400 });
            }

            // Check connection limits
            if (this.connections.size >= this.config.maxConnectionsPerUser) {
                return new Response('Connection limit exceeded', { status: 429 });
            }

            // Create WebSocket pair
            const webSocketPair = new WebSocketPair();
            const client = webSocketPair[0];
            const server = webSocketPair[1];

            // Create connection metadata
            const connectionId = crypto.randomUUID();
            const metadata: ConnectionMetadata = {
                connectionId,
                userId: verified.userId,
                clientType: handshake.clientType,
                sessionId: handshake.sessionId,
                machineId: handshake.machineId,
                connectedAt: Date.now(),
                lastActivityAt: Date.now(),
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
            // Uses {event, data} for compatibility with happy-cli and happy-app
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

            // Broadcast machine online status to user-scoped connections (mobile apps)
            // This allows the UI to show daemon online/offline status
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

            // Log connection (avoid excessive logging in production)
            if (this.env.ENVIRONMENT !== 'production') {
                console.log(
                    `[ConnectionManager] New connection: ${connectionId}, type: ${handshake.clientType}, user: ${verified.userId}`
                );
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
        if (normalized.ack !== undefined && normalized.messageId) {
            // This is an acknowledgement - forward it to the appropriate connection
            // For now, just log and continue (acks are typically responses, not requests)
            return;
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
            case 'rpc-request':
                // Forward RPC requests to the appropriate session/machine scoped connection
                // The RPC message should contain target info in payload
                if (metadata?.clientType !== 'user-scoped') {
                    // Forward to user-scoped connections (mobile app handles RPC routing)
                    this.broadcastClientMessage(
                        {
                            event: normalized.type,
                            data: normalized.payload,
                            ackId: normalized.messageId,
                        },
                        { type: 'user-scoped-only' }
                    );
                } else {
                    // User-scoped client sending RPC - forward to session/machine scoped
                    const rpcPayload = normalized.payload as { method?: string } | undefined;
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

                            if (hasMachineConnection) {
                                // Target is a machine - route to machine-scoped connection
                                this.broadcastClientMessage(
                                    {
                                        event: 'rpc-request',
                                        data: normalized.payload,
                                        ackId: normalized.messageId,
                                    },
                                    { type: 'machine', machineId: targetId }
                                );
                            } else {
                                // Target is a session - route to session-scoped connections and user-scoped
                                this.broadcastClientMessage(
                                    {
                                        event: 'rpc-request',
                                        data: normalized.payload,
                                        ackId: normalized.messageId,
                                    },
                                    { type: 'all-interested-in-session', sessionId: targetId }
                                );
                            }
                        }
                    }
                }
                break;

            case 'rpc-response':
                // Forward RPC response back to the requesting client
                // The ackId identifies the original request
                if (normalized.messageId) {
                    // Broadcast to all connections - the one with matching pending ack will handle it
                    this.broadcastClientMessage(
                        {
                            event: 'rpc-response',
                            ackId: normalized.messageId,
                            ack: normalized.payload,
                        },
                        { type: 'all' }
                    );
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
     * Logs the error and closes the connection.
     *
     * @param ws - The WebSocket that errored
     * @param error - The error that occurred
     */
    override async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
        const metadata = this.connections.get(ws);
        console.error(
            `[ConnectionManager] WebSocket error for connection ${metadata?.connectionId || 'unknown'}:`,
            error
        );

        // Clean up the connection
        this.connections.delete(ws);

        try {
            ws.close(CloseCode.INTERNAL_ERROR, 'Internal error');
        } catch {
            // Already closed, ignore
        }
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
     * @param metadata - Connection metadata
     * @returns Array of tags for this connection
     */
    private buildConnectionTags(metadata: ConnectionMetadata): string[] {
        const tags: string[] = [
            `type:${metadata.clientType}`,
            `conn:${metadata.connectionId.slice(0, 8)}`, // Shortened for tag limit
        ];

        if (metadata.sessionId) {
            tags.push(`session:${metadata.sessionId.slice(0, 50)}`);
        }

        if (metadata.machineId) {
            tags.push(`machine:${metadata.machineId.slice(0, 50)}`);
        }

        return tags;
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
     * Broadcast a message to connections matching a filter
     *
     * @param message - Message to broadcast
     * @param filter - Optional filter to select target connections
     * @returns Number of connections the message was delivered to
     */
    private broadcast(message: WebSocketMessage, filter?: MessageFilter): number {
        const messageStr = JSON.stringify(message);
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
     * @param message Client-format message to broadcast
     * @param filter Optional filter to target specific connections
     * @returns Number of connections the message was delivered to
     *
     * @see HAP-271 - Protocol alignment between clients and Workers backend
     */
    private broadcastClientMessage(message: ClientMessage, filter?: MessageFilter): number {
        const messageStr = JSON.stringify(message);
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
     * Check if a connection matches a broadcast filter
     *
     * @param metadata - Connection metadata
     * @param filter - Filter to check against
     * @returns True if connection matches filter
     */
    private matchesFilter(metadata: ConnectionMetadata, filter?: MessageFilter): boolean {
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
}
