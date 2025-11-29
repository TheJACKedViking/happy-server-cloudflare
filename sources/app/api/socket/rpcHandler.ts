import { eventRouter } from "@/app/events/eventRouter";
import { log } from "@/utils/log";
import { Socket } from "socket.io";
import { randomUUID } from "crypto";

// Track pending RPC requests for cancellation support
// Key: requestId, Value: { targetSocket, method }
const pendingRequests = new Map<string, { targetSocket: Socket; method: string }>();

export function rpcHandler(userId: string, socket: Socket, rpcListeners: Map<string, Socket>) {

    // RPC cancel - Cancel an in-flight RPC request (from app to server)
    socket.on('rpc-cancel', async (data: { requestId: string }) => {
        try {
            const { requestId } = data;
            if (!requestId || typeof requestId !== 'string') {
                return;
            }

            const pending = pendingRequests.get(requestId);
            if (pending && pending.targetSocket.connected) {
                // Forward cancellation to the target CLI socket
                pending.targetSocket.emit('rpc-cancel', { requestId, method: pending.method });
            }
            pendingRequests.delete(requestId);
        } catch (error) {
            log({ module: 'websocket', level: 'error' }, `Error in rpc-cancel: ${error}`);
        }
    });

    // RPC register - Register this socket as a listener for an RPC method
    socket.on('rpc-register', async (data: any) => {
        try {
            const { method } = data;

            if (!method || typeof method !== 'string') {
                socket.emit('rpc-error', { type: 'register', error: 'Invalid method name' });
                return;
            }

            // Check if method was already registered
            const previousSocket = rpcListeners.get(method);
            if (previousSocket && previousSocket !== socket) {
                // log({ module: 'websocket-rpc' }, `RPC method ${method} re-registered: ${previousSocket.id} -> ${socket.id}`);
            }

            // Register this socket as the listener for this method
            rpcListeners.set(method, socket);

            socket.emit('rpc-registered', { method });
            // log({ module: 'websocket-rpc' }, `RPC method registered: ${method} on socket ${socket.id} (user: ${userId})`);
            // log({ module: 'websocket-rpc' }, `Active RPC methods for user ${userId}: ${Array.from(rpcListeners.keys()).join(', ')}`);
        } catch (error) {
            log({ module: 'websocket', level: 'error' }, `Error in rpc-register: ${error}`);
            socket.emit('rpc-error', { type: 'register', error: 'Internal error' });
        }
    });

    // RPC unregister - Remove this socket as a listener for an RPC method
    socket.on('rpc-unregister', async (data: any) => {
        try {
            const { method } = data;

            if (!method || typeof method !== 'string') {
                socket.emit('rpc-error', { type: 'unregister', error: 'Invalid method name' });
                return;
            }

            if (rpcListeners.get(method) === socket) {
                rpcListeners.delete(method);
                // log({ module: 'websocket-rpc' }, `RPC method unregistered: ${method} from socket ${socket.id} (user: ${userId})`);

                if (rpcListeners.size === 0) {
                    rpcListeners.delete(userId);
                    // log({ module: 'websocket-rpc' }, `All RPC methods unregistered for user ${userId}`);
                } else {
                    // log({ module: 'websocket-rpc' }, `Remaining RPC methods for user ${userId}: ${Array.from(rpcListeners.keys()).join(', ')}`);
                }
            } else {
                // log({ module: 'websocket-rpc' }, `RPC unregister ignored: ${method} not registered on socket ${socket.id}`);
            }

            socket.emit('rpc-unregistered', { method });
        } catch (error) {
            log({ module: 'websocket', level: 'error' }, `Error in rpc-unregister: ${error}`);
            socket.emit('rpc-error', { type: 'unregister', error: 'Internal error' });
        }
    });

    // RPC call - Call an RPC method on another socket of the same user
    socket.on('rpc-call', async (data: any, callback: (response: any) => void) => {
        // Generate unique request ID for cancellation tracking
        const requestId = randomUUID();

        try {
            const { method, params } = data;

            if (!method || typeof method !== 'string') {
                if (callback) {
                    callback({
                        ok: false,
                        error: 'Invalid parameters: method is required'
                    });
                }
                return;
            }

            const targetSocket = rpcListeners.get(method);
            if (!targetSocket || !targetSocket.connected) {
                // log({ module: 'websocket-rpc' }, `RPC call failed: Method ${method} not available (disconnected or not registered)`);
                if (callback) {
                    callback({
                        ok: false,
                        error: 'RPC method not available'
                    });
                }
                return;
            }

            // Don't allow calling your own socket
            if (targetSocket === socket) {
                // log({ module: 'websocket-rpc' }, `RPC call failed: Attempted self-call on method ${method}`);
                if (callback) {
                    callback({
                        ok: false,
                        error: 'Cannot call RPC on the same socket'
                    });
                }
                return;
            }

            // Track the pending request for cancellation support
            pendingRequests.set(requestId, { targetSocket, method });

            // Log RPC call initiation
            const startTime = Date.now();
            // log({ module: 'websocket-rpc' }, `RPC call initiated: ${socket.id} -> ${method} (target: ${targetSocket.id})`);

            // Forward the RPC request to the target socket using emitWithAck
            try {
                const response = await targetSocket.timeout(30000).emitWithAck('rpc-request', {
                    requestId,
                    method,
                    params
                });

                // Clean up tracking on success
                pendingRequests.delete(requestId);

                const duration = Date.now() - startTime;
                // log({ module: 'websocket-rpc' }, `RPC call succeeded: ${method} (${duration}ms)`);

                // Forward the response back to the caller via callback
                if (callback) {
                    callback({
                        ok: true,
                        result: response,
                        requestId
                    });
                }

            } catch (error) {
                const duration = Date.now() - startTime;
                const errorMsg = error instanceof Error ? error.message : 'RPC call failed';
                const isTimeout = errorMsg.includes('timeout') || errorMsg.includes('Timeout');

                // On timeout, send cancellation to the target CLI
                if (isTimeout && targetSocket.connected) {
                    targetSocket.emit('rpc-cancel', { requestId, method });
                }

                // Clean up tracking
                pendingRequests.delete(requestId);

                // log({ module: 'websocket-rpc' }, `RPC call failed: ${method} - ${errorMsg} (${duration}ms)`);

                // Timeout or error occurred
                if (callback) {
                    callback({
                        ok: false,
                        error: errorMsg,
                        requestId,
                        cancelled: isTimeout
                    });
                }
            }
        } catch (error) {
            // Clean up tracking on unexpected error
            pendingRequests.delete(requestId);

            // log({ module: 'websocket', level: 'error' }, `Error in rpc-call: ${error}`);
            if (callback) {
                callback({
                    ok: false,
                    error: 'Internal error',
                    requestId
                });
            }
        }
    });

    socket.on('disconnect', () => {

        const methodsToRemove: string[] = [];
        for (const [method, registeredSocket] of rpcListeners.entries()) {
            if (registeredSocket === socket) {
                methodsToRemove.push(method);
            }
        }

        if (methodsToRemove.length > 0) {
            // log({ module: 'websocket-rpc' }, `Cleaning up RPC methods on disconnect for socket ${socket.id}: ${methodsToRemove.join(', ')}`);
            methodsToRemove.forEach(method => rpcListeners.delete(method));
        }

        if (rpcListeners.size === 0) {
            rpcListeners.delete(userId);
            // log({ module: 'websocket-rpc' }, `All RPC listeners removed for user ${userId}`);
        }

        // Clean up pending requests where this socket was the target
        // This prevents memory leaks when CLI disconnects while requests are in flight
        const requestsToCleanup: string[] = [];
        for (const [requestId, pending] of pendingRequests.entries()) {
            if (pending.targetSocket === socket) {
                requestsToCleanup.push(requestId);
            }
        }
        requestsToCleanup.forEach(id => pendingRequests.delete(id));
    });
}