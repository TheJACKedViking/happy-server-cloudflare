/**
 * Unit Tests for Durable Objects Types
 *
 * Tests utility functions from the types module:
 * - isClientMessage - Type guard for client messages
 * - isServerMessage - Type guard for server messages
 * - normalizeMessage - Message format normalizer
 *
 * @module __tests__/durable-objects-types.spec
 */

import { describe, it, expect, vi } from 'vitest';

// Mock cloudflare:workers module
vi.mock('cloudflare:workers', () => ({
    DurableObject: class DurableObject {
        ctx: DurableObjectState;
        env: unknown;
        constructor(ctx: DurableObjectState, env: unknown) {
            this.ctx = ctx;
            this.env = env;
        }
    },
}));

import {
    isClientMessage,
    isServerMessage,
    normalizeMessage,
    CloseCode,
    DEFAULT_CONFIG,
    type ClientMessage,
    type WebSocketMessage,
    type ClientType,
} from '@/durable-objects/types';

describe('Durable Objects Types', () => {
    describe('isClientMessage', () => {
        it('should return true for valid client message', () => {
            const msg: ClientMessage = {
                event: 'sessionUpdate',
                data: { sessionId: '123' },
            };
            expect(isClientMessage(msg)).toBe(true);
        });

        it('should return true for client message with ackId', () => {
            const msg: ClientMessage = {
                event: 'rpc-call',
                data: { method: 'test' },
                ackId: 'uuid-123',
            };
            expect(isClientMessage(msg)).toBe(true);
        });

        it('should return true for client message with ack response', () => {
            const msg: ClientMessage = {
                event: 'rpc-response',
                ack: { result: 'success' },
            };
            expect(isClientMessage(msg)).toBe(true);
        });

        it('should return false for null', () => {
            expect(isClientMessage(null)).toBe(false);
        });

        it('should return false for undefined', () => {
            expect(isClientMessage(undefined)).toBe(false);
        });

        it('should return false for primitive types', () => {
            expect(isClientMessage('string')).toBe(false);
            expect(isClientMessage(123)).toBe(false);
            expect(isClientMessage(true)).toBe(false);
        });

        it('should return false for object without event field', () => {
            expect(isClientMessage({ data: 'test' })).toBe(false);
        });

        it('should return false for object with non-string event', () => {
            expect(isClientMessage({ event: 123 })).toBe(false);
            expect(isClientMessage({ event: null })).toBe(false);
            expect(isClientMessage({ event: {} })).toBe(false);
        });

        it('should return false for server message format', () => {
            const serverMsg: WebSocketMessage = {
                type: 'broadcast',
                payload: { test: true },
                timestamp: Date.now(),
            };
            expect(isClientMessage(serverMsg)).toBe(false);
        });
    });

    describe('isServerMessage', () => {
        it('should return true for valid server message', () => {
            const msg: WebSocketMessage = {
                type: 'broadcast',
                payload: { test: true },
                timestamp: Date.now(),
            };
            expect(isServerMessage(msg)).toBe(true);
        });

        it('should return true for server message with messageId', () => {
            const msg: WebSocketMessage = {
                type: 'rpc-request',
                payload: { method: 'test' },
                timestamp: Date.now(),
                messageId: 'msg-123',
            };
            expect(isServerMessage(msg)).toBe(true);
        });

        it('should return true for server message without payload', () => {
            const msg: WebSocketMessage = {
                type: 'ping',
                timestamp: Date.now(),
            };
            expect(isServerMessage(msg)).toBe(true);
        });

        it('should return false for null', () => {
            expect(isServerMessage(null)).toBe(false);
        });

        it('should return false for undefined', () => {
            expect(isServerMessage(undefined)).toBe(false);
        });

        it('should return false for primitive types', () => {
            expect(isServerMessage('string')).toBe(false);
            expect(isServerMessage(123)).toBe(false);
            expect(isServerMessage(true)).toBe(false);
        });

        it('should return false for object without type field', () => {
            expect(isServerMessage({ payload: 'test' })).toBe(false);
        });

        it('should return false for object with non-string type', () => {
            expect(isServerMessage({ type: 123 })).toBe(false);
            expect(isServerMessage({ type: null })).toBe(false);
            expect(isServerMessage({ type: {} })).toBe(false);
        });
    });

    describe('normalizeMessage', () => {
        it('should normalize client message to unified format', () => {
            const clientMsg: ClientMessage = {
                event: 'sessionUpdate',
                data: { sessionId: '123' },
                ackId: 'ack-uuid',
            };

            const normalized = normalizeMessage(clientMsg);
            expect(normalized).toEqual({
                type: 'sessionUpdate',
                payload: { sessionId: '123' },
                messageId: 'ack-uuid',
                ack: undefined,
            });
        });

        it('should normalize client message with ack response', () => {
            const clientMsg: ClientMessage = {
                event: 'rpc-response',
                ack: { result: 'success' },
            };

            const normalized = normalizeMessage(clientMsg);
            expect(normalized).toEqual({
                type: 'rpc-response',
                payload: undefined,
                messageId: undefined,
                ack: { result: 'success' },
            });
        });

        it('should normalize server message to unified format', () => {
            const now = Date.now();
            const serverMsg: WebSocketMessage = {
                type: 'broadcast',
                payload: { test: true },
                timestamp: now,
                messageId: 'msg-123',
            };

            const normalized = normalizeMessage(serverMsg);
            expect(normalized).toEqual({
                type: 'broadcast',
                payload: { test: true },
                timestamp: now,
                messageId: 'msg-123',
            });
        });

        it('should normalize server message without optional fields', () => {
            const now = Date.now();
            const serverMsg: WebSocketMessage = {
                type: 'ping',
                timestamp: now,
            };

            const normalized = normalizeMessage(serverMsg);
            expect(normalized).toEqual({
                type: 'ping',
                payload: undefined,
                timestamp: now,
                messageId: undefined,
            });
        });

        it('should return null for invalid message format', () => {
            expect(normalizeMessage(null)).toBeNull();
            expect(normalizeMessage(undefined)).toBeNull();
            expect(normalizeMessage('string')).toBeNull();
            expect(normalizeMessage(123)).toBeNull();
            expect(normalizeMessage({})).toBeNull();
            expect(normalizeMessage({ data: 'test' })).toBeNull();
        });

        it('should handle message with both event and type (client wins)', () => {
            // If a message has both, isClientMessage checks event first
            const ambiguousMsg = {
                event: 'clientEvent',
                type: 'serverType',
                data: 'clientData',
                payload: 'serverPayload',
            };

            const normalized = normalizeMessage(ambiguousMsg);
            // Should normalize as client message since event exists
            expect(normalized?.type).toBe('clientEvent');
            expect(normalized?.payload).toBe('clientData');
        });
    });

    describe('CloseCode constants', () => {
        it('should have standard WebSocket close codes', () => {
            expect(CloseCode.NORMAL).toBe(1000);
            expect(CloseCode.GOING_AWAY).toBe(1001);
            expect(CloseCode.PROTOCOL_ERROR).toBe(1002);
            expect(CloseCode.UNSUPPORTED_DATA).toBe(1003);
            expect(CloseCode.POLICY_VIOLATION).toBe(1008);
            expect(CloseCode.MESSAGE_TOO_BIG).toBe(1009);
            expect(CloseCode.INTERNAL_ERROR).toBe(1011);
        });

        it('should have custom application close codes in 4xxx range', () => {
            expect(CloseCode.AUTH_FAILED).toBe(4001);
            expect(CloseCode.INVALID_HANDSHAKE).toBe(4002);
            expect(CloseCode.MISSING_SESSION_ID).toBe(4003);
            expect(CloseCode.MISSING_MACHINE_ID).toBe(4004);
            expect(CloseCode.CONNECTION_LIMIT_EXCEEDED).toBe(4005);
            expect(CloseCode.DUPLICATE_CONNECTION).toBe(4006);
        });
    });

    describe('DEFAULT_CONFIG', () => {
        it('should have default max connections per user', () => {
            expect(DEFAULT_CONFIG.maxConnectionsPerUser).toBe(100);
        });

        it('should have default connection timeout of 5 minutes', () => {
            expect(DEFAULT_CONFIG.connectionTimeoutMs).toBe(5 * 60 * 1000);
        });

        it('should enable auto response by default', () => {
            expect(DEFAULT_CONFIG.enableAutoResponse).toBe(true);
        });

        it('should have default max message size of 1MB', () => {
            expect(DEFAULT_CONFIG.maxMessageSize).toBe(1024 * 1024);
        });
    });

    describe('Type definitions', () => {
        it('should support all ClientType values', () => {
            const types: ClientType[] = ['user-scoped', 'session-scoped', 'machine-scoped'];
            expect(types).toHaveLength(3);
        });
    });
});
