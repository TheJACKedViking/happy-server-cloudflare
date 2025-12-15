/**
 * Integration Tests for Dev Routes
 *
 * Tests development/debugging endpoints:
 * - POST /logs-combined-from-cli-and-mobile-for-simple-ai-debugging
 *
 * Achieves 100% coverage by testing:
 * - Disabled state (403 response)
 * - Enabled state (200 response)
 * - All log levels (error, warn, warning, debug, info/default)
 * - Source types (mobile, cli)
 * - Platform variations (ios, android, web)
 * - Optional fields (messageRawObject, platform)
 *
 * @module __tests__/dev.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    createMockDrizzle,
    createMockR2,
    createMockDurableObjectNamespace,
    jsonBody,
    expectOk,
    expectStatus,
} from './test-utils';

// Store the mock instance for test access
let drizzleMock: ReturnType<typeof createMockDrizzle>;

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

// Mock auth module
vi.mock('@/lib/auth', () => ({
    initAuth: vi.fn().mockResolvedValue(undefined),
    verifyToken: vi.fn().mockImplementation(async (token: string) => {
        if (token === 'valid-token') {
            return { userId: 'test-user-123', extras: {} };
        }
        return null;
    }),
    createToken: vi.fn().mockResolvedValue('generated-token-abc123'),
    resetAuth: vi.fn(),
}));

// Mock the getDb function to return our mock Drizzle client
vi.mock('@/db/client', () => ({
    getDb: vi.fn(() => {
        return drizzleMock?.mockDb;
    }),
}));

// Import app AFTER mocks are set up
import app from '@/index';

/**
 * Create mock environment for Hono app.request()
 * This provides the env object as the third parameter to app.request()
 */
function createTestEnv(enableDebugLogging: boolean = false) {
    return {
        ENVIRONMENT: 'development' as const,
        HANDY_MASTER_SECRET: 'test-secret-for-vitest-tests',
        DB: {} as D1Database, // Placeholder - actual DB calls are intercepted by getDb mock
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
        // Key environment variable for dev routes
        DANGEROUSLY_LOG_TO_SERVER_FOR_AI_AUTO_DEBUGGING: enableDebugLogging ? 'true' : undefined,
    };
}

describe('Dev Routes', () => {
    // Store console spies
    let consoleInfoSpy: ReturnType<typeof vi.spyOn>;
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;
    let consoleErrorSpy: ReturnType<typeof vi.spyOn>;
    let consoleDebugSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        vi.clearAllMocks();
        // Create fresh mock for each test
        drizzleMock = createMockDrizzle();

        // Spy on console methods to verify logging behavior
        consoleInfoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
        consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        consoleDebugSpy = vi.spyOn(console, 'debug').mockImplementation(() => {});
    });

    afterEach(() => {
        drizzleMock?.clearAll();
        // Restore console methods
        consoleInfoSpy.mockRestore();
        consoleWarnSpy.mockRestore();
        consoleErrorSpy.mockRestore();
        consoleDebugSpy.mockRestore();
    });

    describe('POST /logs-combined-from-cli-and-mobile-for-simple-ai-debugging', () => {
        const validLogData = {
            timestamp: '2024-12-03T10:30:00.000Z',
            level: 'info',
            message: 'Test log message',
            source: 'mobile' as const,
            platform: 'ios',
        };

        // ============================================================================
        // Tests for DISABLED state (lines 74-76)
        // ============================================================================
        describe('when debug logging is DISABLED (default)', () => {
            it('should return 403 when DANGEROUSLY_LOG_TO_SERVER_FOR_AI_AUTO_DEBUGGING is not set', async () => {
                const testEnv = createTestEnv(false);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody(validLogData),
                    },
                    testEnv
                );

                const body = await expectStatus<{ error: string }>(res, 403);
                expect(body).toHaveProperty('error', 'Debug logging is disabled');
            });

            it('should return 403 when env var is empty string', async () => {
                const testEnv = {
                    ...createTestEnv(false),
                    DANGEROUSLY_LOG_TO_SERVER_FOR_AI_AUTO_DEBUGGING: '',
                };

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody(validLogData),
                    },
                    testEnv
                );

                expect(res.status).toBe(403);
                const body = await res.json();
                expect(body).toHaveProperty('error', 'Debug logging is disabled');
            });
        });

        // ============================================================================
        // Tests for ENABLED state (lines 78-105)
        // ============================================================================
        describe('when debug logging is ENABLED', () => {
            let enabledEnv: ReturnType<typeof createTestEnv>;

            beforeEach(() => {
                enabledEnv = createTestEnv(true);
            });

            // ------------------------------------------------------------
            // Log Level Tests (lines 90-103 - switch statement)
            // ------------------------------------------------------------
            describe('log levels', () => {
                it('should log with console.error for level "error"', async () => {
                    const logData = {
                        ...validLogData,
                        level: 'error',
                        message: 'Error occurred',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    // Verify console.error was called
                    expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
                    expect(consoleErrorSpy).toHaveBeenCalledWith(
                        '[mobile] Error occurred',
                        expect.objectContaining({
                            source: 'mobile',
                            platform: 'ios',
                            timestamp: logData.timestamp,
                        })
                    );
                });

                it('should log with console.warn for level "warn"', async () => {
                    const logData = {
                        ...validLogData,
                        level: 'warn',
                        message: 'Warning issued',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
                    expect(consoleWarnSpy).toHaveBeenCalledWith(
                        '[mobile] Warning issued',
                        expect.objectContaining({
                            source: 'mobile',
                        })
                    );
                });

                it('should log with console.warn for level "warning"', async () => {
                    const logData = {
                        ...validLogData,
                        level: 'warning',
                        message: 'Another warning',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
                });

                it('should log with console.debug for level "debug"', async () => {
                    const logData = {
                        ...validLogData,
                        level: 'debug',
                        message: 'Debug info',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleDebugSpy).toHaveBeenCalledTimes(1);
                    expect(consoleDebugSpy).toHaveBeenCalledWith(
                        '[mobile] Debug info',
                        expect.objectContaining({
                            source: 'mobile',
                        })
                    );
                });

                it('should log with console.info for level "info" (default case)', async () => {
                    const logData = {
                        ...validLogData,
                        level: 'info',
                        message: 'Info message',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledTimes(1);
                });

                it('should log with console.info for unknown log level (default case)', async () => {
                    const logData = {
                        ...validLogData,
                        level: 'trace', // Unknown level, should fall to default
                        message: 'Trace message',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    // Should fall through to default (console.info)
                    expect(consoleInfoSpy).toHaveBeenCalledTimes(1);
                });

                it('should handle uppercase log level (case insensitive)', async () => {
                    const logData = {
                        ...validLogData,
                        level: 'ERROR', // Uppercase
                        message: 'Uppercase error',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    // toLowerCase() should convert to 'error'
                    expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
                });

                it('should handle mixed case log level', async () => {
                    const logData = {
                        ...validLogData,
                        level: 'WaRn', // Mixed case
                        message: 'Mixed case warning',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
                });
            });

            // ------------------------------------------------------------
            // Source Type Tests (lines 78-88 - source in logData)
            // ------------------------------------------------------------
            describe('source types', () => {
                it('should accept source "mobile"', async () => {
                    const logData = {
                        ...validLogData,
                        source: 'mobile' as const,
                        message: 'Mobile log',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledWith(
                        '[mobile] Mobile log',
                        expect.objectContaining({ source: 'mobile' })
                    );
                });

                it('should accept source "cli"', async () => {
                    const logData = {
                        ...validLogData,
                        source: 'cli' as const,
                        message: 'CLI log',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledWith(
                        '[cli] CLI log',
                        expect.objectContaining({ source: 'cli' })
                    );
                });
            });

            // ------------------------------------------------------------
            // Platform Variations Tests (lines 83-88 - platform in logData)
            // ------------------------------------------------------------
            describe('platform variations', () => {
                it('should accept platform "ios"', async () => {
                    const logData = {
                        ...validLogData,
                        platform: 'ios',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledWith(
                        expect.any(String),
                        expect.objectContaining({ platform: 'ios' })
                    );
                });

                it('should accept platform "android"', async () => {
                    const logData = {
                        ...validLogData,
                        platform: 'android',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledWith(
                        expect.any(String),
                        expect.objectContaining({ platform: 'android' })
                    );
                });

                it('should accept platform "web"', async () => {
                    const logData = {
                        ...validLogData,
                        platform: 'web',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledWith(
                        expect.any(String),
                        expect.objectContaining({ platform: 'web' })
                    );
                });

                it('should accept platform "macos"', async () => {
                    const logData = {
                        ...validLogData,
                        source: 'cli' as const,
                        platform: 'macos',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledWith(
                        expect.any(String),
                        expect.objectContaining({ platform: 'macos' })
                    );
                });

                it('should accept platform "linux"', async () => {
                    const logData = {
                        ...validLogData,
                        source: 'cli' as const,
                        platform: 'linux',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });
                });

                it('should handle missing platform (optional field)', async () => {
                    const logData = {
                        timestamp: '2024-12-03T10:30:00.000Z',
                        level: 'info',
                        message: 'No platform specified',
                        source: 'mobile' as const,
                        // platform is omitted
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledWith(
                        '[mobile] No platform specified',
                        expect.objectContaining({
                            source: 'mobile',
                            platform: undefined,
                        })
                    );
                });
            });

            // ------------------------------------------------------------
            // messageRawObject Tests (lines 83-88 - messageRawObject in logData)
            // ------------------------------------------------------------
            describe('messageRawObject field', () => {
                it('should include messageRawObject when provided', async () => {
                    const rawObject = { userId: '123', action: 'test', nested: { foo: 'bar' } };
                    const logData = {
                        ...validLogData,
                        messageRawObject: rawObject,
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledWith(
                        expect.any(String),
                        expect.objectContaining({
                            messageRawObject: rawObject,
                        })
                    );
                });

                it('should handle missing messageRawObject (optional field)', async () => {
                    const logData = {
                        timestamp: '2024-12-03T10:30:00.000Z',
                        level: 'info',
                        message: 'No raw object',
                        source: 'cli' as const,
                        // messageRawObject is omitted
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleInfoSpy).toHaveBeenCalledWith(
                        '[cli] No raw object',
                        expect.objectContaining({
                            source: 'cli',
                            messageRawObject: undefined,
                        })
                    );
                });

                it('should handle null messageRawObject', async () => {
                    const logData = {
                        ...validLogData,
                        messageRawObject: null,
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });
                });

                it('should handle array messageRawObject', async () => {
                    const logData = {
                        ...validLogData,
                        messageRawObject: [1, 2, 3, 'test'],
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });
                });

                it('should handle string messageRawObject', async () => {
                    const logData = {
                        ...validLogData,
                        messageRawObject: 'just a string',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });
                });
            });

            // ------------------------------------------------------------
            // Complete logData object Tests (lines 83-88)
            // ------------------------------------------------------------
            describe('complete logData construction', () => {
                it('should construct logData with all fields', async () => {
                    const rawObject = { userId: 'u123', event: 'click' };
                    const logData = {
                        timestamp: '2024-12-03T12:00:00.000Z',
                        level: 'warn',
                        message: 'Complete test',
                        messageRawObject: rawObject,
                        source: 'mobile' as const,
                        platform: 'android',
                    };

                    const res = await app.request(
                        '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                        {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: jsonBody(logData),
                        },
                        enabledEnv
                    );

                    const body = await expectOk<{ success: true }>(res);
                    expect(body).toEqual({ success: true });

                    expect(consoleWarnSpy).toHaveBeenCalledWith(
                        '[mobile] Complete test',
                        {
                            source: 'mobile',
                            platform: 'android',
                            timestamp: '2024-12-03T12:00:00.000Z',
                            messageRawObject: rawObject,
                        }
                    );
                });
            });
        });

        // ============================================================================
        // Validation Tests (request body validation)
        // ============================================================================
        describe('request validation', () => {
            it('should validate required timestamp field', async () => {
                const testEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody({
                            level: 'info',
                            message: 'Test',
                            source: 'mobile',
                        }),
                    },
                    testEnv
                );

                expect(res.status).toBe(400);
            });

            it('should validate required level field', async () => {
                const testEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody({
                            timestamp: '2024-12-03T10:30:00.000Z',
                            message: 'Test',
                            source: 'mobile',
                        }),
                    },
                    testEnv
                );

                expect(res.status).toBe(400);
            });

            it('should validate required message field', async () => {
                const testEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody({
                            timestamp: '2024-12-03T10:30:00.000Z',
                            level: 'info',
                            source: 'mobile',
                        }),
                    },
                    testEnv
                );

                expect(res.status).toBe(400);
            });

            it('should validate required source field', async () => {
                const testEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody({
                            timestamp: '2024-12-03T10:30:00.000Z',
                            level: 'info',
                            message: 'Test',
                        }),
                    },
                    testEnv
                );

                expect(res.status).toBe(400);
            });

            it('should validate source enum (must be "mobile" or "cli")', async () => {
                const testEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody({
                            timestamp: '2024-12-03T10:30:00.000Z',
                            level: 'info',
                            message: 'Test',
                            source: 'invalid-source',
                        }),
                    },
                    testEnv
                );

                expect(res.status).toBe(400);
            });

            it('should reject empty request body', async () => {
                const testEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: '{}',
                    },
                    testEnv
                );

                expect(res.status).toBe(400);
            });

            it('should reject non-JSON content type', async () => {
                const testEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'text/plain' },
                        body: 'invalid',
                    },
                    testEnv
                );

                // May return 400, 415, or 500 depending on how Hono handles content type
                expect([400, 415, 500]).toContain(res.status);
            });

            it('should reject invalid JSON', async () => {
                const testEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: 'not-valid-json',
                    },
                    testEnv
                );

                // Should fail with parse error (400) or internal error (500)
                expect([400, 500]).toContain(res.status);
            });
        });

        // ============================================================================
        // Edge Cases
        // ============================================================================
        describe('edge cases', () => {
            it('should handle very long messages', async () => {
                const enabledEnv = createTestEnv(true);
                const longMessage = 'A'.repeat(10000);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody({
                            ...validLogData,
                            message: longMessage,
                        }),
                    },
                    enabledEnv
                );

                const body = await expectOk<{ success: true }>(res);
                expect(body).toEqual({ success: true });
            });

            it('should handle special characters in message', async () => {
                const enabledEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody({
                            ...validLogData,
                            message: 'Special chars: <>&"\'/\\n\\t',
                        }),
                    },
                    enabledEnv
                );

                const body = await expectOk<{ success: true }>(res);
                expect(body).toEqual({ success: true });
            });

            it('should handle unicode in message', async () => {
                const enabledEnv = createTestEnv(true);

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody({
                            ...validLogData,
                            message: 'Unicode: emoji test',
                        }),
                    },
                    enabledEnv
                );

                const body = await expectOk<{ success: true }>(res);
                expect(body).toEqual({ success: true });
            });

            it('should handle deeply nested messageRawObject', async () => {
                const enabledEnv = createTestEnv(true);
                const deepObject = {
                    level1: {
                        level2: {
                            level3: {
                                level4: {
                                    value: 'deep',
                                },
                            },
                        },
                    },
                };

                const res = await app.request(
                    '/logs-combined-from-cli-and-mobile-for-simple-ai-debugging',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: jsonBody({
                            ...validLogData,
                            messageRawObject: deepObject,
                        }),
                    },
                    enabledEnv
                );

                const body = await expectOk<{ success: true }>(res);
                expect(body).toEqual({ success: true });
            });
        });
    });
});
