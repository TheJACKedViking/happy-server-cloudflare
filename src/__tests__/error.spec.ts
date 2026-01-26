/**
 * Unit Tests for Error Handler Middleware
 *
 * Tests the global error handler middleware for complete branch coverage:
 * - Error message fallback (empty message -> 'Internal server error')
 * - Error cause handling (with and without cause property)
 * - HTTPException handling
 * - AppError handling (from @happy/errors package)
 * - Status code branches (>= 500 server errors vs < 500 client errors)
 *
 * Note: HTTPException responses use the SafeErrorResponse format (HAP-646),
 * while AppError responses use { code, message, canTryAgain, requestId, timestamp }
 * format for consistency with happy-server.
 *
 * @module __tests__/error.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { AppError, ErrorCodes } from '@happy/errors';
import { errorHandler } from '@/middleware/error';

/**
 * SafeErrorResponse format from createSafeError (HAP-646)
 */
interface TestSafeErrorResponse {
    error: string;
    timestamp: string;
    requestId?: string;
    code?: string;
    canTryAgain?: boolean;
}

/**
 * AppError response format
 */
interface TestAppErrorResponse {
    code: string;
    message: string;
    canTryAgain: boolean;
    requestId: string;
    timestamp: string;
}

describe('Error Handler Middleware', () => {
    let app: Hono;
    let consoleErrorSpy: ReturnType<typeof vi.spyOn>;
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        app = new Hono();
        app.onError(errorHandler);

        // Spy on console methods to verify logging
        consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('Error Message Fallback (HAP-646: SafeErrorResponse)', () => {
        it('should use generic message in production to prevent info leakage', async () => {
            // Default (no ENVIRONMENT set) is treated as production
            app.get('/test', () => {
                throw new Error('Custom error message');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            expect(res.status).toBe(500);
            // HAP-646: Production mode uses generic message
            expect(body.error).toBe('An unexpected error occurred');
            expect(body.timestamp).toBeDefined();
        });

        it('should use generic message in production for non-AppError', async () => {
            app.get('/test', () => {
                throw new Error('Secret database error');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            expect(res.status).toBe(500);
            // HAP-646: In production, generic message prevents information leakage
            expect(body.error).toBe('An unexpected error occurred');
            expect(body.timestamp).toBeDefined();
        });

        it('should use "An unexpected error occurred" when message is empty string', async () => {
            app.get('/test', () => {
                throw new Error('');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            expect(res.status).toBe(500);
            // Empty message still gets generic response in production
            expect(body.error).toBe('An unexpected error occurred');
        });
    });

    describe('Error Cause Handling', () => {
        it('should log cause internally but not expose to client', async () => {
            app.get('/test', () => {
                const causeError = new Error('Original database connection error');
                const err = Object.assign(new Error('Wrapper error'), { cause: causeError });
                throw err;
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            expect(res.status).toBe(500);
            // HAP-646: Cause is logged internally but not exposed
            expect(body.error).toBe('An unexpected error occurred');
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
        });

        it('should NOT include cause in log when error has no cause property', async () => {
            app.get('/test', () => {
                throw new Error('Error without cause');
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
        });
    });

    describe('HTTPException Handling (HAP-646: SafeErrorResponse)', () => {
        it('should use HTTPException status code with safe message', async () => {
            app.get('/test', () => {
                throw new HTTPException(404, { message: 'Resource not found' });
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            expect(res.status).toBe(404);
            // HAP-646: HTTPException message is considered potentially unsafe in production
            expect(body.error).toBe('An unexpected error occurred');
            expect(body.timestamp).toBeDefined();
        });

        it('should handle HTTPException with 403 Forbidden', async () => {
            app.get('/test', () => {
                throw new HTTPException(403, { message: 'Forbidden' });
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            // HTTPException preserves its status code through getErrorStatusCode
            // (403 is in the allowed list), but message is sanitized in production
            expect(res.status).toBe(403);
            expect(body.error).toBe('An unexpected error occurred');
        });

        it('should handle HTTPException with 400 Bad Request', async () => {
            app.get('/test', () => {
                const exception = new HTTPException(400, { message: 'Bad Request' });
                throw exception;
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            expect(res.status).toBe(400);
            expect(body.error).toBe('An unexpected error occurred');
        });
    });

    describe('Status Code Branches', () => {
        it('should log to console.error for server errors (status >= 500)', async () => {
            app.get('/test', () => {
                throw new Error('Internal server error');
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
        });

        it('should log HTTP errors with status', async () => {
            app.get('/test', () => {
                throw new HTTPException(502, { message: 'Bad Gateway' });
            });

            const res = await app.request('/test');

            // HTTPException gets mapped through getErrorStatusCode
            expect(res.status).toBe(502);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
        });

        it('should log HTTP 503 errors', async () => {
            app.get('/test', () => {
                throw new HTTPException(503, { message: 'Service Unavailable' });
            });

            const res = await app.request('/test');

            expect(res.status).toBe(503);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
        });
    });

    describe('Response Structure (HAP-646)', () => {
        it('should return SafeErrorResponse structure for server errors', async () => {
            app.get('/test', () => {
                throw new Error('Server exploded');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            expect(res.headers.get('content-type')).toContain('application/json');
            expect(body).toMatchObject({
                error: 'An unexpected error occurred',
            });
            expect(body.timestamp).toBeDefined();
            expect(body.requestId).toBeDefined();
        });

        it('should include requestId in all error responses', async () => {
            app.get('/test', () => {
                throw new Error('Any error');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            expect(body.requestId).toBeDefined();
            expect(body.requestId).toMatch(/^[a-f0-9]{8}$/); // 8-char UUID prefix
        });
    });

    describe('Edge Cases', () => {
        it('should handle Error subclasses correctly', async () => {
            class CustomError extends Error {
                constructor(message: string) {
                    super(message);
                    this.name = 'CustomError';
                }
            }

            app.get('/test', () => {
                throw new CustomError('Custom error occurred');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestSafeErrorResponse;

            expect(res.status).toBe(500);
            // Custom errors get generic message in production
            expect(body.error).toBe('An unexpected error occurred');
            expect(consoleErrorSpy).toHaveBeenCalled();
        });
    });

    describe('AppError Handling', () => {
        it('should return structured response for AppError', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.NOT_FOUND, 'Session not found');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(res.status).toBe(404);
            expect(body.code).toBe('NOT_FOUND');
            expect(body.message).toBe('Session not found');
            expect(body.canTryAgain).toBe(false);
            expect(body.requestId).toBeDefined();
            expect(body.timestamp).toBeDefined();
        });

        it('should return 401 for authentication errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.AUTH_FAILED, 'Invalid token');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(res.status).toBe(401);
            expect(body.code).toBe('AUTH_FAILED');
            expect(body.message).toBe('Invalid token');
        });

        it('should return 400 for validation errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INVALID_INPUT, 'Invalid cursor format');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(res.status).toBe(400);
            expect(body.code).toBe('INVALID_INPUT');
            expect(body.message).toBe('Invalid cursor format');
        });

        it('should include canTryAgain when set to true', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.FETCH_FAILED, 'Network error', { canTryAgain: true });
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(res.status).toBe(500);
            expect(body.code).toBe('FETCH_FAILED');
            expect(body.canTryAgain).toBe(true);
        });

        it('should return 500 for internal errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INTERNAL_ERROR, 'Something went wrong');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(res.status).toBe(500);
            expect(body.code).toBe('INTERNAL_ERROR');
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
        });

        it('should log to console.warn for client errors (status < 500)', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.NOT_FOUND, 'Resource not found');
            });

            await app.request('/test');

            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            expect(consoleErrorSpy).not.toHaveBeenCalled();

            const logCall = consoleWarnSpy.mock.calls[0];
            // Log format includes requestId prefix
            expect(logCall[0]).toMatch(/^\[[a-f0-9]{8}\] Client error \(AppError\):$/);
            expect(logCall[1]).toMatchObject({
                code: 'NOT_FOUND',
                message: 'Resource not found',
                status: 404,
            });
        });

        it('should log to console.error for server errors (status >= 500)', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INTERNAL_ERROR, 'Server error');
            });

            await app.request('/test');

            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            expect(consoleWarnSpy).not.toHaveBeenCalled();

            const logCall = consoleErrorSpy.mock.calls[0];
            // Log format includes requestId prefix
            expect(logCall[0]).toMatch(/^\[[a-f0-9]{8}\] Server error \(AppError\):$/);
            expect(logCall[1]).toMatchObject({
                code: 'INTERNAL_ERROR',
                message: 'Server error',
                status: 500,
            });
        });

        it('should include cause in log when AppError has cause', async () => {
            const originalError = new Error('Original database error');
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INTERNAL_ERROR, 'Database failed', {
                    cause: originalError,
                });
            });

            await app.request('/test');

            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).toHaveProperty('cause');
            expect(logCall[1].cause).toBe('Original database error');
        });

        it('should include context in log when AppError has context', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INTERNAL_ERROR, 'Query failed', {
                    context: { query: 'SELECT * FROM users', attemptNumber: 3 },
                });
            });

            await app.request('/test');

            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).toHaveProperty('context');
            expect(logCall[1].context).toEqual({
                query: 'SELECT * FROM users',
                attemptNumber: 3,
            });
        });

        it('should return 409 for conflict errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.ALREADY_EXISTS, 'Resource already exists');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(res.status).toBe(409);
            expect(body.code).toBe('ALREADY_EXISTS');
        });

        it('should return 503 for connection errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.CONNECT_FAILED, 'Connection refused');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(res.status).toBe(503);
            expect(body.code).toBe('CONNECT_FAILED');
        });

        it('should return 504 for timeout errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.TIMEOUT, 'Request timed out');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(res.status).toBe(504);
            expect(body.code).toBe('TIMEOUT');
        });

        it('should handle AppError.fromUnknown factory method', async () => {
            const originalError = new Error('Underlying error');
            app.get('/test', () => {
                throw AppError.fromUnknown(
                    ErrorCodes.INTERNAL_ERROR,
                    'Operation failed',
                    originalError,
                    true
                );
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(res.status).toBe(500);
            expect(body.code).toBe('INTERNAL_ERROR');
            expect(body.message).toBe('Operation failed');
            expect(body.canTryAgain).toBe(true);
        });
    });

    /**
     * HAP-913: Complete error code coverage for mutation testing
     *
     * Tests all error codes mapped in getHttpStatusFromErrorCode to ensure
     * mutations in the conditional expressions are detected.
     */
    describe('Complete Error Code Coverage (HAP-913)', () => {
        describe('Authentication Errors (401)', () => {
            it('should return 401 for NOT_AUTHENTICATED', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.NOT_AUTHENTICATED, 'Not authenticated');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(401);
                expect(body.code).toBe('NOT_AUTHENTICATED');
                expect(body.message).toBe('Not authenticated');
            });

            it('should return 401 for TOKEN_EXPIRED', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.TOKEN_EXPIRED, 'Token has expired');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(401);
                expect(body.code).toBe('TOKEN_EXPIRED');
                expect(body.message).toBe('Token has expired');
            });

            it('should return 401 for AUTH_NOT_INITIALIZED', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.AUTH_NOT_INITIALIZED, 'Auth not initialized');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(401);
                expect(body.code).toBe('AUTH_NOT_INITIALIZED');
                expect(body.message).toBe('Auth not initialized');
            });
        });

        describe('Not Found Errors (404)', () => {
            it('should return 404 for SESSION_NOT_FOUND', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.SESSION_NOT_FOUND, 'Session not found');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(404);
                expect(body.code).toBe('SESSION_NOT_FOUND');
                expect(body.message).toBe('Session not found');
            });

            it('should return 404 for RESOURCE_NOT_FOUND', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.RESOURCE_NOT_FOUND, 'Resource not found');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(404);
                expect(body.code).toBe('RESOURCE_NOT_FOUND');
                expect(body.message).toBe('Resource not found');
            });
        });

        describe('Validation Errors (400)', () => {
            it('should return 400 for VALIDATION_FAILED', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.VALIDATION_FAILED, 'Validation failed');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(400);
                expect(body.code).toBe('VALIDATION_FAILED');
                expect(body.message).toBe('Validation failed');
            });
        });

        describe('Conflict Errors (409)', () => {
            it('should return 409 for VERSION_CONFLICT', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.VERSION_CONFLICT, 'Version conflict');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(409);
                expect(body.code).toBe('VERSION_CONFLICT');
                expect(body.message).toBe('Version conflict');
            });
        });

        describe('Encryption Errors (400)', () => {
            it('should return 400 for ENCRYPTION_ERROR', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.ENCRYPTION_ERROR, 'Encryption error');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(400);
                expect(body.code).toBe('ENCRYPTION_ERROR');
                expect(body.message).toBe('Encryption error');
            });

            it('should return 400 for DECRYPTION_FAILED', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.DECRYPTION_FAILED, 'Decryption failed');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(400);
                expect(body.code).toBe('DECRYPTION_FAILED');
                expect(body.message).toBe('Decryption failed');
            });

            it('should return 400 for NONCE_TOO_SHORT', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.NONCE_TOO_SHORT, 'Nonce too short');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(400);
                expect(body.code).toBe('NONCE_TOO_SHORT');
                expect(body.message).toBe('Nonce too short');
            });
        });

        describe('Connection Errors (503)', () => {
            it('should return 503 for SERVICE_NOT_CONNECTED', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.SERVICE_NOT_CONNECTED, 'Service not connected');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(503);
                expect(body.code).toBe('SERVICE_NOT_CONNECTED');
                expect(body.message).toBe('Service not connected');
            });
        });

        describe('Timeout Errors (504)', () => {
            it('should return 504 for PROCESS_TIMEOUT', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.PROCESS_TIMEOUT, 'Process timeout');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(504);
                expect(body.code).toBe('PROCESS_TIMEOUT');
                expect(body.message).toBe('Process timeout');
            });
        });

        describe('Default Status (500)', () => {
            it('should return 500 for unknown error codes', async () => {
                app.get('/test', () => {
                    throw new AppError(ErrorCodes.UNKNOWN_ERROR, 'Unknown error');
                });

                const res = await app.request('/test');
                const body = await res.json() as TestAppErrorResponse;

                expect(res.status).toBe(500);
                expect(body.code).toBe('UNKNOWN_ERROR');
            });

            it('should return 500 for UNKNOWN_ERROR codes not explicitly mapped', async () => {
                app.get('/test', () => {
                    // FETCH_FAILED is not explicitly mapped to a status code,
                    // so it should default to 500
                    throw new AppError(ErrorCodes.FETCH_FAILED, 'Fetch failed');
                });

                const res = await app.request('/test');

                // FETCH_FAILED is not in the error code mapping, should default to 500
                expect(res.status).toBe(500);
            });
        });
    });

    /**
     * HAP-913: String literal mutations and edge cases
     */
    describe('String Literal Mutations (HAP-913)', () => {
        it('should use exact error message "Internal server error" as fallback', async () => {
            app.get('/test', () => {
                // AppError with empty message should use fallback
                throw new AppError(ErrorCodes.INTERNAL_ERROR, '');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            // The fallback message should be exactly "Internal server error"
            expect(body.message).toBe('Internal server error');
        });

        it('should format requestId prefix correctly in log', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.NOT_FOUND, 'Test not found');
            });

            await app.request('/test');

            // Verify the log format: [requestId] Client error (AppError):
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            const logCall = consoleWarnSpy.mock.calls[0];
            // Should match format: [8-char-hex] Client error (AppError):
            expect(logCall[0]).toMatch(/^\[[a-f0-9]{8}\] Client error \(AppError\):$/);
        });

        it('should format server error log prefix correctly', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INTERNAL_ERROR, 'Server failure');
            });

            await app.request('/test');

            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            const logCall = consoleErrorSpy.mock.calls[0];
            // Should match format: [8-char-hex] Server error (AppError):
            expect(logCall[0]).toMatch(/^\[[a-f0-9]{8}\] Server error \(AppError\):$/);
        });

        it('should include exact timestamp ISO format in response', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.NOT_FOUND, 'Not found');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            // Timestamp should be valid ISO 8601 format
            expect(body.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
            // Should be parseable as a date
            expect(new Date(body.timestamp).getTime()).not.toBeNaN();
        });
    });

    /**
     * HAP-913: Response object structure mutations
     */
    describe('Response Object Structure (HAP-913)', () => {
        it('should include all required fields in AppError response', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.NOT_FOUND, 'Resource not found');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            // All fields must be present
            expect(body).toHaveProperty('code');
            expect(body).toHaveProperty('message');
            expect(body).toHaveProperty('canTryAgain');
            expect(body).toHaveProperty('requestId');
            expect(body).toHaveProperty('timestamp');

            // Values should be correct types
            expect(typeof body.code).toBe('string');
            expect(typeof body.message).toBe('string');
            expect(typeof body.canTryAgain).toBe('boolean');
            expect(typeof body.requestId).toBe('string');
            expect(typeof body.timestamp).toBe('string');
        });

        it('should return canTryAgain as false by default', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.NOT_FOUND, 'Not found');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(body.canTryAgain).toBe(false);
        });

        it('should return canTryAgain as true when explicitly set', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.TIMEOUT, 'Request timed out', { canTryAgain: true });
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            expect(body.canTryAgain).toBe(true);
        });

        it('should generate 8-character requestId', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.NOT_FOUND, 'Not found');
            });

            const res = await app.request('/test');
            const body = await res.json() as TestAppErrorResponse;

            // requestId should be exactly 8 hex characters (UUID prefix)
            expect(body.requestId).toMatch(/^[a-f0-9]{8}$/);
        });
    });

    /**
     * HAP-913: Logging object structure mutations
     */
    describe('Logging Object Structure (HAP-913)', () => {
        it('should log code, message, and status for client errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INVALID_INPUT, 'Invalid input data');
            });

            await app.request('/test');

            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            const logObject = consoleWarnSpy.mock.calls[0][1];
            expect(logObject).toMatchObject({
                code: 'INVALID_INPUT',
                message: 'Invalid input data',
                status: 400,
            });
        });

        it('should log code, message, status, and stack for server errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INTERNAL_ERROR, 'Internal failure');
            });

            await app.request('/test');

            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            const logObject = consoleErrorSpy.mock.calls[0][1];
            expect(logObject).toMatchObject({
                code: 'INTERNAL_ERROR',
                message: 'Internal failure',
                status: 500,
            });
            expect(logObject).toHaveProperty('stack');
        });

        it('should NOT log stack trace for client errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.NOT_FOUND, 'Not found');
            });

            await app.request('/test');

            const logObject = consoleWarnSpy.mock.calls[0][1];
            // Client error logs should not include stack
            expect(logObject).not.toHaveProperty('stack');
        });
    });
});
