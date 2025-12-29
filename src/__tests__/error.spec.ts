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
 * Note: HTTPException responses use the flat { error: string } format,
 * while AppError responses use { code, message, canTryAgain } format
 * for consistency with happy-server.
 *
 * @module __tests__/error.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { AppError, ErrorCodes } from '@happy/errors';
import { errorHandler } from '@/middleware/error';

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

    describe('Error Message Fallback', () => {
        it('should use error message when provided', async () => {
            app.get('/test', () => {
                throw new Error('Custom error message');
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            expect(res.status).toBe(500);
            expect(body.error).toBe('Custom error message');
        });

        it('should use "Internal server error" when message is empty string', async () => {
            app.get('/test', () => {
                throw new Error('');
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            expect(res.status).toBe(500);
            expect(body.error).toBe('Internal server error');
        });

        it('should use "Internal server error" when error has no message', async () => {
            app.get('/test', () => {
                const err = new Error();
                err.message = ''; // Explicitly empty
                throw err;
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            expect(res.status).toBe(500);
            expect(body.error).toBe('Internal server error');
        });
    });

    describe('Error Cause Handling', () => {
        it('should include cause in log when error has cause property', async () => {
            app.get('/test', () => {
                const causeError = new Error('Original cause');
                const err = Object.assign(new Error('Wrapper error'), { cause: causeError });
                throw err;
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[0]).toBe('[Error Handler] Server error:');
            expect(logCall[1]).toHaveProperty('cause');
            expect(logCall[1].cause).toBeInstanceOf(Error);
            expect((logCall[1].cause as Error).message).toBe('Original cause');
        });

        it('should include cause when cause is a string', async () => {
            app.get('/test', () => {
                const err = Object.assign(new Error('Error with string cause'), { cause: 'string cause' });
                throw err;
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).toHaveProperty('cause');
            expect(logCall[1].cause).toBe('string cause');
        });

        it('should include cause when cause is an object', async () => {
            app.get('/test', () => {
                const err = Object.assign(new Error('Error with object cause'), {
                    cause: { code: 'ECONNREFUSED', port: 5432 },
                });
                throw err;
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).toHaveProperty('cause');
            expect(logCall[1].cause).toEqual({ code: 'ECONNREFUSED', port: 5432 });
        });

        it('should NOT include cause in log when error has no cause property', async () => {
            app.get('/test', () => {
                throw new Error('Error without cause');
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).not.toHaveProperty('cause');
        });

        it('should NOT include cause when cause is undefined', async () => {
            app.get('/test', () => {
                const err = Object.assign(new Error('Error with undefined cause'), { cause: undefined });
                throw err;
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            const logCall = consoleErrorSpy.mock.calls[0];
            // When cause is undefined, the conditional spread should NOT add it
            expect(logCall[1]).not.toHaveProperty('cause');
        });
    });

    describe('HTTPException Handling', () => {
        it('should use HTTPException status code', async () => {
            app.get('/test', () => {
                throw new HTTPException(404, { message: 'Resource not found' });
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            expect(res.status).toBe(404);
            expect(body.error).toBe('Resource not found');
        });

        it('should handle HTTPException with res property (message takes precedence)', async () => {
            app.get('/test', () => {
                const response = new Response('Not Found', {
                    status: 404,
                    statusText: 'Not Found',
                });
                throw new HTTPException(404, {
                    message: 'Resource not found',
                    res: response,
                });
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            expect(res.status).toBe(404);
            // Flat error format only includes message, not details
            expect(body.error).toBe('Resource not found');
        });

        it('should handle HTTPException without res property', async () => {
            app.get('/test', () => {
                throw new HTTPException(403, { message: 'Forbidden' });
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            expect(res.status).toBe(403);
            expect(body.error).toBe('Forbidden');
        });

        it('should handle HTTPException with undefined res', async () => {
            app.get('/test', () => {
                // HTTPException constructor doesn't accept null for res,
                // but we can test the branch by not providing res at all
                const exception = new HTTPException(400, { message: 'Bad Request' });
                // Verify res is undefined
                expect(exception.res).toBeUndefined();
                throw exception;
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            expect(res.status).toBe(400);
            expect(body.error).toBe('Bad Request');
        });
    });

    describe('Status Code Branches', () => {
        it('should log to console.error for status >= 500 (server error)', async () => {
            app.get('/test', () => {
                throw new Error('Internal server error');
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            expect(consoleWarnSpy).not.toHaveBeenCalled();

            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[0]).toBe('[Error Handler] Server error:');
            expect(logCall[1]).toMatchObject({
                message: 'Internal server error',
                status: 500,
            });
            expect(logCall[1]).toHaveProperty('stack');
        });

        it('should log to console.error for status 500', async () => {
            app.get('/test', () => {
                throw new HTTPException(500, { message: 'Server error' });
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });

        it('should log to console.error for status 502', async () => {
            app.get('/test', () => {
                throw new HTTPException(502, { message: 'Bad Gateway' });
            });

            const res = await app.request('/test');

            expect(res.status).toBe(502);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });

        it('should log to console.error for status 503', async () => {
            app.get('/test', () => {
                throw new HTTPException(503, { message: 'Service Unavailable' });
            });

            const res = await app.request('/test');

            expect(res.status).toBe(503);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });

        it('should log to console.warn for status < 500 (client error)', async () => {
            app.get('/test', () => {
                throw new HTTPException(400, { message: 'Bad request' });
            });

            const res = await app.request('/test');

            expect(res.status).toBe(400);
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            expect(consoleErrorSpy).not.toHaveBeenCalled();

            const logCall = consoleWarnSpy.mock.calls[0];
            expect(logCall[0]).toBe('[Error Handler] Client error:');
            expect(logCall[1]).toEqual({
                message: 'Bad request',
                status: 400,
            });
        });

        it('should log to console.warn for status 401', async () => {
            app.get('/test', () => {
                throw new HTTPException(401, { message: 'Unauthorized' });
            });

            const res = await app.request('/test');

            expect(res.status).toBe(401);
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            expect(consoleErrorSpy).not.toHaveBeenCalled();
        });

        it('should log to console.warn for status 403', async () => {
            app.get('/test', () => {
                throw new HTTPException(403, { message: 'Forbidden' });
            });

            const res = await app.request('/test');

            expect(res.status).toBe(403);
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            expect(consoleErrorSpy).not.toHaveBeenCalled();
        });

        it('should log to console.warn for status 404', async () => {
            app.get('/test', () => {
                throw new HTTPException(404, { message: 'Not found' });
            });

            const res = await app.request('/test');

            expect(res.status).toBe(404);
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            expect(consoleErrorSpy).not.toHaveBeenCalled();
        });

        it('should log to console.warn for status 499 (edge case)', async () => {
            app.get('/test', () => {
                // 499 is non-standard (nginx) but tests the < 500 boundary
                throw new HTTPException(499 as 400, { message: 'Client closed request' });
            });

            const res = await app.request('/test');

            expect(res.status).toBe(499);
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
            expect(consoleErrorSpy).not.toHaveBeenCalled();
        });
    });

    describe('Response Structure', () => {
        it('should return flat { error: string } structure for server errors', async () => {
            app.get('/test', () => {
                throw new Error('Server exploded');
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            expect(res.headers.get('content-type')).toContain('application/json');
            expect(body).toEqual({ error: 'Server exploded' });
        });

        it('should return flat { error: string } structure for client errors', async () => {
            app.get('/test', () => {
                throw new HTTPException(422, { message: 'Validation failed' });
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            expect(res.headers.get('content-type')).toContain('application/json');
            expect(body).toEqual({ error: 'Validation failed' });
        });

        it('should return flat { error: string } structure even when res is provided', async () => {
            app.get('/test', () => {
                const response = new Response('Entity Too Large', {
                    status: 413,
                    statusText: 'Payload Too Large',
                });
                throw new HTTPException(413, {
                    message: 'File too large',
                    res: response,
                });
            });

            const res = await app.request('/test');
            const body = await res.json() as { error: string };

            // Flat format - no details field
            expect(body).toEqual({ error: 'File too large' });
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
            const body = await res.json() as { error: string };

            expect(res.status).toBe(500);
            expect(body.error).toBe('Custom error occurred');
            expect(consoleErrorSpy).toHaveBeenCalled();
        });

        it('should handle error with cause property but undefined value', async () => {
            app.get('/test', () => {
                // Create an error where 'cause' property exists but is undefined
                const err = new Error('Error with explicit undefined cause');
                Object.defineProperty(err, 'cause', {
                    value: undefined,
                    enumerable: true,
                    configurable: true,
                    writable: true,
                });
                throw err;
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            // The 'cause' in err check returns true, but errorCause is undefined
            // so the spread should NOT include cause
            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).not.toHaveProperty('cause');
        });

        it('should handle error with cause property set to null', async () => {
            app.get('/test', () => {
                const err = new Error('Error with null cause');
                Object.defineProperty(err, 'cause', {
                    value: null,
                    enumerable: true,
                    configurable: true,
                    writable: true,
                });
                throw err;
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            // null !== undefined, so cause should be included
            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).toHaveProperty('cause');
            expect(logCall[1].cause).toBeNull();
        });

        it('should handle error with cause property set to 0', async () => {
            app.get('/test', () => {
                const err = new Error('Error with zero cause');
                Object.defineProperty(err, 'cause', {
                    value: 0,
                    enumerable: true,
                    configurable: true,
                    writable: true,
                });
                throw err;
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            // 0 !== undefined, so cause should be included
            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).toHaveProperty('cause');
            expect(logCall[1].cause).toBe(0);
        });

        it('should handle error with cause property set to false', async () => {
            app.get('/test', () => {
                const err = new Error('Error with false cause');
                Object.defineProperty(err, 'cause', {
                    value: false,
                    enumerable: true,
                    configurable: true,
                    writable: true,
                });
                throw err;
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            // false !== undefined, so cause should be included
            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).toHaveProperty('cause');
            expect(logCall[1].cause).toBe(false);
        });

        it('should handle error with cause property set to empty string', async () => {
            app.get('/test', () => {
                const err = new Error('Error with empty string cause');
                Object.defineProperty(err, 'cause', {
                    value: '',
                    enumerable: true,
                    configurable: true,
                    writable: true,
                });
                throw err;
            });

            const res = await app.request('/test');

            expect(res.status).toBe(500);
            expect(consoleErrorSpy).toHaveBeenCalledTimes(1);

            // '' !== undefined, so cause should be included
            const logCall = consoleErrorSpy.mock.calls[0];
            expect(logCall[1]).toHaveProperty('cause');
            expect(logCall[1].cause).toBe('');
        });
    });

    describe('AppError Handling', () => {
        it('should return structured response for AppError', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.NOT_FOUND, 'Session not found');
            });

            const res = await app.request('/test');
            const body = (await res.json()) as { code: string; message: string; canTryAgain: boolean };

            expect(res.status).toBe(404);
            expect(body.code).toBe('NOT_FOUND');
            expect(body.message).toBe('Session not found');
            expect(body.canTryAgain).toBe(false);
        });

        it('should return 401 for authentication errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.AUTH_FAILED, 'Invalid token');
            });

            const res = await app.request('/test');
            const body = (await res.json()) as { code: string; message: string; canTryAgain: boolean };

            expect(res.status).toBe(401);
            expect(body.code).toBe('AUTH_FAILED');
            expect(body.message).toBe('Invalid token');
        });

        it('should return 400 for validation errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INVALID_INPUT, 'Invalid cursor format');
            });

            const res = await app.request('/test');
            const body = (await res.json()) as { code: string; message: string; canTryAgain: boolean };

            expect(res.status).toBe(400);
            expect(body.code).toBe('INVALID_INPUT');
            expect(body.message).toBe('Invalid cursor format');
        });

        it('should include canTryAgain when set to true', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.FETCH_FAILED, 'Network error', { canTryAgain: true });
            });

            const res = await app.request('/test');
            const body = (await res.json()) as { code: string; message: string; canTryAgain: boolean };

            expect(res.status).toBe(500);
            expect(body.code).toBe('FETCH_FAILED');
            expect(body.canTryAgain).toBe(true);
        });

        it('should return 500 for internal errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.INTERNAL_ERROR, 'Something went wrong');
            });

            const res = await app.request('/test');
            const body = (await res.json()) as { code: string; message: string; canTryAgain: boolean };

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
            expect(logCall[0]).toBe('[Error Handler] Client error (AppError):');
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
            expect(logCall[0]).toBe('[Error Handler] Server error (AppError):');
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
            const body = (await res.json()) as { code: string; message: string; canTryAgain: boolean };

            expect(res.status).toBe(409);
            expect(body.code).toBe('ALREADY_EXISTS');
        });

        it('should return 503 for connection errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.CONNECT_FAILED, 'Connection refused');
            });

            const res = await app.request('/test');
            const body = (await res.json()) as { code: string; message: string; canTryAgain: boolean };

            expect(res.status).toBe(503);
            expect(body.code).toBe('CONNECT_FAILED');
        });

        it('should return 504 for timeout errors', async () => {
            app.get('/test', () => {
                throw new AppError(ErrorCodes.TIMEOUT, 'Request timed out');
            });

            const res = await app.request('/test');
            const body = (await res.json()) as { code: string; message: string; canTryAgain: boolean };

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
            const body = (await res.json()) as { code: string; message: string; canTryAgain: boolean };

            expect(res.status).toBe(500);
            expect(body.code).toBe('INTERNAL_ERROR');
            expect(body.message).toBe('Operation failed');
            expect(body.canTryAgain).toBe(true);
        });
    });
});
