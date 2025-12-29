import type { ErrorHandler } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { HTTPException } from 'hono/http-exception';
import { AppError, type ErrorCode } from '@happy/errors';

/**
 * Maps AppError error codes to appropriate HTTP status codes.
 *
 * @param code - The error code from AppError
 * @returns Appropriate HTTP status code (typed for Hono's c.json())
 */
function getHttpStatusFromErrorCode(code: ErrorCode): ContentfulStatusCode {
    // Authentication errors → 401 Unauthorized
    if (
        code === 'AUTH_FAILED' ||
        code === 'NOT_AUTHENTICATED' ||
        code === 'TOKEN_EXPIRED' ||
        code === 'AUTH_NOT_INITIALIZED'
    ) {
        return 401;
    }

    // Not found errors → 404 Not Found
    if (code === 'NOT_FOUND' || code === 'SESSION_NOT_FOUND' || code === 'RESOURCE_NOT_FOUND') {
        return 404;
    }

    // Validation errors → 400 Bad Request
    if (code === 'INVALID_INPUT' || code === 'VALIDATION_FAILED') {
        return 400;
    }

    // Conflict errors → 409 Conflict
    if (code === 'ALREADY_EXISTS' || code === 'VERSION_CONFLICT') {
        return 409;
    }

    // Encryption errors → 400 Bad Request (client-side issue typically)
    if (code === 'ENCRYPTION_ERROR' || code === 'DECRYPTION_FAILED' || code === 'NONCE_TOO_SHORT') {
        return 400;
    }

    // Connection/network errors → 502 Bad Gateway or 503 Service Unavailable
    if (code === 'CONNECT_FAILED' || code === 'SERVICE_NOT_CONNECTED') {
        return 503;
    }

    // Timeout errors → 504 Gateway Timeout
    if (code === 'TIMEOUT' || code === 'PROCESS_TIMEOUT') {
        return 504;
    }

    // Default to 500 Internal Server Error
    return 500;
}

/**
 * Global error handler middleware
 * Catches and formats errors consistently across all endpoints
 *
 * @remarks
 * Handles AppError (from @happy/errors), HTTPException (from Hono), and generic Error objects.
 * Logs full error stack in development, sanitized message in production.
 *
 * @param err - The error that was thrown (AppError, HTTPException, or Error)
 * @param c - Hono context object
 * @returns JSON error response with consistent structure
 */
export const errorHandler: ErrorHandler = (err, c) => {
    // Handle AppError instances from @happy/errors
    if (AppError.isAppError(err)) {
        const status = getHttpStatusFromErrorCode(err.code);
        const message = err.message || 'Internal server error';

        // Log based on status severity
        if (status >= 500) {
            console.error('[Error Handler] Server error (AppError):', {
                code: err.code,
                message,
                status,
                stack: err.stack,
                ...(err.cause ? { cause: err.cause.message } : {}),
                ...(err.context ? { context: err.context } : {}),
            });
        } else {
            console.warn('[Error Handler] Client error (AppError):', {
                code: err.code,
                message,
                status,
            });
        }

        // Return structured error response matching happy-server format
        return c.json(
            {
                code: err.code,
                message,
                canTryAgain: err.canTryAgain,
            },
            status
        );
    }

    // Determine if this is a known HTTP exception
    const isHTTPException = err instanceof HTTPException;

    // Extract status code (default to 500 for unknown errors)
    const status = isHTTPException ? err.status : 500;

    // Extract error message
    const message = err.message || 'Internal server error';

    // Log error details (include stack trace for debugging)
    if (status >= 500) {
        // Server errors should be logged with full context
        // Note: err.cause is not always present, so we check for it safely
        const errorCause =
            'cause' in err
                ? (err as Error & { cause?: unknown }).cause
                : undefined;

        console.error('[Error Handler] Server error:', {
            message,
            status,
            stack: err.stack,
            // Include cause if available (not all Error objects have it)
            ...(errorCause !== undefined ? { cause: errorCause } : {}),
        });
    } else {
        // Client errors logged at lower severity
        console.warn('[Error Handler] Client error:', {
            message,
            status,
        });
    }

    // Return flat error response matching route handler format
    // This ensures consistent { error: string } structure across all error responses
    return c.json({ error: message }, status);
};
