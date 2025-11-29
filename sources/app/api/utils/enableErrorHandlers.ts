import { log } from "@/utils/log";
import { Fastify } from "../types";

// Type guard to check if an error has Fastify error properties
function isFastifyError(error: unknown): error is { statusCode?: number; code?: string; stack?: string; name?: string; message?: string } {
    return typeof error === 'object' && error !== null;
}

// Safely get error message
function getErrorMessage(error: unknown): string {
    if (error instanceof Error) return error.message;
    if (isFastifyError(error) && error.message) return error.message;
    return 'Unknown error';
}

// Safely get error properties
function getErrorProps(error: unknown): { statusCode: number; code?: string; stack?: string; name?: string; message: string } {
    const message = getErrorMessage(error);
    if (isFastifyError(error)) {
        return {
            statusCode: error.statusCode || 500,
            code: error.code,
            stack: error.stack,
            name: error.name,
            message
        };
    }
    return { statusCode: 500, message };
}

export function enableErrorHandlers(app: Fastify) {
    // Global error handler
    app.setErrorHandler(async (error, request, reply) => {
        const method = request.method;
        const url = request.url;
        const userAgent = request.headers['user-agent'] || 'unknown';
        const ip = request.ip || 'unknown';
        const errorProps = getErrorProps(error);

        // Log the error with comprehensive context
        log({
            module: 'fastify-error',
            level: 'error',
            method,
            url,
            userAgent,
            ip,
            statusCode: errorProps.statusCode,
            errorCode: errorProps.code,
            stack: errorProps.stack
        }, `Unhandled error: ${errorProps.message}`);

        // Return appropriate error response
        const statusCode = errorProps.statusCode;

        if (statusCode >= 500) {
            // Internal server errors - don't expose details
            return reply.code(statusCode).send({
                error: 'Internal Server Error',
                message: 'An unexpected error occurred',
                statusCode
            });
        } else {
            // Client errors - can expose more details
            return reply.code(statusCode).send({
                error: errorProps.name || 'Error',
                message: errorProps.message,
                statusCode
            });
        }
    });

    // Catch-all route for debugging 404s
    app.setNotFoundHandler((request, reply) => {
        log({ module: '404-handler' }, `404 - Method: ${request.method}, Path: ${request.url}, Headers: ${JSON.stringify(request.headers)}`);
        reply.code(404).send({ error: 'Not found', path: request.url, method: request.method });
    });

    // Error hook for additional logging
    app.addHook('onError', async (request, reply, error) => {
        const method = request.method;
        const url = request.url;
        const duration = (Date.now() - (request.startTime || Date.now())) / 1000;
        const hookErrorProps = getErrorProps(error);

        log({
            module: 'fastify-hook-error',
            level: 'error',
            method,
            url,
            duration,
            statusCode: reply.statusCode || hookErrorProps.statusCode,
            errorName: hookErrorProps.name,
            errorCode: hookErrorProps.code
        }, `Request error: ${hookErrorProps.message}`);
    });

    // Handle uncaught exceptions in routes
    app.addHook('preHandler', async (request, reply) => {
        // Store original reply.send to catch errors in response serialization
        const originalSend = reply.send.bind(reply);
        reply.send = function (payload: unknown) {
            try {
                return originalSend(payload);
            } catch (error: unknown) {
                const serErrorProps = getErrorProps(error);
                log({
                    module: 'fastify-serialization-error',
                    level: 'error',
                    method: request.method,
                    url: request.url,
                    stack: serErrorProps.stack
                }, `Response serialization error: ${serErrorProps.message}`);
                throw error;
            }
        };
    });
}