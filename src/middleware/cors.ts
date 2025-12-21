import type { MiddlewareHandler } from 'hono';
import { cors as honoCors } from 'hono/cors';

/**
 * CORS middleware configuration for Happy Server Workers
 *
 * @remarks
 * Configures Cross-Origin Resource Sharing (CORS) for the Happy Server API.
 * In development, allows localhost origins for testing with happy-cli and happy-app.
 * In production, restricts to specific allowed domains for security.
 *
 * @returns Hono CORS middleware handler
 *
 * @example
 * ```typescript
 * app.use('*', cors());
 * ```
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS}
 */
export const cors = (): MiddlewareHandler => {
    return honoCors({
        /**
         * Origin validation function
         * Determines whether to allow requests from a given origin
         *
         * @param origin - The origin header from the request
         * @param c - The Hono context, used to access environment variables
         * @returns The allowed origin or null to reject
         */
        origin: (origin, c) => {
            // Allow requests with no origin (e.g., Postman, curl, mobile apps)
            if (!origin) {
                return '*';
            }

            // Development: Allow localhost and 127.0.0.1 on any port
            const isLocalhost =
                origin.includes('localhost') || origin.includes('127.0.0.1');
            if (isLocalhost) {
                return origin;
            }

            // Production: Whitelist specific domains
            const allowedDomains: readonly string[] = [
                // Primary production and development domains
                'https://happy.enflamemedia.com',
                'https://happy-dev.enflamemedia.com',
                // Reserved future domains
                'https://happy.app',
                'https://www.happy.app',
                'https://api.happy.app',
            ];

            if (allowedDomains.includes(origin)) {
                return origin;
            }

            // Environment-aware origin validation
            // Default to production behavior (reject) if ENVIRONMENT is undefined for security
            const environment = c.env.ENVIRONMENT ?? 'production';
            const isProduction = environment === 'production';

            if (isProduction) {
                // Security: Reject unknown origins in production
                console.warn('[CORS] Rejecting unrecognized origin:', origin);
                return null;
            }

            // Development/Staging: Allow unknown origins for easier testing
            console.warn('[CORS] Allowing unrecognized origin (non-production):', origin);
            return origin;
        },

        // HTTP methods allowed for CORS requests
        allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],

        // Headers that can be used in requests
        allowHeaders: [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
            'X-Request-Id',
            'X-Client-Version',
        ],

        // Headers that can be exposed to the client
        exposeHeaders: [
            'Content-Length',
            'X-Request-Id',
            'X-RateLimit-Limit',
            'X-Response-Time',
            'Server-Timing',
        ],

        // Cache preflight requests for 24 hours
        maxAge: 86400,

        // Allow cookies and authorization headers
        credentials: true,
    });
};
