import type { MiddlewareHandler } from 'hono';
import { verifyToken, type TokenExtras } from '@/lib/auth';

/**
 * Environment bindings that include D1 database
 * Used for distributed token blacklist check
 */
interface AuthEnv {
    DB: D1Database;
}

/**
 * Extended context with authenticated user information
 */
export interface AuthVariables {
    userId: string;
    sessionExtras?: TokenExtras;
}

/**
 * Authentication middleware for Hono
 *
 * Verifies the JWT token from the Authorization header and attaches
 * user information to the context. Protected routes should use this middleware.
 *
 * @returns Hono middleware handler
 *
 * @example
 * ```typescript
 * import { authMiddleware } from '@/middleware/auth';
 *
 * // Protect a route
 * app.get('/v1/sessions', authMiddleware(), async (c) => {
 *     const userId = c.get('userId');
 *     // ... fetch user's sessions
 * });
 * ```
 *
 * @remarks
 * **Token Format:**
 * - Header: `Authorization: Bearer <token>`
 * - The token is a jose JWT (EdDSA/Ed25519) containing user ID
 *
 * **Distributed Token Invalidation (HAP-452):**
 * - Checks D1 token blacklist for revoked tokens
 * - Ensures logout and token revocation work globally across all Workers
 *
 * **Failure Modes:**
 * - 401 if no Authorization header
 * - 401 if token format is invalid
 * - 401 if token verification fails
 * - 401 if token is in the distributed blacklist
 */
export function authMiddleware(): MiddlewareHandler<{
    Bindings: AuthEnv;
    Variables: AuthVariables;
}> {
    return async (c, next) => {
        // Extract Authorization header
        const authHeader = c.req.header('Authorization');

        if (!authHeader) {
            return c.json({ error: 'Missing Authorization header' }, 401);
        }

        // Parse Bearer token
        const parts = authHeader.split(' ');
        if (parts.length !== 2 || parts[0] !== 'Bearer') {
            return c.json(
                { error: 'Invalid Authorization header format (expected: Bearer <token>)' },
                401
            );
        }

        const token = parts[1];
        if (!token) {
            return c.json({ error: 'Empty token in Authorization header' }, 401);
        }

        // Verify token with distributed blacklist check (HAP-452)
        // Pass D1 database for global revocation checking if available
        const db = c.env?.DB;
        const verified = await verifyToken(token, db);

        if (!verified) {
            return c.json({ error: 'Invalid or expired token' }, 401);
        }

        // Attach user info to context
        c.set('userId', verified.userId);
        if (verified.extras) {
            c.set('sessionExtras', verified.extras);
        }

        return await next();
    };
}

/**
 * Optional authentication middleware
 *
 * Like authMiddleware(), but doesn't fail if no token is provided.
 * Useful for routes that have optional authentication (e.g., public data
 * with enhanced features for authenticated users).
 *
 * Also checks the distributed token blacklist (HAP-452).
 *
 * @returns Hono middleware handler
 *
 * @example
 * ```typescript
 * import { optionalAuthMiddleware } from '@/middleware/auth';
 *
 * app.get('/v1/public/sessions', optionalAuthMiddleware(), async (c) => {
 *     const userId = c.get('userId'); // May be undefined
 *     if (userId) {
 *         // Show user's private sessions
 *     } else {
 *         // Show public sessions only
 *     }
 * });
 * ```
 */
export function optionalAuthMiddleware(): MiddlewareHandler<{
    Bindings: AuthEnv;
    Variables: Partial<AuthVariables>;
}> {
    return async (c, next) => {
        const authHeader = c.req.header('Authorization');

        if (authHeader) {
            const parts = authHeader.split(' ');
            if (parts.length === 2 && parts[0] === 'Bearer') {
                const token = parts[1];
                if (token) {
                    // Verify token with distributed blacklist check (HAP-452)
                    const db = c.env?.DB;
                    const verified = await verifyToken(token, db);

                    if (verified) {
                        c.set('userId', verified.userId);
                        if (verified.extras) {
                            c.set('sessionExtras', verified.extras);
                        }
                    }
                }
            }
        }

        // Always proceed to next, regardless of auth status
        return await next();
    };
}
