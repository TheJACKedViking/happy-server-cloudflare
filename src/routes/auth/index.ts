import { createRoute, OpenAPIHono, z } from '@hono/zod-openapi';
// Encoding utilities for base64/hex operations (Workers-compatible)
import * as privacyKit from '@/lib/privacy-kit-shim';
import { createToken, refreshToken } from '@/lib/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { eq } from 'drizzle-orm';
import { createId } from '@/utils/id';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { checkRateLimit, type RateLimitConfig } from '@/lib/rate-limit';
import type { Context } from 'hono';
import {
    DirectAuthRequestSchema,
    AuthSuccessResponseSchema,
    TerminalAuthRequestSchema,
    TerminalAuthRequestResponseSchema,
    TerminalAuthStatusQuerySchema,
    TerminalAuthStatusResponseSchema,
    TerminalAuthResponseSchema,
    ApprovalSuccessResponseSchema,
    AccountAuthRequestSchema,
    AccountAuthResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshFailedResponseSchema,
    UnauthorizedErrorSchema,
    NotFoundErrorSchema,
} from '@/schemas/auth';

/**
 * Rate limit configuration for auth endpoints (HAP-453)
 * More restrictive than ticket endpoint (5 vs 10) since auth attempts
 * are a primary target for brute-force attacks.
 */
const AUTH_RATE_LIMIT: RateLimitConfig = {
    maxRequests: 5,
    windowMs: 60_000, // 1 minute
    expirationTtl: 120, // 2 minutes (covers window + cleanup margin)
};

/**
 * OpenAPI schema for rate limit exceeded response
 */
const RateLimitExceededSchema = z.object({
    error: z.literal('Rate limit exceeded'),
    retryAfter: z.number().describe('Seconds until rate limit resets'),
});

/**
 * OpenAPI schema for service unavailable response
 */
const ServiceUnavailableSchema = z.object({
    error: z.literal('Service temporarily unavailable'),
    code: z.literal('RATE_LIMIT_UNAVAILABLE'),
});

/**
 * Environment bindings for auth routes
 */
interface Env {
    DB: D1Database;
    /** Master secret (preferred) */
    HAPPY_MASTER_SECRET?: string;
    /** Master secret (deprecated) */
    HANDY_MASTER_SECRET?: string;
    /** KV namespace for rate limiting (HAP-453) */
    RATE_LIMIT_KV?: KVNamespace;
    /** Current deployment environment */
    ENVIRONMENT?: 'development' | 'staging' | 'production';
}

/**
 * Check if we should fail closed when rate limiting is unavailable (HAP-620)
 *
 * In production, we fail closed (503) when RATE_LIMIT_KV is not configured
 * to prevent security bypass. In development/staging, we continue with
 * fallback memory-based rate limiting and log a warning.
 *
 * @param env - Environment bindings
 * @returns true if we should fail closed
 */
function shouldFailClosedForRateLimiting(env: Env): boolean {
    // In production, KV is required for security-critical auth endpoints
    return env.ENVIRONMENT === 'production' && !env.RATE_LIMIT_KV;
}

/**
 * Auth routes module
 *
 * Implements all authentication endpoints for Happy Server:
 * - Direct public key authentication
 * - Terminal pairing flow (CLI → Mobile approval)
 * - Account pairing flow (Mobile → Mobile)
 *
 * All routes use OpenAPI schemas for automatic documentation and validation.
 */
const authRoutes = new OpenAPIHono<{ Bindings: Env }>();

// ============================================================================
// POST /v1/auth - Direct Public Key Authentication
// ============================================================================

const directAuthRoute = createRoute({
    method: 'post',
    path: '/v1/auth',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: DirectAuthRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: AuthSuccessResponseSchema,
                },
            },
            description: 'Successfully authenticated',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Invalid signature',
        },
        429: {
            content: {
                'application/json': {
                    schema: RateLimitExceededSchema,
                },
            },
            headers: {
                'Retry-After': {
                    schema: { type: 'string' },
                    description: 'Seconds until the rate limit resets',
                },
                'X-RateLimit-Limit': {
                    schema: { type: 'string' },
                    description: 'Maximum requests per window',
                },
                'X-RateLimit-Remaining': {
                    schema: { type: 'string' },
                    description: 'Remaining requests in current window',
                },
            },
            description: 'Too Many Requests - rate limit exceeded (5 per minute)',
        },
        503: {
            content: {
                'application/json': {
                    schema: ServiceUnavailableSchema,
                },
            },
            description: 'Service Unavailable - rate limiting not configured in production (HAP-620)',
        },
    },
    tags: ['Authentication'],
    summary: 'Direct public key authentication',
    description:
        'Authenticate using Ed25519 public key signature verification. The client signs a challenge with their private key, and the server verifies the signature. Rate limited to 5 requests per minute per public key.',
});

authRoutes.openapi(directAuthRoute, async (c) => {
    const { publicKey, challenge, signature } = c.req.valid('json');

    // HAP-620: Fail closed in production when rate limiting is unavailable
    if (shouldFailClosedForRateLimiting(c.env)) {
        console.error('[Auth] CRITICAL: RATE_LIMIT_KV not configured in production');
        return c.json(
            {
                error: 'Service temporarily unavailable' as const,
                code: 'RATE_LIMIT_UNAVAILABLE' as const,
            },
            503
        );
    }

    // Check rate limit (HAP-453, HAP-620)
    // Rate limiting is applied before crypto operations to prevent DoS via expensive signature verification
    // When KV is not configured, falls back to per-isolate memory-based rate limiting
    const rateLimitResult = await checkRateLimit(
        c.env.RATE_LIMIT_KV,
        'auth',
        publicKey, // Use publicKey as identifier (base64, already unique per client)
        AUTH_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
        return c.json(
            {
                error: 'Rate limit exceeded' as const,
                retryAfter: rateLimitResult.retryAfter,
            },
            429,
            {
                'Retry-After': String(rateLimitResult.retryAfter),
                'X-RateLimit-Limit': String(rateLimitResult.limit),
                'X-RateLimit-Remaining': '0',
            }
        );
    }

    // Import TweetNaCl for signature verification
    const tweetnacl = (await import('tweetnacl')).default;

    // Decode Base64 inputs
    const publicKeyBytes = privacyKit.decodeBase64(publicKey);
    const challengeBytes = privacyKit.decodeBase64(challenge);
    const signatureBytes = privacyKit.decodeBase64(signature);

    // Verify Ed25519 signature
    const isValid = tweetnacl.sign.detached.verify(challengeBytes, signatureBytes, publicKeyBytes);

    if (!isValid) {
        return c.json({ error: 'Invalid signature' }, 401);
    }

    // Create or update account in database
    const db = getDb(c.env.DB);
    const publicKeyHex = privacyKit.encodeHex(publicKeyBytes);

    const existingAccount = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.publicKey, publicKeyHex),
    });

    let userId: string;

    if (existingAccount) {
        // Update existing account timestamp
        await db.update(schema.accounts).set({ updatedAt: new Date() }).where(eq(schema.accounts.id, existingAccount.id));
        userId = existingAccount.id;
    } else {
        // Create new account
        const newAccounts = await db
            .insert(schema.accounts)
            .values({
                id: createId(),
                publicKey: publicKeyHex,
                seq: 0,
                feedSeq: 0,
            })
            .returning();

        // Ensure account was created successfully
        if (!newAccounts[0]) {
            return c.json({ error: 'Failed to create account' }, 401);
        }

        userId = newAccounts[0].id;
    }

    // Generate authentication token
    const token = await createToken(userId);

    return c.json({
        success: true,
        token,
    }, 200);
});

// ============================================================================
// POST /v1/auth/request - Terminal Authentication Request (CLI Pairing)
// ============================================================================

const terminalAuthRequestRoute = createRoute({
    method: 'post',
    path: '/v1/auth/request',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: TerminalAuthRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: TerminalAuthRequestResponseSchema,
                },
            },
            description: 'Auth request created or already authorized',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Invalid public key',
        },
        429: {
            content: {
                'application/json': {
                    schema: RateLimitExceededSchema,
                },
            },
            headers: {
                'Retry-After': {
                    schema: { type: 'string' },
                    description: 'Seconds until the rate limit resets',
                },
                'X-RateLimit-Limit': {
                    schema: { type: 'string' },
                    description: 'Maximum requests per window',
                },
                'X-RateLimit-Remaining': {
                    schema: { type: 'string' },
                    description: 'Remaining requests in current window',
                },
            },
            description: 'Too Many Requests - rate limit exceeded (5 per minute)',
        },
        503: {
            content: {
                'application/json': {
                    schema: ServiceUnavailableSchema,
                },
            },
            description: 'Service Unavailable - rate limiting not configured in production (HAP-620)',
        },
    },
    tags: ['Authentication'],
    summary: 'Initiate terminal pairing',
    description:
        'Used by happy-cli to start pairing flow. Creates an auth request that waits for mobile approval. CLI polls this endpoint until approved. Rate limited to 5 requests per minute per public key.',
});

authRoutes.openapi(terminalAuthRequestRoute, async (c) => {
    const { publicKey, supportsV2 } = c.req.valid('json');

    // HAP-620: Fail closed in production when rate limiting is unavailable
    if (shouldFailClosedForRateLimiting(c.env)) {
        console.error('[Auth] CRITICAL: RATE_LIMIT_KV not configured in production');
        return c.json(
            {
                error: 'Service temporarily unavailable' as const,
                code: 'RATE_LIMIT_UNAVAILABLE' as const,
            },
            503
        );
    }

    // Check rate limit (HAP-453, HAP-620)
    const rateLimitResult = await checkRateLimit(
        c.env.RATE_LIMIT_KV,
        'auth-request',
        publicKey,
        AUTH_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
        return c.json(
            {
                error: 'Rate limit exceeded' as const,
                retryAfter: rateLimitResult.retryAfter,
            },
            429,
            {
                'Retry-After': String(rateLimitResult.retryAfter),
                'X-RateLimit-Limit': String(rateLimitResult.limit),
                'X-RateLimit-Remaining': '0',
            }
        );
    }

    // Import TweetNaCl for key validation
    const tweetnacl = (await import('tweetnacl')).default;

    // Decode and validate public key
    const publicKeyBytes = privacyKit.decodeBase64(publicKey);
    const isValid = tweetnacl.box.publicKeyLength === publicKeyBytes.length;

    if (!isValid) {
        return c.json({ error: 'Invalid public key' }, 401);
    }

    // Upsert terminal auth request
    const db = getDb(c.env.DB);
    const publicKeyHex = privacyKit.encodeHex(publicKeyBytes);

    const existingRequest = await db.query.terminalAuthRequests.findFirst({
        where: (requests, { eq }) => eq(requests.publicKey, publicKeyHex),
    });

    if (existingRequest) {
        // Check if already authorized
        if (existingRequest.response && existingRequest.responseAccountId) {
            const token = await createToken(existingRequest.responseAccountId, { session: existingRequest.id });
            return c.json({
                state: 'authorized' as const,
                token,
                response: existingRequest.response,
            }, 200);
        }
        // Still pending
        return c.json({ state: 'requested' as const }, 200);
    }

    // Create new auth request
    await db.insert(schema.terminalAuthRequests).values({
        id: createId(),
        publicKey: publicKeyHex,
        supportsV2: supportsV2 ?? false,
    });

    return c.json({ state: 'requested' as const }, 200);
});

// ============================================================================
// GET /v1/auth/request/status - Check Terminal Auth Status
// ============================================================================

const terminalAuthStatusRoute = createRoute({
    method: 'get',
    path: '/v1/auth/request/status',
    request: {
        query: TerminalAuthStatusQuerySchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: TerminalAuthStatusResponseSchema,
                },
            },
            description: 'Auth request status',
        },
    },
    tags: ['Authentication'],
    summary: 'Check terminal auth status',
    description: 'Query the status of a terminal auth request by public key.',
});

authRoutes.openapi(terminalAuthStatusRoute, async (c) => {
    const { publicKey } = c.req.valid('query');

    // Import TweetNaCl for key validation
    const tweetnacl = (await import('tweetnacl')).default;

    // Decode and validate public key
    const publicKeyBytes = privacyKit.decodeBase64(publicKey);
    const isValid = tweetnacl.box.publicKeyLength === publicKeyBytes.length;

    if (!isValid) {
        return c.json({ status: 'not_found' as const, supportsV2: false });
    }

    // Look up auth request
    const db = getDb(c.env.DB);
    const publicKeyHex = privacyKit.encodeHex(publicKeyBytes);

    const authRequest = await db.query.terminalAuthRequests.findFirst({
        where: (requests, { eq }) => eq(requests.publicKey, publicKeyHex),
    });

    if (!authRequest) {
        return c.json({ status: 'not_found' as const, supportsV2: false });
    }

    if (authRequest.response && authRequest.responseAccountId) {
        return c.json({ status: 'authorized' as const, supportsV2: authRequest.supportsV2 });
    }

    return c.json({ status: 'pending' as const, supportsV2: authRequest.supportsV2 });
});

// ============================================================================
// POST /v1/auth/response - Approve Terminal Auth Request (Mobile)
// ============================================================================

const terminalAuthResponseRoute = createRoute({
    method: 'post',
    path: '/v1/auth/response',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: TerminalAuthResponseSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ApprovalSuccessResponseSchema,
                },
            },
            description: 'Auth request approved',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Invalid public key',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Auth request not found',
        },
    },
    tags: ['Authentication'],
    summary: 'Approve terminal pairing',
    description: 'Used by happy-app to approve a CLI pairing request. Requires authentication (future: add auth middleware).',
});

// Apply auth middleware to specific route
authRoutes.use('/v1/auth/response', authMiddleware());

authRoutes.openapi(terminalAuthResponseRoute, async (c) => {
    const { publicKey, response } = c.req.valid('json');

    // Get authenticated user ID from middleware (combine Bindings and Variables for proper typing)
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');

    // Import TweetNaCl for key validation
    const tweetnacl = (await import('tweetnacl')).default;

    // Decode and validate public key
    const publicKeyBytes = privacyKit.decodeBase64(publicKey);
    const isValid = tweetnacl.box.publicKeyLength === publicKeyBytes.length;

    if (!isValid) {
        return c.json({ error: 'Invalid public key' }, 401);
    }

    // Look up auth request
    const db = getDb(c.env.DB);
    const publicKeyHex = privacyKit.encodeHex(publicKeyBytes);

    const authRequest = await db.query.terminalAuthRequests.findFirst({
        where: (requests, { eq }) => eq(requests.publicKey, publicKeyHex),
    });

    if (!authRequest) {
        return c.json({ error: 'Request not found' }, 404);
    }

    // Update auth request with response (only if not already responded)
    if (!authRequest.response) {
        await db
            .update(schema.terminalAuthRequests)
            .set({
                response,
                responseAccountId: userId,
            })
            .where(eq(schema.terminalAuthRequests.id, authRequest.id));
    }

    return c.json({ success: true }, 200);
});

// ============================================================================
// POST /v1/auth/account/request - Account Authentication Request (Mobile Pairing)
// ============================================================================

const accountAuthRequestRoute = createRoute({
    method: 'post',
    path: '/v1/auth/account/request',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: AccountAuthRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: TerminalAuthRequestResponseSchema,
                },
            },
            description: 'Account auth request created or already authorized',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Invalid public key',
        },
        429: {
            content: {
                'application/json': {
                    schema: RateLimitExceededSchema,
                },
            },
            headers: {
                'Retry-After': {
                    schema: { type: 'string' },
                    description: 'Seconds until the rate limit resets',
                },
                'X-RateLimit-Limit': {
                    schema: { type: 'string' },
                    description: 'Maximum requests per window',
                },
                'X-RateLimit-Remaining': {
                    schema: { type: 'string' },
                    description: 'Remaining requests in current window',
                },
            },
            description: 'Too Many Requests - rate limit exceeded (5 per minute)',
        },
        503: {
            content: {
                'application/json': {
                    schema: ServiceUnavailableSchema,
                },
            },
            description: 'Service Unavailable - rate limiting not configured in production (HAP-620)',
        },
    },
    tags: ['Authentication'],
    summary: 'Initiate account pairing',
    description: 'Used by happy-app to pair with another mobile device. Rate limited to 5 requests per minute per public key.',
});

authRoutes.openapi(accountAuthRequestRoute, async (c) => {
    const { publicKey } = c.req.valid('json');

    // HAP-620: Fail closed in production when rate limiting is unavailable
    if (shouldFailClosedForRateLimiting(c.env)) {
        console.error('[Auth] CRITICAL: RATE_LIMIT_KV not configured in production');
        return c.json(
            {
                error: 'Service temporarily unavailable' as const,
                code: 'RATE_LIMIT_UNAVAILABLE' as const,
            },
            503
        );
    }

    // Check rate limit (HAP-453, HAP-620)
    const rateLimitResult = await checkRateLimit(
        c.env.RATE_LIMIT_KV,
        'auth-account-request',
        publicKey,
        AUTH_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
        return c.json(
            {
                error: 'Rate limit exceeded' as const,
                retryAfter: rateLimitResult.retryAfter,
            },
            429,
            {
                'Retry-After': String(rateLimitResult.retryAfter),
                'X-RateLimit-Limit': String(rateLimitResult.limit),
                'X-RateLimit-Remaining': '0',
            }
        );
    }

    // Import TweetNaCl for key validation
    const tweetnacl = (await import('tweetnacl')).default;

    // Decode and validate public key
    const publicKeyBytes = privacyKit.decodeBase64(publicKey);
    const isValid = tweetnacl.box.publicKeyLength === publicKeyBytes.length;

    if (!isValid) {
        return c.json({ error: 'Invalid public key' }, 401);
    }

    // Upsert account auth request
    const db = getDb(c.env.DB);
    const publicKeyHex = privacyKit.encodeHex(publicKeyBytes);

    const existingRequest = await db.query.accountAuthRequests.findFirst({
        where: (requests, { eq }) => eq(requests.publicKey, publicKeyHex),
    });

    if (existingRequest) {
        // Check if already authorized
        if (existingRequest.response && existingRequest.responseAccountId) {
            const token = await createToken(existingRequest.responseAccountId);
            return c.json({
                state: 'authorized' as const,
                token,
                response: existingRequest.response,
            }, 200);
        }
        // Still pending
        return c.json({ state: 'requested' as const }, 200);
    }

    // Create new auth request
    await db.insert(schema.accountAuthRequests).values({
        id: createId(),
        publicKey: publicKeyHex,
    });

    return c.json({ state: 'requested' as const }, 200);
});

// ============================================================================
// POST /v1/auth/account/response - Approve Account Auth Request
// ============================================================================

const accountAuthResponseRoute = createRoute({
    method: 'post',
    path: '/v1/auth/account/response',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: AccountAuthResponseSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ApprovalSuccessResponseSchema,
                },
            },
            description: 'Account auth request approved',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Invalid public key',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Auth request not found',
        },
    },
    tags: ['Authentication'],
    summary: 'Approve account pairing',
    description: 'Used by happy-app to approve another mobile device pairing. Requires authentication.',
});

// Apply auth middleware to specific route
authRoutes.use('/v1/auth/account/response', authMiddleware());

authRoutes.openapi(accountAuthResponseRoute, async (c) => {
    const { publicKey, response } = c.req.valid('json');

    // Get authenticated user ID from middleware (combine Bindings and Variables for proper typing)
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');

    // Import TweetNaCl for key validation
    const tweetnacl = (await import('tweetnacl')).default;

    // Decode and validate public key
    const publicKeyBytes = privacyKit.decodeBase64(publicKey);
    const isValid = tweetnacl.box.publicKeyLength === publicKeyBytes.length;

    if (!isValid) {
        return c.json({ error: 'Invalid public key' }, 401);
    }

    // Look up auth request
    const db = getDb(c.env.DB);
    const publicKeyHex = privacyKit.encodeHex(publicKeyBytes);

    const authRequest = await db.query.accountAuthRequests.findFirst({
        where: (requests, { eq }) => eq(requests.publicKey, publicKeyHex),
    });

    if (!authRequest) {
        return c.json({ error: 'Request not found' }, 404);
    }

    // Update auth request with response (only if not already responded)
    if (!authRequest.response) {
        await db
            .update(schema.accountAuthRequests)
            .set({
                response,
                responseAccountId: userId,
            })
            .where(eq(schema.accountAuthRequests.id, authRequest.id));
    }

    return c.json({ success: true }, 200);
});

// ============================================================================
// POST /v1/auth/refresh - Refresh Authentication Token
// ============================================================================

const tokenRefreshRoute = createRoute({
    method: 'post',
    path: '/v1/auth/refresh',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: TokenRefreshResponseSchema,
                },
            },
            description: 'Token refreshed successfully',
        },
        401: {
            content: {
                'application/json': {
                    schema: TokenRefreshFailedResponseSchema,
                },
            },
            description: 'Token refresh failed (expired beyond grace period, invalid, or revoked)',
        },
    },
    tags: ['Authentication'],
    summary: 'Refresh authentication token',
    description:
        'Refresh an authentication token before or shortly after expiration. ' +
        'Tokens can be refreshed within a 7-day grace period after expiration. ' +
        'Requires a valid Bearer token in the Authorization header. ' +
        'Returns a new token with a fresh 30-day expiration.',
    security: [{ Bearer: [] }],
});

authRoutes.openapi(tokenRefreshRoute, async (c) => {
    // Extract token from Authorization header
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return c.json({
            success: false as const,
            error: 'Missing or invalid Authorization header',
            code: 'TOKEN_INVALID' as const,
        }, 401);
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Attempt to refresh the token
    const result = await refreshToken(token, c.env.DB);

    if (!result) {
        // Refresh failed - token is expired beyond grace period, invalid, or revoked
        return c.json({
            success: false as const,
            error: 'Token expired beyond grace period or is invalid',
            code: 'TOKEN_EXPIRED' as const,
        }, 401);
    }

    // Success - return new token
    const THIRTY_DAYS_IN_SECONDS = 30 * 24 * 60 * 60;
    return c.json({
        success: true as const,
        token: result.token,
        expiresIn: THIRTY_DAYS_IN_SECONDS,
    }, 200);
});

export default authRoutes;
