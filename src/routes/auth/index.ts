import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
// Encoding utilities for base64/hex operations (Workers-compatible)
import * as privacyKit from '@/lib/privacy-kit-shim';
import { createToken } from '@/lib/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { eq } from 'drizzle-orm';
import { createId } from '@/utils/id';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
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
    UnauthorizedErrorSchema,
    NotFoundErrorSchema,
} from '@/schemas/auth';

/**
 * Environment bindings for auth routes
 */
interface Env {
    DB: D1Database;
    HANDY_MASTER_SECRET: string;
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
    },
    tags: ['Authentication'],
    summary: 'Direct public key authentication',
    description:
        'Authenticate using Ed25519 public key signature verification. The client signs a challenge with their private key, and the server verifies the signature.',
});

authRoutes.openapi(directAuthRoute, async (c) => {
    const { publicKey, challenge, signature } = c.req.valid('json');

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
    },
    tags: ['Authentication'],
    summary: 'Initiate terminal pairing',
    description:
        'Used by happy-cli to start pairing flow. Creates an auth request that waits for mobile approval. CLI polls this endpoint until approved.',
});

authRoutes.openapi(terminalAuthRequestRoute, async (c) => {
    const { publicKey, supportsV2 } = c.req.valid('json');

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
    },
    tags: ['Authentication'],
    summary: 'Initiate account pairing',
    description: 'Used by happy-app to pair with another mobile device.',
});

authRoutes.openapi(accountAuthRequestRoute, async (c) => {
    const { publicKey } = c.req.valid('json');

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

export default authRoutes;
