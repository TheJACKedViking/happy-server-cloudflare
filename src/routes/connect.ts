import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { createId } from '@/utils/id';
import { eq, and } from 'drizzle-orm';
import {
    GitHubOAuthParamsResponseSchema,
    GitHubOAuthCallbackQuerySchema,
    GitHubDisconnectResponseSchema,
    GitHubWebhookHeadersSchema,
    GitHubWebhookResponseSchema,
    AIVendorParamSchema,
    RegisterAITokenRequestSchema,
    RegisterAITokenResponseSchema,
    GetAITokenResponseSchema,
    DeleteAITokenResponseSchema,
    ListAITokensResponseSchema,
    BadRequestErrorSchema,
    NotFoundErrorSchema,
    UnauthorizedErrorSchema,
} from '@/schemas/connect';

/**
 * Environment bindings for connect routes
 */
interface Env {
    DB: D1Database;
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
    GITHUB_REDIRECT_URL?: string;
    GITHUB_WEBHOOK_SECRET?: string;
    HANDY_MASTER_SECRET: string;
}

/**
 * Connect routes module
 *
 * Implements integration endpoints:
 * - GitHub OAuth flow (params, callback, webhook, disconnect)
 * - AI service token management (OpenAI, Anthropic, Gemini)
 *
 * Note: Device pairing is handled by auth routes (POST /v1/auth/request, etc.)
 * NOT by connect routes in happy-server-workers.
 *
 * All routes use OpenAPI schemas for automatic documentation and validation.
 */
const connectRoutes = new OpenAPIHono<{ Bindings: Env }>();

// ============================================================================
// GitHub OAuth Integration
// ============================================================================

/**
 * GET /v1/connect/github/params - Get GitHub OAuth URL
 */
const githubOAuthParamsRoute = createRoute({
    method: 'get',
    path: '/v1/connect/github/params',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GitHubOAuthParamsResponseSchema,
                },
            },
            description: 'GitHub OAuth authorization URL',
        },
        400: {
            content: {
                'application/json': {
                    schema: BadRequestErrorSchema,
                },
            },
            description: 'GitHub OAuth not configured',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Connect'],
    summary: 'Get GitHub OAuth parameters',
    description: 'Generate GitHub OAuth authorization URL with state token.',
});

connectRoutes.use('/v1/connect/github/params', authMiddleware());

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
connectRoutes.openapi(githubOAuthParamsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const clientId = c.env.GITHUB_CLIENT_ID;
    const redirectUri = c.env.GITHUB_REDIRECT_URL;

    if (!clientId || !redirectUri) {
        return c.json({ error: 'GitHub OAuth not configured' }, 400);
    }

    // Generate ephemeral state token (placeholder - should use auth.createGithubToken)
    // For now, just use a simple implementation
    const state = `state_${userId}_${Date.now()}`;

    // Build complete OAuth URL
    const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: 'read:user,user:email,read:org,codespace',
        state: state,
    });

    const url = `https://github.com/login/oauth/authorize?${params.toString()}`;

    return c.json({ url });
});

/**
 * GET /v1/connect/github/callback - GitHub OAuth callback
 *
 * Note: This implementation is simplified. In production, it should:
 * 1. Exchange code for access token
 * 2. Fetch user profile from GitHub
 * 3. Store encrypted token in database
 * 4. Redirect to app with success/error
 */
const githubOAuthCallbackRoute = createRoute({
    method: 'get',
    path: '/v1/connect/github/callback',
    request: {
        query: GitHubOAuthCallbackQuerySchema,
    },
    responses: {
        302: {
            description: 'Redirect to app with success/error',
        },
    },
    tags: ['Connect'],
    summary: 'GitHub OAuth callback',
    description: 'Handles GitHub OAuth redirect, exchanges code for token, and stores user data.',
});

connectRoutes.openapi(githubOAuthCallbackRoute, async (c) => {
    // Query params available via c.req.valid('query') when implementing OAuth flow
    // TODO: Implement full OAuth flow
    // 1. Verify state token
    // 2. Exchange code for access token
    // 3. Fetch user profile
    // 4. Store in database
    // 5. Redirect to app

    // Placeholder: redirect to app with error
    return c.redirect('https://app.happy.engineering?error=not_implemented', 302);
});

/**
 * POST /v1/connect/github/webhook - GitHub webhook handler
 *
 * Note: This implementation is simplified. In production, it should:
 * 1. Verify webhook signature
 * 2. Process webhook event
 * 3. Update database accordingly
 */
const githubWebhookRoute = createRoute({
    method: 'post',
    path: '/v1/connect/github/webhook',
    request: {
        headers: GitHubWebhookHeadersSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GitHubWebhookResponseSchema,
                },
            },
            description: 'Webhook received',
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
    tags: ['Connect'],
    summary: 'GitHub webhook handler',
    description: 'Receives and processes GitHub webhook events.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
connectRoutes.openapi(githubWebhookRoute, async (_c) => {
    // TODO: Implement webhook verification and processing
    // 1. Verify signature using GITHUB_WEBHOOK_SECRET
    // 2. Parse event type and payload
    // 3. Process event accordingly

    // Placeholder: accept all webhooks
    return _c.json({ received: true as const });
});

/**
 * DELETE /v1/connect/github - Disconnect GitHub account
 */
const githubDisconnectRoute = createRoute({
    method: 'delete',
    path: '/v1/connect/github',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GitHubDisconnectResponseSchema,
                },
            },
            description: 'GitHub account disconnected',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'GitHub account not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Connect'],
    summary: 'Disconnect GitHub',
    description: 'Disconnect the user\'s GitHub account.',
});

connectRoutes.use('/v1/connect/github', authMiddleware());

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
connectRoutes.openapi(githubDisconnectRoute, async (c) => {
    // TODO: Implement GitHub disconnect - will use these when implemented
    // const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    // const db = getDb(c.env.DB);
    void c.env.DB; // Silence unused warning

    // TODO: Implement GitHub disconnect
    // 1. Remove GitHub user link
    // 2. Clear stored tokens
    // 3. Clean up related data

    // Placeholder: return success
    return c.json({ success: true as const });
});

// ============================================================================
// AI Service Token Management
// ============================================================================

/**
 * POST /v1/connect/:vendor/register - Register AI service token
 */
const registerAITokenRoute = createRoute({
    method: 'post',
    path: '/v1/connect/:vendor/register',
    request: {
        params: AIVendorParamSchema,
        body: {
            content: {
                'application/json': {
                    schema: RegisterAITokenRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: RegisterAITokenResponseSchema,
                },
            },
            description: 'Token registered',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Connect'],
    summary: 'Register AI service token',
    description: 'Store encrypted API token for an AI service (OpenAI, Anthropic, Gemini).',
});

connectRoutes.use('/v1/connect/:vendor/*', authMiddleware());

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
connectRoutes.openapi(registerAITokenRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { vendor } = c.req.valid('param');
    const { token } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // TODO: Encrypt token using privacy-kit or similar
    // For now, store as-is (NOT SECURE - implement encryption in production)
    const encryptedToken = Buffer.from(token, 'utf8');

    // Upsert service account token
    const existing = await db.query.serviceAccountTokens.findFirst({
        where: (tokens, { eq, and }) =>
            and(eq(tokens.accountId, userId), eq(tokens.vendor, vendor)),
    });

    if (existing) {
        // Update existing
        await db
            .update(schema.serviceAccountTokens)
            .set({
                token: encryptedToken,
                updatedAt: new Date(),
            })
            .where(
                and(
                    eq(schema.serviceAccountTokens.accountId, userId),
                    eq(schema.serviceAccountTokens.vendor, vendor)
                )
            );
    } else {
        // Create new
        await db.insert(schema.serviceAccountTokens).values({
            id: createId(),
            accountId: userId,
            vendor,
            token: encryptedToken,
        });
    }

    return c.json({ success: true });
});

/**
 * GET /v1/connect/:vendor/token - Get AI service token
 */
const getAITokenRoute = createRoute({
    method: 'get',
    path: '/v1/connect/:vendor/token',
    request: {
        params: AIVendorParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetAITokenResponseSchema,
                },
            },
            description: 'Token retrieved or null if not found',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Connect'],
    summary: 'Get AI service token',
    description: 'Retrieve decrypted API token for an AI service.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
connectRoutes.openapi(getAITokenRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { vendor } = c.req.valid('param');
    const db = getDb(c.env.DB);

    const serviceToken = await db.query.serviceAccountTokens.findFirst({
        where: (tokens, { eq, and }) =>
            and(eq(tokens.accountId, userId), eq(tokens.vendor, vendor)),
    });

    if (!serviceToken) {
        return c.json({ token: null });
    }

    // TODO: Decrypt token using privacy-kit or similar
    // For now, decode as-is (NOT SECURE - implement decryption in production)
    const decryptedToken = serviceToken.token.toString('utf8');

    return c.json({ token: decryptedToken });
});

/**
 * DELETE /v1/connect/:vendor - Delete AI service token
 */
const deleteAITokenRoute = createRoute({
    method: 'delete',
    path: '/v1/connect/:vendor',
    request: {
        params: AIVendorParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: DeleteAITokenResponseSchema,
                },
            },
            description: 'Token deleted',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Connect'],
    summary: 'Delete AI service token',
    description: 'Remove API token for an AI service.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
connectRoutes.openapi(deleteAITokenRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { vendor } = c.req.valid('param');
    const db = getDb(c.env.DB);

    await db
        .delete(schema.serviceAccountTokens)
        .where(
            and(
                eq(schema.serviceAccountTokens.accountId, userId),
                eq(schema.serviceAccountTokens.vendor, vendor)
            )
        );

    return c.json({ success: true as const });
});

/**
 * GET /v1/connect/tokens - List all AI service tokens
 */
const listAITokensRoute = createRoute({
    method: 'get',
    path: '/v1/connect/tokens',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: ListAITokensResponseSchema,
                },
            },
            description: 'List of AI service tokens',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
    },
    tags: ['Connect'],
    summary: 'List AI service tokens',
    description: 'Get all registered AI service tokens for the user.',
});

connectRoutes.use('/v1/connect/tokens', authMiddleware());

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
connectRoutes.openapi(listAITokensRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    const serviceTokens = await db.query.serviceAccountTokens.findMany({
        where: (tokens, { eq }) => eq(tokens.accountId, userId),
    });

    // TODO: Decrypt tokens using privacy-kit or similar
    const decryptedTokens = serviceTokens.map((st) => ({
        vendor: st.vendor,
        token: st.token.toString('utf8'), // NOT SECURE - implement decryption in production
    }));

    return c.json({ tokens: decryptedTokens });
});

export default connectRoutes;
