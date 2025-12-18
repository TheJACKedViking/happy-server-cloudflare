import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { createId } from '@/utils/id';
import { eq, and } from 'drizzle-orm';
import {
    initEncryption,
    isEncryptionInitialized,
    encryptString,
    decryptString,
} from '@/lib/encryption';
import { getEventRouter, buildUpdateAccountUpdate } from '@/lib/eventRouter';
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
 * GitHub user profile from API
 * @see https://docs.github.com/en/rest/users/users#get-the-authenticated-user
 */
interface GitHubProfile {
    id: number;
    login: string;
    type: string;
    site_admin: boolean;
    avatar_url: string;
    gravatar_id: string | null;
    name: string | null;
    company: string | null;
    blog: string | null;
    location: string | null;
    email: string | null;
    hireable: boolean | null;
    bio: string | null;
    twitter_username: string | null;
    public_repos: number;
    public_gists: number;
    followers: number;
    following: number;
    created_at: string;
    updated_at: string;
}

/**
 * Separates a full name into first and last name parts.
 * Returns empty strings if name is null/undefined.
 */
function separateName(name: string | null): { firstName: string; lastName: string } {
    if (!name) {
        return { firstName: '', lastName: '' };
    }
    const trimmed = name.trim();
    const spaceIndex = trimmed.indexOf(' ');
    if (spaceIndex === -1) {
        return { firstName: trimmed, lastName: '' };
    }
    return {
        firstName: trimmed.substring(0, spaceIndex),
        lastName: trimmed.substring(spaceIndex + 1),
    };
}

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
    CONNECTION_MANAGER: DurableObjectNamespace;
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

/**
 * GitHub OAuth Callback Handler
 *
 * Flow:
 * 1. Validate state token (CSRF protection) - extracts userId
 * 2. Exchange authorization code for access token via GitHub API
 * 3. Fetch GitHub user profile using the access token
 * 4. Store/update GitHubUser record and link to Account
 * 5. Redirect to app with success or error status
 */
connectRoutes.openapi(githubOAuthCallbackRoute, async (c) => {
    const { code, state } = c.req.valid('query');
    const APP_URL = 'https://app.happy.engineering';

    // Step 1: Validate state token and extract userId
    // State format: state_{userId}_{timestamp}
    const stateMatch = state.match(/^state_([^_]+)_(\d+)$/);
    if (!stateMatch || !stateMatch[1] || !stateMatch[2]) {
        console.error('[github-oauth] Invalid state token format:', state);
        return c.redirect(`${APP_URL}?error=invalid_state`, 302);
    }

    const userId: string = stateMatch[1];
    const stateTimestamp = parseInt(stateMatch[2], 10);

    // Verify state is not expired (5 minute TTL)
    const STATE_TTL_MS = 5 * 60 * 1000;
    if (Date.now() - stateTimestamp > STATE_TTL_MS) {
        console.error('[github-oauth] State token expired');
        return c.redirect(`${APP_URL}?error=state_expired`, 302);
    }

    // Step 2: Verify environment configuration
    const clientId = c.env.GITHUB_CLIENT_ID;
    const clientSecret = c.env.GITHUB_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
        console.error('[github-oauth] GitHub OAuth not configured');
        return c.redirect(`${APP_URL}?error=server_config`, 302);
    }

    try {
        // Step 3: Exchange code for access token
        const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                client_id: clientId,
                client_secret: clientSecret,
                code: code,
            }),
        });

        const tokenData = (await tokenResponse.json()) as {
            access_token?: string;
            error?: string;
            error_description?: string;
        };

        if (tokenData.error) {
            console.error('[github-oauth] Token exchange error:', tokenData.error);
            return c.redirect(
                `${APP_URL}?error=${encodeURIComponent(tokenData.error)}`,
                302
            );
        }

        const accessToken = tokenData.access_token;
        if (!accessToken) {
            console.error('[github-oauth] No access token in response');
            return c.redirect(`${APP_URL}?error=no_access_token`, 302);
        }

        // Step 4: Fetch GitHub user profile
        const userResponse = await fetch('https://api.github.com/user', {
            headers: {
                Authorization: `Bearer ${accessToken}`,
                Accept: 'application/vnd.github.v3+json',
                'User-Agent': 'Happy-Server-Workers/1.0',
            },
        });

        if (!userResponse.ok) {
            console.error('[github-oauth] Failed to fetch GitHub user:', userResponse.status);
            return c.redirect(`${APP_URL}?error=github_user_fetch_failed`, 302);
        }

        const githubProfile = (await userResponse.json()) as GitHubProfile;
        const githubUserId = githubProfile.id.toString();

        // Step 5: Store in database
        const db = getDb(c.env.DB);

        // Initialize encryption for storing the access token
        if (!isEncryptionInitialized()) {
            await initEncryption(c.env.HANDY_MASTER_SECRET);
        }

        // Encrypt the access token for storage
        const encryptedToken = await encryptString(
            ['user', userId, 'github', 'token'],
            accessToken
        );

        // Check if user account exists
        const existingAccount = await db.query.accounts.findFirst({
            where: (accounts, { eq }) => eq(accounts.id, userId),
        });

        if (!existingAccount) {
            console.error('[github-oauth] User account not found:', userId);
            return c.redirect(`${APP_URL}?error=user_not_found`, 302);
        }

        // Check if this GitHub account is connected to another user
        const existingGithubConnection = await db.query.accounts.findFirst({
            where: (accounts, { eq, and, ne }) =>
                and(eq(accounts.githubUserId, githubUserId), ne(accounts.id, userId)),
        });

        // If connected to another user, disconnect from that user first
        if (existingGithubConnection) {
            await db
                .update(schema.accounts)
                .set({
                    githubUserId: null,
                    updatedAt: new Date(),
                })
                .where(eq(schema.accounts.id, existingGithubConnection.id));
        }

        // Upsert GitHubUser record
        const existingGithubUser = await db.query.githubUsers.findFirst({
            where: (users, { eq }) => eq(users.id, githubUserId),
        });

        if (existingGithubUser) {
            // Update existing GitHub user
            await db
                .update(schema.githubUsers)
                .set({
                    profile: githubProfile,
                    token: Buffer.from(encryptedToken),
                    updatedAt: new Date(),
                })
                .where(eq(schema.githubUsers.id, githubUserId));
        } else {
            // Create new GitHub user
            await db.insert(schema.githubUsers).values({
                id: githubUserId,
                profile: githubProfile,
                token: Buffer.from(encryptedToken),
            });
        }

        // Extract name parts from GitHub profile
        const nameParts = separateName(githubProfile.name);

        // Link GitHub account to user and update profile
        await db
            .update(schema.accounts)
            .set({
                githubUserId: githubUserId,
                username: githubProfile.login,
                firstName: nameParts.firstName,
                lastName: nameParts.lastName,
                updatedAt: new Date(),
            })
            .where(eq(schema.accounts.id, userId));

        // Step 6: Redirect to app with success
        const successUrl = `${APP_URL}?github=connected&user=${encodeURIComponent(githubProfile.login)}`;
        return c.redirect(successUrl, 302);
    } catch (error) {
        console.error('[github-oauth] Error in OAuth callback:', error);
        return c.redirect(`${APP_URL}?error=server_error`, 302);
    }
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
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    // Step 1: Find user's GitHub connection
    const account = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
    });

    if (!account || !account.githubUserId) {
        return c.json({ error: 'GitHub account not connected' }, 404);
    }

    const githubUserId = account.githubUserId;
    const newSeq = account.seq + 1;

    // Step 2: Clear GitHub link from account and increment seq (single UPDATE)
    await db
        .update(schema.accounts)
        .set({
            githubUserId: null,
            seq: newSeq,
            updatedAt: new Date(),
        })
        .where(eq(schema.accounts.id, userId));

    // Step 3: Delete GitHub user record (clears stored tokens)
    await db.delete(schema.githubUsers).where(eq(schema.githubUsers.id, githubUserId));

    const eventRouter = getEventRouter(c.env);
    await eventRouter.emitUpdate({
        userId,
        payload: buildUpdateAccountUpdate(userId, { github: null }, newSeq, createId()),
    });

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

    // Initialize encryption if not already done
    if (!isEncryptionInitialized()) {
        await initEncryption(c.env.HANDY_MASTER_SECRET);
    }

    // Encrypt token using path-based key derivation (matches happy-server pattern)
    // Path: ['user', userId, 'vendors', vendor, 'token']
    const encryptedToken = await encryptString(
        ['user', userId, 'vendors', vendor, 'token'],
        token
    );

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
                token: Buffer.from(encryptedToken),
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
            token: Buffer.from(encryptedToken),
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

    // Initialize encryption if not already done
    if (!isEncryptionInitialized()) {
        await initEncryption(c.env.HANDY_MASTER_SECRET);
    }

    // Decrypt token using path-based key derivation (matches happy-server pattern)
    const decryptedToken = await decryptString(
        ['user', userId, 'vendors', vendor, 'token'],
        new Uint8Array(serviceToken.token)
    );

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

    // Initialize encryption if not already done
    if (!isEncryptionInitialized()) {
        await initEncryption(c.env.HANDY_MASTER_SECRET);
    }

    // Decrypt all tokens using path-based key derivation
    // Filter out tokens that fail to decrypt (e.g., corrupted data, key rotation)
    const decryptedTokens: Array<{ vendor: string; token: string }> = [];

    for (const st of serviceTokens) {
        try {
            const token = await decryptString(
                ['user', userId, 'vendors', st.vendor, 'token'],
                new Uint8Array(st.token)
            );
            decryptedTokens.push({ vendor: st.vendor, token });
        } catch {
            // Skip tokens that fail to decrypt - they may be corrupted or from a different key
            console.error(`Failed to decrypt token for vendor ${st.vendor}, user ${userId}`);
        }
    }

    return c.json({ tokens: decryptedTokens });
});

export default connectRoutes;
