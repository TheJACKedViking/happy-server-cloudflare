import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { eq } from 'drizzle-orm';
import {
    GetAccountResponseSchema,
    UpdateAccountRequestSchema,
    UpdateAccountSuccessSchema,
    UsernameConflictErrorSchema,
    GetPreferencesResponseSchema,
    UpdatePreferencesRequestSchema,
    UpdatePreferencesSuccessSchema,
    VersionMismatchErrorSchema,
    UnauthorizedErrorSchema,
    NotFoundErrorSchema,
    InternalErrorSchema,
} from '@/schemas/account';

/**
 * Environment bindings for account routes
 */
interface Env {
    DB: D1Database;
}

/**
 * Account routes module
 *
 * Implements account management endpoints:
 * - GET /v1/account - Get user profile with connected services
 * - PUT /v1/account - Update user profile (firstName, lastName, username)
 * - GET /v1/account/preferences - Get account settings
 * - PUT /v1/account/preferences - Update settings with optimistic locking
 *
 * All routes require authentication and use OpenAPI schemas for validation.
 */
const accountRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all account routes
accountRoutes.use('/v1/account/*', authMiddleware());
accountRoutes.use('/v1/account', authMiddleware());

// ============================================================================
// Helper: Get profile data for a user (shared between /v1/account and /v1/account/profile)
// ============================================================================

async function getProfileData(userId: string, db: ReturnType<typeof getDb>) {
    // Fetch account with GitHub profile
    const account = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
        with: {
            githubUser: true,
        },
    });

    if (!account) {
        return null;
    }

    // Fetch connected AI service vendors
    const tokens = await db.query.serviceAccountTokens.findMany({
        where: (tokens, { eq }) => eq(tokens.accountId, userId),
        columns: {
            vendor: true,
        },
    });
    const connectedServices = tokens.map((t) => t.vendor);

    return {
        id: userId,
        timestamp: Date.now(),
        firstName: account.firstName,
        lastName: account.lastName,
        username: account.username,
        github: account.githubUser?.profile ?? null,
        connectedServices,
    };
}

// ============================================================================
// GET /v1/account - Get Account Profile
// ============================================================================

const getAccountRoute = createRoute({
    method: 'get',
    path: '/v1/account',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetAccountResponseSchema,
                },
            },
            description: 'User profile with connected services',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Account not found',
        },
    },
    tags: ['Account'],
    summary: 'Get user profile',
    description: 'Get current user profile including connected GitHub and AI service information.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accountRoutes.openapi(getAccountRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    const profile = await getProfileData(userId, db);
    if (!profile) {
        return c.json({ error: 'Account not found' }, 404);
    }

    return c.json(profile);
});

// ============================================================================
// GET /v1/account/profile - Alias for GET /v1/account (backward compatibility)
// ============================================================================

const getAccountProfileRoute = createRoute({
    method: 'get',
    path: '/v1/account/profile',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetAccountResponseSchema,
                },
            },
            description: 'User profile with connected services',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Account not found',
        },
    },
    tags: ['Account'],
    summary: 'Get user profile (alias)',
    description: 'Alias for GET /v1/account - backward compatibility with happy-app.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accountRoutes.openapi(getAccountProfileRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    const profile = await getProfileData(userId, db);
    if (!profile) {
        return c.json({ error: 'Account not found' }, 404);
    }

    return c.json(profile);
});

// ============================================================================
// PUT /v1/account - Update Account Profile
// ============================================================================

const updateAccountRoute = createRoute({
    method: 'put',
    path: '/v1/account',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: UpdateAccountRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UpdateAccountSuccessSchema,
                },
            },
            description: 'Profile updated successfully',
        },
        409: {
            content: {
                'application/json': {
                    schema: UsernameConflictErrorSchema,
                },
            },
            description: 'Username already taken',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Account not found',
        },
        500: {
            content: {
                'application/json': {
                    schema: InternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Account'],
    summary: 'Update user profile',
    description: 'Update current user profile fields (firstName, lastName, username). Username must be unique.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accountRoutes.openapi(updateAccountRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { firstName, lastName, username } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Check if username is taken by another user
    if (username) {
        const existingUser = await db.query.accounts.findFirst({
            where: (accounts, { eq, and, ne }) =>
                and(eq(accounts.username, username), ne(accounts.id, userId)),
        });

        if (existingUser) {
            return c.json({ success: false as const, error: 'username-taken' as const }, 409);
        }
    }

    // Build update object with only provided fields
    const updateData: Partial<{
        firstName: string;
        lastName: string | null;
        username: string;
        updatedAt: Date;
    }> = {
        updatedAt: new Date(),
    };

    if (firstName !== undefined) updateData.firstName = firstName;
    if (lastName !== undefined) updateData.lastName = lastName;
    if (username !== undefined) updateData.username = username;

    // Update account
    await db
        .update(schema.accounts)
        .set(updateData)
        .where(eq(schema.accounts.id, userId));

    // Fetch updated account with GitHub profile
    const account = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
        with: {
            githubUser: true,
        },
    });

    if (!account) {
        return c.json({ error: 'Account not found' }, 404);
    }

    // Fetch connected AI service vendors
    const tokens = await db.query.serviceAccountTokens.findMany({
        where: (tokens, { eq }) => eq(tokens.accountId, userId),
        columns: {
            vendor: true,
        },
    });
    const connectedServices = tokens.map((t) => t.vendor);

    return c.json({
        success: true as const,
        profile: {
            id: userId,
            timestamp: Date.now(),
            firstName: account.firstName,
            lastName: account.lastName,
            username: account.username,
            github: account.githubUser?.profile ?? null,
            connectedServices,
        },
    });
});

// ============================================================================
// GET /v1/account/preferences - Get Account Preferences
// ============================================================================

const getPreferencesRoute = createRoute({
    method: 'get',
    path: '/v1/account/preferences',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetPreferencesResponseSchema,
                },
            },
            description: 'Account settings/preferences',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        500: {
            content: {
                'application/json': {
                    schema: InternalErrorSchema,
                },
            },
            description: 'Failed to get preferences',
        },
    },
    tags: ['Account'],
    summary: 'Get account preferences',
    description: 'Get encrypted account settings/preferences with version number for optimistic concurrency.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accountRoutes.openapi(getPreferencesRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    const account = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
        columns: {
            settings: true,
            settingsVersion: true,
        },
    });

    if (!account) {
        return c.json({ error: 'Failed to get account preferences' }, 500);
    }

    return c.json({
        settings: account.settings,
        settingsVersion: account.settingsVersion,
    });
});

// ============================================================================
// PUT /v1/account/preferences - Update Account Preferences
// ============================================================================

const updatePreferencesRoute = createRoute({
    method: 'put',
    path: '/v1/account/preferences',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: UpdatePreferencesRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UpdatePreferencesSuccessSchema.or(VersionMismatchErrorSchema),
                },
            },
            description: 'Preferences updated or version mismatch',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        500: {
            content: {
                'application/json': {
                    schema: InternalErrorSchema,
                },
            },
            description: 'Failed to update preferences',
        },
    },
    tags: ['Account'],
    summary: 'Update account preferences',
    description: 'Update account settings with optimistic concurrency control. Returns version mismatch if expectedVersion does not match current version.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accountRoutes.openapi(updatePreferencesRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { settings, expectedVersion } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Get current settings for version check
    const currentAccount = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
        columns: {
            settings: true,
            settingsVersion: true,
        },
    });

    if (!currentAccount) {
        return c.json({ error: 'Failed to update account preferences' }, 500);
    }

    // Check version for optimistic concurrency
    if (currentAccount.settingsVersion !== expectedVersion) {
        return c.json({
            success: false as const,
            error: 'version-mismatch' as const,
            currentVersion: currentAccount.settingsVersion,
            currentSettings: currentAccount.settings,
        });
    }

    // Update settings with version check (optimistic lock)
    const result = await db
        .update(schema.accounts)
        .set({
            settings,
            settingsVersion: expectedVersion + 1,
            updatedAt: new Date(),
        })
        .where(eq(schema.accounts.id, userId))
        .returning({ id: schema.accounts.id });

    if (result.length === 0) {
        // Re-fetch to get current version for error response
        const account = await db.query.accounts.findFirst({
            where: (accounts, { eq }) => eq(accounts.id, userId),
            columns: {
                settings: true,
                settingsVersion: true,
            },
        });

        return c.json({
            success: false as const,
            error: 'version-mismatch' as const,
            currentVersion: account?.settingsVersion ?? 0,
            currentSettings: account?.settings ?? null,
        });
    }

    return c.json({
        success: true as const,
        version: expectedVersion + 1,
    });
});

// ============================================================================
// GET /v1/account/settings - Alias for GET /v1/account/preferences (backward compatibility)
// ============================================================================

const getSettingsRoute = createRoute({
    method: 'get',
    path: '/v1/account/settings',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetPreferencesResponseSchema,
                },
            },
            description: 'Account settings/preferences',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        500: {
            content: {
                'application/json': {
                    schema: InternalErrorSchema,
                },
            },
            description: 'Failed to get settings',
        },
    },
    tags: ['Account'],
    summary: 'Get account settings (alias)',
    description: 'Alias for GET /v1/account/preferences - backward compatibility with happy-app.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accountRoutes.openapi(getSettingsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    const account = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
        columns: {
            settings: true,
            settingsVersion: true,
        },
    });

    if (!account) {
        return c.json({ error: 'Failed to get account settings' }, 500);
    }

    return c.json({
        settings: account.settings,
        settingsVersion: account.settingsVersion,
    });
});

// ============================================================================
// POST /v1/account/settings - Alias for PUT /v1/account/preferences (backward compatibility)
// ============================================================================

const postSettingsRoute = createRoute({
    method: 'post',
    path: '/v1/account/settings',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: UpdatePreferencesRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UpdatePreferencesSuccessSchema.or(VersionMismatchErrorSchema),
                },
            },
            description: 'Settings updated or version mismatch',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        500: {
            content: {
                'application/json': {
                    schema: InternalErrorSchema,
                },
            },
            description: 'Failed to update settings',
        },
    },
    tags: ['Account'],
    summary: 'Update account settings (alias)',
    description: 'Alias for PUT /v1/account/preferences - backward compatibility with happy-app. Uses POST instead of PUT.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
accountRoutes.openapi(postSettingsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { settings, expectedVersion } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Get current settings for version check
    const currentAccount = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
        columns: {
            settings: true,
            settingsVersion: true,
        },
    });

    if (!currentAccount) {
        return c.json({ error: 'Failed to update account settings' }, 500);
    }

    // Check version for optimistic concurrency
    if (currentAccount.settingsVersion !== expectedVersion) {
        return c.json({
            success: false as const,
            error: 'version-mismatch' as const,
            currentVersion: currentAccount.settingsVersion,
            currentSettings: currentAccount.settings,
        });
    }

    // Update settings with version check (optimistic lock)
    const result = await db
        .update(schema.accounts)
        .set({
            settings,
            settingsVersion: expectedVersion + 1,
            updatedAt: new Date(),
        })
        .where(eq(schema.accounts.id, userId))
        .returning({ id: schema.accounts.id });

    if (result.length === 0) {
        // Re-fetch to get current version for error response
        const account = await db.query.accounts.findFirst({
            where: (accounts, { eq }) => eq(accounts.id, userId),
            columns: {
                settings: true,
                settingsVersion: true,
            },
        });

        return c.json({
            success: false as const,
            error: 'version-mismatch' as const,
            currentVersion: account?.settingsVersion ?? 0,
            currentSettings: account?.settings ?? null,
        });
    }

    return c.json({
        success: true as const,
        version: expectedVersion + 1,
    });
});

export default accountRoutes;
