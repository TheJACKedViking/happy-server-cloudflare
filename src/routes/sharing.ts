import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { createId } from '@/utils/id';
import { eq, and, sql } from 'drizzle-orm';
import { checkRateLimit, type RateLimitConfig } from '@/lib/rate-limit';
import { sendInvitationEmail } from '@/lib/email';
import {
    SessionIdParamSchema,
    ShareIdParamSchema,
    InvitationIdParamSchema,
    ShareTokenParamSchema,
    InvitationTokenParamSchema,
    AddShareRequestSchema,
    UpdateShareRequestSchema,
    UpdateUrlSharingRequestSchema,
    SendInvitationRequestSchema,
    AccessSharedSessionRequestSchema,
    GetSharingSettingsResponseSchema,
    AddShareResponseSchema,
    UpdateShareResponseSchema,
    DeleteShareResponseSchema,
    UpdateUrlSharingResponseSchema,
    AccessSharedSessionResponseSchema,
    SendInvitationResponseSchema,
    AcceptInvitationResponseSchema,
    RevokeInvitationResponseSchema,
    UnauthorizedErrorSchema,
    NotFoundErrorSchema,
    ForbiddenErrorSchema,
    BadRequestErrorSchema,
    ConflictErrorSchema,
    RateLimitErrorSchema,
    PasswordRequiredErrorSchema,
} from '@/schemas/sharing';

/**
 * Environment bindings for sharing routes
 */
interface Env {
    DB: D1Database;
    RATE_LIMIT_KV?: KVNamespace;
    /** Resend API key for sending invitation emails (HAP-805) */
    RESEND_API_KEY?: string;
    /** Base URL for the Happy app (for building invitation links) */
    HAPPY_APP_URL?: string;
    /** Current environment (development/production) */
    ENVIRONMENT?: string;
}

/**
 * Rate limiting configuration
 */
const RATE_LIMIT = {
    /** Maximum invitations per user per hour */
    MAX_INVITATIONS_PER_HOUR: 10,
    /** Rate limit window in seconds */
    WINDOW_SECONDS: 3600,
};

/**
 * Rate limiting configuration for invitation acceptance endpoint (HAP-825)
 *
 * Uses a short window (1 minute) to protect against brute-force token guessing.
 * Rate limits are applied per IP address AND per invitation token.
 *
 * Thresholds:
 * - Per IP: 10 attempts per minute (allows trying a few invitations)
 * - Per token: 5 attempts per minute (more strict to prevent token brute-forcing)
 */
const INVITE_ACCEPT_RATE_LIMIT: {
    perIp: RateLimitConfig;
    perToken: RateLimitConfig;
} = {
    perIp: {
        maxRequests: 10,
        windowMs: 60_000, // 1 minute
        expirationTtl: 120, // 2 minutes
    },
    perToken: {
        maxRequests: 5,
        windowMs: 60_000, // 1 minute
        expirationTtl: 120, // 2 minutes
    },
};

/**
 * Invitation expiration configuration
 */
const INVITATION_EXPIRY_DAYS = 7;

/**
 * Session Sharing routes module (HAP-772)
 *
 * Implements all session sharing endpoints:
 * - GET /v1/sessions/:id/sharing - Get sharing settings
 * - POST /v1/sessions/:id/sharing - Add a share
 * - PATCH /v1/sessions/:id/sharing/:shareId - Update share permission
 * - DELETE /v1/sessions/:id/sharing/:shareId - Remove a share
 * - PUT /v1/sessions/:id/sharing/url - Configure URL sharing
 * - GET /v1/sessions/shared/:token - Access session via share URL
 * - POST /v1/sessions/:id/sharing/invite - Send email invitation
 * - GET /v1/invitations/:token/accept - Accept invitation
 * - DELETE /v1/sessions/:id/sharing/invitations/:invitationId - Revoke invitation
 *
 * All routes use OpenAPI schemas for automatic documentation and validation.
 */
const sharingRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to protected routes
sharingRoutes.use('/v1/sessions/:id/sharing', authMiddleware());
sharingRoutes.use('/v1/sessions/:id/sharing/*', authMiddleware());
sharingRoutes.use('/v1/invitations/:token/accept', authMiddleware());

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Normalize an email address for consistent storage and comparison (HAP-822).
 * Trims whitespace and converts to lowercase to prevent duplicate invites
 * for case-variant emails (e.g., "User@Example.com" vs "user@example.com").
 *
 * @param email - The email address to normalize
 * @returns Normalized email address (trimmed and lowercase)
 */
function normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
}

/**
 * Verify that the current user owns the session
 */
async function verifySessionOwnership(
    db: ReturnType<typeof getDb>,
    sessionId: string,
    userId: string
): Promise<{ error?: string; session?: typeof schema.sessions.$inferSelect }> {
    const session = await db.query.sessions.findFirst({
        where: (sessions, { eq, and }) =>
            and(eq(sessions.id, sessionId), eq(sessions.accountId, userId)),
    });

    if (!session) {
        return { error: 'Session not found or you do not have permission' };
    }

    return { session };
}

/**
 * Check rate limit for invitations
 */
async function checkInvitationRateLimit(
    kv: KVNamespace | undefined,
    userId: string
): Promise<{ allowed: boolean; retryAfter?: number }> {
    if (!kv) {
        // Rate limiting not configured, allow all
        return { allowed: true };
    }

    const key = `invite_rate:${userId}`;
    const current = await kv.get(key);
    const count = current ? parseInt(current, 10) : 0;

    if (count >= RATE_LIMIT.MAX_INVITATIONS_PER_HOUR) {
        // Rate limit exceeded, return default retry-after
        // KV doesn't expose TTL, so we use the window duration
        return { allowed: false, retryAfter: RATE_LIMIT.WINDOW_SECONDS };
    }

    // Increment counter
    await kv.put(key, String(count + 1), {
        expirationTtl: RATE_LIMIT.WINDOW_SECONDS,
    });

    return { allowed: true };
}

/**
 * Auto-expire pending invitations that are past their expiresAt time.
 * Updates the status in the database and returns the IDs of expired invitations.
 * This provides cleanup on-read without requiring accept attempts (HAP-824).
 */
async function expirePendingInvitations(
    db: ReturnType<typeof getDb>,
    sessionId?: string
): Promise<string[]> {
    const now = new Date();

    // Build the where clause based on whether we're filtering by session
    const baseCondition = and(
        eq(schema.sessionShareInvitations.status, 'pending'),
        sql`${schema.sessionShareInvitations.expiresAt} < ${now.getTime()}`
    );

    const whereCondition = sessionId
        ? and(baseCondition, eq(schema.sessionShareInvitations.sessionId, sessionId))
        : baseCondition;

    // Find expired invitations
    const expiredInvitations = await db
        .select({ id: schema.sessionShareInvitations.id })
        .from(schema.sessionShareInvitations)
        .where(whereCondition);

    if (expiredInvitations.length === 0) {
        return [];
    }

    // Update status to expired
    const expiredIds = expiredInvitations.map((inv) => inv.id);
    for (const id of expiredIds) {
        await db
            .update(schema.sessionShareInvitations)
            .set({ status: 'expired', updatedAt: now })
            .where(eq(schema.sessionShareInvitations.id, id));
    }

    return expiredIds;
}

/**
 * Get the canonical email for a user account
 * Currently sources from GitHub profile if connected
 * Returns null if no email can be determined
 *
 * HAP-823: Used for invitation acceptance validation
 */
async function getUserEmail(
    db: ReturnType<typeof getDb>,
    userId: string
): Promise<string | null> {
    // Get the user's account with GitHub connection
    const account = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
        with: {
            githubUser: true,
        },
    });

    if (!account) {
        return null;
    }

    // Try to get email from GitHub profile
    if (account.githubUser) {
        const profile = account.githubUser.profile as { email?: string | null } | null;
        if (profile?.email) {
            return normalizeEmail(profile.email);
        }
    }

    // Fallback: check if username looks like an email
    if (account.username && account.username.includes('@')) {
        return normalizeEmail(account.username);
    }

    return null;
}

/**
 * Get a display name for a user account (HAP-805)
 * Used for personalizing invitation emails
 * Returns the first available of: firstName + lastName, username, or null
 */
async function getUserDisplayName(
    db: ReturnType<typeof getDb>,
    userId: string
): Promise<string | null> {
    const account = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
    });

    if (!account) {
        return null;
    }

    // Try full name first
    if (account.firstName && account.lastName) {
        return `${account.firstName} ${account.lastName}`;
    }

    // Try first name only
    if (account.firstName) {
        return account.firstName;
    }

    // Fall back to username
    if (account.username) {
        return account.username;
    }

    return null;
}

/**
 * Hash a password using Web Crypto API (bcrypt alternative for Workers)
 * Uses PBKDF2 with SHA-256
 */
async function hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        256
    );

    // Encode salt and hash as base64
    const saltBase64 = btoa(String.fromCharCode(...salt));
    const hashBase64 = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));

    return `$pbkdf2$${saltBase64}$${hashBase64}`;
}

/**
 * Verify a password against a hash
 */
async function verifyPassword(password: string, hash: string): Promise<boolean> {
    if (!hash.startsWith('$pbkdf2$')) {
        return false;
    }

    const parts = hash.split('$');
    if (parts.length !== 4) {
        return false;
    }

    const saltBase64 = parts[2];
    const expectedHashBase64 = parts[3];

    if (!saltBase64) {
        return false;
    }

    const salt = new Uint8Array(
        atob(saltBase64)
            .split('')
            .map((c) => c.charCodeAt(0))
    );

    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        256
    );

    const actualHashBase64 = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));

    return actualHashBase64 === expectedHashBase64;
}

// ============================================================================
// GET /v1/sessions/:id/sharing - Get Sharing Settings
// ============================================================================

const getSharingSettingsRoute = createRoute({
    method: 'get',
    path: '/v1/sessions/{id}/sharing',
    request: {
        params: SessionIdParamSchema,
    },
    responses: {
        200: {
            content: { 'application/json': { schema: GetSharingSettingsResponseSchema } },
            description: 'Sharing settings for the session',
        },
        401: {
            content: { 'application/json': { schema: UnauthorizedErrorSchema } },
            description: 'Unauthorized',
        },
        404: {
            content: { 'application/json': { schema: NotFoundErrorSchema } },
            description: 'Session not found',
        },
    },
    tags: ['Session Sharing'],
    summary: 'Get sharing settings',
    description: 'Returns all sharing settings for a session including shares, URL config, and invitations.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sharingRoutes.openapi(getSharingSettingsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId } = c.req.valid('param');
    const db = getDb(c.env.DB);

    // Verify ownership
    const { error } = await verifySessionOwnership(db, sessionId, userId);
    if (error) {
        return c.json({ error }, 404);
    }

    // Auto-expire any pending invitations past their expiration time (HAP-824)
    await expirePendingInvitations(db, sessionId);

    // Get shares
    const shares = await db
        .select()
        .from(schema.sessionShares)
        .where(eq(schema.sessionShares.sessionId, sessionId));

    // Get user profiles for shares
    const shareEntries = await Promise.all(
        shares.map(async (share) => {
            const user = await db.query.accounts.findFirst({
                where: (accounts, { eq }) => eq(accounts.id, share.userId),
            });
            return {
                id: share.id,
                userId: share.userId,
                userProfile: user
                    ? {
                          id: user.id,
                          firstName: user.firstName,
                          lastName: user.lastName,
                          username: user.username,
                      }
                    : undefined,
                permission: share.permission,
                sharedAt: share.sharedAt.toISOString(),
                sharedBy: share.sharedBy,
            };
        })
    );

    // Get URL sharing config
    const urlConfig = await db.query.sessionShareUrls.findFirst({
        where: (urls, { eq }) => eq(urls.sessionId, sessionId),
    });

    // Get pending invitations
    const invitations = await db
        .select()
        .from(schema.sessionShareInvitations)
        .where(
            and(
                eq(schema.sessionShareInvitations.sessionId, sessionId),
                eq(schema.sessionShareInvitations.status, 'pending')
            )
        );

    return c.json({
        sessionId,
        shares: shareEntries,
        urlSharing: urlConfig
            ? {
                  enabled: true,
                  token: urlConfig.token,
                  permission: urlConfig.permission,
                  expiresAt: urlConfig.expiresAt?.toISOString(),
              }
            : {
                  enabled: false,
                  permission: 'view_only' as const,
              },
        invitations: invitations.map((inv) => ({
            id: inv.id,
            email: inv.email,
            permission: inv.permission,
            invitedAt: inv.invitedAt.toISOString(),
            invitedBy: inv.invitedBy,
            status: inv.status,
            expiresAt: inv.expiresAt.toISOString(),
        })),
    });
});

// ============================================================================
// POST /v1/sessions/:id/sharing - Add Share
// ============================================================================

const addShareRoute = createRoute({
    method: 'post',
    path: '/v1/sessions/{id}/sharing',
    request: {
        params: SessionIdParamSchema,
        body: {
            content: { 'application/json': { schema: AddShareRequestSchema } },
            description: 'Share details (either userId or email required)',
        },
    },
    responses: {
        200: {
            content: { 'application/json': { schema: AddShareResponseSchema } },
            description: 'Share or invitation created successfully',
        },
        400: {
            content: { 'application/json': { schema: BadRequestErrorSchema } },
            description: 'Invalid request',
        },
        401: {
            content: { 'application/json': { schema: UnauthorizedErrorSchema } },
            description: 'Unauthorized',
        },
        404: {
            content: { 'application/json': { schema: NotFoundErrorSchema } },
            description: 'Session or user not found',
        },
        409: {
            content: { 'application/json': { schema: ConflictErrorSchema } },
            description: 'User already has access',
        },
        429: {
            content: { 'application/json': { schema: RateLimitErrorSchema } },
            description: 'Rate limit exceeded',
        },
    },
    tags: ['Session Sharing'],
    summary: 'Add a share',
    description: 'Share a session with a user (by userId) or send an email invitation.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sharingRoutes.openapi(addShareRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId } = c.req.valid('param');
    const body = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Verify ownership
    const { error } = await verifySessionOwnership(db, sessionId, userId);
    if (error) {
        return c.json({ error }, 404);
    }

    // Handle share with existing user
    if (body.userId) {
        // Check if user exists
        const targetUser = await db.query.accounts.findFirst({
            where: (accounts, { eq }) => eq(accounts.id, body.userId!),
        });

        if (!targetUser) {
            return c.json({ error: 'User not found' }, 404);
        }

        // Check if already shared
        const existing = await db.query.sessionShares.findFirst({
            where: (shares, { eq, and }) =>
                and(eq(shares.sessionId, sessionId), eq(shares.userId, body.userId!)),
        });

        if (existing) {
            return c.json({ error: 'User already has access to this session' }, 409);
        }

        // Create share
        const share = {
            id: createId(),
            sessionId,
            userId: body.userId,
            permission: body.permission,
            sharedAt: new Date(),
            sharedBy: userId,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        await db.insert(schema.sessionShares).values(share);

        return c.json({
            success: true,
            share: {
                id: share.id,
                userId: share.userId,
                userProfile: {
                    id: targetUser.id,
                    firstName: targetUser.firstName,
                    lastName: targetUser.lastName,
                    username: targetUser.username,
                },
                permission: share.permission,
                sharedAt: share.sharedAt.toISOString(),
                sharedBy: share.sharedBy,
            },
        });
    }

    // Handle email invitation
    if (body.email) {
        // Normalize email for consistent storage and comparison (HAP-822)
        const normalizedEmail = normalizeEmail(body.email);

        // Auto-expire any pending invitations past their expiration time (HAP-824)
        await expirePendingInvitations(db, sessionId);

        // Check rate limit
        const rateLimit = await checkInvitationRateLimit(c.env.RATE_LIMIT_KV, userId);
        if (!rateLimit.allowed) {
            return c.json(
                {
                    error: `Rate limit exceeded. Maximum ${RATE_LIMIT.MAX_INVITATIONS_PER_HOUR} invitations per hour.`,
                    retryAfter: rateLimit.retryAfter,
                },
                429
            );
        }

        // Check if invitation already exists (using normalized email to prevent duplicates)
        const existing = await db.query.sessionShareInvitations.findFirst({
            where: (invs, { eq, and }) =>
                and(
                    eq(invs.sessionId, sessionId),
                    eq(invs.email, normalizedEmail),
                    eq(invs.status, 'pending')
                ),
        });

        if (existing) {
            return c.json({ error: 'Invitation already sent to this email' }, 409);
        }

        // NOTE: We intentionally do NOT check accounts.username for email matches (HAP-822).
        // The accounts.username field is a username, not an email address.
        // When Better Auth is integrated (HAP-29), we can add proper email-based user lookup
        // using the auth user table's email field.

        // Create invitation with normalized email
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + INVITATION_EXPIRY_DAYS);

        const invitation = {
            id: createId(),
            sessionId,
            email: normalizedEmail,
            permission: body.permission,
            token: crypto.randomUUID(),
            status: 'pending' as const,
            invitedAt: new Date(),
            invitedBy: userId,
            expiresAt,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        await db.insert(schema.sessionShareInvitations).values(invitation);

        // Send invitation email (HAP-805)
        const inviterName = await getUserDisplayName(db, userId);
        const emailResult = await sendInvitationEmail(c.env, {
            recipientEmail: normalizedEmail,
            invitationToken: invitation.token,
            inviterName: inviterName ?? undefined,
            permission: body.permission,
            expiresAt: invitation.expiresAt,
        });

        if (!emailResult.success) {
            // Email failed - delete the invitation and return error
            // This ensures we don't create orphaned invites
            await db
                .delete(schema.sessionShareInvitations)
                .where(eq(schema.sessionShareInvitations.id, invitation.id));

            return c.json(
                { error: emailResult.error ?? 'Failed to send invitation email' },
                500
            );
        }

        return c.json({
            success: true,
            invitation: {
                id: invitation.id,
                email: invitation.email,
                permission: invitation.permission,
                invitedAt: invitation.invitedAt.toISOString(),
                invitedBy: invitation.invitedBy,
                status: invitation.status,
                expiresAt: invitation.expiresAt.toISOString(),
            },
        });
    }

    return c.json({ error: 'Either userId or email must be provided' }, 400);
});

// ============================================================================
// PATCH /v1/sessions/:id/sharing/:shareId - Update Share Permission
// ============================================================================

const updateShareRoute = createRoute({
    method: 'patch',
    path: '/v1/sessions/{id}/sharing/{shareId}',
    request: {
        params: ShareIdParamSchema,
        body: {
            content: { 'application/json': { schema: UpdateShareRequestSchema } },
            description: 'New permission level',
        },
    },
    responses: {
        200: {
            content: { 'application/json': { schema: UpdateShareResponseSchema } },
            description: 'Share updated successfully',
        },
        401: {
            content: { 'application/json': { schema: UnauthorizedErrorSchema } },
            description: 'Unauthorized',
        },
        404: {
            content: { 'application/json': { schema: NotFoundErrorSchema } },
            description: 'Session or share not found',
        },
    },
    tags: ['Session Sharing'],
    summary: 'Update share permission',
    description: 'Update the permission level for an existing share.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sharingRoutes.openapi(updateShareRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId, shareId } = c.req.valid('param');
    const { permission } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Verify ownership
    const { error } = await verifySessionOwnership(db, sessionId, userId);
    if (error) {
        return c.json({ error }, 404);
    }

    // Find and update share
    const share = await db.query.sessionShares.findFirst({
        where: (shares, { eq, and }) =>
            and(eq(shares.id, shareId), eq(shares.sessionId, sessionId)),
    });

    if (!share) {
        return c.json({ error: 'Share not found' }, 404);
    }

    await db
        .update(schema.sessionShares)
        .set({ permission, updatedAt: new Date() })
        .where(eq(schema.sessionShares.id, shareId));

    // Get user profile
    const user = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, share.userId),
    });

    return c.json({
        success: true,
        share: {
            id: share.id,
            userId: share.userId,
            userProfile: user
                ? {
                      id: user.id,
                      firstName: user.firstName,
                      lastName: user.lastName,
                      username: user.username,
                  }
                : undefined,
            permission,
            sharedAt: share.sharedAt.toISOString(),
            sharedBy: share.sharedBy,
        },
    });
});

// ============================================================================
// DELETE /v1/sessions/:id/sharing/:shareId - Remove Share
// ============================================================================

const deleteShareRoute = createRoute({
    method: 'delete',
    path: '/v1/sessions/{id}/sharing/{shareId}',
    request: {
        params: ShareIdParamSchema,
    },
    responses: {
        200: {
            content: { 'application/json': { schema: DeleteShareResponseSchema } },
            description: 'Share removed successfully',
        },
        401: {
            content: { 'application/json': { schema: UnauthorizedErrorSchema } },
            description: 'Unauthorized',
        },
        404: {
            content: { 'application/json': { schema: NotFoundErrorSchema } },
            description: 'Session or share not found',
        },
    },
    tags: ['Session Sharing'],
    summary: 'Remove a share',
    description: 'Remove a user\'s access to the session.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sharingRoutes.openapi(deleteShareRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId, shareId } = c.req.valid('param');
    const db = getDb(c.env.DB);

    // Verify ownership
    const { error } = await verifySessionOwnership(db, sessionId, userId);
    if (error) {
        return c.json({ error }, 404);
    }

    // Delete share
    await db
        .delete(schema.sessionShares)
        .where(
            and(
                eq(schema.sessionShares.id, shareId),
                eq(schema.sessionShares.sessionId, sessionId)
            )
        );

    return c.json({ success: true });
});

// ============================================================================
// PUT /v1/sessions/:id/sharing/url - Configure URL Sharing
// ============================================================================

const updateUrlSharingRoute = createRoute({
    method: 'put',
    path: '/v1/sessions/{id}/sharing/url',
    request: {
        params: SessionIdParamSchema,
        body: {
            content: { 'application/json': { schema: UpdateUrlSharingRequestSchema } },
            description: 'URL sharing configuration',
        },
    },
    responses: {
        200: {
            content: { 'application/json': { schema: UpdateUrlSharingResponseSchema } },
            description: 'URL sharing updated successfully',
        },
        401: {
            content: { 'application/json': { schema: UnauthorizedErrorSchema } },
            description: 'Unauthorized',
        },
        404: {
            content: { 'application/json': { schema: NotFoundErrorSchema } },
            description: 'Session not found',
        },
    },
    tags: ['Session Sharing'],
    summary: 'Configure URL sharing',
    description: 'Enable, disable, or configure URL sharing for a session.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sharingRoutes.openapi(updateUrlSharingRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId } = c.req.valid('param');
    const body = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Verify ownership
    const { error } = await verifySessionOwnership(db, sessionId, userId);
    if (error) {
        return c.json({ error }, 404);
    }

    // Get existing config
    const existing = await db.query.sessionShareUrls.findFirst({
        where: (urls, { eq }) => eq(urls.sessionId, sessionId),
    });

    if (!body.enabled) {
        // Disable URL sharing
        if (existing) {
            await db
                .delete(schema.sessionShareUrls)
                .where(eq(schema.sessionShareUrls.sessionId, sessionId));
        }
        return c.json({
            success: true,
            urlSharing: {
                enabled: false,
                permission: 'view_only' as const,
            },
        });
    }

    // Enable or update URL sharing
    const passwordHash =
        body.password === null
            ? null
            : body.password
              ? await hashPassword(body.password)
              : existing?.passwordHash ?? null;

    const permission = body.permission ?? existing?.permission ?? 'view_only';
    const token = existing?.token ?? crypto.randomUUID();

    if (existing) {
        await db
            .update(schema.sessionShareUrls)
            .set({
                passwordHash,
                permission,
                updatedAt: new Date(),
            })
            .where(eq(schema.sessionShareUrls.sessionId, sessionId));
    } else {
        await db.insert(schema.sessionShareUrls).values({
            sessionId,
            token,
            passwordHash,
            permission,
            createdAt: new Date(),
            updatedAt: new Date(),
        });
    }

    return c.json({
        success: true,
        urlSharing: {
            enabled: true,
            token,
            permission,
        },
    });
});

// ============================================================================
// GET /v1/sessions/shared/:token - Access Session via Share URL
// ============================================================================

const accessSharedSessionRoute = createRoute({
    method: 'post',
    path: '/v1/sessions/shared/{token}',
    request: {
        params: ShareTokenParamSchema,
        body: {
            content: { 'application/json': { schema: AccessSharedSessionRequestSchema } },
            description: 'Password if required',
            required: false,
        },
    },
    responses: {
        200: {
            content: { 'application/json': { schema: AccessSharedSessionResponseSchema } },
            description: 'Session data',
        },
        401: {
            content: { 'application/json': { schema: PasswordRequiredErrorSchema } },
            description: 'Password required',
        },
        403: {
            content: { 'application/json': { schema: ForbiddenErrorSchema } },
            description: 'Invalid password',
        },
        404: {
            content: { 'application/json': { schema: NotFoundErrorSchema } },
            description: 'Share not found or expired',
        },
    },
    tags: ['Session Sharing'],
    summary: 'Access shared session',
    description: 'Access a session via a share URL token. No authentication required.',
});

// @ts-expect-error - OpenAPI handler type inference with mixed response types
sharingRoutes.openapi(accessSharedSessionRoute, async (c) => {
    const { token } = c.req.valid('param');
    const body = await c.req.json().catch(() => ({}));
    const db = getDb(c.env.DB);

    // Find share URL config
    const shareUrl = await db.query.sessionShareUrls.findFirst({
        where: (urls, { eq }) => eq(urls.token, token),
    });

    if (!shareUrl) {
        return c.json({ error: 'Share not found or expired' }, 404);
    }

    // Check expiration
    if (shareUrl.expiresAt && shareUrl.expiresAt < new Date()) {
        return c.json({ error: 'Share has expired' }, 404);
    }

    // Check password
    if (shareUrl.passwordHash) {
        if (!body.password) {
            return c.json({ error: 'Password required', passwordRequired: true }, 401);
        }

        const validPassword = await verifyPassword(body.password, shareUrl.passwordHash);
        if (!validPassword) {
            return c.json({ error: 'Invalid password' }, 403);
        }
    }

    // Get session
    const session = await db.query.sessions.findFirst({
        where: (sessions, { eq }) => eq(sessions.id, shareUrl.sessionId),
    });

    if (!session) {
        return c.json({ error: 'Session not found' }, 404);
    }

    return c.json({
        session: {
            id: session.id,
            metadata: session.metadata,
            permission: shareUrl.permission,
        },
    });
});

// ============================================================================
// POST /v1/sessions/:id/sharing/invite - Send Email Invitation
// ============================================================================

const sendInvitationRoute = createRoute({
    method: 'post',
    path: '/v1/sessions/{id}/sharing/invite',
    request: {
        params: SessionIdParamSchema,
        body: {
            content: { 'application/json': { schema: SendInvitationRequestSchema } },
            description: 'Invitation details',
        },
    },
    responses: {
        200: {
            content: { 'application/json': { schema: SendInvitationResponseSchema } },
            description: 'Invitation sent successfully',
        },
        401: {
            content: { 'application/json': { schema: UnauthorizedErrorSchema } },
            description: 'Unauthorized',
        },
        404: {
            content: { 'application/json': { schema: NotFoundErrorSchema } },
            description: 'Session not found',
        },
        409: {
            content: { 'application/json': { schema: ConflictErrorSchema } },
            description: 'Invitation already exists',
        },
        429: {
            content: { 'application/json': { schema: RateLimitErrorSchema } },
            description: 'Rate limit exceeded',
        },
    },
    tags: ['Session Sharing'],
    summary: 'Send email invitation',
    description: 'Send an email invitation to share a session with a non-user.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sharingRoutes.openapi(sendInvitationRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId } = c.req.valid('param');
    const { email, permission } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Normalize email for consistent storage and comparison (HAP-822)
    const normalizedEmail = normalizeEmail(email);

    // Verify ownership
    const { error } = await verifySessionOwnership(db, sessionId, userId);
    if (error) {
        return c.json({ error }, 404);
    }

    // Auto-expire any pending invitations past their expiration time (HAP-824)
    await expirePendingInvitations(db, sessionId);

    // Check rate limit
    const rateLimit = await checkInvitationRateLimit(c.env.RATE_LIMIT_KV, userId);
    if (!rateLimit.allowed) {
        return c.json(
            {
                error: `Rate limit exceeded. Maximum ${RATE_LIMIT.MAX_INVITATIONS_PER_HOUR} invitations per hour.`,
                retryAfter: rateLimit.retryAfter,
            },
            429
        );
    }

    // Check if invitation already exists (using normalized email to prevent duplicates)
    const existing = await db.query.sessionShareInvitations.findFirst({
        where: (invs, { eq, and }) =>
            and(eq(invs.sessionId, sessionId), eq(invs.email, normalizedEmail), eq(invs.status, 'pending')),
    });

    if (existing) {
        return c.json({ error: 'Invitation already sent to this email' }, 409);
    }

    // Create invitation with normalized email
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + INVITATION_EXPIRY_DAYS);

    const invitation = {
        id: createId(),
        sessionId,
        email: normalizedEmail,
        permission,
        token: crypto.randomUUID(),
        status: 'pending' as const,
        invitedAt: new Date(),
        invitedBy: userId,
        expiresAt,
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    await db.insert(schema.sessionShareInvitations).values(invitation);

    // Send invitation email (HAP-805)
    const inviterName = await getUserDisplayName(db, userId);
    const emailResult = await sendInvitationEmail(c.env, {
        recipientEmail: normalizedEmail,
        invitationToken: invitation.token,
        inviterName: inviterName ?? undefined,
        permission,
        expiresAt: invitation.expiresAt,
    });

    if (!emailResult.success) {
        // Email failed - delete the invitation and return error
        // This ensures we don't create orphaned invites
        await db
            .delete(schema.sessionShareInvitations)
            .where(eq(schema.sessionShareInvitations.id, invitation.id));

        return c.json(
            { error: emailResult.error ?? 'Failed to send invitation email' },
            500
        );
    }

    return c.json({
        success: true,
        invitation: {
            id: invitation.id,
            email: invitation.email,
            permission: invitation.permission,
            invitedAt: invitation.invitedAt.toISOString(),
            invitedBy: invitation.invitedBy,
            status: invitation.status,
            expiresAt: invitation.expiresAt.toISOString(),
        },
    });
});

// ============================================================================
// GET /v1/invitations/:token/accept - Accept Invitation
// ============================================================================

const acceptInvitationRoute = createRoute({
    method: 'get',
    path: '/v1/invitations/{token}/accept',
    request: {
        params: InvitationTokenParamSchema,
    },
    responses: {
        200: {
            content: { 'application/json': { schema: AcceptInvitationResponseSchema } },
            description: 'Invitation accepted successfully',
        },
        401: {
            content: { 'application/json': { schema: UnauthorizedErrorSchema } },
            description: 'Unauthorized',
        },
        404: {
            content: { 'application/json': { schema: NotFoundErrorSchema } },
            description: 'Invitation not found or expired',
        },
        403: {
            content: { 'application/json': { schema: ForbiddenErrorSchema } },
            description: 'User email does not match invitation recipient',
        },
        409: {
            content: { 'application/json': { schema: ConflictErrorSchema } },
            description: 'Already have access',
        },
        429: {
            content: { 'application/json': { schema: RateLimitErrorSchema } },
            description: 'Rate limit exceeded for invitation acceptance attempts',
        },
    },
    tags: ['Session Sharing'],
    summary: 'Accept invitation',
    description: 'Accept an email invitation and gain access to the shared session. Validates that the authenticated user email matches the invitation recipient. Rate limited to prevent brute-force attacks on invitation tokens.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sharingRoutes.openapi(acceptInvitationRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { token } = c.req.valid('param');
    const db = getDb(c.env.DB);

    // Rate limiting (HAP-825): Check both per-IP and per-token limits
    // This prevents brute-force attempts to guess invitation tokens
    const clientIp =
        c.req.header('CF-Connecting-IP') ?? c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() ?? 'unknown';

    // Check per-IP rate limit first (allows legitimate users trying multiple invitations)
    const ipRateLimit = await checkRateLimit(
        c.env.RATE_LIMIT_KV,
        'invite_accept_ip',
        clientIp,
        INVITE_ACCEPT_RATE_LIMIT.perIp
    );

    if (!ipRateLimit.allowed) {
        return c.json(
            {
                error: 'Too many invitation acceptance attempts. Please try again later.',
                retryAfter: ipRateLimit.retryAfter,
            },
            429,
            { 'Retry-After': String(ipRateLimit.retryAfter) }
        );
    }

    // Check per-token rate limit (stricter - prevents targeted brute-force on specific tokens)
    const tokenRateLimit = await checkRateLimit(
        c.env.RATE_LIMIT_KV,
        'invite_accept_token',
        token,
        INVITE_ACCEPT_RATE_LIMIT.perToken
    );

    if (!tokenRateLimit.allowed) {
        return c.json(
            {
                error: 'Too many attempts for this invitation. Please try again later.',
                retryAfter: tokenRateLimit.retryAfter,
            },
            429,
            { 'Retry-After': String(tokenRateLimit.retryAfter) }
        );
    }

    // Find invitation
    const invitation = await db.query.sessionShareInvitations.findFirst({
        where: (invs, { eq, and }) => and(eq(invs.token, token), eq(invs.status, 'pending')),
    });

    if (!invitation) {
        return c.json({ error: 'Invitation not found or expired' }, 404);
    }

    // Check expiration
    if (invitation.expiresAt < new Date()) {
        // Mark as expired
        await db
            .update(schema.sessionShareInvitations)
            .set({ status: 'expired', updatedAt: new Date() })
            .where(eq(schema.sessionShareInvitations.id, invitation.id));
        return c.json({ error: 'Invitation has expired' }, 404);
    }

    // HAP-823: Validate that authenticated user email matches invitation recipient
    // This prevents invitation tokens from being used by unintended users if leaked
    const userEmail = await getUserEmail(db, userId);
    const invitationEmail = normalizeEmail(invitation.email);

    if (!userEmail) {
        // User has no email associated with their account
        return c.json(
            { error: 'Your account has no email address. Please connect GitHub or set an email to accept invitations.' },
            403
        );
    }

    if (userEmail !== invitationEmail) {
        // Email mismatch - invitation was sent to a different email address
        return c.json(
            { error: 'This invitation was sent to a different email address.' },
            403
        );
    }

    // Check if already has access
    const existing = await db.query.sessionShares.findFirst({
        where: (shares, { eq, and }) =>
            and(eq(shares.sessionId, invitation.sessionId), eq(shares.userId, userId)),
    });

    if (existing) {
        return c.json({ error: 'You already have access to this session' }, 409);
    }

    // Create share
    const share = {
        id: createId(),
        sessionId: invitation.sessionId,
        userId,
        permission: invitation.permission,
        sharedAt: new Date(),
        sharedBy: invitation.invitedBy,
        createdAt: new Date(),
        updatedAt: new Date(),
    };

    await db.insert(schema.sessionShares).values(share);

    // Mark invitation as accepted
    await db
        .update(schema.sessionShareInvitations)
        .set({ status: 'accepted', updatedAt: new Date() })
        .where(eq(schema.sessionShareInvitations.id, invitation.id));

    // Get current user profile
    const user = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, userId),
    });

    return c.json({
        success: true,
        share: {
            id: share.id,
            userId: share.userId,
            userProfile: user
                ? {
                      id: user.id,
                      firstName: user.firstName,
                      lastName: user.lastName,
                      username: user.username,
                  }
                : undefined,
            permission: share.permission,
            sharedAt: share.sharedAt.toISOString(),
            sharedBy: share.sharedBy,
        },
        sessionId: invitation.sessionId,
    });
});

// ============================================================================
// DELETE /v1/sessions/:id/sharing/invitations/:invitationId - Revoke Invitation
// ============================================================================

const revokeInvitationRoute = createRoute({
    method: 'delete',
    path: '/v1/sessions/{id}/sharing/invitations/{invitationId}',
    request: {
        params: InvitationIdParamSchema,
    },
    responses: {
        200: {
            content: { 'application/json': { schema: RevokeInvitationResponseSchema } },
            description: 'Invitation revoked successfully',
        },
        401: {
            content: { 'application/json': { schema: UnauthorizedErrorSchema } },
            description: 'Unauthorized',
        },
        404: {
            content: { 'application/json': { schema: NotFoundErrorSchema } },
            description: 'Session or invitation not found',
        },
    },
    tags: ['Session Sharing'],
    summary: 'Revoke invitation',
    description: 'Revoke a pending email invitation.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
sharingRoutes.openapi(revokeInvitationRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id: sessionId, invitationId } = c.req.valid('param');
    const db = getDb(c.env.DB);

    // Verify ownership
    const { error } = await verifySessionOwnership(db, sessionId, userId);
    if (error) {
        return c.json({ error }, 404);
    }

    // Update invitation to revoked
    await db
        .update(schema.sessionShareInvitations)
        .set({ status: 'revoked', updatedAt: new Date() })
        .where(
            and(
                eq(schema.sessionShareInvitations.id, invitationId),
                eq(schema.sessionShareInvitations.sessionId, sessionId),
                eq(schema.sessionShareInvitations.status, 'pending')
            )
        );

    return c.json({ success: true });
});

export default sharingRoutes;
