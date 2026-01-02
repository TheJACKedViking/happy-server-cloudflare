import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { userRelationships, accounts } from '@/db/schema';
import { eq, and } from 'drizzle-orm';
import { createId } from '@/utils/id';
import {
    getEventRouter,
    buildRelationshipUpdatedEvent,
    buildNewFeedPostUpdate,
} from '@/lib/eventRouter';
import { userFeedItems } from '@/db/schema';
import {
    UserSearchQuerySchema,
    UserSearchResponseSchema,
    UserIdParamSchema,
    GetUserResponseSchema,
    UnauthorizedErrorSchema,
    NotFoundErrorSchema,
    BadRequestErrorSchema,
    FriendRequestBodySchema,
    FriendOperationResponseSchema,
    FriendListResponseSchema,
    PrivacySettingsResponseSchema,
    UpdatePrivacySettingsBodySchema,
    type RelationshipStatusSchema,
} from '@/schemas/user';
import { z } from '@hono/zod-openapi';

/**
 * Environment bindings for user routes
 */
interface Env {
    DB: D1Database;
    CONNECTION_MANAGER: DurableObjectNamespace;
}

/**
 * Type for relationship status values
 */
type RelationshipStatus = z.infer<typeof RelationshipStatusSchema>;

/**
 * User routes module
 *
 * Implements user discovery, profile, and friend management endpoints:
 * - GET /v1/users/search - Search users by username (prefix match, case-insensitive)
 * - GET /v1/users/:id - Get user profile by ID with relationship status
 * - POST /v1/friends/add - Add friend or accept friend request
 * - POST /v1/friends/remove - Remove friend or cancel/reject request
 * - GET /v1/friends - List friends and pending requests
 *
 * All routes require authentication and use OpenAPI schemas for validation.
 *
 * Friend management implements the relationship state machine:
 * - none → requested (sender) / pending (receiver)
 * - requested/pending → friend (both when accepted)
 * - friend → pending/requested (on unfriend)
 * - requested → rejected (on cancel)
 * - pending → none (on reject)
 *
 * Events are broadcast via WebSocket when relationships change.
 * Feed notifications are created for friend requests and acceptances.
 */
const userRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all user routes
userRoutes.use('/v1/users/*', authMiddleware());
userRoutes.use('/v1/friends/*', authMiddleware());
userRoutes.use('/v1/friends', authMiddleware());
userRoutes.use('/v1/privacy', authMiddleware());

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get relationship status between two users
 *
 * @param db - Database instance
 * @param fromUserId - Current user ID
 * @param toUserId - Target user ID
 * @returns Relationship status or 'none' if no relationship exists
 */
async function getRelationshipStatus(
    db: ReturnType<typeof getDb>,
    fromUserId: string,
    toUserId: string
): Promise<RelationshipStatus> {
    const relationship = await db.query.userRelationships.findFirst({
        where: (rels, { eq, and }) =>
            and(eq(rels.fromUserId, fromUserId), eq(rels.toUserId, toUserId)),
    });

    return (relationship?.status as RelationshipStatus) ?? 'none';
}

/**
 * Build user profile object with relationship status
 *
 * @param user - User account record
 * @param status - Relationship status with current user
 * @returns User profile object for API response
 */
function buildUserProfile(
    user: {
        id: string;
        firstName: string | null;
        lastName: string | null;
        username: string | null;
    },
    status: RelationshipStatus
) {
    return {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        status,
    };
}

/**
 * Set or update a relationship between two users
 *
 * @param db - Database instance
 * @param fromUserId - Source user ID
 * @param toUserId - Target user ID
 * @param status - New relationship status
 */
async function relationshipSet(
    db: ReturnType<typeof getDb>,
    fromUserId: string,
    toUserId: string,
    status: RelationshipStatus
): Promise<void> {
    const now = new Date();
    const existingRelationship = await db.query.userRelationships.findFirst({
        where: (rels, { eq: e, and: a }) =>
            a(e(rels.fromUserId, fromUserId), e(rels.toUserId, toUserId)),
    });

    if (existingRelationship) {
        // Update existing relationship
        await db
            .update(userRelationships)
            .set({
                status,
                updatedAt: now,
                acceptedAt: status === 'friend' ? now : null,
            })
            .where(
                and(
                    eq(userRelationships.fromUserId, fromUserId),
                    eq(userRelationships.toUserId, toUserId)
                )
            );
    } else {
        // Create new relationship
        await db.insert(userRelationships).values({
            fromUserId,
            toUserId,
            status,
            createdAt: now,
            updatedAt: now,
            acceptedAt: status === 'friend' ? now : null,
            lastNotifiedAt: null,
        });
    }
}

/**
 * Check if a notification should be sent based on the last notification time
 * Returns true if no previous notification was sent OR 24 hours have passed
 * AND the relationship is not rejected
 */
function shouldSendNotification(
    lastNotifiedAt: Date | null,
    status: RelationshipStatus
): boolean {
    if (status === 'rejected') {
        return false;
    }
    if (!lastNotifiedAt) {
        return true;
    }
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    return lastNotifiedAt < twentyFourHoursAgo;
}

/**
 * Create a feed notification for a friend request or acceptance
 */
async function createFeedNotification(
    db: ReturnType<typeof getDb>,
    userId: string,
    kind: 'friend_request' | 'friend_accepted',
    targetUid: string
): Promise<{ id: string; counter: number; createdAt: Date } | null> {
    // Get the user's current feedSeq
    const user = await db.query.accounts.findFirst({
        where: (accts, { eq: e }) => e(accts.id, userId),
        columns: { feedSeq: true },
    });

    if (!user) {
        return null;
    }

    const newSeq = user.feedSeq + 1;
    const feedId = createId();
    const now = new Date();
    const repeatKey = `${kind}_${targetUid}`;

    // Check if feed item with same repeatKey exists
    const existingItem = await db.query.userFeedItems.findFirst({
        where: (items, { eq: e, and: a }) =>
            a(e(items.userId, userId), e(items.repeatKey, repeatKey)),
    });

    if (existingItem) {
        // Update existing feed item instead of creating duplicate
        await db
            .update(userFeedItems)
            .set({
                body: { kind, uid: targetUid },
                updatedAt: now,
            })
            .where(eq(userFeedItems.id, existingItem.id));
        return { id: existingItem.id, counter: existingItem.counter, createdAt: now };
    }

    // Create new feed item
    await db.insert(userFeedItems).values({
        id: feedId,
        userId,
        counter: newSeq,
        repeatKey,
        body: { kind, uid: targetUid },
        createdAt: now,
        updatedAt: now,
    });

    // Update user's feedSeq
    await db.update(accounts).set({ feedSeq: newSeq }).where(eq(accounts.id, userId));

    return { id: feedId, counter: newSeq, createdAt: now };
}

/**
 * Broadcast a relationship update event to both users
 */
async function broadcastRelationshipUpdate(
    env: Env,
    userId: string,
    targetUserId: string,
    userStatus: RelationshipStatus,
    targetStatus: RelationshipStatus
): Promise<void> {
    const eventRouter = getEventRouter(env);
    const now = Date.now();

    // Broadcast to the current user
    await eventRouter.emitUpdate({
        userId,
        payload: buildRelationshipUpdatedEvent(
            { uid: targetUserId, status: userStatus, timestamp: now },
            0, // seq is managed by the client
            createId()
        ),
    });

    // Broadcast to the target user
    await eventRouter.emitUpdate({
        userId: targetUserId,
        payload: buildRelationshipUpdatedEvent(
            { uid: userId, status: targetStatus, timestamp: now },
            0,
            createId()
        ),
    });
}

// ============================================================================
// GET /v1/users/search - Search Users
// ============================================================================

const searchUsersRoute = createRoute({
    method: 'get',
    path: '/v1/users/search',
    request: {
        query: UserSearchQuerySchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UserSearchResponseSchema,
                },
            },
            description: 'List of matching users',
        },
        400: {
            content: {
                'application/json': {
                    schema: BadRequestErrorSchema,
                },
            },
            description: 'Invalid query parameter',
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
    tags: ['Users'],
    summary: 'Search users by username',
    description: 'Search for users by username prefix (case-insensitive). Returns up to 10 matching users with relationship status.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
userRoutes.openapi(searchUsersRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { query, limit = 10 } = c.req.valid('query');
    const db = getDb(c.env.DB);

    // Search for users by username prefix (case-insensitive)
    // SQLite LIKE is case-insensitive for ASCII characters by default
    const users = await db.query.accounts.findMany({
        where: (accounts, { like, ne, and, isNotNull }) =>
            and(
                like(accounts.username, `${query}%`),
                ne(accounts.id, userId), // Exclude self from search results
                isNotNull(accounts.username) // Only users with usernames
            ),
        columns: {
            id: true,
            firstName: true,
            lastName: true,
            username: true,
        },
        limit,
        orderBy: (accounts, { asc }) => [asc(accounts.username)],
    });

    // Build user profiles with relationship status
    const userProfiles = await Promise.all(
        users.map(async (user) => {
            const status = await getRelationshipStatus(db, userId, user.id);
            return buildUserProfile(user, status);
        })
    );

    return c.json({
        users: userProfiles,
    });
});

// ============================================================================
// GET /v1/users/:id - Get User Profile
// ============================================================================

const getUserRoute = createRoute({
    method: 'get',
    path: '/v1/users/:id',
    request: {
        params: UserIdParamSchema,
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetUserResponseSchema,
                },
            },
            description: 'User profile',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'User not found',
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
    tags: ['Users'],
    summary: 'Get user profile by ID',
    description: 'Get a user profile by their ID, including the relationship status with the current user.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
userRoutes.openapi(getUserRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { id } = c.req.valid('param');
    const db = getDb(c.env.DB);

    // Fetch user
    const user = await db.query.accounts.findFirst({
        where: (accounts, { eq }) => eq(accounts.id, id),
        columns: {
            id: true,
            firstName: true,
            lastName: true,
            username: true,
        },
    });

    if (!user) {
        return c.json({ error: 'User not found' }, 404);
    }

    // Get relationship status
    const status = await getRelationshipStatus(db, userId, id);

    return c.json({
        user: buildUserProfile(user, status),
    });
});

// ============================================================================
// POST /v1/friends/add - Add Friend
// ============================================================================

const addFriendRoute = createRoute({
    method: 'post',
    path: '/v1/friends/add',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: FriendRequestBodySchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: FriendOperationResponseSchema,
                },
            },
            description: 'Friend request sent or friendship accepted',
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
    tags: ['Friends'],
    summary: 'Add friend or accept friend request',
    description: `Send a friend request or accept an incoming friend request.

**State machine:**
- If target has a pending request to you → both become friends
- If your current status is none or rejected → create a new friend request
- Otherwise, no change is made

**Notifications:**
- When sending a request: target receives a friend_request feed notification (with 24h cooldown)
- When accepting: both users receive friend_accepted feed notifications

**Events:**
- Broadcasts 'relationship-updated' event to both users via WebSocket`,
});

/**
 * Add a friend or accept a friend request.
 * Handles:
 * - Accepting incoming friend requests (both users become friends)
 * - Sending new friend requests
 * - Sending appropriate notifications with 24-hour cooldown
 */
// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
userRoutes.openapi(addFriendRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { uid: targetUserId } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Prevent self-friendship
    if (userId === targetUserId) {
        return c.json({ user: null });
    }

    // Fetch both users
    const currentUser = await db.query.accounts.findFirst({
        where: (accts, { eq: e }) => e(accts.id, userId),
        columns: { id: true, firstName: true, lastName: true, username: true },
    });

    const targetUser = await db.query.accounts.findFirst({
        where: (accts, { eq: e }) => e(accts.id, targetUserId),
        columns: { id: true, firstName: true, lastName: true, username: true },
    });

    if (!currentUser || !targetUser) {
        return c.json({ user: null });
    }

    // Get current relationship statuses
    const currentUserRelationship = await getRelationshipStatus(db, userId, targetUserId);
    const targetUserRelationship = await getRelationshipStatus(db, targetUserId, userId);

    // Case 1: Target has a pending request to current user - accept it
    if (targetUserRelationship === 'requested') {
        // Accept the friend request - update both to friends
        await relationshipSet(db, targetUserId, userId, 'friend');
        await relationshipSet(db, userId, targetUserId, 'friend');

        // Send friendship established notifications to both users
        const currentUserFeed = await createFeedNotification(db, userId, 'friend_accepted', targetUserId);
        const targetUserFeed = await createFeedNotification(db, targetUserId, 'friend_accepted', userId);

        // Broadcast relationship update events
        await broadcastRelationshipUpdate(c.env, userId, targetUserId, 'friend', 'friend');

        // Broadcast feed updates if created
        const eventRouter = getEventRouter(c.env);
        if (currentUserFeed) {
            await eventRouter.emitUpdate({
                userId,
                payload: buildNewFeedPostUpdate(
                    {
                        id: currentUserFeed.id,
                        body: { kind: 'friend_accepted', uid: targetUserId },
                        cursor: `cursor_${currentUserFeed.counter}`,
                        createdAt: currentUserFeed.createdAt.getTime(),
                    },
                    0,
                    createId()
                ),
            });
        }
        if (targetUserFeed) {
            await eventRouter.emitUpdate({
                userId: targetUserId,
                payload: buildNewFeedPostUpdate(
                    {
                        id: targetUserFeed.id,
                        body: { kind: 'friend_accepted', uid: userId },
                        cursor: `cursor_${targetUserFeed.counter}`,
                        createdAt: targetUserFeed.createdAt.getTime(),
                    },
                    0,
                    createId()
                ),
            });
        }

        return c.json({ user: buildUserProfile(targetUser, 'friend') });
    }

    // Case 2: If status is none or rejected, create a new request
    if (currentUserRelationship === 'none' || currentUserRelationship === 'rejected') {
        await relationshipSet(db, userId, targetUserId, 'requested');

        // If other side is in none state, set it to pending
        if (targetUserRelationship === 'none') {
            await relationshipSet(db, targetUserId, userId, 'pending');
        }

        // Check if we should send notification (respecting 24h cooldown)
        const targetRelRecord = await db.query.userRelationships.findFirst({
            where: (rels, { eq: e, and: a }) =>
                a(e(rels.fromUserId, targetUserId), e(rels.toUserId, userId)),
        });

        if (targetRelRecord && shouldSendNotification(targetRelRecord.lastNotifiedAt, targetRelRecord.status as RelationshipStatus)) {
            // Create feed notification for the target
            const feedItem = await createFeedNotification(db, targetUserId, 'friend_request', userId);

            // Update lastNotifiedAt
            await db
                .update(userRelationships)
                .set({ lastNotifiedAt: new Date() })
                .where(
                    and(
                        eq(userRelationships.fromUserId, targetUserId),
                        eq(userRelationships.toUserId, userId)
                    )
                );

            // Broadcast feed update
            if (feedItem) {
                const eventRouter = getEventRouter(c.env);
                await eventRouter.emitUpdate({
                    userId: targetUserId,
                    payload: buildNewFeedPostUpdate(
                        {
                            id: feedItem.id,
                            body: { kind: 'friend_request', uid: userId },
                            cursor: `cursor_${feedItem.counter}`,
                            createdAt: feedItem.createdAt.getTime(),
                        },
                        0,
                        createId()
                    ),
                });
            }
        }

        // Broadcast relationship update events
        await broadcastRelationshipUpdate(
            c.env,
            userId,
            targetUserId,
            'requested',
            targetUserRelationship === 'none' ? 'pending' : targetUserRelationship
        );

        return c.json({ user: buildUserProfile(targetUser, 'requested') });
    }

    // No change - return current status
    return c.json({ user: buildUserProfile(targetUser, currentUserRelationship) });
});

// ============================================================================
// POST /v1/friends/remove - Remove Friend
// ============================================================================

const removeFriendRoute = createRoute({
    method: 'post',
    path: '/v1/friends/remove',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: FriendRequestBodySchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: FriendOperationResponseSchema,
                },
            },
            description: 'Friend removed or request cancelled',
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
    tags: ['Friends'],
    summary: 'Remove friend or cancel request',
    description: `Remove a friend or cancel/reject a friend request.

**State machine:**
- If your status is 'requested' → set to 'rejected' (cancel your request)
- If your status is 'friend' → revert to 'pending'/'requested' (unfriend)
- If your status is 'pending' → set both to 'none' (reject incoming request)

**Events:**
- Broadcasts 'relationship-updated' event to both users via WebSocket`,
});

/**
 * Remove a friend or cancel/reject a friend request.
 */
// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
userRoutes.openapi(removeFriendRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { uid: targetUserId } = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Fetch both users
    const currentUser = await db.query.accounts.findFirst({
        where: (accts, { eq: e }) => e(accts.id, userId),
        columns: { id: true, firstName: true, lastName: true, username: true },
    });

    const targetUser = await db.query.accounts.findFirst({
        where: (accts, { eq: e }) => e(accts.id, targetUserId),
        columns: { id: true, firstName: true, lastName: true, username: true },
    });

    if (!currentUser || !targetUser) {
        return c.json({ user: null });
    }

    // Get current relationship statuses
    const currentUserRelationship = await getRelationshipStatus(db, userId, targetUserId);
    const targetUserRelationship = await getRelationshipStatus(db, targetUserId, userId);

    // Case 1: If status is requested, set it to rejected (cancel outgoing request)
    if (currentUserRelationship === 'requested') {
        await relationshipSet(db, userId, targetUserId, 'rejected');

        // Broadcast relationship update events
        await broadcastRelationshipUpdate(c.env, userId, targetUserId, 'rejected', targetUserRelationship);

        return c.json({ user: buildUserProfile(targetUser, 'rejected') });
    }

    // Case 2: If they are friends, change to pending/requested (unfriend)
    if (currentUserRelationship === 'friend') {
        await relationshipSet(db, targetUserId, userId, 'requested');
        await relationshipSet(db, userId, targetUserId, 'pending');

        // Broadcast relationship update events
        await broadcastRelationshipUpdate(c.env, userId, targetUserId, 'pending', 'requested');

        return c.json({ user: buildUserProfile(targetUser, 'pending') });
    }

    // Case 3: If status is pending, set to none (reject incoming request)
    if (currentUserRelationship === 'pending') {
        await relationshipSet(db, userId, targetUserId, 'none');
        if (targetUserRelationship !== 'rejected') {
            await relationshipSet(db, targetUserId, userId, 'none');
        }

        // Broadcast relationship update events
        await broadcastRelationshipUpdate(
            c.env,
            userId,
            targetUserId,
            'none',
            targetUserRelationship === 'rejected' ? 'rejected' : 'none'
        );

        return c.json({ user: buildUserProfile(targetUser, 'none') });
    }

    // No change - return current status
    return c.json({ user: buildUserProfile(targetUser, currentUserRelationship) });
});

// ============================================================================
// GET /v1/friends - List Friends
// ============================================================================

const listFriendsRoute = createRoute({
    method: 'get',
    path: '/v1/friends',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: FriendListResponseSchema,
                },
            },
            description: 'List of friends and pending requests',
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
    tags: ['Friends'],
    summary: 'List friends and pending requests',
    description: `Get all relationships with status 'friend', 'pending', or 'requested'.

Returns user profiles with their relationship status to the current user.`,
});

/**
 * List all friends and pending friend requests.
 * Returns relationships where current user is fromUserId with friend, pending, or requested status.
 */
// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
userRoutes.openapi(listFriendsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    // Query all relationships where current user is fromUserId with friend, pending, or requested status
    const relationships = await db.query.userRelationships.findMany({
        where: (rels, { eq: e, and: a, inArray: inn }) =>
            a(
                e(rels.fromUserId, userId),
                inn(rels.status, ['friend', 'pending', 'requested'])
            ),
        with: {
            toUser: {
                columns: {
                    id: true,
                    firstName: true,
                    lastName: true,
                    username: true,
                },
            },
        },
    });

    // Build user profiles
    const friends = relationships.map((rel) =>
        buildUserProfile(rel.toUser, rel.status as RelationshipStatus)
    );

    return c.json({ friends });
});

// ============================================================================
// GET /v1/users/me/privacy - Get Privacy Settings (HAP-727)
// ============================================================================

const getPrivacyRoute = createRoute({
    method: 'get',
    path: '/v1/users/me/privacy',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: PrivacySettingsResponseSchema,
                },
            },
            description: 'Current privacy settings',
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
    tags: ['Privacy'],
    summary: 'Get privacy settings',
    description: 'Get the current user\'s privacy settings.',
});

/**
 * Get privacy settings for the current user.
 */
// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
userRoutes.openapi(getPrivacyRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const db = getDb(c.env.DB);

    // Fetch user's privacy settings
    const user = await db.query.accounts.findFirst({
        where: (accts, { eq: e }) => e(accts.id, userId),
        columns: { showOnlineStatus: true },
    });

    if (!user) {
        return c.json({ error: 'Unauthorized' }, 401);
    }

    return c.json({
        showOnlineStatus: user.showOnlineStatus,
    });
});

// ============================================================================
// PATCH /v1/users/me/privacy - Update Privacy Settings (HAP-727)
// ============================================================================

const updatePrivacyRoute = createRoute({
    method: 'patch',
    path: '/v1/users/me/privacy',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: UpdatePrivacySettingsBodySchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: PrivacySettingsResponseSchema,
                },
            },
            description: 'Updated privacy settings',
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
    tags: ['Privacy'],
    summary: 'Update privacy settings',
    description: `Update the current user's privacy settings.

**showOnlineStatus:**
- When true (default): Friends can see when you're online
- When false: You appear offline to all friends

Note: This affects presence broadcast to friends.`,
});

/**
 * Update privacy settings for the current user.
 * Currently supports:
 * - showOnlineStatus: Whether to broadcast online status to friends
 */
// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
userRoutes.openapi(updatePrivacyRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const body = c.req.valid('json');
    const db = getDb(c.env.DB);

    // Build update object with only provided fields
    const updateData: { showOnlineStatus?: boolean; updatedAt: Date } = {
        updatedAt: new Date(),
    };

    if (body.showOnlineStatus !== undefined) {
        updateData.showOnlineStatus = body.showOnlineStatus;
    }

    // Update user's privacy settings
    await db
        .update(accounts)
        .set(updateData)
        .where(eq(accounts.id, userId));

    // Fetch updated settings
    const user = await db.query.accounts.findFirst({
        where: (accts, { eq: e }) => e(accts.id, userId),
        columns: { showOnlineStatus: true },
    });

    if (!user) {
        return c.json({ error: 'Unauthorized' }, 401);
    }

    return c.json({
        showOnlineStatus: user.showOnlineStatus,
    });
});

export default userRoutes;
