import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for user management endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for user routes:
 * - GET /v1/users/search - Search users by username
 * - GET /v1/users/:id - Get user profile by ID
 */

// ============================================================================
// Common Schemas
// ============================================================================

/**
 * Schema for relationship status between users
 */
export const RelationshipStatusSchema = z
    .enum(['none', 'requested', 'pending', 'friend', 'rejected'])
    .openapi('RelationshipStatus');

/**
 * Schema for user profile in API responses
 * Note: Avatar removed - frontend generates avatars dynamically
 * @internal Used for composing response schemas
 */
const UserProfileSchema = z
    .object({
        id: z.string().openapi({
            description: 'Unique user identifier',
            example: 'cmed556s4002bvb2020igg8jf',
        }),
        firstName: z.string().nullable().openapi({
            description: 'User first name',
            example: 'Jane',
        }),
        lastName: z.string().nullable().openapi({
            description: 'User last name',
            example: 'Smith',
        }),
        username: z.string().nullable().openapi({
            description: 'Unique username for discovery',
            example: 'janesmith',
        }),
        status: RelationshipStatusSchema.openapi({
            description: 'Relationship status between current user and this user',
            example: 'none',
        }),
    })
    .openapi('UserProfile');

// ============================================================================
// GET /v1/users/search - Search Users
// ============================================================================

/**
 * Schema for user search query parameters
 */
export const UserSearchQuerySchema = z.object({
    query: z.string().min(1).max(100).openapi({
        param: {
            name: 'query',
            in: 'query',
        },
        description: 'Search query (username prefix, case-insensitive)',
        example: 'john',
    }),
    limit: z
        .string()
        .default('10')
        .transform((v) => parseInt(v, 10))
        .pipe(z.number().int().min(1).max(50))
        .optional()
        .openapi({
            param: {
                name: 'limit',
                in: 'query',
            },
            description: 'Maximum number of results (1-50, default 10)',
            example: '10',
        }),
});

/**
 * Schema for user search response
 */
export const UserSearchResponseSchema = z
    .object({
        users: z.array(UserProfileSchema).openapi({
            description: 'Array of matching user profiles',
        }),
    })
    .openapi('UserSearchResponse');

// ============================================================================
// GET /v1/users/:id - Get User Profile
// ============================================================================

/**
 * Schema for user ID path parameter
 */
export const UserIdParamSchema = z.object({
    id: z.string().openapi({
        param: {
            name: 'id',
            in: 'path',
        },
        description: 'User identifier',
        example: 'cmed556s4002bvb2020igg8jf',
    }),
});

/**
 * Schema for get user response
 */
export const GetUserResponseSchema = z
    .object({
        user: UserProfileSchema.openapi({
            description: 'Requested user profile',
        }),
    })
    .openapi('GetUserResponse');

// ============================================================================
// Error Responses
// ============================================================================

/**
 * Schema for 401 Unauthorized error
 */
export const UnauthorizedErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Unauthorized',
        }),
    })
    .openapi('UnauthorizedError');

/**
 * Schema for 404 Not Found error
 */
export const NotFoundErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'User not found',
        }),
    })
    .openapi('NotFoundError');

/**
 * Schema for 400 Bad Request error
 */
export const BadRequestErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Query parameter is required',
        }),
    })
    .openapi('BadRequestError');

/**
 * Schema for 403 Forbidden error (friend request permission denied)
 */
export const ForbiddenErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message explaining why the request was denied',
            example: 'User is not accepting friend requests',
        }),
    })
    .openapi('ForbiddenError');

// ============================================================================
// Friend Management Routes
// ============================================================================

/**
 * Schema for add/remove friend request body
 */
export const FriendRequestBodySchema = z
    .object({
        uid: z.string().openapi({
            description: 'Target user ID',
            example: 'cmed556s4002bvb2020igg8jf',
        }),
    })
    .openapi('FriendRequestBody');

/**
 * Schema for friend operation response
 */
export const FriendOperationResponseSchema = z
    .object({
        user: UserProfileSchema.nullable().openapi({
            description: 'Updated user profile with new relationship status, or null if operation failed',
        }),
    })
    .openapi('FriendOperationResponse');

/**
 * Schema for friend list response
 */
export const FriendListResponseSchema = z
    .object({
        friends: z.array(UserProfileSchema).openapi({
            description: 'Array of friends with their relationship status',
        }),
    })
    .openapi('FriendListResponse');

// ============================================================================
// Privacy Settings Routes (HAP-727)
// ============================================================================

/**
 * Schema for privacy settings
 */
const PrivacySettingsSchema = z
    .object({
        showOnlineStatus: z.boolean().openapi({
            description: 'Whether to show online status to friends',
            example: true,
        }),
    })
    .openapi('PrivacySettings');

/**
 * Schema for privacy settings response
 */
export const PrivacySettingsResponseSchema = PrivacySettingsSchema.openapi('PrivacySettingsResponse');

/**
 * Schema for update privacy settings request body
 */
export const UpdatePrivacySettingsBodySchema = z
    .object({
        showOnlineStatus: z.boolean().optional().openapi({
            description: 'Whether to show online status to friends',
            example: true,
        }),
    })
    .openapi('UpdatePrivacySettingsBody');
