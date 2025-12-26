import { z } from '@hono/zod-openapi';

// ============================================================================
// Push Token Schemas
// ============================================================================

/**
 * Request for registering a push token
 */
export const RegisterPushTokenRequestSchema = z
    .object({
        token: z.string().openapi({
            description: 'Push notification token from APNs, FCM, or Web Push',
            example: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
        }),
    })
    .openapi('RegisterPushTokenRequest');

/**
 * Success response for push token operations
 */
export const PushTokenSuccessSchema = z
    .object({
        success: z.literal(true),
    })
    .openapi('PushTokenSuccess');

/**
 * Path parameter for token
 */
export const PushTokenParamSchema = z
    .object({
        token: z.string().openapi({
            description: 'Push token to delete',
            example: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
        }),
    })
    .openapi('PushTokenParam');

/**
 * Single push token item
 * @internal Used for composing response schemas
 */
const PushTokenItemSchema = z
    .object({
        id: z.string().openapi({
            description: 'Token record ID',
            example: 'cld123abc',
        }),
        token: z.string().openapi({
            description: 'Push notification token',
            example: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
        }),
        createdAt: z.number().openapi({
            description: 'Creation timestamp in milliseconds',
            example: 1701432000000,
        }),
        updatedAt: z.number().openapi({
            description: 'Last update timestamp in milliseconds',
            example: 1701432000000,
        }),
    })
    .openapi('PushTokenItem');

/**
 * Response for listing push tokens
 */
export const ListPushTokensResponseSchema = z
    .object({
        tokens: z.array(PushTokenItemSchema),
    })
    .openapi('ListPushTokensResponse');

/**
 * Error responses
 */
export const PushTokenErrorSchema = z
    .object({
        error: z.string(),
    })
    .openapi('PushTokenError');

export const UnauthorizedErrorSchema = z
    .object({
        error: z.literal('Unauthorized'),
    })
    .openapi('UnauthorizedError');
