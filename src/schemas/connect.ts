import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for connect/integration endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for:
 * - GitHub OAuth integration
 * - AI service token management (OpenAI, Anthropic, Gemini)
 *
 * Note: The connect routes in happy-server handle both GitHub OAuth AND device pairing.
 * However, device pairing logic is handled by the auth routes (POST /v1/auth/request, etc.)
 * in happy-server-workers, NOT by connect routes. These schemas only cover GitHub + AI vendors.
 */

// ============================================================================
// GitHub OAuth Integration
// ============================================================================

/**
 * Schema for GitHub OAuth params response
 */
export const GitHubOAuthParamsResponseSchema = z
    .object({
        url: z.string().url().openapi({
            description: 'Complete GitHub OAuth authorization URL',
            example: 'https://github.com/login/oauth/authorize?client_id=...&redirect_uri=...&scope=...&state=...',
        }),
    })
    .openapi('GitHubOAuthParamsResponse');

/**
 * Schema for GitHub OAuth callback query parameters
 */
export const GitHubOAuthCallbackQuerySchema = z.object({
    code: z.string().openapi({
        param: {
            name: 'code',
            in: 'query',
        },
        description: 'OAuth authorization code from GitHub',
        example: 'abc123def456',
    }),
    state: z.string().openapi({
        param: {
            name: 'state',
            in: 'query',
        },
        description: 'State token for CSRF protection',
        example: 'state_token_xyz',
    }),
});

/**
 * Schema for successful GitHub disconnect
 */
export const GitHubDisconnectResponseSchema = z
    .object({
        success: z.literal(true).openapi({
            description: 'Always true for successful disconnect',
            example: true,
        }),
    })
    .openapi('GitHubDisconnectResponse');

/**
 * Schema for GitHub webhook headers
 */
export const GitHubWebhookHeadersSchema = z
    .object({
        'x-hub-signature-256': z.string().openapi({
            description: 'HMAC signature for webhook verification',
            example: 'sha256=abc123...',
        }),
        'x-github-event': z.string().openapi({
            description: 'GitHub event type',
            example: 'push',
        }),
        'x-github-delivery': z.string().optional().openapi({
            description: 'Unique webhook delivery ID',
            example: 'abc123-def456-ghi789',
        }),
    })
    .passthrough();

/**
 * Schema for GitHub webhook response
 */
export const GitHubWebhookResponseSchema = z
    .object({
        received: z.literal(true).openapi({
            description: 'Whether webhook was successfully received and verified',
            example: true,
        }),
        event: z.string().openapi({
            description: 'The GitHub event type that was processed',
            example: 'push',
        }),
        processed: z.boolean().openapi({
            description: 'Whether the event was handled by a specific handler',
            example: true,
        }),
        message: z.string().openapi({
            description: 'Status message about event processing',
            example: 'push acknowledged',
        }),
    })
    .openapi('GitHubWebhookResponse');

// ============================================================================
// AI Service Token Management
// ============================================================================

/**
 * Schema for AI vendor types
 * @internal Used for path parameter validation
 */
const AIVendorSchema = z.enum(['openai', 'anthropic', 'gemini']);

/**
 * Schema for AI vendor path parameter
 */
export const AIVendorParamSchema = z.object({
    vendor: AIVendorSchema.openapi({
        param: {
            name: 'vendor',
            in: 'path',
        },
        description: 'AI service vendor',
        example: 'anthropic',
    }),
});

/**
 * Schema for registering an AI service token
 */
export const RegisterAITokenRequestSchema = z
    .object({
        token: z.string().min(1).openapi({
            description: 'API token for the AI service',
            example: 'sk-ant-api03-...',
        }),
    })
    .openapi('RegisterAITokenRequest');

/**
 * Schema for successful token registration
 */
export const RegisterAITokenResponseSchema = z
    .object({
        success: z.boolean().openapi({
            description: 'Whether the operation succeeded',
            example: true,
        }),
    })
    .openapi('RegisterAITokenResponse');

/**
 * Schema for get AI token response
 */
export const GetAITokenResponseSchema = z
    .object({
        token: z.string().nullable().openapi({
            description: 'Decrypted API token or null if not found',
            example: 'sk-ant-api03-...',
        }),
    })
    .openapi('GetAITokenResponse');

/**
 * Schema for delete AI token response
 */
export const DeleteAITokenResponseSchema = z
    .object({
        success: z.literal(true).openapi({
            description: 'Always true for successful deletion',
            example: true,
        }),
    })
    .openapi('DeleteAITokenResponse');

/**
 * Schema for AI token object
 * @internal Used for composing response schemas
 */
const AITokenSchema = z
    .object({
        vendor: z.string().openapi({
            description: 'AI service vendor',
            example: 'anthropic',
        }),
        token: z.string().openapi({
            description: 'Decrypted API token',
            example: 'sk-ant-api03-...',
        }),
    })
    .openapi('AIToken');

/**
 * Schema for list all AI tokens response
 */
export const ListAITokensResponseSchema = z
    .object({
        tokens: z.array(AITokenSchema).openapi({
            description: 'Array of AI service tokens',
        }),
    })
    .openapi('ListAITokensResponse');

// ============================================================================
// Error Responses
// ============================================================================

/**
 * Schema for 400 Bad Request error
 */
export const BadRequestErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'GitHub OAuth not configured',
        }),
    })
    .openapi('BadRequestError');

/**
 * Schema for 404 Not Found error
 */
export const NotFoundErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'GitHub account not found',
        }),
    })
    .openapi('NotFoundError');

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

