import { z } from '@hono/zod-openapi';

/**
 * Zod schemas for authentication endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for all auth routes.
 * They provide both runtime validation (via Zod) and automatic OpenAPI
 * documentation generation (via .openapi() extensions).
 */

// ============================================================================
// Direct Authentication (POST /v1/auth)
// ============================================================================

/**
 * Schema for direct public key authentication request
 *
 * Used when a client has a keypair and wants to authenticate directly
 * by signing a challenge with their private key.
 */
export const DirectAuthRequestSchema = z
    .object({
        publicKey: z
            .string()
            .min(1)
            .openapi({
                description: 'Base64-encoded Ed25519 public key',
                example: '3q2+7wQbKq9u3rXhOCvH5wPqVZ6ZkA4kZJ6gBRH5mO0=', // 32-byte raw key
            }),
        challenge: z
            .string()
            .min(1)
            .openapi({
                description: 'Base64-encoded challenge message',
                example: 'Y2hhbGxlbmdlLXRleHQtZ29lcy1oZXJl',
            }),
        signature: z
            .string()
            .min(1)
            .openapi({
                description: 'Base64-encoded Ed25519 signature of the challenge',
                example: 'c2lnbmF0dXJlLWdvZXMtaGVyZQ==',
            }),
    })
    .openapi('DirectAuthRequest');

/**
 * Schema for successful authentication response
 */
export const AuthSuccessResponseSchema = z
    .object({
        success: z.boolean().openapi({
            description: 'Always true for successful auth',
            example: true,
        }),
        token: z.string().openapi({
            description: 'JWT authentication token for subsequent API requests',
            example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        }),
    })
    .openapi('AuthSuccessResponse');

// ============================================================================
// Terminal Pairing Flow (POST /v1/auth/request, POST /v1/auth/response)
// ============================================================================

/**
 * Schema for terminal authentication request (CLI pairing flow)
 *
 * Used by happy-cli to initiate pairing. The CLI generates a keypair,
 * shows a QR code with the public key, and polls this endpoint until
 * approved by mobile app.
 */
export const TerminalAuthRequestSchema = z
    .object({
        publicKey: z
            .string()
            .min(1)
            .openapi({
                description: 'Base64-encoded X25519 public key for encryption',
                example: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            }),
        supportsV2: z
            .boolean()
            .nullish()
            .openapi({
                description: 'Whether the CLI supports V2 auth protocol',
                example: true,
            }),
    })
    .openapi('TerminalAuthRequest');

/**
 * Schema for terminal auth request response when pending approval
 * @internal Used in union type
 */
const TerminalAuthRequestedResponseSchema = z
    .object({
        state: z.literal('requested').openapi({
            description: 'Auth request created, waiting for mobile approval',
        }),
    })
    .openapi('TerminalAuthRequestedResponse');

/**
 * Schema for terminal auth request response when already authorized
 * @internal Used in union type
 */
const TerminalAuthAuthorizedResponseSchema = z
    .object({
        state: z.literal('authorized').openapi({
            description: 'Auth request already approved by mobile app',
        }),
        token: z.string().openapi({
            description: 'JWT authentication token',
            example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        }),
        response: z.string().openapi({
            description: 'Base64-encoded encrypted response from mobile app',
            example: 'ZW5jcnlwdGVkLXJlc3BvbnNlLWRhdGE=',
        }),
    })
    .openapi('TerminalAuthAuthorizedResponse');

/**
 * Union type for terminal auth request responses
 */
export const TerminalAuthRequestResponseSchema = z.union([
    TerminalAuthRequestedResponseSchema,
    TerminalAuthAuthorizedResponseSchema,
]);

/**
 * Schema for terminal auth approval request (from mobile app)
 *
 * Sent by happy-app when user approves a CLI pairing request.
 */
export const TerminalAuthResponseSchema = z
    .object({
        publicKey: z
            .string()
            .min(1)
            .openapi({
                description: 'Base64-encoded public key of the terminal being approved',
                example: 'MCowBQYDK2VwAyEA3J66p/1p+3T1X0nTtA9r8qY4x3P9F3d4x2w0u3v5k8Q=',
            }),
        response: z
            .string()
            .min(1)
            .openapi({
                description: 'Base64-encoded encrypted approval response',
                example: 'ZW5jcnlwdGVkLXJlc3BvbnNlLWRhdGE=',
            }),
    })
    .openapi('TerminalAuthResponse');

/**
 * Schema for successful approval response
 */
export const ApprovalSuccessResponseSchema = z
    .object({
        success: z.boolean().openapi({
            description: 'Always true for successful approval',
            example: true,
        }),
    })
    .openapi('ApprovalSuccessResponse');

// ============================================================================
// Terminal Auth Status (GET /v1/auth/request/status)
// ============================================================================

/**
 * Schema for terminal auth status request query parameters
 */
export const TerminalAuthStatusQuerySchema = z.object({
    publicKey: z
        .string()
        .min(1)
        .openapi({
            param: {
                name: 'publicKey',
                in: 'query',
            },
            description: 'Base64-encoded public key to check status for',
            example: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        }),
});

/**
 * Schema for terminal auth status response
 */
export const TerminalAuthStatusResponseSchema = z
    .object({
        status: z.enum(['not_found', 'pending', 'authorized']).openapi({
            description: 'Current status of the auth request',
            example: 'pending',
        }),
        supportsV2: z.boolean().openapi({
            description:
                'Indicates whether this auth request can be completed using the V2 authentication protocol (for example, clients that implement the newer V2 pairing/handshake flow). If true, the client SHOULD use the V2 flow for this request; if false, the client MUST fall back to the legacy/V1 protocol.',
            example: true,
        }),
    })
    .openapi('TerminalAuthStatusResponse');

// ============================================================================
// Account Pairing Flow (POST /v1/auth/account/request, POST /v1/auth/account/response)
// ============================================================================

/**
 * Schema for account authentication request (mobile-to-mobile pairing)
 */
export const AccountAuthRequestSchema = z
    .object({
        publicKey: z
            .string()
            .min(1)
            .openapi({
                description: 'Base64-encoded X25519 public key',
                example: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            }),
    })
    .openapi('AccountAuthRequest');

/**
 * Schema for account auth response (approving another device)
 */
export const AccountAuthResponseSchema = z
    .object({
        publicKey: z
            .string()
            .min(1)
            .openapi({
                description: 'Base64-encoded public key of the account being approved',
                example: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            }),
        response: z
            .string()
            .min(1)
            .openapi({
                description: 'Base64-encoded encrypted approval response',
                example: 'ZW5jcnlwdGVkLXJlc3BvbnNlLWRhdGE=',
            }),
    })
    .openapi('AccountAuthResponse');

// ============================================================================
// Token Refresh (POST /v1/auth/refresh)
// ============================================================================

/**
 * Schema for token refresh response (success)
 *
 * Returns a new token when the current token is valid or within the grace period.
 *
 * @see HAP-451 for token expiration security improvement
 */
export const TokenRefreshResponseSchema = z
    .object({
        success: z.literal(true).openapi({
            description: 'Token refresh succeeded',
            example: true,
        }),
        token: z.string().openapi({
            description: 'New JWT authentication token with fresh expiration',
            example: 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...',
        }),
        expiresIn: z.number().openapi({
            description: 'Token validity in seconds (30 days = 2592000)',
            example: 2592000,
        }),
    })
    .openapi('TokenRefreshResponse');

/**
 * Schema for token refresh failure
 *
 * Returned when the token is expired beyond the grace period or is invalid.
 */
export const TokenRefreshFailedResponseSchema = z
    .object({
        success: z.literal(false).openapi({
            description: 'Token refresh failed',
            example: false,
        }),
        error: z.string().openapi({
            description: 'Error message explaining why refresh failed',
            example: 'Token expired beyond grace period',
        }),
        code: z.enum(['TOKEN_EXPIRED', 'TOKEN_INVALID', 'TOKEN_REVOKED']).openapi({
            description: 'Error code for programmatic handling',
            example: 'TOKEN_EXPIRED',
        }),
    })
    .openapi('TokenRefreshFailedResponse');

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
            example: 'Invalid signature',
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
            example: 'Request not found',
        }),
    })
    .openapi('NotFoundError');
