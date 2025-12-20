import { z } from '@hono/zod-openapi';
import { GitHubProfileSchema as CanonicalGitHubProfileSchema } from '@happy/protocol';

/**
 * Zod schemas for account management endpoints with OpenAPI metadata
 *
 * These schemas define the request/response contracts for account routes:
 * - GET /v1/account - Get user profile
 * - PUT /v1/account - Update user profile
 * - GET /v1/account/preferences - Get account settings/preferences
 * - PUT /v1/account/preferences - Update account settings/preferences
 */

// ============================================================================
// Common Schemas
// ============================================================================

/**
 * Schema for connected service vendor names
 */
export const ServiceVendorSchema = z
    .enum(['openai', 'anthropic', 'gemini'])
    .openapi('ServiceVendor');

/**
 * Schema for GitHub profile data with OpenAPI metadata
 *
 * Uses the canonical GitHubProfileSchema from @happy/protocol and wraps it
 * with OpenAPI metadata for API documentation.
 *
 * Note: We cast to add openapi() method since @hono/zod-openapi extends Zod
 */
export const GithubProfileSchema = (CanonicalGitHubProfileSchema as z.ZodTypeAny)
    .openapi('GithubProfile');

/**
 * Schema for user account profile returned in API responses
 */
export const AccountProfileSchema = z
    .object({
        id: z.string().openapi({
            description: 'Unique account identifier',
            example: 'cmed556s4002bvb2020igg8jf',
        }),
        timestamp: z.number().int().openapi({
            description: 'Response timestamp (Unix milliseconds)',
            example: 1705010400000,
        }),
        firstName: z.string().nullable().openapi({
            description: 'User first name',
            example: 'John',
        }),
        lastName: z.string().nullable().openapi({
            description: 'User last name',
            example: 'Doe',
        }),
        username: z.string().nullable().openapi({
            description: 'Unique username for discovery',
            example: 'johndoe',
        }),
        github: GithubProfileSchema.nullable().openapi({
            description: 'Connected GitHub profile data or null',
        }),
        connectedServices: z.array(z.string()).openapi({
            description: 'List of connected AI service vendors',
            example: ['openai', 'anthropic'],
        }),
    })
    .openapi('AccountProfile');

// ============================================================================
// GET /v1/account - Get Account Profile
// ============================================================================

/**
 * Schema for get account profile response
 */
export const GetAccountResponseSchema = AccountProfileSchema.openapi('GetAccountResponse');

// ============================================================================
// PUT /v1/account - Update Account Profile
// ============================================================================

/**
 * Schema for updating account profile
 */
export const UpdateAccountRequestSchema = z
    .object({
        firstName: z.string().min(1).max(100).optional().openapi({
            description: 'User first name (1-100 characters)',
            example: 'John',
        }),
        lastName: z.string().max(100).nullable().optional().openapi({
            description: 'User last name (up to 100 characters)',
            example: 'Doe',
        }),
        username: z.string().min(3).max(50).regex(/^[a-zA-Z0-9_-]+$/).optional().openapi({
            description: 'Unique username (3-50 alphanumeric characters, underscores, hyphens)',
            example: 'johndoe',
        }),
    })
    .openapi('UpdateAccountRequest');

/**
 * Schema for update account success response
 */
export const UpdateAccountSuccessSchema = z
    .object({
        success: z.literal(true).openapi({
            description: 'Always true for successful update',
            example: true,
        }),
        profile: AccountProfileSchema.openapi({
            description: 'Updated account profile',
        }),
    })
    .openapi('UpdateAccountSuccess');

/**
 * Schema for username conflict error
 */
export const UsernameConflictErrorSchema = z
    .object({
        success: z.literal(false).openapi({
            description: 'Always false for conflicts',
            example: false,
        }),
        error: z.literal('username-taken').openapi({
            description: 'Error code for username conflict',
            example: 'username-taken',
        }),
    })
    .openapi('UsernameConflictError');

// ============================================================================
// GET /v1/account/preferences - Get Account Preferences (Settings)
// ============================================================================

/**
 * Schema for get preferences response
 */
export const GetPreferencesResponseSchema = z
    .object({
        settings: z.string().nullable().openapi({
            description: 'Encrypted settings string (JSON)',
            example: '{"theme":"dark","notifications":true}',
        }),
        settingsVersion: z.number().int().openapi({
            description: 'Settings version for optimistic concurrency control',
            example: 5,
        }),
    })
    .openapi('GetPreferencesResponse');

// ============================================================================
// PUT /v1/account/preferences - Update Account Preferences (Settings)
// ============================================================================

/**
 * Schema for updating preferences
 */
export const UpdatePreferencesRequestSchema = z
    .object({
        settings: z.string().nullable().openapi({
            description: 'Encrypted settings string (JSON) or null to clear',
            example: '{"theme":"dark","notifications":true}',
        }),
        expectedVersion: z.number().int().min(0).openapi({
            description: 'Expected current version for optimistic concurrency',
            example: 5,
        }),
    })
    .openapi('UpdatePreferencesRequest');

/**
 * Schema for successful preferences update
 */
export const UpdatePreferencesSuccessSchema = z
    .object({
        success: z.literal(true).openapi({
            description: 'Always true for successful update',
            example: true,
        }),
        version: z.number().int().openapi({
            description: 'New settings version after update',
            example: 6,
        }),
    })
    .openapi('UpdatePreferencesSuccess');

/**
 * Schema for version mismatch error (optimistic concurrency failure)
 */
export const VersionMismatchErrorSchema = z
    .object({
        success: z.literal(false).openapi({
            description: 'Always false for version mismatch',
            example: false,
        }),
        error: z.literal('version-mismatch').openapi({
            description: 'Error code for version conflict',
            example: 'version-mismatch',
        }),
        currentVersion: z.number().int().openapi({
            description: 'Current settings version in database',
            example: 6,
        }),
        currentSettings: z.string().nullable().openapi({
            description: 'Current settings value',
            example: '{"theme":"light"}',
        }),
    })
    .openapi('VersionMismatchError');

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
            example: 'Account not found',
        }),
    })
    .openapi('NotFoundError');

/**
 * Schema for 500 Internal Server Error
 */
export const InternalErrorSchema = z
    .object({
        error: z.string().openapi({
            description: 'Error message',
            example: 'Failed to update account',
        }),
    })
    .openapi('InternalError');
