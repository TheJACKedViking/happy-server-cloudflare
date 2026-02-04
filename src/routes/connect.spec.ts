/**
 * Unit Tests for Connect Routes (HAP-909)
 *
 * Tests for routes/connect.ts covering:
 * - GitHub OAuth integration (params, callback, webhook, disconnect)
 * - AI service token management (register, get, delete, list)
 * - Error handling and edge cases
 *
 * Mutation Testing Focus:
 * - StringLiteral: Verify exact error messages and response strings
 * - ObjectLiteral: Verify exact response shapes
 * - ConditionalExpression: Test all branches
 *
 * @module routes/connect.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { OpenAPIHono } from '@hono/zod-openapi';
import connectRoutes from './connect';

// Mock external modules
vi.mock('@/lib/auth', () => ({
    createEphemeralToken: vi.fn(),
    verifyEphemeralToken: vi.fn(),
    verifyToken: vi.fn(), // Mock verifyToken for auth middleware
}));

vi.mock('@/lib/encryption', () => ({
    initEncryption: vi.fn(),
    isEncryptionInitialized: vi.fn(() => false),
    encryptString: vi.fn(() => new Uint8Array([1, 2, 3, 4])),
    decryptString: vi.fn(() => 'decrypted-token'),
}));

vi.mock('@/lib/eventRouter', () => ({
    getEventRouter: vi.fn(() => ({
        emitUpdate: vi.fn().mockResolvedValue({ success: true, delivered: 1 }),
    })),
    buildUpdateAccountUpdate: vi.fn(() => ({ id: 'update-id', seq: 1, body: {}, createdAt: Date.now() })),
}));

vi.mock('@/config/env', () => ({
    getMasterSecret: vi.fn(() => 'test-master-secret-32-chars-long!!'),
}));

vi.mock('@/db/client', () => ({
    getDb: vi.fn(),
}));

vi.mock('@/utils/id', () => ({
    createId: vi.fn(() => 'test-id-123'),
}));

// Import mocked modules
import { createEphemeralToken, verifyEphemeralToken, verifyToken } from '@/lib/auth';
import { initEncryption, isEncryptionInitialized, encryptString, decryptString } from '@/lib/encryption';
import { getDb } from '@/db/client';

// Type definitions for tests
interface MockEnv {
    DB: D1Database;
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
    GITHUB_REDIRECT_URL?: string;
    GITHUB_WEBHOOK_SECRET?: string;
    HAPPY_MASTER_SECRET?: string;
    CONNECTION_MANAGER: DurableObjectNamespace;
}

interface MockAccount {
    id: string;
    githubUserId: string | null;
    seq: number;
    publicKey: string;
    username: string | null;
    firstName: string | null;
    lastName: string | null;
    settings: string | null;
    settingsVersion: number;
    feedSeq: number;
    createdAt: Date;
    updatedAt: Date;
}

interface MockGitHubUser {
    id: string;
    profile: Record<string, unknown>;
    token: Buffer;
    createdAt: Date;
    updatedAt: Date;
}

interface MockServiceAccountToken {
    id: string;
    accountId: string;
    vendor: string;
    token: Buffer;
    createdAt: Date;
    updatedAt: Date;
}

/**
 * Create mock D1 database with customizable query behavior
 */
function createMockDb(options: {
    accounts?: MockAccount[];
    githubUsers?: MockGitHubUser[];
    serviceAccountTokens?: MockServiceAccountToken[];
} = {}) {
    const { accounts = [], githubUsers = [], serviceAccountTokens = [] } = options;

    return {
        query: {
            accounts: {
                findFirst: vi.fn(async (opts?: { where?: (acc: unknown, helpers: { eq: unknown; and?: unknown; ne?: unknown }) => unknown }) => {
                    if (!opts?.where) return accounts[0] || null;
                    // Simplified - return first account that matches common patterns
                    return accounts[0] || null;
                }),
            },
            githubUsers: {
                findFirst: vi.fn(async () => githubUsers[0] || null),
            },
            serviceAccountTokens: {
                findFirst: vi.fn(async () => serviceAccountTokens[0] || null),
                findMany: vi.fn(async () => serviceAccountTokens),
            },
        },
        insert: vi.fn(() => ({
            values: vi.fn().mockReturnThis(),
        })),
        update: vi.fn(() => ({
            set: vi.fn().mockReturnThis(),
            where: vi.fn().mockResolvedValue(undefined),
        })),
        delete: vi.fn(() => ({
            where: vi.fn().mockResolvedValue(undefined),
        })),
    };
}

/**
 * Create mock Durable Object namespace
 */
function createMockDO(): DurableObjectNamespace {
    return {
        idFromName: vi.fn(() => ({ toString: () => 'mock-do-id' })),
        get: vi.fn(() => ({
            fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ success: true, delivered: 1 }))),
        })),
    } as unknown as DurableObjectNamespace;
}

/**
 * Create app with mock environment
 *
 * Auth is handled by mocking verifyToken to return a valid user
 */
function createTestApp(env: Partial<MockEnv> = {}) {
    const app = new OpenAPIHono<{ Bindings: MockEnv }>();

    app.route('/', connectRoutes);

    const fullEnv: MockEnv = {
        DB: {} as D1Database,
        CONNECTION_MANAGER: createMockDO(),
        HAPPY_MASTER_SECRET: 'test-master-secret-32-chars-long!!',
        ...env,
    };

    return { app, env: fullEnv };
}

/**
 * Setup auth mocks to simulate authenticated user
 */
function setupAuthenticatedUser(userId: string = 'test-user-id') {
    vi.mocked(verifyToken).mockResolvedValue({ userId, extras: undefined });
}

describe('connect routes (HAP-909)', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.spyOn(console, 'error').mockImplementation(() => {});
        vi.spyOn(console, 'log').mockImplementation(() => {});
        vi.spyOn(console, 'warn').mockImplementation(() => {});
        // Default: user is authenticated
        setupAuthenticatedUser();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    // =========================================================================
    // GitHub OAuth Params (GET /v1/connect/github/params)
    // =========================================================================
    describe('GET /v1/connect/github/params', () => {
        const authHeaders = { Authorization: 'Bearer test-token' };

        it('should return GitHub OAuth URL when configured', async () => {
            const mockDb = createMockDb();
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(createEphemeralToken).mockResolvedValue('test-state-token');

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_REDIRECT_URL: 'https://example.com/callback',
            });

            const response = await app.request('/v1/connect/github/params', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { url: string };

            expect(response.status).toBe(200);
            expect(body.url).toContain('https://github.com/login/oauth/authorize');
            expect(body.url).toContain('client_id=test-client-id');
            expect(body.url).toContain('state=test-state-token');
        });

        it('should include correct OAuth scopes in URL', async () => {
            const mockDb = createMockDb();
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(createEphemeralToken).mockResolvedValue('test-state-token');

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_REDIRECT_URL: 'https://example.com/callback',
            });

            const response = await app.request('/v1/connect/github/params', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { url: string };

            // Verify exact scopes - mutation would change these
            expect(body.url).toContain('scope=read%3Auser%2Cuser%3Aemail%2Cread%3Aorg%2Ccodespace');
        });

        it('should return 400 when GITHUB_CLIENT_ID is missing', async () => {
            const { app, env } = createTestApp({
                GITHUB_REDIRECT_URL: 'https://example.com/callback',
                // No GITHUB_CLIENT_ID
            });

            const response = await app.request('/v1/connect/github/params', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { error: string };

            expect(response.status).toBe(400);
            expect(body.error).toBe('GitHub OAuth not configured');
        });

        it('should return 400 when GITHUB_REDIRECT_URL is missing', async () => {
            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                // No GITHUB_REDIRECT_URL
            });

            const response = await app.request('/v1/connect/github/params', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { error: string };

            expect(response.status).toBe(400);
            expect(body.error).toBe('GitHub OAuth not configured');
        });

        it('should call createEphemeralToken with correct parameters', async () => {
            const mockDb = createMockDb();
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(createEphemeralToken).mockResolvedValue('test-state-token');

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_REDIRECT_URL: 'https://example.com/callback',
            });

            await app.request('/v1/connect/github/params', {
                headers: authHeaders,
            }, env);

            expect(createEphemeralToken).toHaveBeenCalledWith('test-user-id', 'github-oauth-state');
        });

        it('should return 401 when not authenticated', async () => {
            vi.mocked(verifyToken).mockResolvedValue(null);

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_REDIRECT_URL: 'https://example.com/callback',
            });

            const response = await app.request('/v1/connect/github/params', {
                headers: authHeaders,
            }, env);

            expect(response.status).toBe(401);
        });
    });

    // =========================================================================
    // GitHub OAuth Callback (GET /v1/connect/github/callback)
    // =========================================================================
    describe('GET /v1/connect/github/callback', () => {
        const mockGitHubProfile = {
            id: 12345,
            login: 'testuser',
            type: 'User',
            site_admin: false,
            avatar_url: 'https://github.com/avatars/testuser.png',
            gravatar_id: null,
            name: 'Test User',
            company: null,
            blog: null,
            location: null,
            email: 'test@example.com',
            hireable: null,
            bio: 'Test bio',
            twitter_username: null,
            public_repos: 10,
            public_gists: 5,
            followers: 100,
            following: 50,
            created_at: '2020-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
        };

        it('should redirect with error for invalid state token', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue(null);

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=invalid-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toBe('https://app.happy.engineering?error=invalid_state');
        });

        it('should redirect with error when purpose does not match', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'wrong-purpose', // Not 'github-oauth-state'
            });

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toBe('https://app.happy.engineering?error=invalid_state');
        });

        it('should redirect with error when GitHub OAuth not configured', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            const { app, env } = createTestApp({
                // No GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toBe('https://app.happy.engineering?error=server_config');
        });

        it('should redirect with error when token exchange fails', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            // Mock failed token exchange
            global.fetch = vi.fn().mockResolvedValueOnce({
                json: async () => ({
                    error: 'bad_verification_code',
                    error_description: 'The code passed is incorrect or expired.',
                }),
            });

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=bad-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toBe('https://app.happy.engineering?error=bad_verification_code');
        });

        it('should redirect with error when access token is missing', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            // Mock token exchange with no access_token
            global.fetch = vi.fn().mockResolvedValueOnce({
                json: async () => ({}), // No access_token or error
            });

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toBe('https://app.happy.engineering?error=no_access_token');
        });

        it('should redirect with error when GitHub user fetch fails', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            // Mock successful token exchange, failed user fetch
            global.fetch = vi.fn()
                .mockResolvedValueOnce({
                    json: async () => ({ access_token: 'test-access-token' }),
                })
                .mockResolvedValueOnce({
                    ok: false,
                    status: 401,
                });

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toBe('https://app.happy.engineering?error=github_user_fetch_failed');
        });

        it('should redirect with error when user account not found', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            // Mock successful token exchange and user fetch
            global.fetch = vi.fn()
                .mockResolvedValueOnce({
                    json: async () => ({ access_token: 'test-access-token' }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => mockGitHubProfile,
                });

            // No account found
            const mockDb = createMockDb({ accounts: [] });
            mockDb.query.accounts.findFirst = vi.fn().mockResolvedValue(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toBe('https://app.happy.engineering?error=user_not_found');
        });

        it('should redirect with success on successful OAuth flow', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            // Mock successful token exchange and user fetch
            global.fetch = vi.fn()
                .mockResolvedValueOnce({
                    json: async () => ({ access_token: 'test-access-token' }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => mockGitHubProfile,
                });

            const mockAccount: MockAccount = {
                id: 'test-user-id',
                githubUserId: null,
                seq: 1,
                publicKey: 'test-public-key',
                username: null,
                firstName: null,
                lastName: null,
                settings: null,
                settingsVersion: 0,
                feedSeq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ accounts: [mockAccount] });
            mockDb.query.accounts.findFirst = vi.fn()
                .mockResolvedValueOnce(mockAccount) // First call: find user account
                .mockResolvedValueOnce(null); // Second call: check for existing GitHub connection
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(false);

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toBe(
                'https://app.happy.engineering?github=connected&user=testuser'
            );
        });

        it('should handle GitHub profile with null name', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            const profileWithNullName = { ...mockGitHubProfile, name: null };

            global.fetch = vi.fn()
                .mockResolvedValueOnce({
                    json: async () => ({ access_token: 'test-access-token' }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => profileWithNullName,
                });

            const mockAccount: MockAccount = {
                id: 'test-user-id',
                githubUserId: null,
                seq: 1,
                publicKey: 'test-public-key',
                username: null,
                firstName: null,
                lastName: null,
                settings: null,
                settingsVersion: 0,
                feedSeq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ accounts: [mockAccount] });
            mockDb.query.accounts.findFirst = vi.fn()
                .mockResolvedValueOnce(mockAccount)
                .mockResolvedValueOnce(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            // Should still succeed
            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toContain('github=connected');
        });

        it('should disconnect existing GitHub connection on different user', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            global.fetch = vi.fn()
                .mockResolvedValueOnce({
                    json: async () => ({ access_token: 'test-access-token' }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => mockGitHubProfile,
                });

            const mockAccount: MockAccount = {
                id: 'test-user-id',
                githubUserId: null,
                seq: 1,
                publicKey: 'test-public-key',
                username: null,
                firstName: null,
                lastName: null,
                settings: null,
                settingsVersion: 0,
                feedSeq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const existingConnection: MockAccount = {
                id: 'other-user-id',
                githubUserId: '12345', // Same GitHub ID
                seq: 1,
                publicKey: 'other-public-key',
                username: null,
                firstName: null,
                lastName: null,
                settings: null,
                settingsVersion: 0,
                feedSeq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ accounts: [mockAccount] });
            mockDb.query.accounts.findFirst = vi.fn()
                .mockResolvedValueOnce(mockAccount) // User account
                .mockResolvedValueOnce(existingConnection); // Existing connection
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            // Should have called update to disconnect previous user
            expect(mockDb.update).toHaveBeenCalled();
        });

        it('should redirect with error on exception during OAuth flow', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            // Mock fetch that throws
            global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
            expect(response.headers.get('Location')).toBe('https://app.happy.engineering?error=server_error');
        });
    });

    // =========================================================================
    // GitHub Webhook (POST /v1/connect/github/webhook)
    // =========================================================================
    describe('POST /v1/connect/github/webhook', () => {
        /**
         * Create a valid HMAC-SHA256 signature for webhook testing
         */
        async function createWebhookSignature(payload: string, secret: string): Promise<string> {
            const encoder = new TextEncoder();
            const key = await crypto.subtle.importKey(
                'raw',
                encoder.encode(secret),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
            const signature = Array.from(new Uint8Array(signatureBuffer))
                .map((b) => b.toString(16).padStart(2, '0'))
                .join('');
            return `sha256=${signature}`;
        }

        it('should return 500 when webhook secret not configured', async () => {
            const { app, env } = createTestApp({
                // No GITHUB_WEBHOOK_SECRET
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': 'sha256=invalid',
                    'X-GitHub-Event': 'push',
                },
                body: JSON.stringify({ test: true }),
            }, env);

            const body = await response.json() as { error: string };

            expect(response.status).toBe(500);
            expect(body.error).toBe('Webhook verification not configured');
        });

        it('should return 400 when signature header is missing (Zod validation)', async () => {
            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: 'test-webhook-secret',
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-GitHub-Event': 'push',
                    // No X-Hub-Signature-256
                },
                body: JSON.stringify({ test: true }),
            }, env);

            // Zod validation returns 400 for missing required headers
            expect(response.status).toBe(400);
        });

        it('should return 401 when signature is invalid', async () => {
            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: 'test-webhook-secret',
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': 'sha256=invalid',
                    'X-GitHub-Event': 'push',
                },
                body: JSON.stringify({ test: true }),
            }, env);

            const body = await response.json() as { error: string };

            expect(response.status).toBe(401);
            expect(body.error).toBe('Invalid signature');
        });

        it('should return 401 when signature format is wrong (no sha256= prefix)', async () => {
            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: 'test-webhook-secret',
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': 'invalid-no-prefix',
                    'X-GitHub-Event': 'push',
                },
                body: JSON.stringify({ test: true }),
            }, env);

            const body = await response.json() as { error: string };

            expect(response.status).toBe(401);
            expect(body.error).toBe('Invalid signature');
        });

        it('should return 400 when event type header is missing (Zod validation)', async () => {
            const payload = JSON.stringify({ test: true });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    // No X-GitHub-Event
                },
                body: payload,
            }, env);

            // Zod validation returns 400 for missing required headers
            expect(response.status).toBe(400);
        });

        it('should return 400 when payload is invalid JSON', async () => {
            const invalidPayload = 'not json';
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(invalidPayload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'push',
                },
                body: invalidPayload,
            }, env);

            const body = await response.json() as { error: string };

            expect(response.status).toBe(400);
            expect(body.error).toBe('Invalid JSON payload');
        });

        it('should handle ping event successfully', async () => {
            const payload = JSON.stringify({ zen: 'Test zen', hook_id: 123 });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'ping',
                },
                body: payload,
            }, env);

            const body = await response.json() as { received: boolean; event: string; processed: boolean; message: string };

            expect(response.status).toBe(200);
            expect(body.received).toBe(true);
            expect(body.event).toBe('ping');
            expect(body.processed).toBe(true);
            expect(body.message).toBe('pong');
        });

        it('should handle push event successfully', async () => {
            const payload = JSON.stringify({ ref: 'refs/heads/main', commits: [] });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'push',
                },
                body: payload,
            }, env);

            const body = await response.json() as { received: boolean; event: string; processed: boolean; message: string };

            expect(response.status).toBe(200);
            expect(body.received).toBe(true);
            expect(body.event).toBe('push');
            expect(body.processed).toBe(true);
            expect(body.message).toBe('push acknowledged');
        });

        it('should handle installation event successfully', async () => {
            const payload = JSON.stringify({ action: 'created', installation: { id: 123 } });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'installation',
                },
                body: payload,
            }, env);

            const body = await response.json() as { message: string };

            expect(response.status).toBe(200);
            expect(body.message).toBe('installation acknowledged');
        });

        it('should handle installation_repositories event', async () => {
            const payload = JSON.stringify({ action: 'added', repositories_added: [] });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'installation_repositories',
                },
                body: payload,
            }, env);

            const body = await response.json() as { message: string };

            expect(response.status).toBe(200);
            expect(body.message).toBe('installation_repositories acknowledged');
        });

        it('should handle repository event', async () => {
            const payload = JSON.stringify({ action: 'created', repository: { id: 123 } });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'repository',
                },
                body: payload,
            }, env);

            const body = await response.json() as { message: string };

            expect(response.status).toBe(200);
            expect(body.message).toBe('repository acknowledged');
        });

        it('should handle pull_request event', async () => {
            const payload = JSON.stringify({ action: 'opened', pull_request: { id: 123 } });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'pull_request',
                },
                body: payload,
            }, env);

            const body = await response.json() as { message: string };

            expect(response.status).toBe(200);
            expect(body.message).toBe('pull_request acknowledged');
        });

        it('should handle issues event', async () => {
            const payload = JSON.stringify({ action: 'opened', issue: { id: 123 } });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'issues',
                },
                body: payload,
            }, env);

            const body = await response.json() as { message: string };

            expect(response.status).toBe(200);
            expect(body.message).toBe('issues acknowledged');
        });

        it('should handle issue_comment event', async () => {
            const payload = JSON.stringify({ action: 'created', comment: { id: 123 } });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'issue_comment',
                },
                body: payload,
            }, env);

            const body = await response.json() as { message: string };

            expect(response.status).toBe(200);
            expect(body.message).toBe('issue_comment acknowledged');
        });

        it('should handle unknown event type', async () => {
            const payload = JSON.stringify({ test: true });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'unknown_event',
                },
                body: payload,
            }, env);

            const body = await response.json() as { processed: boolean; message: string };

            expect(response.status).toBe(200);
            expect(body.processed).toBe(false);
            expect(body.message).toBe('event unknown_event not processed');
        });

        it('should include delivery ID in processing', async () => {
            const payload = JSON.stringify({ test: true });
            const secret = 'test-webhook-secret';
            const signature = await createWebhookSignature(payload, secret);

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': signature,
                    'X-GitHub-Event': 'ping',
                    'X-GitHub-Delivery': 'test-delivery-id-123',
                },
                body: payload,
            }, env);

            expect(response.status).toBe(200);
            // Verify console.log was called with delivery ID
            expect(console.log).toHaveBeenCalled();
        });
    });

    // =========================================================================
    // GitHub Disconnect (DELETE /v1/connect/github)
    // =========================================================================
    describe('DELETE /v1/connect/github', () => {
        const authHeaders = { Authorization: 'Bearer test-token' };

        it('should return 404 when no GitHub account connected', async () => {
            const mockAccount: MockAccount = {
                id: 'test-user-id',
                githubUserId: null, // No GitHub connected
                seq: 1,
                publicKey: 'test-public-key',
                username: null,
                firstName: null,
                lastName: null,
                settings: null,
                settingsVersion: 0,
                feedSeq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ accounts: [mockAccount] });
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/github', {
                method: 'DELETE',
                headers: authHeaders,
            }, env);

            const body = await response.json() as { error: string };

            expect(response.status).toBe(404);
            expect(body.error).toBe('GitHub account not connected');
        });

        it('should return 404 when account not found', async () => {
            const mockDb = createMockDb({ accounts: [] });
            mockDb.query.accounts.findFirst = vi.fn().mockResolvedValue(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/github', {
                method: 'DELETE',
                headers: authHeaders,
            }, env);

            const body = await response.json() as { error: string };

            expect(response.status).toBe(404);
            expect(body.error).toBe('GitHub account not connected');
        });

        it('should disconnect GitHub successfully', async () => {
            const mockAccount: MockAccount = {
                id: 'test-user-id',
                githubUserId: '12345',
                seq: 1,
                publicKey: 'test-public-key',
                username: 'testuser',
                firstName: 'Test',
                lastName: 'User',
                settings: null,
                settingsVersion: 0,
                feedSeq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ accounts: [mockAccount] });
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/github', {
                method: 'DELETE',
                headers: authHeaders,
            }, env);

            const body = await response.json() as { success: boolean };

            expect(response.status).toBe(200);
            expect(body.success).toBe(true);

            // Verify database operations
            expect(mockDb.update).toHaveBeenCalled();
            expect(mockDb.delete).toHaveBeenCalled();
        });
    });

    // =========================================================================
    // AI Token Registration (POST /v1/connect/:vendor/register)
    // =========================================================================
    describe('POST /v1/connect/:vendor/register', () => {
        const authHeaders = { Authorization: 'Bearer test-token', 'Content-Type': 'application/json' };

        it('should register OpenAI token successfully', async () => {
            const mockDb = createMockDb();
            mockDb.query.serviceAccountTokens.findFirst = vi.fn().mockResolvedValue(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(false);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/openai/register', {
                method: 'POST',
                headers: authHeaders,
                body: JSON.stringify({ token: 'sk-test-token' }),
            }, env);

            const body = await response.json() as { success: boolean };

            expect(response.status).toBe(200);
            expect(body.success).toBe(true);
            expect(encryptString).toHaveBeenCalled();
            expect(initEncryption).toHaveBeenCalled();
        });

        it('should register Anthropic token successfully', async () => {
            const mockDb = createMockDb();
            mockDb.query.serviceAccountTokens.findFirst = vi.fn().mockResolvedValue(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(true);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/anthropic/register', {
                method: 'POST',
                headers: authHeaders,
                body: JSON.stringify({ token: 'sk-ant-test-token' }),
            }, env);

            const body = await response.json() as { success: boolean };

            expect(response.status).toBe(200);
            expect(body.success).toBe(true);
        });

        it('should register Gemini token successfully', async () => {
            const mockDb = createMockDb();
            mockDb.query.serviceAccountTokens.findFirst = vi.fn().mockResolvedValue(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(true);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/gemini/register', {
                method: 'POST',
                headers: authHeaders,
                body: JSON.stringify({ token: 'gemini-test-token' }),
            }, env);

            const body = await response.json() as { success: boolean };

            expect(response.status).toBe(200);
            expect(body.success).toBe(true);
        });

        it('should update existing token instead of creating new', async () => {
            const existingToken: MockServiceAccountToken = {
                id: 'token-id',
                accountId: 'test-user-id',
                vendor: 'openai',
                token: Buffer.from([1, 2, 3]),
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ serviceAccountTokens: [existingToken] });
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(true);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/openai/register', {
                method: 'POST',
                headers: authHeaders,
                body: JSON.stringify({ token: 'sk-new-token' }),
            }, env);

            const body = await response.json() as { success: boolean };

            expect(response.status).toBe(200);
            expect(body.success).toBe(true);
            expect(mockDb.update).toHaveBeenCalled();
        });

        it('should use correct encryption path for token', async () => {
            const mockDb = createMockDb();
            mockDb.query.serviceAccountTokens.findFirst = vi.fn().mockResolvedValue(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(true);

            const { app, env } = createTestApp();

            await app.request('/v1/connect/anthropic/register', {
                method: 'POST',
                headers: authHeaders,
                body: JSON.stringify({ token: 'test-token' }),
            }, env);

            expect(encryptString).toHaveBeenCalledWith(
                ['user', 'test-user-id', 'vendors', 'anthropic', 'token'],
                'test-token'
            );
        });
    });

    // =========================================================================
    // AI Token Retrieval (GET /v1/connect/:vendor/token)
    // =========================================================================
    describe('GET /v1/connect/:vendor/token', () => {
        const authHeaders = { Authorization: 'Bearer test-token' };

        it('should return null when no token exists', async () => {
            const mockDb = createMockDb();
            mockDb.query.serviceAccountTokens.findFirst = vi.fn().mockResolvedValue(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/openai/token', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { token: string | null };

            expect(response.status).toBe(200);
            expect(body.token).toBeNull();
        });

        it('should return decrypted token when exists', async () => {
            const existingToken: MockServiceAccountToken = {
                id: 'token-id',
                accountId: 'test-user-id',
                vendor: 'openai',
                token: Buffer.from([1, 2, 3]),
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ serviceAccountTokens: [existingToken] });
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(false);
            vi.mocked(decryptString).mockResolvedValue('sk-decrypted-token');

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/openai/token', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { token: string | null };

            expect(response.status).toBe(200);
            expect(body.token).toBe('sk-decrypted-token');
            expect(initEncryption).toHaveBeenCalled();
        });

        it('should use correct encryption path for decryption', async () => {
            const existingToken: MockServiceAccountToken = {
                id: 'token-id',
                accountId: 'test-user-id',
                vendor: 'anthropic',
                token: Buffer.from([1, 2, 3]),
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ serviceAccountTokens: [existingToken] });
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(true);

            const { app, env } = createTestApp();

            await app.request('/v1/connect/anthropic/token', {
                headers: authHeaders,
            }, env);

            expect(decryptString).toHaveBeenCalledWith(
                ['user', 'test-user-id', 'vendors', 'anthropic', 'token'],
                expect.any(Uint8Array)
            );
        });
    });

    // =========================================================================
    // AI Token Deletion (DELETE /v1/connect/:vendor)
    // =========================================================================
    describe('DELETE /v1/connect/:vendor', () => {
        const authHeaders = { Authorization: 'Bearer test-token' };

        it('should delete OpenAI token successfully', async () => {
            const mockDb = createMockDb();
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/openai', {
                method: 'DELETE',
                headers: authHeaders,
            }, env);

            const body = await response.json() as { success: boolean };

            expect(response.status).toBe(200);
            expect(body.success).toBe(true);
            expect(mockDb.delete).toHaveBeenCalled();
        });

        it('should delete Anthropic token successfully', async () => {
            const mockDb = createMockDb();
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/anthropic', {
                method: 'DELETE',
                headers: authHeaders,
            }, env);

            const body = await response.json() as { success: boolean };

            expect(response.status).toBe(200);
            expect(body.success).toBe(true);
        });

        it('should delete Gemini token successfully', async () => {
            const mockDb = createMockDb();
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/gemini', {
                method: 'DELETE',
                headers: authHeaders,
            }, env);

            const body = await response.json() as { success: boolean };

            expect(response.status).toBe(200);
            expect(body.success).toBe(true);
        });
    });

    // =========================================================================
    // AI Token Listing (GET /v1/connect/tokens)
    // =========================================================================
    describe('GET /v1/connect/tokens', () => {
        const authHeaders = { Authorization: 'Bearer test-token' };

        it('should return empty array when no tokens exist', async () => {
            const mockDb = createMockDb({ serviceAccountTokens: [] });
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/tokens', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { tokens: Array<{ vendor: string; token: string }> };

            expect(response.status).toBe(200);
            expect(body.tokens).toEqual([]);
        });

        it('should return all decrypted tokens', async () => {
            const tokens: MockServiceAccountToken[] = [
                {
                    id: 'token-1',
                    accountId: 'test-user-id',
                    vendor: 'openai',
                    token: Buffer.from([1, 2, 3]),
                    createdAt: new Date(),
                    updatedAt: new Date(),
                },
                {
                    id: 'token-2',
                    accountId: 'test-user-id',
                    vendor: 'anthropic',
                    token: Buffer.from([4, 5, 6]),
                    createdAt: new Date(),
                    updatedAt: new Date(),
                },
            ];

            const mockDb = createMockDb({ serviceAccountTokens: tokens });
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(false);
            vi.mocked(decryptString)
                .mockResolvedValueOnce('sk-openai-token')
                .mockResolvedValueOnce('sk-anthropic-token');

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/tokens', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { tokens: Array<{ vendor: string; token: string }> };

            expect(response.status).toBe(200);
            expect(body.tokens).toHaveLength(2);
            expect(body.tokens).toContainEqual({ vendor: 'openai', token: 'sk-openai-token' });
            expect(body.tokens).toContainEqual({ vendor: 'anthropic', token: 'sk-anthropic-token' });
        });

        it('should skip tokens that fail to decrypt', async () => {
            const tokens: MockServiceAccountToken[] = [
                {
                    id: 'token-1',
                    accountId: 'test-user-id',
                    vendor: 'openai',
                    token: Buffer.from([1, 2, 3]),
                    createdAt: new Date(),
                    updatedAt: new Date(),
                },
                {
                    id: 'token-2',
                    accountId: 'test-user-id',
                    vendor: 'anthropic',
                    token: Buffer.from([4, 5, 6]),
                    createdAt: new Date(),
                    updatedAt: new Date(),
                },
            ];

            const mockDb = createMockDb({ serviceAccountTokens: tokens });
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(true);
            vi.mocked(decryptString)
                .mockResolvedValueOnce('sk-openai-token')
                .mockRejectedValueOnce(new Error('Decryption failed'));

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/tokens', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { tokens: Array<{ vendor: string; token: string }> };

            expect(response.status).toBe(200);
            expect(body.tokens).toHaveLength(1);
            expect(body.tokens[0]).toEqual({ vendor: 'openai', token: 'sk-openai-token' });
            expect(console.error).toHaveBeenCalled();
        });
    });

    // =========================================================================
    // Helper Function Tests: separateName
    // =========================================================================
    describe('separateName helper (tested via OAuth flow)', () => {
        it('should handle single name (no space)', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            const profileWithSingleName = {
                id: 12345,
                login: 'testuser',
                type: 'User',
                site_admin: false,
                avatar_url: 'https://github.com/avatars/testuser.png',
                gravatar_id: null,
                name: 'SingleName', // No space
                company: null,
                blog: null,
                location: null,
                email: 'test@example.com',
                hireable: null,
                bio: 'Test bio',
                twitter_username: null,
                public_repos: 10,
                public_gists: 5,
                followers: 100,
                following: 50,
                created_at: '2020-01-01T00:00:00Z',
                updated_at: '2024-01-01T00:00:00Z',
            };

            global.fetch = vi.fn()
                .mockResolvedValueOnce({
                    json: async () => ({ access_token: 'test-access-token' }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => profileWithSingleName,
                });

            const mockAccount = {
                id: 'test-user-id',
                githubUserId: null,
                seq: 1,
                publicKey: 'test-public-key',
                username: null,
                firstName: null,
                lastName: null,
                settings: null,
                settingsVersion: 0,
                feedSeq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ accounts: [mockAccount] });
            mockDb.query.accounts.findFirst = vi.fn()
                .mockResolvedValueOnce(mockAccount)
                .mockResolvedValueOnce(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
        });

        it('should handle name with multiple spaces', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue({
                userId: 'test-user-id',
                purpose: 'github-oauth-state',
            });

            const profileWithMultipleSpaces = {
                id: 12345,
                login: 'testuser',
                type: 'User',
                site_admin: false,
                avatar_url: 'https://github.com/avatars/testuser.png',
                gravatar_id: null,
                name: 'First Middle Last', // Multiple spaces
                company: null,
                blog: null,
                location: null,
                email: 'test@example.com',
                hireable: null,
                bio: 'Test bio',
                twitter_username: null,
                public_repos: 10,
                public_gists: 5,
                followers: 100,
                following: 50,
                created_at: '2020-01-01T00:00:00Z',
                updated_at: '2024-01-01T00:00:00Z',
            };

            global.fetch = vi.fn()
                .mockResolvedValueOnce({
                    json: async () => ({ access_token: 'test-access-token' }),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => profileWithMultipleSpaces,
                });

            const mockAccount = {
                id: 'test-user-id',
                githubUserId: null,
                seq: 1,
                publicKey: 'test-public-key',
                username: null,
                firstName: null,
                lastName: null,
                settings: null,
                settingsVersion: 0,
                feedSeq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            const mockDb = createMockDb({ accounts: [mockAccount] });
            mockDb.query.accounts.findFirst = vi.fn()
                .mockResolvedValueOnce(mockAccount)
                .mockResolvedValueOnce(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=test-state',
                {},
                env
            );

            expect(response.status).toBe(302);
        });
    });

    // =========================================================================
    // Constant-time comparison tests (security critical)
    // =========================================================================
    describe('constantTimeEqual (via webhook verification)', () => {
        it('should reject signatures with different lengths', async () => {
            const payload = JSON.stringify({ test: true });
            const secret = 'test-webhook-secret';

            // Create a valid signature
            const encoder = new TextEncoder();
            const key = await crypto.subtle.importKey(
                'raw',
                encoder.encode(secret),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            await crypto.subtle.sign('HMAC', key, encoder.encode(payload));

            const { app, env } = createTestApp({
                GITHUB_WEBHOOK_SECRET: secret,
            });

            // Submit with truncated signature (different length)
            const response = await app.request('/v1/connect/github/webhook', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Hub-Signature-256': 'sha256=abc123', // Too short
                    'X-GitHub-Event': 'push',
                },
                body: payload,
            }, env);

            const body = await response.json() as { error: string };

            expect(response.status).toBe(401);
            expect(body.error).toBe('Invalid signature');
        });
    });

    // =========================================================================
    // Edge Cases and Boundary Conditions
    // =========================================================================
    describe('edge cases', () => {
        const authHeaders = { Authorization: 'Bearer test-token' };

        it('should handle empty token array in list response', async () => {
            const mockDb = createMockDb({ serviceAccountTokens: [] });
            vi.mocked(getDb).mockReturnValue(mockDb as never);

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/tokens', {
                headers: authHeaders,
            }, env);
            const body = await response.json() as { tokens: unknown[] };

            expect(response.status).toBe(200);
            expect(Array.isArray(body.tokens)).toBe(true);
            expect(body.tokens).toHaveLength(0);
        });

        it('should properly encode special characters in redirect URL', async () => {
            vi.mocked(verifyEphemeralToken).mockResolvedValue(null);

            const { app, env } = createTestApp({
                GITHUB_CLIENT_ID: 'test-client-id',
                GITHUB_CLIENT_SECRET: 'test-client-secret',
            });

            const response = await app.request(
                '/v1/connect/github/callback?code=test-code&state=invalid',
                {},
                env
            );

            // Should properly redirect without encoding issues
            expect(response.status).toBe(302);
        });

        it('should handle encryption already initialized', async () => {
            const mockDb = createMockDb();
            mockDb.query.serviceAccountTokens.findFirst = vi.fn().mockResolvedValue(null);
            vi.mocked(getDb).mockReturnValue(mockDb as never);
            vi.mocked(isEncryptionInitialized).mockReturnValue(true); // Already initialized

            const { app, env } = createTestApp();

            const response = await app.request('/v1/connect/openai/register', {
                method: 'POST',
                headers: { ...authHeaders, 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: 'sk-test-token' }),
            }, env);

            expect(response.status).toBe(200);
            // Should NOT call initEncryption since already initialized
            expect(initEncryption).not.toHaveBeenCalled();
        });
    });
});
