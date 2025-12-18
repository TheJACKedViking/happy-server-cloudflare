import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createTestApp, authHeader, TEST_USER_ID, createMockServiceToken } from './__test__/testUtils';
import { connectRoutes } from './connectRoutes';
import type { Fastify } from '../types';

// Mock external dependencies
vi.mock('@/storage/db', () => ({
    db: {
        serviceAccountToken: {
            findUnique: vi.fn(),
            findMany: vi.fn(),
            upsert: vi.fn(),
            delete: vi.fn(),
        },
    },
}));

vi.mock('@/app/auth/auth', () => ({
    auth: {
        createGithubToken: vi.fn().mockResolvedValue('mock-github-state-token'),
        verifyGithubToken: vi.fn(),
    },
}));

vi.mock('@/app/events/eventRouter', () => ({
    eventRouter: {
        emitUpdate: vi.fn(),
    },
}));

vi.mock('@/app/github/githubConnect', () => ({
    githubConnect: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/app/github/githubDisconnect', () => ({
    githubDisconnect: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('@/modules/encrypt', () => ({
    encryptString: vi.fn().mockReturnValue(new Uint8Array([1, 2, 3, 4])),
    decryptString: vi.fn().mockReturnValue('decrypted-token-value'),
}));

vi.mock('@/context', () => ({
    Context: {
        create: vi.fn().mockReturnValue({ userId: TEST_USER_ID }),
    },
}));

vi.mock('@/utils/log', () => ({
    log: vi.fn(),
}));

vi.mock('@/modules/github', () => ({
    getWebhooks: vi.fn(),
}));

import { db } from '@/storage/db';
import { auth } from '@/app/auth/auth';
import { githubDisconnect } from '@/app/github/githubDisconnect';
import { decryptString } from '@/modules/encrypt';
import { getWebhooks } from '@/modules/github';

describe('connectRoutes', () => {
    let app: Fastify;

    beforeEach(async () => {
        app = createTestApp();
        connectRoutes(app);
        await app.ready();
        vi.clearAllMocks();
    });

    afterEach(async () => {
        await app.close();
    });

    describe('GET /v1/connect/github/params', () => {
        it('should return GitHub OAuth URL when properly configured', async () => {
            // Set up environment variables
            const originalClientId = process.env.GITHUB_CLIENT_ID;
            const originalRedirectUrl = process.env.GITHUB_REDIRECT_URL;
            process.env.GITHUB_CLIENT_ID = 'test-client-id';
            process.env.GITHUB_REDIRECT_URL = 'https://app.example.com/callback';

            try {
                const response = await app.inject({
                    method: 'GET',
                    url: '/v1/connect/github/params',
                    headers: authHeader(),
                });

                expect(response.statusCode).toBe(200);
                const body = JSON.parse(response.payload);
                expect(body.url).toBeDefined();
                expect(body.url).toContain('https://github.com/login/oauth/authorize');
                expect(body.url).toContain('client_id=test-client-id');
                expect(body.url).toContain('state=mock-github-state-token');
            } finally {
                process.env.GITHUB_CLIENT_ID = originalClientId;
                process.env.GITHUB_REDIRECT_URL = originalRedirectUrl;
            }
        });

        it('should return 400 when GitHub OAuth is not configured', async () => {
            const originalClientId = process.env.GITHUB_CLIENT_ID;
            const originalRedirectUrl = process.env.GITHUB_REDIRECT_URL;
            delete process.env.GITHUB_CLIENT_ID;
            delete process.env.GITHUB_REDIRECT_URL;

            try {
                const response = await app.inject({
                    method: 'GET',
                    url: '/v1/connect/github/params',
                    headers: authHeader(),
                });

                expect(response.statusCode).toBe(400);
                const body = JSON.parse(response.payload);
                expect(body.error).toBe('GitHub OAuth not configured');
            } finally {
                process.env.GITHUB_CLIENT_ID = originalClientId;
                process.env.GITHUB_REDIRECT_URL = originalRedirectUrl;
            }
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/github/params',
            });

            expect(response.statusCode).toBe(401);
        });
    });

    describe('GET /v1/connect/github/callback', () => {
        it('should redirect to error page when state is invalid', async () => {
            vi.mocked(auth.verifyGithubToken).mockResolvedValue(null);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/github/callback?code=test-code&state=invalid-state',
            });

            expect(response.statusCode).toBe(302);
            expect(response.headers.location).toContain('error=invalid_state');
        });

        it('should redirect to error page when GitHub OAuth is not configured', async () => {
            vi.mocked(auth.verifyGithubToken).mockResolvedValue({ userId: TEST_USER_ID });
            const originalClientId = process.env.GITHUB_CLIENT_ID;
            const originalClientSecret = process.env.GITHUB_CLIENT_SECRET;
            delete process.env.GITHUB_CLIENT_ID;
            delete process.env.GITHUB_CLIENT_SECRET;

            try {
                const response = await app.inject({
                    method: 'GET',
                    url: '/v1/connect/github/callback?code=test-code&state=valid-state',
                });

                expect(response.statusCode).toBe(302);
                expect(response.headers.location).toContain('error=server_config');
            } finally {
                process.env.GITHUB_CLIENT_ID = originalClientId;
                process.env.GITHUB_CLIENT_SECRET = originalClientSecret;
            }
        });

        it('should return 400 when code or state is missing', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/github/callback?code=test-code',
                // Missing state
            });

            expect(response.statusCode).toBe(400);
        });
    });

    describe('POST /v1/connect/github/webhook', () => {
        it('should return 500 when webhooks not configured', async () => {
            vi.mocked(getWebhooks).mockReturnValue(null);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/github/webhook',
                headers: {
                    'x-hub-signature-256': 'sha256=test-signature',
                    'x-github-event': 'push',
                    'x-github-delivery': 'test-delivery-id',
                    'Content-Type': 'application/json',
                },
                payload: { test: 'data' },
            });

            expect(response.statusCode).toBe(500);
            const body = JSON.parse(response.payload);
            expect(body.error).toBe('Webhooks not configured');
        });

        it('should return 200 when signature is valid and webhook is processed', async () => {
            const mockWebhooks = {
                verifyAndReceive: vi.fn().mockResolvedValue(undefined),
            };
            vi.mocked(getWebhooks).mockReturnValue(mockWebhooks as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/github/webhook',
                headers: {
                    'x-hub-signature-256': 'sha256=valid-signature',
                    'x-github-event': 'push',
                    'x-github-delivery': 'delivery-123',
                    'Content-Type': 'application/json',
                },
                payload: { repository: { full_name: 'test/repo' } },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.received).toBe(true);
            expect(mockWebhooks.verifyAndReceive).toHaveBeenCalledWith({
                id: 'delivery-123',
                name: 'push',
                payload: expect.any(String),
                signature: 'sha256=valid-signature',
            });
        });

        it('should return 401 when signature is invalid', async () => {
            const signatureError = new Error('[@octokit/webhooks] signature does not match event payload and secret');
            const mockWebhooks = {
                verifyAndReceive: vi.fn().mockRejectedValue(signatureError),
            };
            vi.mocked(getWebhooks).mockReturnValue(mockWebhooks as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/github/webhook',
                headers: {
                    'x-hub-signature-256': 'sha256=invalid-signature',
                    'x-github-event': 'push',
                    'x-github-delivery': 'delivery-456',
                    'Content-Type': 'application/json',
                },
                payload: { repository: { full_name: 'test/repo' } },
            });

            expect(response.statusCode).toBe(401);
            const body = JSON.parse(response.payload);
            expect(body.error).toBe('Invalid signature');
        });

        it('should return 401 when signature error is in AggregateError format', async () => {
            const innerError = new Error('signature does not match');
            const aggregateError = new AggregateError([innerError], 'Validation failed');
            (aggregateError as any).errors = [innerError];
            const mockWebhooks = {
                verifyAndReceive: vi.fn().mockRejectedValue(aggregateError),
            };
            vi.mocked(getWebhooks).mockReturnValue(mockWebhooks as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/github/webhook',
                headers: {
                    'x-hub-signature-256': 'sha256=bad-signature',
                    'x-github-event': 'installation',
                    'x-github-delivery': 'delivery-789',
                    'Content-Type': 'application/json',
                },
                payload: { action: 'created' },
            });

            expect(response.statusCode).toBe(401);
            const body = JSON.parse(response.payload);
            expect(body.error).toBe('Invalid signature');
        });

        it('should return 500 for non-signature processing errors', async () => {
            const processingError = new Error('Handler threw an error');
            const mockWebhooks = {
                verifyAndReceive: vi.fn().mockRejectedValue(processingError),
            };
            vi.mocked(getWebhooks).mockReturnValue(mockWebhooks as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/github/webhook',
                headers: {
                    'x-hub-signature-256': 'sha256=valid-signature',
                    'x-github-event': 'push',
                    'x-github-delivery': 'delivery-error',
                    'Content-Type': 'application/json',
                },
                payload: { repository: { full_name: 'test/repo' } },
            });

            expect(response.statusCode).toBe(500);
            const body = JSON.parse(response.payload);
            expect(body.error).toBe('Internal server error');
        });

        it('should use delivery-id as unknown when not provided', async () => {
            const mockWebhooks = {
                verifyAndReceive: vi.fn().mockResolvedValue(undefined),
            };
            vi.mocked(getWebhooks).mockReturnValue(mockWebhooks as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/github/webhook',
                headers: {
                    'x-hub-signature-256': 'sha256=valid-signature',
                    'x-github-event': 'ping',
                    'Content-Type': 'application/json',
                },
                payload: { zen: 'Design for failure.' },
            });

            expect(response.statusCode).toBe(200);
            expect(mockWebhooks.verifyAndReceive).toHaveBeenCalledWith(
                expect.objectContaining({
                    id: 'unknown',
                })
            );
        });

        it('should handle installation event type', async () => {
            const mockWebhooks = {
                verifyAndReceive: vi.fn().mockResolvedValue(undefined),
            };
            vi.mocked(getWebhooks).mockReturnValue(mockWebhooks as any);

            const installationPayload = {
                action: 'created',
                installation: {
                    id: 12345,
                    account: { login: 'test-org', type: 'Organization' },
                },
                sender: { login: 'test-user' },
                repositories: [{ full_name: 'test-org/repo1' }],
            };

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/github/webhook',
                headers: {
                    'x-hub-signature-256': 'sha256=valid-signature',
                    'x-github-event': 'installation',
                    'x-github-delivery': 'install-delivery-id',
                    'Content-Type': 'application/json',
                },
                payload: installationPayload,
            });

            expect(response.statusCode).toBe(200);
            expect(mockWebhooks.verifyAndReceive).toHaveBeenCalledWith({
                id: 'install-delivery-id',
                name: 'installation',
                payload: JSON.stringify(installationPayload),
                signature: 'sha256=valid-signature',
            });
        });

        it('should handle installation_repositories event type', async () => {
            const mockWebhooks = {
                verifyAndReceive: vi.fn().mockResolvedValue(undefined),
            };
            vi.mocked(getWebhooks).mockReturnValue(mockWebhooks as any);

            const repoPayload = {
                action: 'added',
                installation: {
                    id: 12345,
                    account: { login: 'test-org' },
                },
                repositories_added: [{ full_name: 'test-org/new-repo' }],
                repositories_removed: [],
                sender: { login: 'test-user' },
            };

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/github/webhook',
                headers: {
                    'x-hub-signature-256': 'sha256=valid-signature',
                    'x-github-event': 'installation_repositories',
                    'x-github-delivery': 'repo-delivery-id',
                    'Content-Type': 'application/json',
                },
                payload: repoPayload,
            });

            expect(response.statusCode).toBe(200);
            expect(mockWebhooks.verifyAndReceive).toHaveBeenCalledWith({
                id: 'repo-delivery-id',
                name: 'installation_repositories',
                payload: JSON.stringify(repoPayload),
                signature: 'sha256=valid-signature',
            });
        });

        it('should return 400 when required headers are missing', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/github/webhook',
                headers: {
                    'Content-Type': 'application/json',
                    // Missing x-hub-signature-256 and x-github-event
                },
                payload: { test: 'data' },
            });

            expect(response.statusCode).toBe(400);
        });
    });

    describe('DELETE /v1/connect/github', () => {
        it('should disconnect GitHub account successfully', async () => {
            vi.mocked(githubDisconnect).mockResolvedValue(undefined);

            const response = await app.inject({
                method: 'DELETE',
                url: '/v1/connect/github',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(true);
        });

        it('should return 500 on disconnect error', async () => {
            vi.mocked(githubDisconnect).mockRejectedValue(new Error('Disconnect failed'));

            const response = await app.inject({
                method: 'DELETE',
                url: '/v1/connect/github',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(500);
            const body = JSON.parse(response.payload);
            expect(body.error).toBe('Failed to disconnect GitHub account');
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'DELETE',
                url: '/v1/connect/github',
            });

            expect(response.statusCode).toBe(401);
        });

        it('should call githubDisconnect with correct context', async () => {
            vi.mocked(githubDisconnect).mockResolvedValue(undefined);

            const response = await app.inject({
                method: 'DELETE',
                url: '/v1/connect/github',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            expect(githubDisconnect).toHaveBeenCalledTimes(1);
            expect(githubDisconnect).toHaveBeenCalledWith(
                expect.objectContaining({ userId: TEST_USER_ID })
            );
        });
    });

    describe('POST /v1/connect/:vendor/register', () => {
        it('should register OpenAI token', async () => {
            vi.mocked(db.serviceAccountToken.upsert).mockResolvedValue({} as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/openai/register',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    token: 'sk-test-openai-token',
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(true);
            expect(vi.mocked(db.serviceAccountToken.upsert)).toHaveBeenCalled();
        });

        it('should register Anthropic token', async () => {
            vi.mocked(db.serviceAccountToken.upsert).mockResolvedValue({} as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/anthropic/register',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    token: 'sk-ant-test-token',
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(true);
        });

        it('should register Gemini token', async () => {
            vi.mocked(db.serviceAccountToken.upsert).mockResolvedValue({} as any);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/gemini/register',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    token: 'gemini-api-key',
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(true);
        });

        it('should return 400 for invalid vendor', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/invalid-vendor/register',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    token: 'test-token',
                },
            });

            expect(response.statusCode).toBe(400);
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/openai/register',
                headers: {
                    'Content-Type': 'application/json',
                },
                payload: {
                    token: 'test-token',
                },
            });

            expect(response.statusCode).toBe(401);
        });

        it('should return validation error when token is missing', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/connect/openai/register',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {},
            });

            expect(response.statusCode).toBe(400);
        });
    });

    describe('GET /v1/connect/:vendor/token', () => {
        it('should return decrypted token for OpenAI', async () => {
            const mockToken = createMockServiceToken({ vendor: 'openai' });
            vi.mocked(db.serviceAccountToken.findUnique).mockResolvedValue(mockToken as any);
            vi.mocked(decryptString).mockReturnValue('decrypted-openai-token');

            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/openai/token',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.token).toBe('decrypted-openai-token');
        });

        it('should return null when token not found', async () => {
            vi.mocked(db.serviceAccountToken.findUnique).mockResolvedValue(null);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/anthropic/token',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.token).toBeNull();
        });

        it('should return 400 for invalid vendor', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/invalid-vendor/token',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(400);
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/openai/token',
            });

            expect(response.statusCode).toBe(401);
        });
    });

    describe('DELETE /v1/connect/:vendor', () => {
        it('should delete OpenAI token', async () => {
            vi.mocked(db.serviceAccountToken.delete).mockResolvedValue({} as any);

            const response = await app.inject({
                method: 'DELETE',
                url: '/v1/connect/openai',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(true);
        });

        it('should delete Anthropic token', async () => {
            vi.mocked(db.serviceAccountToken.delete).mockResolvedValue({} as any);

            const response = await app.inject({
                method: 'DELETE',
                url: '/v1/connect/anthropic',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(true);
        });

        it('should delete Gemini token', async () => {
            vi.mocked(db.serviceAccountToken.delete).mockResolvedValue({} as any);

            const response = await app.inject({
                method: 'DELETE',
                url: '/v1/connect/gemini',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.success).toBe(true);
        });

        it('should return 400 for invalid vendor', async () => {
            const response = await app.inject({
                method: 'DELETE',
                url: '/v1/connect/invalid-vendor',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(400);
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'DELETE',
                url: '/v1/connect/openai',
            });

            expect(response.statusCode).toBe(401);
        });
    });

    describe('GET /v1/connect/tokens', () => {
        it('should return all tokens for user', async () => {
            const mockTokens = [
                createMockServiceToken({ vendor: 'openai' }),
                createMockServiceToken({ vendor: 'anthropic' }),
            ];
            vi.mocked(db.serviceAccountToken.findMany).mockResolvedValue(mockTokens as any);
            vi.mocked(decryptString)
                .mockReturnValueOnce('openai-decrypted')
                .mockReturnValueOnce('anthropic-decrypted');

            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/tokens',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.tokens).toHaveLength(2);
            expect(body.tokens[0].vendor).toBe('openai');
            expect(body.tokens[0].token).toBe('openai-decrypted');
            expect(body.tokens[1].vendor).toBe('anthropic');
            expect(body.tokens[1].token).toBe('anthropic-decrypted');
        });

        it('should return empty array when user has no tokens', async () => {
            vi.mocked(db.serviceAccountToken.findMany).mockResolvedValue([]);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/tokens',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.tokens).toHaveLength(0);
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/connect/tokens',
            });

            expect(response.statusCode).toBe(401);
        });
    });
});
