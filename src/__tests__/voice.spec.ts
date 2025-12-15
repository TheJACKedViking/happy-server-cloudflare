/**
 * Integration Tests for Voice Routes
 *
 * Tests all voice endpoints including:
 * - POST /v1/voice/token - Get ElevenLabs conversation token
 *
 * Tests cover:
 * - Authentication requirements
 * - Development mode bypass
 * - Production mode subscription verification
 * - ElevenLabs API integration
 * - All error paths and edge cases
 *
 * @module __tests__/voice.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    createMockDrizzle,
    createMockR2,
    createMockDurableObjectNamespace,
    TEST_USER_ID,
} from './test-utils';

// Store the mock instance for test access
let drizzleMock: ReturnType<typeof createMockDrizzle>;

// Mock cloudflare:workers module
vi.mock('cloudflare:workers', () => ({
    DurableObject: class DurableObject {
        ctx: DurableObjectState;
        env: unknown;
        constructor(ctx: DurableObjectState, env: unknown) {
            this.ctx = ctx;
            this.env = env;
        }
    },
}));

// Mock auth module
vi.mock('@/lib/auth', () => ({
    initAuth: vi.fn().mockResolvedValue(undefined),
    verifyToken: vi.fn().mockImplementation(async (token: string) => {
        if (token === 'valid-token') {
            return { userId: TEST_USER_ID, extras: {} };
        }
        return null;
    }),
    createToken: vi.fn().mockResolvedValue('generated-token-abc123'),
    resetAuth: vi.fn(),
}));

// Mock the getDb function to return our mock Drizzle client
vi.mock('@/db/client', () => ({
    getDb: vi.fn(() => {
        return drizzleMock?.mockDb;
    }),
}));

// Import app AFTER mocks are set up
import app from '@/index';

/**
 * Create mock environment for Hono app.request()
 * This provides the env object as the third parameter to app.request()
 */
function createTestEnv(overrides: {
    ENVIRONMENT?: 'development' | 'staging' | 'production';
    ELEVENLABS_API_KEY?: string;
} = {}) {
    return {
        ENVIRONMENT: overrides.ENVIRONMENT ?? 'development',
        HANDY_MASTER_SECRET: 'test-secret-for-vitest-tests',
        DB: {} as D1Database,
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
        ELEVENLABS_API_KEY: overrides.ELEVENLABS_API_KEY,
    };
}

describe('Voice Routes', () => {
    // Store original fetch
    const originalFetch = globalThis.fetch;

    beforeEach(() => {
        vi.clearAllMocks();
        // Create fresh mock for each test
        drizzleMock = createMockDrizzle();
        // Restore original fetch before each test
        globalThis.fetch = originalFetch;
    });

    afterEach(() => {
        drizzleMock?.clearAll();
        // Restore original fetch
        globalThis.fetch = originalFetch;
    });

    /**
     * Helper to make authenticated requests with proper environment
     */
    async function authRequest(
        path: string,
        options: RequestInit = {},
        env?: ReturnType<typeof createTestEnv>,
        token: string = 'valid-token'
    ): Promise<Response> {
        const headers = new Headers(options.headers);
        headers.set('Authorization', `Bearer ${token}`);
        headers.set('Content-Type', 'application/json');

        return app.request(path, { ...options, headers }, env ?? createTestEnv());
    }

    /**
     * Helper for unauthenticated requests
     */
    async function unauthRequest(
        path: string,
        options: RequestInit = {},
        env?: ReturnType<typeof createTestEnv>
    ): Promise<Response> {
        const headers = new Headers(options.headers);
        headers.set('Content-Type', 'application/json');
        return app.request(path, { ...options, headers }, env ?? createTestEnv());
    }

    describe('POST /v1/voice/token - Get ElevenLabs Token', () => {
        // ============================================================================
        // Authentication Tests
        // ============================================================================

        describe('Authentication', () => {
            it('should require authentication (401 without token)', async () => {
                const res = await unauthRequest('/v1/voice/token', {
                    method: 'POST',
                    body: JSON.stringify({
                        agentId: 'test-agent-id',
                    }),
                });

                expect(res.status).toBe(401);
                const body = await res.json();
                // Auth middleware returns { error: { message, status } }
                expect(body.error).toBeDefined();
                expect(body.error.status).toBe(401);
            });

            it('should reject invalid token (401)', async () => {
                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    createTestEnv(),
                    'invalid-token'
                );

                expect(res.status).toBe(401);
                const body = await res.json();
                // Auth middleware returns { error: { message, status } }
                expect(body.error).toBeDefined();
                expect(body.error.status).toBe(401);
            });
        });

        // ============================================================================
        // Request Validation Tests
        // ============================================================================

        describe('Request Validation', () => {
            it('should require agentId in request body (400)', async () => {
                const res = await authRequest('/v1/voice/token', {
                    method: 'POST',
                    body: JSON.stringify({}),
                });

                expect(res.status).toBe(400);
            });

            it('should reject invalid agentId type (400)', async () => {
                const res = await authRequest('/v1/voice/token', {
                    method: 'POST',
                    body: JSON.stringify({
                        agentId: 12345, // Should be string
                    }),
                });

                expect(res.status).toBe(400);
            });

            it('should accept valid agentId string', async () => {
                // Mock ElevenLabs API success
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: 'xi-test-token-12345' }),
                });

                const env = createTestEnv({ ELEVENLABS_API_KEY: 'test-api-key' });
                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'valid-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
            });

            it('should accept optional revenueCatPublicKey', async () => {
                // Mock ElevenLabs API success
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: 'xi-test-token-12345' }),
                });

                const env = createTestEnv({ ELEVENLABS_API_KEY: 'test-api-key' });
                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            revenueCatPublicKey: 'rc_public_key_12345',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
            });
        });

        // ============================================================================
        // Development Mode Tests
        // ============================================================================

        describe('Development Mode', () => {
            it('should bypass subscription check in development mode', async () => {
                // Mock ElevenLabs API success
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: 'xi-dev-token' }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            // No revenueCatPublicKey - should be OK in dev
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: true,
                    token: 'xi-dev-token',
                    agentId: 'test-agent-id',
                });
            });

            it('should bypass subscription check in staging mode', async () => {
                // Mock ElevenLabs API success
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: 'xi-staging-token' }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'staging',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body.allowed).toBe(true);
                expect(body.token).toBe('xi-staging-token');
            });
        });

        // ============================================================================
        // Production Mode Tests - Subscription Verification
        // ============================================================================

        describe('Production Mode - Subscription Verification', () => {
            it('should require revenueCatPublicKey in production (400)', async () => {
                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            // Missing revenueCatPublicKey
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    error: 'RevenueCat public key required',
                });
            });

            it('should check RevenueCat subscription in production', async () => {
                // Mock RevenueCat API success with active subscription
                const mockFetch = vi.fn()
                    .mockResolvedValueOnce({
                        ok: true,
                        json: async () => ({
                            subscriber: {
                                entitlements: {
                                    active: {
                                        pro: { expires_date: '2030-01-01T00:00:00Z' },
                                    },
                                },
                            },
                        }),
                    })
                    // Mock ElevenLabs API success
                    .mockResolvedValueOnce({
                        ok: true,
                        json: async () => ({ token: 'xi-prod-token' }),
                    });

                globalThis.fetch = mockFetch;

                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            revenueCatPublicKey: 'rc_test_key',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: true,
                    token: 'xi-prod-token',
                    agentId: 'test-agent-id',
                });

                // Verify RevenueCat was called correctly
                expect(mockFetch).toHaveBeenCalledTimes(2);
                expect(mockFetch).toHaveBeenNthCalledWith(
                    1,
                    `https://api.revenuecat.com/v1/subscribers/${TEST_USER_ID}`,
                    {
                        method: 'GET',
                        headers: {
                            Authorization: 'Bearer rc_test_key',
                            'Content-Type': 'application/json',
                        },
                    }
                );
            });

            it('should deny access when RevenueCat API returns error', async () => {
                // Mock RevenueCat API failure
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: false,
                    status: 404,
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            revenueCatPublicKey: 'rc_test_key',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    agentId: 'test-agent-id',
                });
            });

            it('should deny access when user has no active pro entitlement', async () => {
                // Mock RevenueCat API success but no pro entitlement
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        subscriber: {
                            entitlements: {
                                active: {
                                    // No pro entitlement
                                },
                            },
                        },
                    }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            revenueCatPublicKey: 'rc_test_key',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    agentId: 'test-agent-id',
                });
            });

            it('should deny access when subscriber has empty entitlements', async () => {
                // Mock RevenueCat API success but empty active entitlements
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        subscriber: {
                            entitlements: {
                                active: {},
                            },
                        },
                    }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            revenueCatPublicKey: 'rc_test_key',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body.allowed).toBe(false);
            });

            it('should deny access when subscriber data is malformed', async () => {
                // Mock RevenueCat API success but malformed response
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        subscriber: null,
                    }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            revenueCatPublicKey: 'rc_test_key',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body.allowed).toBe(false);
            });

            it('should handle RevenueCat network error gracefully', async () => {
                // Mock network error
                globalThis.fetch = vi.fn().mockRejectedValueOnce(new Error('Network error'));

                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            revenueCatPublicKey: 'rc_test_key',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    agentId: 'test-agent-id',
                });
            });
        });

        // ============================================================================
        // ElevenLabs API Key Tests
        // ============================================================================

        describe('ElevenLabs API Key Configuration', () => {
            it('should return error when ElevenLabs API key is missing (400)', async () => {
                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    // No ELEVENLABS_API_KEY
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    error: 'Missing ElevenLabs API key on the server',
                });
            });

            it('should return error when ElevenLabs API key is empty string', async () => {
                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: '',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    error: 'Missing ElevenLabs API key on the server',
                });
            });
        });

        // ============================================================================
        // ElevenLabs API Integration Tests
        // ============================================================================

        describe('ElevenLabs API Integration', () => {
            it('should successfully fetch token from ElevenLabs', async () => {
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: 'xi-valid-token-abc123' }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'xi-api-key-test',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'agent-xyz-789',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: true,
                    token: 'xi-valid-token-abc123',
                    agentId: 'agent-xyz-789',
                });

                // Verify ElevenLabs API was called correctly
                expect(globalThis.fetch).toHaveBeenCalledWith(
                    'https://api.elevenlabs.io/v1/convai/conversation/token?agent_id=agent-xyz-789',
                    {
                        method: 'GET',
                        headers: {
                            'xi-api-key': 'xi-api-key-test',
                            Accept: 'application/json',
                        },
                    }
                );
            });

            it('should handle ElevenLabs API failure (400)', async () => {
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: false,
                    status: 500,
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    error: 'Failed to get ElevenLabs token',
                });
            });

            it('should handle ElevenLabs returning 401 (unauthorized)', async () => {
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: false,
                    status: 401,
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'invalid-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body.allowed).toBe(false);
                expect(body.error).toBe('Failed to get ElevenLabs token');
            });

            it('should handle ElevenLabs returning empty token (400)', async () => {
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: '' }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    error: 'ElevenLabs returned empty token',
                });
            });

            it('should handle ElevenLabs returning null token (400)', async () => {
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: null }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    error: 'ElevenLabs returned empty token',
                });
            });

            it('should handle ElevenLabs returning undefined token (400)', async () => {
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({}), // No token property
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    error: 'ElevenLabs returned empty token',
                });
            });

            it('should handle ElevenLabs network error (400)', async () => {
                globalThis.fetch = vi.fn().mockRejectedValueOnce(
                    new Error('Connection refused')
                );

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: false,
                    error: 'ElevenLabs API error',
                });
            });

            it('should handle ElevenLabs timeout error (400)', async () => {
                globalThis.fetch = vi.fn().mockRejectedValueOnce(
                    new Error('Request timeout')
                );

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body.allowed).toBe(false);
                expect(body.error).toBe('ElevenLabs API error');
            });

            it('should handle ElevenLabs JSON parse error (400)', async () => {
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => {
                        throw new Error('Invalid JSON');
                    },
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body.allowed).toBe(false);
                expect(body.error).toBe('ElevenLabs API error');
            });
        });

        // ============================================================================
        // Full Flow Tests - Production with Valid Subscription
        // ============================================================================

        describe('Full Production Flow', () => {
            it('should successfully issue token for subscribed user in production', async () => {
                const mockFetch = vi.fn()
                    // First call: RevenueCat subscription check
                    .mockResolvedValueOnce({
                        ok: true,
                        json: async () => ({
                            subscriber: {
                                entitlements: {
                                    active: {
                                        pro: {
                                            expires_date: '2030-12-31T23:59:59Z',
                                            purchase_date: '2024-01-01T00:00:00Z',
                                        },
                                    },
                                },
                            },
                        }),
                    })
                    // Second call: ElevenLabs token
                    .mockResolvedValueOnce({
                        ok: true,
                        json: async () => ({ token: 'xi-production-token-secure' }),
                    });

                globalThis.fetch = mockFetch;

                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'xi-prod-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'production-agent-id',
                            revenueCatPublicKey: 'rc_prod_key',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body).toEqual({
                    allowed: true,
                    token: 'xi-production-token-secure',
                    agentId: 'production-agent-id',
                });

                // Verify both APIs were called
                expect(mockFetch).toHaveBeenCalledTimes(2);
            });

            it('should not call ElevenLabs API if RevenueCat check fails', async () => {
                const mockFetch = vi.fn().mockResolvedValueOnce({
                    ok: false,
                    status: 401,
                });

                globalThis.fetch = mockFetch;

                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'xi-prod-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'production-agent-id',
                            revenueCatPublicKey: 'rc_invalid_key',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body.allowed).toBe(false);

                // ElevenLabs should NOT be called
                expect(mockFetch).toHaveBeenCalledTimes(1);
            });

            it('should not call ElevenLabs API if user has no subscription', async () => {
                const mockFetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        subscriber: {
                            entitlements: {
                                active: {},
                            },
                        },
                    }),
                });

                globalThis.fetch = mockFetch;

                const env = createTestEnv({
                    ENVIRONMENT: 'production',
                    ELEVENLABS_API_KEY: 'xi-prod-api-key',
                });

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'production-agent-id',
                            revenueCatPublicKey: 'rc_valid_key',
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body.allowed).toBe(false);

                // Only RevenueCat should be called
                expect(mockFetch).toHaveBeenCalledTimes(1);
            });
        });

        // ============================================================================
        // Edge Cases
        // ============================================================================

        describe('Edge Cases', () => {
            it('should handle special characters in agentId', async () => {
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: 'xi-special-token' }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const agentIdWithSpecialChars = 'agent_test-123_abc';
                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: agentIdWithSpecialChars,
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body.agentId).toBe(agentIdWithSpecialChars);
            });

            it('should handle very long agentId', async () => {
                globalThis.fetch = vi.fn().mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: 'xi-long-token' }),
                });

                const env = createTestEnv({
                    ENVIRONMENT: 'development',
                    ELEVENLABS_API_KEY: 'test-api-key',
                });

                const longAgentId = 'a'.repeat(256);
                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: longAgentId,
                        }),
                    },
                    env
                );

                expect(res.status).toBe(200);
                const body = await res.json();
                expect(body.agentId).toBe(longAgentId);
            });

            it('should handle undefined ENVIRONMENT (defaults to production behavior)', async () => {
                // When ENVIRONMENT is undefined, isDevelopment will be false
                // So it should require revenueCatPublicKey
                const env = {
                    HANDY_MASTER_SECRET: 'test-secret-for-vitest-tests',
                    DB: {} as D1Database,
                    UPLOADS: createMockR2(),
                    CONNECTION_MANAGER: createMockDurableObjectNamespace(),
                    ELEVENLABS_API_KEY: 'test-api-key',
                    // ENVIRONMENT is undefined
                };

                const res = await authRequest(
                    '/v1/voice/token',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            agentId: 'test-agent-id',
                            // No revenueCatPublicKey
                        }),
                    },
                    env as ReturnType<typeof createTestEnv>
                );

                // Should require revenueCatPublicKey since it's not development/staging
                expect(res.status).toBe(400);
                const body = await res.json();
                expect(body.error).toBe('RevenueCat public key required');
            });
        });
    });
});
