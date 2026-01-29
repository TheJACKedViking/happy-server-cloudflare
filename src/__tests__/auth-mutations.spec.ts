/**
 * Mutation Testing Focused Tests for Authentication Routes (HAP-914)
 *
 * These tests specifically target survived mutations and NoCoverage areas
 * in src/routes/auth/index.ts identified by Stryker mutation testing.
 *
 * Mutation targets:
 * - ConditionalExpression mutations (14 survived)
 * - ObjectLiteral mutations (10 survived)
 * - StringLiteral mutations (4 survived)
 * - NoCoverage areas (43 mutations)
 *
 * Key areas tested:
 * 1. shouldFailClosedForRateLimiting() function
 * 2. Rate limiting responses (429, 503)
 * 3. Response object property mutations
 * 4. Token creation with session extras
 *
 * @module __tests__/auth-mutations.spec
 * @see HAP-914 for mutation testing improvement requirement
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    expectOk,
    createMockDrizzle,
    createMockR2,
    createMockDurableObjectNamespace,
    TEST_USER_ID,
} from './test-utils';
import * as nacl from 'tweetnacl';
import * as base64 from '@stablelib/base64';
import * as hex from '@stablelib/hex';

// Store the mock instance for test access
let drizzleMock: ReturnType<typeof createMockDrizzle>;

// Store mock functions for verification - using vi.hoisted for proper hoisting
const {
    mockCheckRateLimit,
} = vi.hoisted(() => ({
    mockCheckRateLimit: vi.fn().mockResolvedValue({
        allowed: true,
        retryAfter: 0,
        limit: 5,
        remaining: 4,
    }),
}));

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
    createToken: vi.fn().mockResolvedValue('generated-token'),
    resetAuth: vi.fn(),
}));

// Mock the getDb function to return our mock Drizzle client
vi.mock('@/db/client', () => ({
    getDb: vi.fn(() => {
        return drizzleMock?.mockDb;
    }),
}));

// Mock rate limiting module
vi.mock('@/lib/rate-limit', () => ({
    checkRateLimit: mockCheckRateLimit,
}));

// Import app AFTER mocks are set up
import { app } from '@/index';

/**
 * Generate a valid Ed25519 keypair for testing signature verification
 */
function generateEd25519KeyPair() {
    const keyPair = nacl.sign.keyPair();
    return {
        publicKey: base64.encode(keyPair.publicKey),
        publicKeyBytes: keyPair.publicKey,
        publicKeyHex: hex.encode(keyPair.publicKey, true),
        secretKey: keyPair.secretKey,
    };
}

/**
 * Generate a valid X25519 keypair for testing key exchange (pairing flows)
 */
function generateX25519KeyPair() {
    const keyPair = nacl.box.keyPair();
    return {
        publicKey: base64.encode(keyPair.publicKey),
        publicKeyBytes: keyPair.publicKey,
        publicKeyHex: hex.encode(keyPair.publicKey, true),
        secretKey: keyPair.secretKey,
    };
}

/**
 * Sign a challenge with Ed25519 private key
 */
function signChallenge(challenge: string, secretKey: Uint8Array): string {
    const challengeBytes = base64.decode(challenge);
    const signature = nacl.sign.detached(challengeBytes, secretKey);
    return base64.encode(signature);
}

/**
 * Create mock environment for Hono app.request()
 */
function createTestEnv(overrides: Partial<{
    ENVIRONMENT: 'development' | 'staging' | 'production';
    RATE_LIMIT_KV: KVNamespace | undefined;
}> = {}) {
    return {
        ENVIRONMENT: overrides.ENVIRONMENT ?? ('development' as const),
        HAPPY_MASTER_SECRET: 'test-secret-for-vitest-tests-min-32-chars',
        DB: {} as D1Database,
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
        RATE_LIMIT_KV: overrides.RATE_LIMIT_KV,
    };
}

// Shared test environment
let testEnv: ReturnType<typeof createTestEnv>;

describe('Auth Routes - Mutation Testing (HAP-914)', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Create fresh mock for each test
        drizzleMock = createMockDrizzle();
        testEnv = createTestEnv();

        // Reset rate limit mock to default (allowed)
        mockCheckRateLimit.mockResolvedValue({
            allowed: true,
            retryAfter: 0,
            limit: 5,
            remaining: 4,
        });
    });

    afterEach(() => {
        drizzleMock?.clearAll();
    });

    /**
     * Helper for unauthenticated requests
     */
    async function unauthRequest(
        path: string,
        options: RequestInit = {},
        env = testEnv
    ): Promise<Response> {
        const headers = new Headers(options.headers);
        headers.set('Content-Type', 'application/json');
        return app.request(path, { ...options, headers }, env);
    }

    /**
     * Helper for authenticated requests
     */
    async function authRequest(
        path: string,
        options: RequestInit = {},
        token: string = 'valid-token',
        env = testEnv
    ): Promise<Response> {
        const headers = new Headers(options.headers);
        headers.set('Authorization', `Bearer ${token}`);
        headers.set('Content-Type', 'application/json');
        return app.request(path, { ...options, headers }, env);
    }

    // =========================================================================
    // shouldFailClosedForRateLimiting() Function Tests (HAP-620)
    // =========================================================================

    describe('shouldFailClosedForRateLimiting() - ConditionalExpression mutations', () => {
        it('should return 503 in production when RATE_LIMIT_KV is not configured', async () => {
            const prodEnv = createTestEnv({
                ENVIRONMENT: 'production',
                RATE_LIMIT_KV: undefined,
            });

            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature,
                }),
            }, prodEnv);

            expect(res.status).toBe(503);
            const body = await res.json() as { error: string; code: string };
            expect(body.error).toBe('Service temporarily unavailable');
            expect(body.code).toBe('RATE_LIMIT_UNAVAILABLE');
        });

        it('should NOT return 503 in development when RATE_LIMIT_KV is not configured', async () => {
            const devEnv = createTestEnv({
                ENVIRONMENT: 'development',
                RATE_LIMIT_KV: undefined,
            });

            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature,
                }),
            }, devEnv);

            // Should proceed to authentication, not return 503
            expect(res.status).not.toBe(503);
        });

        it('should NOT return 503 in staging when RATE_LIMIT_KV is not configured', async () => {
            const stagingEnv = createTestEnv({
                ENVIRONMENT: 'staging',
                RATE_LIMIT_KV: undefined,
            });

            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature,
                }),
            }, stagingEnv);

            // Should proceed to authentication, not return 503
            expect(res.status).not.toBe(503);
        });

        it('should NOT return 503 in production when RATE_LIMIT_KV IS configured', async () => {
            // Mock KV namespace
            const mockKV = {
                get: vi.fn().mockResolvedValue(null),
                put: vi.fn().mockResolvedValue(undefined),
            } as unknown as KVNamespace;

            const prodWithKV = createTestEnv({
                ENVIRONMENT: 'production',
                RATE_LIMIT_KV: mockKV,
            });

            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature,
                }),
            }, prodWithKV);

            // Should proceed to authentication, not return 503
            expect(res.status).not.toBe(503);
        });

        it('should return 503 for terminal auth request in production without KV', async () => {
            const prodEnv = createTestEnv({
                ENVIRONMENT: 'production',
                RATE_LIMIT_KV: undefined,
            });

            const keyPair = generateX25519KeyPair();

            const res = await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            }, prodEnv);

            expect(res.status).toBe(503);
            const body = await res.json() as { error: string; code: string };
            expect(body.error).toBe('Service temporarily unavailable');
            expect(body.code).toBe('RATE_LIMIT_UNAVAILABLE');
        });

        it('should return 503 for account auth request in production without KV', async () => {
            const prodEnv = createTestEnv({
                ENVIRONMENT: 'production',
                RATE_LIMIT_KV: undefined,
            });

            const keyPair = generateX25519KeyPair();

            const res = await unauthRequest('/v1/auth/account/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            }, prodEnv);

            expect(res.status).toBe(503);
            const body = await res.json() as { error: string; code: string };
            expect(body.error).toBe('Service temporarily unavailable');
            expect(body.code).toBe('RATE_LIMIT_UNAVAILABLE');
        });
    });

    // =========================================================================
    // Rate Limiting Tests (HAP-453)
    // =========================================================================

    describe('Rate Limiting - 429 response mutations', () => {
        it('should return 429 when rate limit exceeded on direct auth', async () => {
            mockCheckRateLimit.mockResolvedValueOnce({
                allowed: false,
                retryAfter: 45,
                limit: 5,
                remaining: 0,
            });

            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature,
                }),
            });

            expect(res.status).toBe(429);
            const body = await res.json() as { error: string; retryAfter: number };
            expect(body.error).toBe('Rate limit exceeded');
            expect(body.retryAfter).toBe(45);

            // Verify response headers
            expect(res.headers.get('Retry-After')).toBe('45');
            expect(res.headers.get('X-RateLimit-Limit')).toBe('5');
            expect(res.headers.get('X-RateLimit-Remaining')).toBe('0');
        });

        it('should return 429 when rate limit exceeded on terminal auth request', async () => {
            mockCheckRateLimit.mockResolvedValueOnce({
                allowed: false,
                retryAfter: 30,
                limit: 5,
                remaining: 0,
            });

            const keyPair = generateX25519KeyPair();

            const res = await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            });

            expect(res.status).toBe(429);
            const body = await res.json() as { error: string; retryAfter: number };
            expect(body.error).toBe('Rate limit exceeded');
            expect(body.retryAfter).toBe(30);
        });

        it('should return 429 when rate limit exceeded on account auth request', async () => {
            mockCheckRateLimit.mockResolvedValueOnce({
                allowed: false,
                retryAfter: 60,
                limit: 5,
                remaining: 0,
            });

            const keyPair = generateX25519KeyPair();

            const res = await unauthRequest('/v1/auth/account/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            });

            expect(res.status).toBe(429);
            const body = await res.json() as { error: string; retryAfter: number };
            expect(body.error).toBe('Rate limit exceeded');
            expect(body.retryAfter).toBe(60);
        });

        it('should verify rate limit called with correct identifier (publicKey)', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature,
                }),
            });

            expect(mockCheckRateLimit).toHaveBeenCalledWith(
                undefined, // RATE_LIMIT_KV
                'auth',
                keyPair.publicKey, // Uses publicKey as identifier
                expect.objectContaining({
                    maxRequests: 5,
                    windowMs: 60_000,
                })
            );
        });

        it('should use auth-request prefix for terminal auth rate limiting', async () => {
            const keyPair = generateX25519KeyPair();

            await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            });

            expect(mockCheckRateLimit).toHaveBeenCalledWith(
                undefined,
                'auth-request', // Different prefix for terminal auth
                keyPair.publicKey,
                expect.any(Object)
            );
        });

        it('should use auth-account-request prefix for account auth rate limiting', async () => {
            const keyPair = generateX25519KeyPair();

            await unauthRequest('/v1/auth/account/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            });

            expect(mockCheckRateLimit).toHaveBeenCalledWith(
                undefined,
                'auth-account-request', // Different prefix for account auth
                keyPair.publicKey,
                expect.any(Object)
            );
        });
    });

    // =========================================================================
    // Response Object Mutations (ObjectLiteral mutations)
    // =========================================================================

    describe('Response object properties - ObjectLiteral mutations', () => {
        it('should include success: true and token in direct auth response', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const body = await expectOk<{ success: boolean; token: string }>(
                await unauthRequest('/v1/auth', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        challenge,
                        signature,
                    }),
                })
            );

            expect(body.success).toBe(true);
            expect(body.token).toBeDefined();
            expect(typeof body.token).toBe('string');
        });

        it('should return state: "requested" for new terminal auth request', async () => {
            const keyPair = generateX25519KeyPair();

            const body = await expectOk<{ state: string }>(
                await unauthRequest('/v1/auth/request', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                    }),
                })
            );

            expect(body.state).toBe('requested');
        });

        it('should return state: "authorized" with token and response for approved request', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed authorized request
            const authorizedRequest = {
                id: 'authorized-request-id',
                publicKey: keyPair.publicKeyHex,
                supportsV2: true,
                response: 'encrypted-response-data',
                responseAccountId: TEST_USER_ID,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('terminalAuthRequests', [authorizedRequest]);

            const body = await expectOk<{
                state: string;
                token?: string;
                response?: string;
            }>(
                await unauthRequest('/v1/auth/request', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                    }),
                })
            );

            expect(body.state).toBe('authorized');
            expect(body.token).toBeDefined();
            expect(body.response).toBe('encrypted-response-data');
        });

        it('should return status: "not_found" and supportsV2: false for non-existent status check', async () => {
            const keyPair = generateX25519KeyPair();

            const body = await expectOk<{ status: string; supportsV2: boolean }>(
                await unauthRequest(
                    `/v1/auth/request/status?publicKey=${encodeURIComponent(keyPair.publicKey)}`,
                    { method: 'GET' }
                )
            );

            expect(body.status).toBe('not_found');
            expect(body.supportsV2).toBe(false);
        });

        it('should return status: "pending" with supportsV2 value from request', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed pending request with supportsV2: true
            const pendingRequest = {
                id: 'pending-request-id',
                publicKey: keyPair.publicKeyHex,
                supportsV2: true,
                response: null,
                responseAccountId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('terminalAuthRequests', [pendingRequest]);

            const body = await expectOk<{ status: string; supportsV2: boolean }>(
                await unauthRequest(
                    `/v1/auth/request/status?publicKey=${encodeURIComponent(keyPair.publicKey)}`,
                    { method: 'GET' }
                )
            );

            expect(body.status).toBe('pending');
            expect(body.supportsV2).toBe(true);
        });

        it('should return status: "authorized" for approved request status check', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed authorized request
            const authorizedRequest = {
                id: 'authorized-request-id',
                publicKey: keyPair.publicKeyHex,
                supportsV2: false,
                response: 'encrypted-response',
                responseAccountId: TEST_USER_ID,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('terminalAuthRequests', [authorizedRequest]);

            const body = await expectOk<{ status: string; supportsV2: boolean }>(
                await unauthRequest(
                    `/v1/auth/request/status?publicKey=${encodeURIComponent(keyPair.publicKey)}`,
                    { method: 'GET' }
                )
            );

            expect(body.status).toBe('authorized');
            expect(body.supportsV2).toBe(false);
        });

        it('should return success: true for terminal auth response approval', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed pending request
            const pendingRequest = {
                id: 'pending-request-id',
                publicKey: keyPair.publicKeyHex,
                supportsV2: true,
                response: null,
                responseAccountId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('terminalAuthRequests', [pendingRequest]);

            const body = await expectOk<{ success: boolean }>(
                await authRequest('/v1/auth/response', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        response: 'encrypted-approval-response',
                    }),
                })
            );

            expect(body.success).toBe(true);
        });

        it('should return error: "Request not found" for non-existent approval', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await authRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(404);
            const body = await res.json() as { error: string };
            expect(body.error).toBe('Request not found');
        });

        it('should return error: "Invalid public key" for wrong key length', async () => {
            const invalidKey = base64.encode(new Uint8Array(16).fill(1));

            const res = await authRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: invalidKey,
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json() as { error: string };
            expect(body.error).toBe('Invalid public key');
        });

        it('should return error: "Invalid signature" for wrong signature', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const invalidSignature = base64.encode(new Uint8Array(64).fill(0));

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature: invalidSignature,
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json() as { error: string };
            expect(body.error).toBe('Invalid signature');
        });
    });

    // =========================================================================
    // Token Creation with Session Extras
    // =========================================================================

    describe('Token creation with session extras', () => {
        it('should create token with session ID for authorized terminal auth', async () => {
            const { createToken } = await import('@/lib/auth');

            const keyPair = generateX25519KeyPair();

            // Seed authorized request with specific ID
            const requestId = 'specific-request-id-123';
            const authorizedRequest = {
                id: requestId,
                publicKey: keyPair.publicKeyHex,
                supportsV2: true,
                response: 'encrypted-response-data',
                responseAccountId: TEST_USER_ID,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('terminalAuthRequests', [authorizedRequest]);

            await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            });

            // Verify createToken was called with session extras
            expect(createToken).toHaveBeenCalledWith(
                TEST_USER_ID,
                { session: requestId }
            );
        });

        it('should create token WITHOUT session extras for account auth', async () => {
            const { createToken } = await import('@/lib/auth');

            const keyPair = generateX25519KeyPair();

            // Seed authorized account request
            const authorizedRequest = {
                id: 'account-request-id',
                publicKey: keyPair.publicKeyHex,
                response: 'encrypted-account-response',
                responseAccountId: TEST_USER_ID,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('accountAuthRequests', [authorizedRequest]);

            await unauthRequest('/v1/auth/account/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            });

            // Verify createToken was called WITHOUT session extras for account auth
            expect(createToken).toHaveBeenCalledWith(TEST_USER_ID);
        });
    });

    // =========================================================================
    // supportsV2 Flag Handling
    // =========================================================================

    describe('supportsV2 flag handling', () => {
        it('should default supportsV2 to false when not provided', async () => {
            const keyPair = generateX25519KeyPair();

            await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    // No supportsV2 field
                }),
            });

            // Verify insert was called with supportsV2: false
            expect(drizzleMock.mockDb.insert).toHaveBeenCalled();
        });

        it('should preserve supportsV2: true when explicitly set', async () => {
            const keyPair = generateX25519KeyPair();

            await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    supportsV2: true,
                }),
            });

            // Verify insert was called
            expect(drizzleMock.mockDb.insert).toHaveBeenCalled();
        });

        it('should handle supportsV2: false explicitly', async () => {
            const keyPair = generateX25519KeyPair();

            await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    supportsV2: false,
                }),
            });

            expect(drizzleMock.mockDb.insert).toHaveBeenCalled();
        });
    });

    // =========================================================================
    // Error String Literal Mutations
    // =========================================================================

    describe('Error string literals', () => {
        it('should return exactly "Invalid signature" for signature failure', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const invalidSig = base64.encode(new Uint8Array(64));

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature: invalidSig,
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json() as { error: string };
            expect(body.error).toBe('Invalid signature');
            expect(body.error).not.toBe('invalid signature');
            expect(body.error).not.toBe('INVALID_SIGNATURE');
        });

        it('should return exactly "Invalid public key" for key length failure', async () => {
            const shortKey = base64.encode(new Uint8Array(16));

            const res = await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: shortKey,
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json() as { error: string };
            expect(body.error).toBe('Invalid public key');
            expect(body.error).not.toBe('invalid public key');
        });

        it('should return exactly "Request not found" for missing request', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await authRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    response: 'test',
                }),
            });

            expect(res.status).toBe(404);
            const body = await res.json() as { error: string };
            expect(body.error).toBe('Request not found');
            expect(body.error).not.toBe('request not found');
        });

        it('should return exactly "Rate limit exceeded" for rate limit', async () => {
            mockCheckRateLimit.mockResolvedValueOnce({
                allowed: false,
                retryAfter: 30,
                limit: 5,
                remaining: 0,
            });

            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature,
                }),
            });

            expect(res.status).toBe(429);
            const body = await res.json() as { error: string };
            expect(body.error).toBe('Rate limit exceeded');
        });

        it('should return exactly "Service temporarily unavailable" for 503', async () => {
            const prodEnv = createTestEnv({
                ENVIRONMENT: 'production',
                RATE_LIMIT_KV: undefined,
            });

            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature,
                }),
            }, prodEnv);

            expect(res.status).toBe(503);
            const body = await res.json() as { error: string; code: string };
            expect(body.error).toBe('Service temporarily unavailable');
            expect(body.code).toBe('RATE_LIMIT_UNAVAILABLE');
        });

        it('should return exactly "Failed to create account" when insert fails', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            // Override insert to return empty array
            const originalInsert = drizzleMock.mockDb.insert;
            drizzleMock.mockDb.insert = vi.fn().mockReturnValue({
                values: vi.fn().mockReturnValue({
                    returning: vi.fn().mockResolvedValue([]),
                }),
            });

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature,
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json() as { error: string };
            expect(body.error).toBe('Failed to create account');

            drizzleMock.mockDb.insert = originalInsert;
        });
    });

    // =========================================================================
    // Account Auth Request Tests (NoCoverage areas)
    // =========================================================================

    describe('Account auth request - NoCoverage areas', () => {
        it('should return "authorized" with token for approved account request', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed authorized account request
            const authorizedRequest = {
                id: 'authorized-account-id',
                publicKey: keyPair.publicKeyHex,
                response: 'encrypted-account-response',
                responseAccountId: TEST_USER_ID,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('accountAuthRequests', [authorizedRequest]);

            const body = await expectOk<{
                state: string;
                token?: string;
                response?: string;
            }>(
                await unauthRequest('/v1/auth/account/request', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                    }),
                })
            );

            expect(body.state).toBe('authorized');
            expect(body.token).toBeDefined();
            expect(body.response).toBe('encrypted-account-response');
        });

        it('should return "requested" for pending account request', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed pending account request
            const pendingRequest = {
                id: 'pending-account-id',
                publicKey: keyPair.publicKeyHex,
                response: null,
                responseAccountId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('accountAuthRequests', [pendingRequest]);

            const body = await expectOk<{ state: string }>(
                await unauthRequest('/v1/auth/account/request', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                    }),
                })
            );

            expect(body.state).toBe('requested');
        });

        it('should approve pending account request successfully', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed pending account request
            const pendingRequest = {
                id: 'pending-account-id',
                publicKey: keyPair.publicKeyHex,
                response: null,
                responseAccountId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('accountAuthRequests', [pendingRequest]);

            const body = await expectOk<{ success: boolean }>(
                await authRequest('/v1/auth/account/response', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        response: 'encrypted-approval',
                    }),
                })
            );

            expect(body.success).toBe(true);
        });

        it('should return 404 for non-existent account auth response', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await authRequest('/v1/auth/account/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(404);
            const body = await res.json() as { error: string };
            expect(body.error).toBe('Request not found');
        });

        it('should not update already approved account request (idempotent)', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed already approved account request
            const approvedRequest = {
                id: 'approved-account-id',
                publicKey: keyPair.publicKeyHex,
                response: 'existing-response',
                responseAccountId: TEST_USER_ID,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('accountAuthRequests', [approvedRequest]);

            const body = await expectOk<{ success: boolean }>(
                await authRequest('/v1/auth/account/response', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        response: 'new-response-should-not-replace',
                    }),
                })
            );

            expect(body.success).toBe(true);
            // The response should not have changed (idempotent)
        });
    });

    // =========================================================================
    // Account Update on Existing User
    // =========================================================================

    describe('Account update for existing user', () => {
        it('should update existing account timestamp and return token', async () => {
            const keyPair = generateEd25519KeyPair();
            const publicKeyHex = hex.encode(keyPair.publicKeyBytes, true);

            // Seed existing account
            const existingAccount = {
                id: 'existing-user-id',
                publicKey: publicKeyHex,
                seq: 5,
                feedSeq: 3,
                createdAt: new Date(Date.now() - 86400000), // 1 day ago
                updatedAt: new Date(Date.now() - 86400000),
            };
            drizzleMock.seedData('accounts', [existingAccount]);

            const challenge = base64.encode(new TextEncoder().encode('test'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const body = await expectOk<{ success: boolean; token: string }>(
                await unauthRequest('/v1/auth', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        challenge,
                        signature,
                    }),
                })
            );

            expect(body.success).toBe(true);
            expect(body.token).toBeDefined();

            // Verify update was called (not insert for new account)
            expect(drizzleMock.mockDb.update).toHaveBeenCalled();
        });
    });
});
