/**
 * Integration Tests for Auth Routes with Drizzle ORM Mocking
 *
 * This test file exercises the authentication endpoints in src/routes/auth/index.ts
 * using the mock Drizzle client for database operations.
 *
 * Routes tested:
 * - POST /v1/auth - Direct public key authentication
 * - POST /v1/auth/request - Terminal pairing flow (CLI)
 * - GET /v1/auth/request/status - Check terminal auth status
 * - POST /v1/auth/response - Approve terminal pairing (Mobile)
 * - POST /v1/auth/account/request - Account pairing flow (Mobile)
 * - POST /v1/auth/account/response - Approve account pairing
 *
 * @module __tests__/auth-drizzle.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    expectOk,
    createMockDrizzle,
    createMockR2,
    createMockDurableObjectNamespace,
    TEST_USER_ID,
    TEST_USER_ID_2,
} from './test-utils';
import * as nacl from 'tweetnacl';
import * as base64 from '@stablelib/base64';
import * as hex from '@stablelib/hex';

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
        if (token === 'user2-token') {
            return { userId: TEST_USER_ID_2, extras: {} };
        }
        return null;
    }),
    createToken: vi.fn().mockResolvedValue('generated-token'),
    resetAuth: vi.fn(),
}));

// Mock the getDb function to return our mock Drizzle client
vi.mock('@/db/client', () => ({
    getDb: vi.fn(() => {
        // Return the mock database client
        return drizzleMock?.mockDb;
    }),
}));

// Import app AFTER mocks are set up
import app from '@/index';

/**
 * Generate a valid Ed25519 keypair for testing signature verification
 */
function generateEd25519KeyPair() {
    const keyPair = nacl.sign.keyPair();
    return {
        publicKey: base64.encode(keyPair.publicKey),
        publicKeyBytes: keyPair.publicKey,
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
function createTestEnv() {
    return {
        ENVIRONMENT: 'development' as const,
        HANDY_MASTER_SECRET: 'test-secret-for-vitest-tests',
        DB: {} as D1Database,
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
    };
}

// Shared test environment
let testEnv: ReturnType<typeof createTestEnv>;

describe('Auth Routes with Drizzle Mocking', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Create fresh mock for each test
        drizzleMock = createMockDrizzle();
        testEnv = createTestEnv();
    });

    afterEach(() => {
        drizzleMock?.clearAll();
    });

    /**
     * Helper to make authenticated requests with proper environment
     */
    async function authRequest(
        path: string,
        options: RequestInit = {},
        token: string = 'valid-token'
    ): Promise<Response> {
        const headers = new Headers(options.headers);
        headers.set('Authorization', `Bearer ${token}`);
        headers.set('Content-Type', 'application/json');

        return app.request(path, { ...options, headers }, testEnv);
    }

    /**
     * Helper for unauthenticated requests
     */
    async function unauthRequest(path: string, options: RequestInit = {}): Promise<Response> {
        const headers = new Headers(options.headers);
        headers.set('Content-Type', 'application/json');
        return app.request(path, { ...options, headers }, testEnv);
    }

    // =========================================================================
    // POST /v1/auth - Direct Public Key Authentication
    // =========================================================================

    describe('POST /v1/auth - Direct Public Key Authentication', () => {
        it('should authenticate with valid Ed25519 signature and create new account', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test-challenge'));
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
            expect(body.token).toBe('generated-token');
        });

        it('should authenticate with valid signature and return token for existing account', async () => {
            const keyPair = generateEd25519KeyPair();
            const publicKeyHex = hex.encode(keyPair.publicKeyBytes, true);

            // Seed existing account
            const existingAccount = {
                id: 'existing-account-id',
                publicKey: publicKeyHex,
                seq: 0,
                feedSeq: 0,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('accounts', [existingAccount]);

            const challenge = base64.encode(new TextEncoder().encode('test-challenge-2'));
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
            expect(body.token).toBe('generated-token');
        });

        it('should return 401 for invalid signature', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test-challenge'));

            // Create an invalid signature (random bytes)
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
            const body = await res.json();
            expect(body.error).toBe('Invalid signature');
        });

        it('should return 401 for signature from wrong key', async () => {
            const keyPair1 = generateEd25519KeyPair();
            const keyPair2 = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test-challenge'));

            // Sign with keyPair2 but send keyPair1's public key
            const signature = signChallenge(challenge, keyPair2.secretKey);

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair1.publicKey,
                    challenge,
                    signature,
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body.error).toBe('Invalid signature');
        });

        it('should return 400 for missing publicKey', async () => {
            const challenge = base64.encode(new TextEncoder().encode('test-challenge'));

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    challenge,
                    signature: 'some-signature',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for missing challenge', async () => {
            const keyPair = generateEd25519KeyPair();

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    signature: 'some-signature',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for missing signature', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test-challenge'));

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for empty publicKey', async () => {
            const challenge = base64.encode(new TextEncoder().encode('test-challenge'));

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: '',
                    challenge,
                    signature: 'some-signature',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for empty challenge', async () => {
            const keyPair = generateEd25519KeyPair();

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge: '',
                    signature: 'some-signature',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for empty signature', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test-challenge'));

            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    challenge,
                    signature: '',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 401 when account creation fails (insert returns empty)', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test-challenge-fail'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            // Override the insert mock to return empty array
            const originalInsert = drizzleMock.mockDb.insert;
            drizzleMock.mockDb.insert = vi.fn().mockReturnValue({
                values: vi.fn().mockReturnValue({
                    returning: vi.fn().mockResolvedValue([]), // Empty array = account creation failed
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
            const body = await res.json();
            expect(body.error).toBe('Failed to create account');

            // Restore original mock
            drizzleMock.mockDb.insert = originalInsert;
        });
    });

    // =========================================================================
    // POST /v1/auth/request - Terminal Authentication Request
    // =========================================================================

    describe('POST /v1/auth/request - Terminal Authentication Request', () => {
        it('should create a new terminal auth request with valid X25519 public key', async () => {
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

        it('should create auth request with supportsV2 flag', async () => {
            const keyPair = generateX25519KeyPair();

            const body = await expectOk<{ state: string }>(
                await unauthRequest('/v1/auth/request', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        supportsV2: true,
                    }),
                })
            );

            expect(body.state).toBe('requested');
        });

        it('should return "requested" state for pending existing request', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed existing pending request
            const existingRequest = {
                id: 'existing-request-id',
                publicKey: keyPair.publicKeyHex,
                supportsV2: false,
                response: null,
                responseAccountId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('terminalAuthRequests', [existingRequest]);

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

        it('should return "authorized" state with token for approved request', async () => {
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
            expect(body.token).toBe('generated-token');
            expect(body.response).toBe('encrypted-response-data');
        });

        it('should return 401 for invalid public key length', async () => {
            // X25519 public keys must be 32 bytes, use an invalid length
            const invalidKey = base64.encode(new Uint8Array(16).fill(1));

            const res = await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: invalidKey,
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body.error).toBe('Invalid public key');
        });

        it('should return 400 for missing publicKey', async () => {
            const res = await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({}),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for empty publicKey', async () => {
            const res = await unauthRequest('/v1/auth/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: '',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should handle supportsV2 as null', async () => {
            const keyPair = generateX25519KeyPair();

            const body = await expectOk<{ state: string }>(
                await unauthRequest('/v1/auth/request', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        supportsV2: null,
                    }),
                })
            );

            expect(body.state).toBe('requested');
        });
    });

    // =========================================================================
    // GET /v1/auth/request/status - Check Terminal Auth Status
    // =========================================================================

    describe('GET /v1/auth/request/status - Check Terminal Auth Status', () => {
        it('should return "not_found" for non-existent request', async () => {
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

        it('should return "pending" for pending request', async () => {
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

            const body = await expectOk<{ status: string; supportsV2: boolean }>(
                await unauthRequest(
                    `/v1/auth/request/status?publicKey=${encodeURIComponent(keyPair.publicKey)}`,
                    { method: 'GET' }
                )
            );

            expect(body.status).toBe('pending');
            expect(body.supportsV2).toBe(true);
        });

        it('should return "authorized" for approved request', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed authorized request
            const authorizedRequest = {
                id: 'authorized-request-id',
                publicKey: keyPair.publicKeyHex,
                supportsV2: true,
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
            expect(body.supportsV2).toBe(true);
        });

        it('should return "not_found" for invalid public key length', async () => {
            const invalidKey = base64.encode(new Uint8Array(16).fill(1));

            const body = await expectOk<{ status: string; supportsV2: boolean }>(
                await unauthRequest(
                    `/v1/auth/request/status?publicKey=${encodeURIComponent(invalidKey)}`,
                    { method: 'GET' }
                )
            );

            expect(body.status).toBe('not_found');
            expect(body.supportsV2).toBe(false);
        });

        it('should return 400 for missing publicKey query param', async () => {
            const res = await unauthRequest('/v1/auth/request/status', {
                method: 'GET',
            });

            expect(res.status).toBe(400);
        });

        it('should return "pending" for request with supportsV2 false', async () => {
            const keyPair = generateX25519KeyPair();

            const pendingRequest = {
                id: 'pending-request-id',
                publicKey: keyPair.publicKeyHex,
                supportsV2: false,
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
            expect(body.supportsV2).toBe(false);
        });
    });

    // =========================================================================
    // POST /v1/auth/response - Approve Terminal Auth Request
    // =========================================================================

    describe('POST /v1/auth/response - Approve Terminal Auth Request', () => {
        it('should require authentication', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await unauthRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(401);
        });

        it('should approve pending request successfully', async () => {
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

        it('should return success when approving already-approved request (idempotent)', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed already approved request
            const approvedRequest = {
                id: 'approved-request-id',
                publicKey: keyPair.publicKeyHex,
                supportsV2: true,
                response: 'existing-response',
                responseAccountId: TEST_USER_ID,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('terminalAuthRequests', [approvedRequest]);

            const body = await expectOk<{ success: boolean }>(
                await authRequest('/v1/auth/response', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        response: 'new-response-should-not-replace',
                    }),
                })
            );

            expect(body.success).toBe(true);
        });

        it('should return 404 for non-existent request', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await authRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(404);
            const body = await res.json();
            expect(body.error).toBe('Request not found');
        });

        it('should return 401 for invalid public key length', async () => {
            const invalidKey = base64.encode(new Uint8Array(16).fill(1));

            const res = await authRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: invalidKey,
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body.error).toBe('Invalid public key');
        });

        it('should return 400 for missing publicKey', async () => {
            const res = await authRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for missing response', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await authRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for empty publicKey', async () => {
            const res = await authRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: '',
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for empty response', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await authRequest('/v1/auth/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    response: '',
                }),
            });

            expect(res.status).toBe(400);
        });
    });

    // =========================================================================
    // POST /v1/auth/account/request - Account Authentication Request
    // =========================================================================

    describe('POST /v1/auth/account/request - Account Authentication Request', () => {
        it('should create a new account auth request with valid X25519 public key', async () => {
            const keyPair = generateX25519KeyPair();

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

        it('should return "requested" state for pending existing request', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed existing pending request
            const existingRequest = {
                id: 'existing-account-request-id',
                publicKey: keyPair.publicKeyHex,
                response: null,
                responseAccountId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('accountAuthRequests', [existingRequest]);

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

        it('should return "authorized" state with token for approved request', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed authorized request
            const authorizedRequest = {
                id: 'authorized-account-request-id',
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
            expect(body.token).toBe('generated-token');
            expect(body.response).toBe('encrypted-account-response');
        });

        it('should return 401 for invalid public key length', async () => {
            const invalidKey = base64.encode(new Uint8Array(16).fill(1));

            const res = await unauthRequest('/v1/auth/account/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: invalidKey,
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body.error).toBe('Invalid public key');
        });

        it('should return 400 for missing publicKey', async () => {
            const res = await unauthRequest('/v1/auth/account/request', {
                method: 'POST',
                body: JSON.stringify({}),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for empty publicKey', async () => {
            const res = await unauthRequest('/v1/auth/account/request', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: '',
                }),
            });

            expect(res.status).toBe(400);
        });
    });

    // =========================================================================
    // POST /v1/auth/account/response - Approve Account Auth Request
    // =========================================================================

    describe('POST /v1/auth/account/response - Approve Account Auth Request', () => {
        it('should require authentication', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await unauthRequest('/v1/auth/account/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(401);
        });

        it('should approve pending account request successfully', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed pending request
            const pendingRequest = {
                id: 'pending-account-request-id',
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
                        response: 'encrypted-account-approval',
                    }),
                })
            );

            expect(body.success).toBe(true);
        });

        it('should return success when approving already-approved request (idempotent)', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed already approved request
            const approvedRequest = {
                id: 'approved-account-request-id',
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
        });

        it('should return 404 for non-existent request', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await authRequest('/v1/auth/account/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(404);
            const body = await res.json();
            expect(body.error).toBe('Request not found');
        });

        it('should return 401 for invalid public key length', async () => {
            const invalidKey = base64.encode(new Uint8Array(16).fill(1));

            const res = await authRequest('/v1/auth/account/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: invalidKey,
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(401);
            const body = await res.json();
            expect(body.error).toBe('Invalid public key');
        });

        it('should return 400 for missing publicKey', async () => {
            const res = await authRequest('/v1/auth/account/response', {
                method: 'POST',
                body: JSON.stringify({
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for missing response', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await authRequest('/v1/auth/account/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for empty publicKey', async () => {
            const res = await authRequest('/v1/auth/account/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: '',
                    response: 'encrypted-response',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 400 for empty response', async () => {
            const keyPair = generateX25519KeyPair();

            const res = await authRequest('/v1/auth/account/response', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: keyPair.publicKey,
                    response: '',
                }),
            });

            expect(res.status).toBe(400);
        });

        it('should work with different authenticated user', async () => {
            const keyPair = generateX25519KeyPair();

            // Seed pending request
            const pendingRequest = {
                id: 'pending-account-request-id',
                publicKey: keyPair.publicKeyHex,
                response: null,
                responseAccountId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            drizzleMock.seedData('accountAuthRequests', [pendingRequest]);

            // Use user2's token
            const body = await expectOk<{ success: boolean }>(
                await authRequest(
                    '/v1/auth/account/response',
                    {
                        method: 'POST',
                        body: JSON.stringify({
                            publicKey: keyPair.publicKey,
                            response: 'encrypted-account-approval-from-user2',
                        }),
                    },
                    'user2-token'
                )
            );

            expect(body.success).toBe(true);
        });
    });

    // =========================================================================
    // Edge cases and error handling
    // =========================================================================

    describe('Edge cases and error handling', () => {
        it('should handle malformed JSON in POST /v1/auth', async () => {
            const res = await app.request(
                '/v1/auth',
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: 'not-valid-json',
                },
                testEnv
            );

            // Should return 400 for malformed JSON
            expect(res.status).toBe(400);
        });

        it('should handle malformed JSON in POST /v1/auth/request', async () => {
            const res = await app.request(
                '/v1/auth/request',
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: '{invalid}',
                },
                testEnv
            );

            expect(res.status).toBe(400);
        });

        it('should handle malformed JSON in POST /v1/auth/account/request', async () => {
            const res = await app.request(
                '/v1/auth/account/request',
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: '{"publicKey":',
                },
                testEnv
            );

            expect(res.status).toBe(400);
        });

        it('should handle invalid base64 in publicKey for direct auth', async () => {
            const res = await unauthRequest('/v1/auth', {
                method: 'POST',
                body: JSON.stringify({
                    publicKey: 'not-valid-base64!!!',
                    challenge: base64.encode(new TextEncoder().encode('test')),
                    signature: base64.encode(new Uint8Array(64)),
                }),
            });

            // The base64 decode will fail, causing an error
            expect([400, 401, 500]).toContain(res.status);
        });

        it('should handle request with extra unknown fields (POST /v1/auth)', async () => {
            const keyPair = generateEd25519KeyPair();
            const challenge = base64.encode(new TextEncoder().encode('test-challenge'));
            const signature = signChallenge(challenge, keyPair.secretKey);

            const body = await expectOk<{ success: boolean; token: string }>(
                await unauthRequest('/v1/auth', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        challenge,
                        signature,
                        extraField: 'should-be-ignored',
                    }),
                })
            );

            expect(body.success).toBe(true);
        });

        it('should handle request with extra unknown fields (POST /v1/auth/request)', async () => {
            const keyPair = generateX25519KeyPair();

            const body = await expectOk<{ state: string }>(
                await unauthRequest('/v1/auth/request', {
                    method: 'POST',
                    body: JSON.stringify({
                        publicKey: keyPair.publicKey,
                        supportsV2: true,
                        extraField: 'should-be-ignored',
                    }),
                })
            );

            expect(body.state).toBe('requested');
        });
    });
});
