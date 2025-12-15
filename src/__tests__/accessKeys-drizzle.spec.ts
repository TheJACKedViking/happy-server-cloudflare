/**
 * Integration Tests for Access Key Routes with Drizzle ORM Mocking
 *
 * Tests all access key management endpoints:
 * - GET /v1/access-keys/:sessionId/:machineId - Get access key
 * - POST /v1/access-keys/:sessionId/:machineId - Create access key
 * - PUT /v1/access-keys/:sessionId/:machineId - Update access key
 *
 * @module __tests__/accessKeys-drizzle.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    expectOk,
    expectStatus,
    createTestSession,
    createTestMachine,
    createTestAccessKey,
    createMockDrizzle,
    createMockR2,
    createMockDurableObjectNamespace,
    TEST_USER_ID,
    TEST_USER_ID_2,
    generateTestId,
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
        return drizzleMock?.mockDb;
    }),
}));

// Import app AFTER mocks are set up
import app from '@/index';

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

describe('Access Key Routes with Drizzle Mocking', () => {
    beforeEach(() => {
        vi.clearAllMocks();
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
        return app.request(path, options, testEnv);
    }

    /**
     * Helper to create and seed test data for a valid session/machine pair
     */
    function seedSessionAndMachine(
        userId: string = TEST_USER_ID,
        sessionId: string = 'session-123',
        machineId: string = 'machine-456'
    ) {
        const session = createTestSession(userId, { id: sessionId });
        const machine = createTestMachine(userId, { id: machineId });
        drizzleMock.seedData('sessions', [session]);
        drizzleMock.seedData('machines', [machine]);
        return { session, machine };
    }

    // ============================================================================
    // GET /v1/access-keys/:sessionId/:machineId - Get Access Key
    // ============================================================================

    describe('GET /v1/access-keys/:sessionId/:machineId - Get Access Key', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v1/access-keys/session-123/machine-456', {
                method: 'GET',
            });
            expect(res.status).toBe(401);
        });

        it('should return 404 when session not found', async () => {
            // Only seed machine, not session
            const machine = createTestMachine(TEST_USER_ID, { id: 'machine-456' });
            drizzleMock.seedData('machines', [machine]);

            const res = await authRequest('/v1/access-keys/non-existent-session/machine-456', {
                method: 'GET',
            });

            expect(res.status).toBe(404);
            const body = await res.json();
            expect(body).toHaveProperty('error', 'Session or machine not found');
        });

        it('should return 404 when machine not found', async () => {
            // Only seed session, not machine
            const session = createTestSession(TEST_USER_ID, { id: 'session-123' });
            drizzleMock.seedData('sessions', [session]);

            const res = await authRequest('/v1/access-keys/session-123/non-existent-machine', {
                method: 'GET',
            });

            expect(res.status).toBe(404);
            const body = await res.json();
            expect(body).toHaveProperty('error', 'Session or machine not found');
        });

        it('should return 404 when both session and machine not found', async () => {
            const res = await authRequest('/v1/access-keys/fake-session/fake-machine', {
                method: 'GET',
            });

            expect(res.status).toBe(404);
            const body = await res.json();
            expect(body).toHaveProperty('error', 'Session or machine not found');
        });

        it('should return 404 when session belongs to another user', async () => {
            // Seed session for user2, machine for user1
            const session = createTestSession(TEST_USER_ID_2, { id: 'session-123' });
            const machine = createTestMachine(TEST_USER_ID, { id: 'machine-456' });
            drizzleMock.seedData('sessions', [session]);
            drizzleMock.seedData('machines', [machine]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'GET',
            });

            expect(res.status).toBe(404);
        });

        it('should return 404 when machine belongs to another user', async () => {
            // Seed session for user1, machine for user2
            const session = createTestSession(TEST_USER_ID, { id: 'session-123' });
            const machine = createTestMachine(TEST_USER_ID_2, { id: 'machine-456' });
            drizzleMock.seedData('sessions', [session]);
            drizzleMock.seedData('machines', [machine]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'GET',
            });

            expect(res.status).toBe(404);
        });

        it('should return accessKey: null when access key not found', async () => {
            seedSessionAndMachine();

            const body = await expectOk<{ accessKey: null }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'GET',
                })
            );

            expect(body.accessKey).toBeNull();
        });

        it('should return access key data when found', async () => {
            seedSessionAndMachine();

            // Seed access key
            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { data: 'encrypted-data', dataVersion: 3 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const body = await expectOk<{
                accessKey: {
                    data: string;
                    dataVersion: number;
                    createdAt: number;
                    updatedAt: number;
                };
            }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'GET',
                })
            );

            expect(body.accessKey).not.toBeNull();
            expect(body.accessKey.data).toBe('encrypted-data');
            expect(body.accessKey.dataVersion).toBe(3);
            expect(typeof body.accessKey.createdAt).toBe('number');
            expect(typeof body.accessKey.updatedAt).toBe('number');
        });

        it('should not return access key belonging to another user', async () => {
            seedSessionAndMachine();

            // Seed access key for user2
            const accessKey = createTestAccessKey(
                TEST_USER_ID_2,
                'session-123',
                'machine-456',
                { data: 'other-user-data' }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const body = await expectOk<{ accessKey: null }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'GET',
                })
            );

            expect(body.accessKey).toBeNull();
        });
    });

    // ============================================================================
    // POST /v1/access-keys/:sessionId/:machineId - Create Access Key
    // ============================================================================

    describe('POST /v1/access-keys/:sessionId/:machineId - Create Access Key', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v1/access-keys/session-123/machine-456', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data: 'encrypted-data' }),
            });
            expect(res.status).toBe(401);
        });

        it('should require data field', async () => {
            seedSessionAndMachine();

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'POST',
                body: JSON.stringify({}),
            });

            expect(res.status).toBe(400);
        });

        it('should return 404 when session not found', async () => {
            const machine = createTestMachine(TEST_USER_ID, { id: 'machine-456' });
            drizzleMock.seedData('machines', [machine]);

            const res = await authRequest('/v1/access-keys/non-existent/machine-456', {
                method: 'POST',
                body: JSON.stringify({ data: 'encrypted-data' }),
            });

            expect(res.status).toBe(404);
            const body = await res.json();
            expect(body).toHaveProperty('error', 'Session or machine not found');
        });

        it('should return 404 when machine not found', async () => {
            const session = createTestSession(TEST_USER_ID, { id: 'session-123' });
            drizzleMock.seedData('sessions', [session]);

            const res = await authRequest('/v1/access-keys/session-123/non-existent', {
                method: 'POST',
                body: JSON.stringify({ data: 'encrypted-data' }),
            });

            expect(res.status).toBe(404);
            const body = await res.json();
            expect(body).toHaveProperty('error', 'Session or machine not found');
        });

        it('should return 404 when both session and machine not found', async () => {
            const res = await authRequest('/v1/access-keys/fake-session/fake-machine', {
                method: 'POST',
                body: JSON.stringify({ data: 'encrypted-data' }),
            });

            expect(res.status).toBe(404);
        });

        it('should return 404 when session belongs to another user', async () => {
            const session = createTestSession(TEST_USER_ID_2, { id: 'session-123' });
            const machine = createTestMachine(TEST_USER_ID, { id: 'machine-456' });
            drizzleMock.seedData('sessions', [session]);
            drizzleMock.seedData('machines', [machine]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'POST',
                body: JSON.stringify({ data: 'encrypted-data' }),
            });

            expect(res.status).toBe(404);
        });

        it('should return 404 when machine belongs to another user', async () => {
            const session = createTestSession(TEST_USER_ID, { id: 'session-123' });
            const machine = createTestMachine(TEST_USER_ID_2, { id: 'machine-456' });
            drizzleMock.seedData('sessions', [session]);
            drizzleMock.seedData('machines', [machine]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'POST',
                body: JSON.stringify({ data: 'encrypted-data' }),
            });

            expect(res.status).toBe(404);
        });

        it('should return 409 when access key already exists', async () => {
            seedSessionAndMachine();

            // Seed existing access key
            const existingKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { data: 'existing-data' }
            );
            drizzleMock.seedData('accessKeys', [existingKey]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'POST',
                body: JSON.stringify({ data: 'new-data' }),
            });

            expect(res.status).toBe(409);
            const body = await res.json();
            expect(body).toHaveProperty('error', 'Access key already exists');
        });

        it('should create access key successfully', async () => {
            seedSessionAndMachine();

            const body = await expectOk<{
                success: boolean;
                accessKey: {
                    data: string;
                    dataVersion: number;
                    createdAt: number;
                    updatedAt: number;
                };
            }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'POST',
                    body: JSON.stringify({ data: 'new-encrypted-data' }),
                })
            );

            expect(body.success).toBe(true);
            expect(body.accessKey).toBeDefined();
            expect(body.accessKey.data).toBe('new-encrypted-data');
            expect(body.accessKey.dataVersion).toBe(1);
            expect(typeof body.accessKey.createdAt).toBe('number');
            expect(typeof body.accessKey.updatedAt).toBe('number');
        });

        it('should not allow creating access key for another users session', async () => {
            // User2 has the session, user1 has the machine
            const session = createTestSession(TEST_USER_ID_2, { id: 'session-other' });
            const machine = createTestMachine(TEST_USER_ID, { id: 'machine-mine' });
            drizzleMock.seedData('sessions', [session]);
            drizzleMock.seedData('machines', [machine]);

            const res = await authRequest('/v1/access-keys/session-other/machine-mine', {
                method: 'POST',
                body: JSON.stringify({ data: 'encrypted-data' }),
            });

            expect(res.status).toBe(404);
        });
    });

    // ============================================================================
    // PUT /v1/access-keys/:sessionId/:machineId - Update Access Key
    // ============================================================================

    describe('PUT /v1/access-keys/:sessionId/:machineId - Update Access Key', () => {
        it('should require authentication', async () => {
            const res = await unauthRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data: 'new-data', expectedVersion: 1 }),
            });
            expect(res.status).toBe(401);
        });

        it('should require data field', async () => {
            seedSessionAndMachine();
            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { dataVersion: 1 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                body: JSON.stringify({ expectedVersion: 1 }),
            });

            expect(res.status).toBe(400);
        });

        it('should require expectedVersion field', async () => {
            seedSessionAndMachine();
            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { dataVersion: 1 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                body: JSON.stringify({ data: 'new-data' }),
            });

            expect(res.status).toBe(400);
        });

        it('should return 404 when access key not found', async () => {
            // Note: PUT doesn't check session/machine - it checks access key directly
            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                body: JSON.stringify({ data: 'new-data', expectedVersion: 1 }),
            });

            expect(res.status).toBe(404);
            const body = await res.json();
            expect(body).toHaveProperty('error', 'Access key not found');
        });

        it('should return 404 when access key belongs to another user', async () => {
            // Seed access key for user2
            const accessKey = createTestAccessKey(
                TEST_USER_ID_2,
                'session-123',
                'machine-456',
                { dataVersion: 1 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                body: JSON.stringify({ data: 'new-data', expectedVersion: 1 }),
            });

            expect(res.status).toBe(404);
        });

        it('should return version-mismatch when expectedVersion does not match', async () => {
            seedSessionAndMachine();

            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { data: 'current-data', dataVersion: 5 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const body = await expectOk<{
                success: boolean;
                error: string;
                currentVersion: number;
                currentData: string;
            }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'PUT',
                    body: JSON.stringify({ data: 'new-data', expectedVersion: 3 }),
                })
            );

            expect(body.success).toBe(false);
            expect(body.error).toBe('version-mismatch');
            expect(body.currentVersion).toBe(5);
            expect(body.currentData).toBe('current-data');
        });

        it('should update access key successfully with correct version', async () => {
            seedSessionAndMachine();

            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { data: 'old-data', dataVersion: 2 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const body = await expectOk<{
                success: boolean;
                version: number;
            }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'PUT',
                    body: JSON.stringify({ data: 'updated-data', expectedVersion: 2 }),
                })
            );

            expect(body.success).toBe(true);
            expect(body.version).toBe(3);
        });

        it('should increment version on each successful update', async () => {
            seedSessionAndMachine();

            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { data: 'initial-data', dataVersion: 1 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            // First update
            const body1 = await expectOk<{ success: boolean; version: number }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'PUT',
                    body: JSON.stringify({ data: 'update-1', expectedVersion: 1 }),
                })
            );

            expect(body1.success).toBe(true);
            expect(body1.version).toBe(2);
        });

        it('should handle concurrent update attempts with version conflict', async () => {
            seedSessionAndMachine();

            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { data: 'original', dataVersion: 1 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            // First update succeeds
            const res1 = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                body: JSON.stringify({ data: 'update-from-device-1', expectedVersion: 1 }),
            });
            expect(res1.status).toBe(200);
            const body1 = await res1.json() as { success: boolean; version?: number };
            expect(body1.success).toBe(true);
            expect(body1.version).toBe(2);

            // Second update with stale version should get version-mismatch
            const res2 = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                body: JSON.stringify({ data: 'update-from-device-2', expectedVersion: 1 }),
            });
            expect(res2.status).toBe(200);
            const body2 = await res2.json() as { success: boolean; error?: string; currentVersion?: number };
            expect(body2.success).toBe(false);
            expect(body2.error).toBe('version-mismatch');
            expect(body2.currentVersion).toBe(2);
        });
    });

    // ============================================================================
    // Cross-user isolation tests
    // ============================================================================

    describe('Cross-user isolation', () => {
        it('user1 cannot access user2 access keys via GET', async () => {
            // Setup user2's resources
            const session = createTestSession(TEST_USER_ID_2, { id: 'user2-session' });
            const machine = createTestMachine(TEST_USER_ID_2, { id: 'user2-machine' });
            const accessKey = createTestAccessKey(
                TEST_USER_ID_2,
                'user2-session',
                'user2-machine',
                { data: 'secret-data' }
            );
            drizzleMock.seedData('sessions', [session]);
            drizzleMock.seedData('machines', [machine]);
            drizzleMock.seedData('accessKeys', [accessKey]);

            // User1 tries to access user2's access key
            const res = await authRequest('/v1/access-keys/user2-session/user2-machine', {
                method: 'GET',
            });

            // Should return 404 because session/machine belong to user2
            expect(res.status).toBe(404);
        });

        it('user1 cannot create access key for user2 session', async () => {
            // User2 owns the session
            const session = createTestSession(TEST_USER_ID_2, { id: 'user2-session' });
            // User1 owns the machine
            const machine = createTestMachine(TEST_USER_ID, { id: 'user1-machine' });
            drizzleMock.seedData('sessions', [session]);
            drizzleMock.seedData('machines', [machine]);

            const res = await authRequest('/v1/access-keys/user2-session/user1-machine', {
                method: 'POST',
                body: JSON.stringify({ data: 'malicious-data' }),
            });

            expect(res.status).toBe(404);
        });

        it('user1 cannot update user2 access key', async () => {
            const accessKey = createTestAccessKey(
                TEST_USER_ID_2,
                'session-123',
                'machine-456',
                { data: 'user2-data', dataVersion: 1 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                body: JSON.stringify({ data: 'hijacked', expectedVersion: 1 }),
            });

            expect(res.status).toBe(404);
        });
    });

    // ============================================================================
    // Schema validation tests
    // ============================================================================

    describe('Schema validation', () => {
        it('should reject GET with invalid sessionId format', async () => {
            // The OpenAPI schema uses string validation - test with empty string
            const res = await authRequest('/v1/access-keys//machine-456', {
                method: 'GET',
            });

            // Either 400 or 404 is acceptable depending on how Hono handles empty params
            expect([400, 404]).toContain(res.status);
        });

        it('should reject POST with non-string data', async () => {
            seedSessionAndMachine();

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'POST',
                body: JSON.stringify({ data: 12345 }),
            });

            expect(res.status).toBe(400);
        });

        it('should reject PUT with non-integer expectedVersion', async () => {
            seedSessionAndMachine();
            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { dataVersion: 1 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                body: JSON.stringify({ data: 'new-data', expectedVersion: 'one' }),
            });

            expect(res.status).toBe(400);
        });

        it('should accept valid data with special characters', async () => {
            seedSessionAndMachine();

            const specialData = 'base64+encoded/data==with-special_chars';
            const body = await expectOk<{
                success: boolean;
                accessKey: { data: string };
            }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'POST',
                    body: JSON.stringify({ data: specialData }),
                })
            );

            expect(body.success).toBe(true);
            expect(body.accessKey.data).toBe(specialData);
        });

        it('should reject empty string as data (min 1 char required)', async () => {
            seedSessionAndMachine();

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'POST',
                body: JSON.stringify({ data: '' }),
            });

            expect(res.status).toBe(400);
        });

        it('should handle very long data strings', async () => {
            seedSessionAndMachine();

            const longData = 'x'.repeat(10000);
            const body = await expectOk<{
                success: boolean;
                accessKey: { data: string };
            }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'POST',
                    body: JSON.stringify({ data: longData }),
                })
            );

            expect(body.success).toBe(true);
            expect(body.accessKey.data).toBe(longData);
        });
    });

    // ============================================================================
    // Edge cases
    // ============================================================================

    describe('Edge cases', () => {
        it('should handle multiple access keys for same user with different session/machine combos', async () => {
            // Setup multiple sessions and machines
            const session1 = createTestSession(TEST_USER_ID, { id: 'session-1' });
            const session2 = createTestSession(TEST_USER_ID, { id: 'session-2' });
            const machine1 = createTestMachine(TEST_USER_ID, { id: 'machine-1' });
            const machine2 = createTestMachine(TEST_USER_ID, { id: 'machine-2' });

            drizzleMock.seedData('sessions', [session1, session2]);
            drizzleMock.seedData('machines', [machine1, machine2]);

            // Create access keys for different combinations
            const key1 = createTestAccessKey(TEST_USER_ID, 'session-1', 'machine-1', { data: 'key-1-1' });
            const key2 = createTestAccessKey(TEST_USER_ID, 'session-1', 'machine-2', { data: 'key-1-2' });
            const key3 = createTestAccessKey(TEST_USER_ID, 'session-2', 'machine-1', { data: 'key-2-1' });
            drizzleMock.seedData('accessKeys', [key1, key2, key3]);

            // Verify we can access each individually
            const body1 = await expectOk<{ accessKey: { data: string } }>(
                await authRequest('/v1/access-keys/session-1/machine-1', { method: 'GET' })
            );
            expect(body1.accessKey.data).toBe('key-1-1');

            const body2 = await expectOk<{ accessKey: { data: string } }>(
                await authRequest('/v1/access-keys/session-1/machine-2', { method: 'GET' })
            );
            expect(body2.accessKey.data).toBe('key-1-2');

            const body3 = await expectOk<{ accessKey: { data: string } }>(
                await authRequest('/v1/access-keys/session-2/machine-1', { method: 'GET' })
            );
            expect(body3.accessKey.data).toBe('key-2-1');

            // Non-existent combo should return null
            const body4 = await expectOk<{ accessKey: null }>(
                await authRequest('/v1/access-keys/session-2/machine-2', { method: 'GET' })
            );
            expect(body4.accessKey).toBeNull();
        });

        it('should handle update with version 0', async () => {
            seedSessionAndMachine();

            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { data: 'initial', dataVersion: 0 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const body = await expectOk<{ success: boolean; version: number }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'PUT',
                    body: JSON.stringify({ data: 'updated', expectedVersion: 0 }),
                })
            );

            expect(body.success).toBe(true);
            expect(body.version).toBe(1);
        });

        it('should reject negative expectedVersion with 400 (schema validation)', async () => {
            seedSessionAndMachine();

            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                { data: 'data', dataVersion: 1 }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const res = await authRequest('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                body: JSON.stringify({ data: 'new', expectedVersion: -1 }),
            });

            // Schema requires expectedVersion >= 0
            expect(res.status).toBe(400);
        });

        it('should return correct timestamps as milliseconds', async () => {
            seedSessionAndMachine();

            const now = new Date();
            const accessKey = createTestAccessKey(
                TEST_USER_ID,
                'session-123',
                'machine-456',
                {
                    data: 'data',
                    createdAt: now,
                    updatedAt: now,
                }
            );
            drizzleMock.seedData('accessKeys', [accessKey]);

            const body = await expectOk<{
                accessKey: {
                    createdAt: number;
                    updatedAt: number;
                };
            }>(
                await authRequest('/v1/access-keys/session-123/machine-456', {
                    method: 'GET',
                })
            );

            // Timestamps should be in milliseconds (large numbers)
            expect(body.accessKey.createdAt).toBeGreaterThan(1700000000000);
            expect(body.accessKey.updatedAt).toBeGreaterThan(1700000000000);
            expect(body.accessKey.createdAt).toBe(now.getTime());
            expect(body.accessKey.updatedAt).toBe(now.getTime());
        });
    });
});
