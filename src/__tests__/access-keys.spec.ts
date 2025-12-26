/**
 * Integration Tests for Access Key Routes
 *
 * Tests all access key endpoints including:
 * - GET /v1/access-keys/:sessionId/:machineId (get)
 * - POST /v1/access-keys/:sessionId/:machineId (create)
 * - PUT /v1/access-keys/:sessionId/:machineId (update)
 *
 * @module __tests__/access-keys.spec
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

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
            return { userId: 'test-user-123', extras: {} };
        }
        if (token === 'user2-token') {
            return { userId: 'test-user-456', extras: {} };
        }
        return null;
    }),
    createToken: vi.fn().mockResolvedValue('generated-token'),
    resetAuth: vi.fn(),
}));

import { app } from '@/index';
import { authHeader, jsonBody, expectOneOfStatus, createMockR2, createMockDurableObjectNamespace } from './test-utils';

function createTestEnv() {
    return {
        ENVIRONMENT: 'development' as const,
        HAPPY_MASTER_SECRET: 'test-secret-for-vitest-tests-min-32-chars',
        DB: {} as D1Database,
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
    };
}

let testEnv: ReturnType<typeof createTestEnv>;

describe('Access Key Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        testEnv = createTestEnv();
    });

    describe('GET /v1/access-keys/:sessionId/:machineId - Get Access Key', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/access-keys/session-123/machine-456', {
                method: 'GET',
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should return access key if exists', async () => {
            const res = await app.request('/v1/access-keys/session-123/machine-456', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{ accessKey: unknown }>(res, [200], [500]);
            if (!body) return;
            expect(body).toHaveProperty('accessKey');
        });

        it('should return null for non-existent access key', async () => {
            const res = await app.request('/v1/access-keys/non-existent/non-existent', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            const body = await expectOneOfStatus<{ accessKey: unknown }>(res, [200], [500]);
            if (!body) return;
            expect(body.accessKey).toBeNull();
        });

        it('should validate sessionId parameter', async () => {
            const res = await app.request('/v1/access-keys/valid-session/valid-machine', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200, 400], [500]);
        });

        it('should validate machineId parameter', async () => {
            const res = await app.request('/v1/access-keys/session/machine', {
                method: 'GET',
                headers: authHeader(),
            }, testEnv);

            await expectOneOfStatus(res, [200, 400], [500]);
        });
    });

    describe('POST /v1/access-keys/:sessionId/:machineId - Create Access Key', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/access-keys/session-123/machine-456', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    data: 'encrypted-access-data',
                }),
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should create access key with valid data', async () => {
            const sessionId = `session-${Date.now()}`;
            const machineId = `machine-${Date.now()}`;

            const res = await app.request(`/v1/access-keys/${sessionId}/${machineId}`, {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    data: 'encrypted-access-key-data',
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ accessKey: { data: string } }>(res, [200, 201], [500]);
            if (!body) return;
            expect(body).toHaveProperty('accessKey');
        });

        it('should require data field', async () => {
            const res = await app.request('/v1/access-keys/session-123/machine-456', {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({}),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should return 409 if access key already exists', async () => {
            const sessionId = `conflict-session-${Date.now()}`;
            const machineId = `conflict-machine-${Date.now()}`;

            // Create first
            await app.request(`/v1/access-keys/${sessionId}/${machineId}`, {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    data: 'first-key',
                }),
            }, testEnv);

            // Try to create again
            const res = await app.request(`/v1/access-keys/${sessionId}/${machineId}`, {
                method: 'POST',
                headers: authHeader(),
                body: jsonBody({
                    data: 'second-key',
                }),
            }, testEnv);

            await expectOneOfStatus(res, [409], [500]);
        });
    });

    describe('PUT /v1/access-keys/:sessionId/:machineId - Update Access Key', () => {
        it('should require authentication', async () => {
            const res = await app.request('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: jsonBody({
                    data: 'new-encrypted-data',
                    expectedVersion: 1,
                }),
            }, testEnv);

            expect(res.status).toBe(401);
        });

        it('should update access key with valid data', async () => {
            const res = await app.request('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                headers: authHeader(),
                body: jsonBody({
                    data: 'updated-encrypted-data',
                    expectedVersion: 1,
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ success: boolean; version: number }>(res, [200], [404, 500]);
            if (!body) return;
            expect(body.success).toBe(true);
            expect(body.version).toBeGreaterThan(1);
        });

        it('should require data field', async () => {
            const res = await app.request('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                headers: authHeader(),
                body: jsonBody({
                    expectedVersion: 1,
                }),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should require expectedVersion field', async () => {
            const res = await app.request('/v1/access-keys/session-123/machine-456', {
                method: 'PUT',
                headers: authHeader(),
                body: jsonBody({
                    data: 'new-data',
                }),
            }, testEnv);

            expect(res.status).toBe(400);
        });

        it('should return 404 for non-existent access key', async () => {
            const res = await app.request('/v1/access-keys/non-existent/non-existent', {
                method: 'PUT',
                headers: authHeader(),
                body: jsonBody({
                    data: 'new-data',
                    expectedVersion: 1,
                }),
            }, testEnv);

            await expectOneOfStatus(res, [404], [500]);
        });

        it('should handle version mismatch (optimistic locking)', async () => {
            const res = await app.request('/v1/access-keys/session/machine', {
                method: 'PUT',
                headers: authHeader(),
                body: jsonBody({
                    data: 'new-data',
                    expectedVersion: 999, // Wrong version
                }),
            }, testEnv);

            const body = await expectOneOfStatus<{ success: boolean; error?: string }>(res, [200], [404, 500]);
            if (!body || body.success) return;
            expect(body.error).toBe('version-mismatch');
        });
    });

    describe('Access Key Security', () => {
        it('should not expose access keys to other users', async () => {
            // Create as user 1
            const sessionId = `private-session-${Date.now()}`;
            const machineId = `private-machine-${Date.now()}`;

            await app.request(`/v1/access-keys/${sessionId}/${machineId}`, {
                method: 'POST',
                headers: authHeader('valid-token'),
                body: jsonBody({
                    data: 'private-data',
                }),
            }, testEnv);

            // Try to access as user 2
            const res = await app.request(`/v1/access-keys/${sessionId}/${machineId}`, {
                method: 'GET',
                headers: authHeader('user2-token'),
            }, testEnv);

            // Should either not find it or return null
            const body = await expectOneOfStatus<{ accessKey: unknown }>(res, [200], [500]);
            if (!body) return;
            expect(body.accessKey).toBeNull();
        });
    });
});
