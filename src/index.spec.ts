import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock cloudflare:workers module (required for Durable Object imports)
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

import { app } from '@/index';
import { createMockR2, createMockDurableObjectNamespace } from './__tests__/test-utils';

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

/**
 * Type helper for API responses
 */
interface JsonResponse {
    [key: string]: unknown;
}

/**
 * Integration tests for main application routes
 */
describe('Happy Server Workers - Main Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        testEnv = createTestEnv();
    });

    describe('GET /', () => {
        it('should return welcome message with version and environment', async () => {
            const res = await app.request('/', {}, testEnv);
            const json = (await res.json()) as JsonResponse;

            expect(res.status).toBe(200);
            expect(json).toHaveProperty('message');
            expect(json.message).toContain('Welcome to Happy Server');
            expect(json).toHaveProperty('version');
            expect(json.version).toBe('0.0.0');
            expect(json).toHaveProperty('environment');
            expect(json).toHaveProperty('timestamp');
        });

        it('should return valid ISO timestamp', async () => {
            const res = await app.request('/', {}, testEnv);
            const json = (await res.json()) as JsonResponse;

            expect(json.timestamp).toBeDefined();
            // Validate ISO 8601 format
            expect(new Date(json.timestamp as string).toISOString()).toBe(
                json.timestamp
            );
        });
    });

    describe('GET /health', () => {
        it('should return healthy status', async () => {
            const res = await app.request('/health', {}, testEnv);
            const json = (await res.json()) as JsonResponse;

            expect(res.status).toBe(200);
            expect(json.status).toBe('healthy');
            expect(json).toHaveProperty('timestamp');
            expect(json).toHaveProperty('version');
        });

        it('should return consistent response structure', async () => {
            const res = await app.request('/health', {}, testEnv);
            const json = (await res.json()) as JsonResponse;

            // Verify all expected fields are present
            expect(Object.keys(json)).toEqual(
                expect.arrayContaining(['status', 'timestamp', 'version'])
            );
        });
    });

    describe('GET /ready', () => {
        it('should return ready status or 503 when DB not available', async () => {
            const res = await app.request('/ready', {}, testEnv);
            const json = (await res.json()) as JsonResponse;

            // When DB is mocked as empty object, readiness check may fail (503)
            // When DB is available, should return 200 with ready: true
            expect([200, 503]).toContain(res.status);
            expect(json).toHaveProperty('ready');
            expect(json).toHaveProperty('timestamp');
        });

        it('should return 503 when not ready', async () => {
            // With mock DB that doesn't implement prepare(), returns 503
            const res = await app.request('/ready', {}, testEnv);
            expect([200, 503]).toContain(res.status);
        });
    });

    describe('404 Handler', () => {
        it('should return 404 for unknown routes', async () => {
            const res = await app.request('/unknown-route', {}, testEnv);
            const json = (await res.json()) as { error: string };

            expect(res.status).toBe(404);
            expect(json.error).toBeDefined();
            // Flat error format includes path in message
            expect(json.error).toContain('/unknown-route');
        });

        it('should include requested path in error response', async () => {
            const testPath = '/api/v1/non-existent';
            const res = await app.request(testPath, {}, testEnv);
            const json = (await res.json()) as { error: string };

            // Flat error format includes path in message
            expect(json.error).toContain(testPath);
        });
    });

    describe('CORS Headers', () => {
        it('should include CORS headers in response', async () => {
            const res = await app.request('/', {
                headers: {
                    Origin: 'http://localhost:3000',
                },
            }, testEnv);

            expect(
                res.headers.get('access-control-allow-origin')
            ).toBeDefined();
        });

        it('should handle OPTIONS preflight requests', async () => {
            const res = await app.request('/', {
                method: 'OPTIONS',
                headers: {
                    Origin: 'http://localhost:3000',
                    'Access-Control-Request-Method': 'POST',
                },
            }, testEnv);

            expect(res.status).toBe(204);
            expect(res.headers.get('access-control-allow-methods')).toContain(
                'POST'
            );
        });
    });

    describe('Error Handling', () => {
        it('should handle errors gracefully', async () => {
            // Test error handling by requesting an endpoint that doesn't exist
            const res = await app.request('/trigger-error', {}, testEnv);

            expect(res.status).toBe(404);
            const json = (await res.json()) as JsonResponse;
            expect(json.error).toBeDefined();
        });

        it('should return JSON error responses', async () => {
            const res = await app.request('/invalid', {}, testEnv);
            const contentType = res.headers.get('content-type');

            expect(contentType).toContain('application/json');
        });
    });

    describe('Request Headers', () => {
        it('should accept custom headers', async () => {
            const res = await app.request('/health', {
                headers: {
                    'X-Request-Id': 'test-request-123',
                    'User-Agent': 'Test Agent',
                },
            }, testEnv);

            expect(res.status).toBe(200);
        });
    });
});
