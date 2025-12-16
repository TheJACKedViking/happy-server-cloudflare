import { describe, it, expect, beforeEach, afterEach, vi, beforeAll, afterAll } from 'vitest';
import { createTestApp, authHeader } from './__test__/testUtils';
import { voiceRoutes } from './voiceRoutes';
import type { Fastify } from '../types';

// Mock the log utility
vi.mock('@/utils/log', () => ({
    log: vi.fn(),
}));

/**
 * Integration tests for voiceRoutes
 *
 * Tests the /v1/voice/token endpoint which generates ElevenLabs voice tokens.
 * The endpoint has different behaviors based on:
 * - Development vs production environment
 * - RevenueCat subscription status (production only)
 * - ElevenLabs API key availability
 *
 * External APIs are mocked using global.fetch.
 */
describe('voiceRoutes', () => {
    describe('in development environment', () => {
        let app: Fastify;
        const originalNodeEnv = process.env.NODE_ENV;
        const originalEnv = process.env.ENV;
        const originalElevenLabsKey = process.env.ELEVENLABS_API_KEY;

        beforeAll(() => {
            process.env.NODE_ENV = 'development';
            process.env.ELEVENLABS_API_KEY = 'test-11labs-key';
        });

        afterAll(() => {
            process.env.NODE_ENV = originalNodeEnv;
            process.env.ENV = originalEnv;
            if (originalElevenLabsKey) {
                process.env.ELEVENLABS_API_KEY = originalElevenLabsKey;
            } else {
                delete process.env.ELEVENLABS_API_KEY;
            }
        });

        beforeEach(async () => {
            app = createTestApp();
            voiceRoutes(app);
            await app.ready();
            vi.clearAllMocks();
        });

        afterEach(async () => {
            await app.close();
            vi.restoreAllMocks();
        });

        it('should bypass RevenueCat and return token in development', async () => {
            // Mock ElevenLabs API response
            vi.spyOn(global, 'fetch').mockResolvedValueOnce({
                ok: true,
                json: async () => ({ token: 'test-elevenlabs-token' }),
            } as Response);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    agentId: 'test-agent-123',
                }
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.allowed).toBe(true);
            expect(body.token).toBe('test-elevenlabs-token');
            expect(body.agentId).toBe('test-agent-123');
        });

        it('should return 400 when ElevenLabs API fails', async () => {
            vi.spyOn(global, 'fetch').mockResolvedValueOnce({
                ok: false,
                status: 500,
            } as Response);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    agentId: 'test-agent-123',
                }
            });

            expect(response.statusCode).toBe(400);
            const body = JSON.parse(response.payload);
            expect(body.allowed).toBe(false);
            expect(body.error).toContain('Failed to get 11Labs token');
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: { 'Content-Type': 'application/json' },
                payload: {
                    agentId: 'test-agent-123',
                }
            });

            expect(response.statusCode).toBe(401);
        });

        it('should return error for missing agentId', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {}
            });

            // Fastify with Zod returns 500 for validation errors in this setup
            // (may vary based on error handler configuration)
            expect(response.statusCode).toBe(500);
        });
    });

    describe('in production environment', () => {
        let app: Fastify;
        const originalNodeEnv = process.env.NODE_ENV;
        const originalEnv = process.env.ENV;
        const originalElevenLabsKey = process.env.ELEVENLABS_API_KEY;

        beforeAll(() => {
            process.env.NODE_ENV = 'production';
            process.env.ENV = 'production';
            process.env.ELEVENLABS_API_KEY = 'test-11labs-key';
        });

        afterAll(() => {
            process.env.NODE_ENV = originalNodeEnv;
            process.env.ENV = originalEnv;
            if (originalElevenLabsKey) {
                process.env.ELEVENLABS_API_KEY = originalElevenLabsKey;
            } else {
                delete process.env.ELEVENLABS_API_KEY;
            }
        });

        beforeEach(async () => {
            app = createTestApp();
            voiceRoutes(app);
            await app.ready();
            vi.clearAllMocks();
        });

        afterEach(async () => {
            await app.close();
            vi.restoreAllMocks();
        });

        it('should return 400 when RevenueCat key is missing in production', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    agentId: 'test-agent-123',
                    // No revenueCatPublicKey
                }
            });

            expect(response.statusCode).toBe(400);
            const body = JSON.parse(response.payload);
            expect(body.allowed).toBe(false);
            expect(body.error).toBe('RevenueCat public key required');
        });

        it('should return denied when RevenueCat API fails', async () => {
            vi.spyOn(global, 'fetch').mockResolvedValueOnce({
                ok: false,
                status: 401,
            } as Response);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    agentId: 'test-agent-123',
                    revenueCatPublicKey: 'test-rc-key',
                }
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.allowed).toBe(false);
            expect(body.agentId).toBe('test-agent-123');
        });

        it('should return denied when user has no active subscription', async () => {
            vi.spyOn(global, 'fetch').mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    subscriber: {
                        entitlements: {
                            active: {}  // No 'pro' entitlement
                        }
                    }
                }),
            } as Response);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    agentId: 'test-agent-123',
                    revenueCatPublicKey: 'test-rc-key',
                }
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.allowed).toBe(false);
            expect(body.agentId).toBe('test-agent-123');
        });

        it('should return token when subscription is active', async () => {
            // First call: RevenueCat subscription check
            // Second call: ElevenLabs token request
            vi.spyOn(global, 'fetch')
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        subscriber: {
                            entitlements: {
                                active: {
                                    pro: { expires_date: '2030-01-01' }
                                }
                            }
                        }
                    }),
                } as Response)
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({ token: 'production-elevenlabs-token' }),
                } as Response);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    agentId: 'test-agent-123',
                    revenueCatPublicKey: 'test-rc-key',
                }
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.allowed).toBe(true);
            expect(body.token).toBe('production-elevenlabs-token');
            expect(body.agentId).toBe('test-agent-123');
        });

        it('should return 400 when ElevenLabs fails after subscription check', async () => {
            vi.spyOn(global, 'fetch')
                .mockResolvedValueOnce({
                    ok: true,
                    json: async () => ({
                        subscriber: {
                            entitlements: {
                                active: {
                                    pro: { expires_date: '2030-01-01' }
                                }
                            }
                        }
                    }),
                } as Response)
                .mockResolvedValueOnce({
                    ok: false,
                    status: 500,
                } as Response);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    agentId: 'test-agent-123',
                    revenueCatPublicKey: 'test-rc-key',
                }
            });

            expect(response.statusCode).toBe(400);
            const body = JSON.parse(response.payload);
            expect(body.allowed).toBe(false);
            expect(body.error).toContain('Failed to get 11Labs token');
        });
    });

    describe('without ElevenLabs API key', () => {
        let app: Fastify;
        const originalElevenLabsKey = process.env.ELEVENLABS_API_KEY;
        const originalNodeEnv = process.env.NODE_ENV;

        beforeAll(() => {
            delete process.env.ELEVENLABS_API_KEY;
            process.env.NODE_ENV = 'development';
        });

        afterAll(() => {
            if (originalElevenLabsKey) {
                process.env.ELEVENLABS_API_KEY = originalElevenLabsKey;
            }
            process.env.NODE_ENV = originalNodeEnv;
        });

        beforeEach(async () => {
            app = createTestApp();
            voiceRoutes(app);
            await app.ready();
        });

        afterEach(async () => {
            await app.close();
        });

        it('should return 400 when ElevenLabs API key is missing', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/voice/token',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    agentId: 'test-agent-123',
                }
            });

            expect(response.statusCode).toBe(400);
            const body = JSON.parse(response.payload);
            expect(body.allowed).toBe(false);
            expect(body.error).toBe('Missing 11Labs API key on the server');
        });
    });
});
