/**
 * Tests for CORS Middleware
 *
 * Tests the CORS configuration including origin validation logic
 * for localhost, production domains, and environment-aware handling.
 *
 * @module middleware/cors.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';

// Import the cors middleware
import { cors } from './cors';

describe('CORS Middleware', () => {
    // Store original console.warn to restore after tests
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        // Spy on console.warn to verify warning messages
        consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
        // Restore console.warn
        consoleWarnSpy.mockRestore();
    });

    /**
     * Create a Hono app with CORS middleware and environment bindings.
     *
     * @param envOverrides - Environment bindings to set on each request
     * @returns Configured Hono app for testing
     */
    function createApp(envOverrides: { ENVIRONMENT?: string } = {}) {
        const app = new Hono<{ Bindings: { ENVIRONMENT?: string } }>();

        // Middleware to inject environment bindings before CORS runs
        app.use('*', async (c, next) => {
            // Initialize c.env if undefined (happens in test environment)
            if (c.env === undefined) {
                // Cast to allow setting on c.env which may be undefined in tests
                Object.defineProperty(c, 'env', {
                    value: {},
                    writable: true,
                    configurable: true,
                });
            }
            // Set environment bindings for the request context
            if (envOverrides.ENVIRONMENT !== undefined) {
                (c.env as Record<string, unknown>).ENVIRONMENT = envOverrides.ENVIRONMENT;
            }
            await next();
        });

        // Apply CORS middleware (runs after env injection)
        app.use('*', cors());

        // Test route
        app.get('/test', (c) => {
            return c.json({ ok: true });
        });

        // POST route for method testing
        app.post('/test', (c) => {
            return c.json({ ok: true });
        });

        return app;
    }

    describe('No Origin Header', () => {
        it('should allow requests with no origin header', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'GET',
            });

            expect(res.status).toBe(200);
            // Should return * for missing origin
            expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
        });
    });

    describe('Localhost Origins', () => {
        it('should allow localhost origins', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'GET',
                headers: {
                    Origin: 'http://localhost:3000',
                },
            });

            expect(res.status).toBe(200);
            expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
                'http://localhost:3000'
            );
        });

        it('should allow 127.0.0.1 origins', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'GET',
                headers: {
                    Origin: 'http://127.0.0.1:8080',
                },
            });

            expect(res.status).toBe(200);
            expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
                'http://127.0.0.1:8080'
            );
        });

        it('should allow localhost on different ports', async () => {
            const app = createApp();

            const origins = [
                'http://localhost:5173',
                'http://localhost:19006',
                'http://localhost',
            ];

            for (const origin of origins) {
                const res = await app.request('/test', {
                    method: 'GET',
                    headers: { Origin: origin },
                });

                expect(res.status).toBe(200);
                expect(res.headers.get('Access-Control-Allow-Origin')).toBe(origin);
            }
        });
    });

    describe('Production Domains', () => {
        it('should allow happy.enflamemedia.com', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'GET',
                headers: {
                    Origin: 'https://happy.enflamemedia.com',
                },
            });

            expect(res.status).toBe(200);
            expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
                'https://happy.enflamemedia.com'
            );
        });

        it('should allow happy-dev.enflamemedia.com', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'GET',
                headers: {
                    Origin: 'https://happy-dev.enflamemedia.com',
                },
            });

            expect(res.status).toBe(200);
            expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
                'https://happy-dev.enflamemedia.com'
            );
        });

        it('should allow future happy.app domains', async () => {
            const app = createApp();

            const domains = [
                'https://happy.app',
                'https://www.happy.app',
                'https://api.happy.app',
            ];

            for (const origin of domains) {
                const res = await app.request('/test', {
                    method: 'GET',
                    headers: { Origin: origin },
                });

                expect(res.status).toBe(200);
                expect(res.headers.get('Access-Control-Allow-Origin')).toBe(origin);
            }
        });
    });

    describe('Preflight Requests', () => {
        it('should handle OPTIONS preflight requests', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'OPTIONS',
                headers: {
                    Origin: 'http://localhost:3000',
                    'Access-Control-Request-Method': 'POST',
                    'Access-Control-Request-Headers': 'Content-Type, Authorization',
                },
            });

            expect(res.status).toBe(204);
            expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
                'http://localhost:3000'
            );
            expect(res.headers.get('Access-Control-Allow-Methods')).toContain('POST');
            expect(res.headers.get('Access-Control-Allow-Headers')).toContain(
                'Content-Type'
            );
        });

        it('should include all allowed methods in preflight response', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'OPTIONS',
                headers: {
                    Origin: 'http://localhost:3000',
                    'Access-Control-Request-Method': 'DELETE',
                },
            });

            const allowedMethods = res.headers.get('Access-Control-Allow-Methods');
            expect(allowedMethods).toContain('GET');
            expect(allowedMethods).toContain('POST');
            expect(allowedMethods).toContain('PUT');
            expect(allowedMethods).toContain('DELETE');
            expect(allowedMethods).toContain('PATCH');
            expect(allowedMethods).toContain('OPTIONS');
        });

        it('should include all allowed headers in preflight response', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'OPTIONS',
                headers: {
                    Origin: 'http://localhost:3000',
                    'Access-Control-Request-Headers': 'Authorization',
                },
            });

            const allowedHeaders = res.headers.get('Access-Control-Allow-Headers');
            expect(allowedHeaders).toContain('Content-Type');
            expect(allowedHeaders).toContain('Authorization');
            expect(allowedHeaders).toContain('X-Requested-With');
            expect(allowedHeaders).toContain('X-Request-Id');
            expect(allowedHeaders).toContain('X-Client-Version');
        });

        it('should set max-age for preflight caching', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'OPTIONS',
                headers: {
                    Origin: 'http://localhost:3000',
                    'Access-Control-Request-Method': 'GET',
                },
            });

            expect(res.headers.get('Access-Control-Max-Age')).toBe('86400');
        });
    });

    describe('Credentials', () => {
        it('should allow credentials', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'GET',
                headers: {
                    Origin: 'http://localhost:3000',
                },
            });

            expect(res.headers.get('Access-Control-Allow-Credentials')).toBe('true');
        });
    });

    describe('Exposed Headers', () => {
        it('should expose configured headers', async () => {
            const app = createApp();

            const res = await app.request('/test', {
                method: 'GET',
                headers: {
                    Origin: 'http://localhost:3000',
                },
            });

            const exposedHeaders = res.headers.get('Access-Control-Expose-Headers');
            expect(exposedHeaders).toContain('Content-Length');
            expect(exposedHeaders).toContain('X-Request-Id');
            expect(exposedHeaders).toContain('X-RateLimit-Limit');
        });
    });

    describe('Environment-Aware Origin Handling', () => {
        /**
         * Test unrecognized origin handling
         * These tests cover lines 61, 66-72 of cors.ts:
         * - Line 61: c.env.ENVIRONMENT ?? 'production' (default to production)
         * - Lines 66-67: Production rejection (return null)
         * - Lines 70-72: Non-production allowance (return origin)
         */

        describe('Production Environment (ENVIRONMENT=production)', () => {
            it('should reject unrecognized origins in production', async () => {
                const app = createApp({ ENVIRONMENT: 'production' });
                const unknownOrigin = 'https://malicious-site.com';

                const res = await app.request('/test', {
                    method: 'GET',
                    headers: {
                        Origin: unknownOrigin,
                    },
                });

                // In production, unrecognized origins should be rejected (no CORS header)
                expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();

                // Verify warning was logged
                expect(consoleWarnSpy).toHaveBeenCalledWith(
                    '[CORS] Rejecting unrecognized origin:',
                    unknownOrigin
                );
            });

            it('should reject random external origins in production', async () => {
                const app = createApp({ ENVIRONMENT: 'production' });

                const maliciousOrigins = [
                    'https://attacker.com',
                    'https://phishing-site.org',
                    'https://unknown-domain.net',
                ];

                for (const origin of maliciousOrigins) {
                    const res = await app.request('/test', {
                        method: 'GET',
                        headers: { Origin: origin },
                    });

                    expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
                }
            });

            it('should still allow whitelisted origins in production', async () => {
                const app = createApp({ ENVIRONMENT: 'production' });

                const res = await app.request('/test', {
                    method: 'GET',
                    headers: {
                        Origin: 'https://happy.enflamemedia.com',
                    },
                });

                expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
                    'https://happy.enflamemedia.com'
                );
            });

            it('should still allow localhost in production for development', async () => {
                const app = createApp({ ENVIRONMENT: 'production' });

                const res = await app.request('/test', {
                    method: 'GET',
                    headers: {
                        Origin: 'http://localhost:3000',
                    },
                });

                expect(res.headers.get('Access-Control-Allow-Origin')).toBe(
                    'http://localhost:3000'
                );
            });
        });

        describe('Development Environment (ENVIRONMENT=development)', () => {
            it('should allow unrecognized origins in development', async () => {
                const app = createApp({ ENVIRONMENT: 'development' });
                const unknownOrigin = 'https://test-domain.com';

                const res = await app.request('/test', {
                    method: 'GET',
                    headers: {
                        Origin: unknownOrigin,
                    },
                });

                // In development, unrecognized origins should be allowed
                expect(res.headers.get('Access-Control-Allow-Origin')).toBe(unknownOrigin);

                // Verify warning was logged
                expect(consoleWarnSpy).toHaveBeenCalledWith(
                    '[CORS] Allowing unrecognized origin (non-production):',
                    unknownOrigin
                );
            });

            it('should allow any external origin in development for testing', async () => {
                const app = createApp({ ENVIRONMENT: 'development' });

                const testOrigins = [
                    'https://my-test-site.com',
                    'https://staging.example.org',
                    'https://preview-deploy.vercel.app',
                ];

                for (const origin of testOrigins) {
                    const res = await app.request('/test', {
                        method: 'GET',
                        headers: { Origin: origin },
                    });

                    expect(res.headers.get('Access-Control-Allow-Origin')).toBe(origin);
                }
            });
        });

        describe('Staging Environment (ENVIRONMENT=staging)', () => {
            it('should allow unrecognized origins in staging', async () => {
                const app = createApp({ ENVIRONMENT: 'staging' });
                const unknownOrigin = 'https://preview.example.com';

                const res = await app.request('/test', {
                    method: 'GET',
                    headers: {
                        Origin: unknownOrigin,
                    },
                });

                // In staging (non-production), unrecognized origins should be allowed
                expect(res.headers.get('Access-Control-Allow-Origin')).toBe(unknownOrigin);

                // Verify warning was logged
                expect(consoleWarnSpy).toHaveBeenCalledWith(
                    '[CORS] Allowing unrecognized origin (non-production):',
                    unknownOrigin
                );
            });
        });

        describe('Undefined Environment (defaults to production)', () => {
            it('should default to production behavior when ENVIRONMENT is undefined', async () => {
                // Create app without setting ENVIRONMENT - should default to production
                const app = createApp();
                const unknownOrigin = 'https://unknown-site.com';

                const res = await app.request('/test', {
                    method: 'GET',
                    headers: {
                        Origin: unknownOrigin,
                    },
                });

                // Should reject like production (line 61: c.env.ENVIRONMENT ?? 'production')
                expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();

                // Verify rejection warning was logged
                expect(consoleWarnSpy).toHaveBeenCalledWith(
                    '[CORS] Rejecting unrecognized origin:',
                    unknownOrigin
                );
            });
        });

        describe('Preflight with Environment-Aware Origins', () => {
            it('should reject preflight from unrecognized origin in production', async () => {
                const app = createApp({ ENVIRONMENT: 'production' });
                const unknownOrigin = 'https://malicious-site.com';

                const res = await app.request('/test', {
                    method: 'OPTIONS',
                    headers: {
                        Origin: unknownOrigin,
                        'Access-Control-Request-Method': 'POST',
                    },
                });

                // Preflight should not have CORS headers for rejected origin
                expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
            });

            it('should allow preflight from unrecognized origin in development', async () => {
                const app = createApp({ ENVIRONMENT: 'development' });
                const unknownOrigin = 'https://dev-testing-site.com';

                const res = await app.request('/test', {
                    method: 'OPTIONS',
                    headers: {
                        Origin: unknownOrigin,
                        'Access-Control-Request-Method': 'POST',
                    },
                });

                // Preflight should succeed for allowed origin
                expect(res.status).toBe(204);
                expect(res.headers.get('Access-Control-Allow-Origin')).toBe(unknownOrigin);
            });
        });
    });
});
