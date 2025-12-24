/**
 * Unit Tests for Environment Validation (HAP-523)
 *
 * Tests the environment validation middleware and /ready endpoint integration:
 * - 500 response when HAPPY_MASTER_SECRET is missing
 * - 500 response when DB binding is missing
 * - Structured JSON error response format with documentation link
 * - /ready endpoint returns 503 when configuration is invalid
 * - /health endpoint works without valid configuration (liveness check)
 * - Normal operation with valid configuration
 *
 * @module __tests__/env-validation.spec
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { validateEnv, getMasterSecret, resetDeprecationWarning } from '@/config/env';

describe('Environment Validation', () => {
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        // Reset deprecation warning state between tests
        resetDeprecationWarning();

        // Spy on console methods to verify logging
        vi.spyOn(console, 'error').mockImplementation(() => {});
        consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('validateEnv function', () => {
        it('should throw when HAPPY_MASTER_SECRET is missing', () => {
            const env = {
                DB: {} as D1Database,
            };

            expect(() => validateEnv(env)).toThrow('HAPPY_MASTER_SECRET is required');
        });

        it('should throw when DB binding is missing', () => {
            const env = {
                HAPPY_MASTER_SECRET: 'test-secret-32-bytes-long-enough',
            };

            expect(() => validateEnv(env)).toThrow('DB (D1 binding) is required');
        });

        it('should return true with valid configuration', () => {
            const env = {
                HAPPY_MASTER_SECRET: 'test-secret-32-bytes-long-enough',
                DB: {} as D1Database,
            };

            expect(validateEnv(env)).toBe(true);
        });

        it('should accept HANDY_MASTER_SECRET with deprecation warning', () => {
            const env = {
                HANDY_MASTER_SECRET: 'legacy-secret-32-bytes-long-enough',
                DB: {} as D1Database,
            };

            expect(validateEnv(env)).toBe(true);
            expect(consoleWarnSpy).toHaveBeenCalledWith(
                expect.stringContaining('HANDY_MASTER_SECRET is deprecated')
            );
        });

        it('should prefer HAPPY_MASTER_SECRET over HANDY_MASTER_SECRET', () => {
            const env = {
                HAPPY_MASTER_SECRET: 'new-secret',
                HANDY_MASTER_SECRET: 'old-secret',
                DB: {} as D1Database,
            };

            expect(validateEnv(env)).toBe(true);
            // No deprecation warning when HAPPY_MASTER_SECRET is present
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });
    });

    describe('getMasterSecret function', () => {
        it('should return undefined when env is undefined', () => {
            expect(getMasterSecret(undefined)).toBeUndefined();
        });

        it('should return undefined when neither secret is set', () => {
            expect(getMasterSecret({})).toBeUndefined();
        });

        it('should return HAPPY_MASTER_SECRET when set', () => {
            const env = { HAPPY_MASTER_SECRET: 'my-secret' };
            expect(getMasterSecret(env)).toBe('my-secret');
        });

        it('should return HANDY_MASTER_SECRET when HAPPY_MASTER_SECRET is not set', () => {
            const env = { HANDY_MASTER_SECRET: 'legacy-secret' };
            expect(getMasterSecret(env)).toBe('legacy-secret');
        });

        it('should log deprecation warning only once for HANDY_MASTER_SECRET', () => {
            const env = { HANDY_MASTER_SECRET: 'legacy-secret' };

            getMasterSecret(env);
            getMasterSecret(env);
            getMasterSecret(env);

            // Warning should only be logged once per Worker instance
            expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
        });
    });

    describe('Error Response Format', () => {
        it('should throw error with setup instructions for missing secret', () => {
            const env = { DB: {} as D1Database };

            try {
                validateEnv(env);
                expect.fail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                const message = (error as Error).message;

                // Verify error includes actionable instructions
                expect(message).toContain('HAPPY_MASTER_SECRET is required');
                expect(message).toContain('openssl rand -hex 32');
                expect(message).toContain('.dev.vars');
                expect(message).toContain('wrangler secret put');
                expect(message).toContain('docs/SECRETS.md');
            }
        });

        it('should throw error with wrangler.toml instructions for missing DB', () => {
            const env = { HAPPY_MASTER_SECRET: 'test-secret' };

            try {
                validateEnv(env);
                expect.fail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                const message = (error as Error).message;

                // Verify error includes actionable instructions
                expect(message).toContain('DB (D1 binding) is required');
                expect(message).toContain('wrangler.toml');
                expect(message).toContain('d1_databases');
                expect(message).toContain('wrangler d1 create');
            }
        });
    });

    describe('Middleware Integration', () => {
        it('should return 500 with structured JSON when secret is missing', async () => {
            const app = new Hono<{ Bindings: { DB?: D1Database } }>();

            // Add validation middleware (simulating index.ts behavior)
            app.use('*', async (c, next): Promise<Response | void> => {
                if (c.req.path === '/health') {
                    await next();
                    return;
                }

                try {
                    validateEnv(c.env);
                } catch (error) {
                    const message = error instanceof Error ? error.message : 'Invalid configuration';
                    return c.json(
                        {
                            error: 'Configuration Error',
                            message,
                            docs: 'https://github.com/Enflame-Media/happy-server-workers/blob/main/docs/SECRETS.md',
                            timestamp: new Date().toISOString(),
                        },
                        500
                    );
                }
                await next();
            });

            app.get('/api/test', (c) => c.json({ ok: true }));
            app.get('/health', (c) => c.json({ status: 'healthy' }));

            // Test that API route returns 500 without secret
            const res = await app.request('/api/test', undefined, {
                DB: {} as D1Database,
            });
            const body = (await res.json()) as {
                error: string;
                message: string;
                docs: string;
                timestamp: string;
            };

            expect(res.status).toBe(500);
            expect(body.error).toBe('Configuration Error');
            expect(body.message).toContain('HAPPY_MASTER_SECRET is required');
            expect(body.docs).toContain('docs/SECRETS.md');
            expect(body.timestamp).toBeDefined();
        });

        it('should allow /health endpoint without valid configuration', async () => {
            const app = new Hono<{ Bindings: { DB?: D1Database } }>();

            // Add validation middleware that skips /health
            app.use('*', async (c, next): Promise<Response | void> => {
                if (c.req.path === '/health') {
                    await next();
                    return;
                }

                try {
                    validateEnv(c.env);
                } catch {
                    return c.json({ error: 'Configuration Error' }, 500);
                }
                await next();
            });

            app.get('/health', (c) => c.json({ status: 'healthy' }));

            // Test that /health works without any configuration
            const res = await app.request('/health', undefined, {});
            const body = (await res.json()) as { status: string };

            expect(res.status).toBe(200);
            expect(body.status).toBe('healthy');
        });

        it('should pass through with valid configuration', async () => {
            const app = new Hono<{
                Bindings: { HAPPY_MASTER_SECRET?: string; DB?: D1Database };
            }>();

            app.use('*', async (c, next): Promise<Response | void> => {
                try {
                    validateEnv(c.env);
                } catch {
                    return c.json({ error: 'Configuration Error' }, 500);
                }
                await next();
            });

            app.get('/api/test', (c) => c.json({ ok: true }));

            const res = await app.request('/api/test', undefined, {
                HAPPY_MASTER_SECRET: 'test-secret-32-bytes-long',
                DB: {} as D1Database,
            });
            const body = (await res.json()) as { ok: boolean };

            expect(res.status).toBe(200);
            expect(body.ok).toBe(true);
        });
    });

    describe('/ready Endpoint Integration', () => {
        it('should include environment check in /ready response', async () => {
            const app = new Hono<{
                Bindings: { HAPPY_MASTER_SECRET?: string; DB?: D1Database };
            }>();

            // Simulate the /ready endpoint behavior
            app.get('/ready', async (c) => {
                let envValid = true;
                let envError: string | null = null;

                try {
                    validateEnv(c.env);
                } catch (error) {
                    envValid = false;
                    envError = error instanceof Error ? error.message : 'Invalid configuration';
                }

                const checks = {
                    environment: envValid,
                    database: true, // Simulated for this test
                };

                const isReady = Object.values(checks).every(Boolean);

                const response: {
                    ready: boolean;
                    checks: Record<string, boolean>;
                    timestamp: string;
                    error?: string;
                    docs?: string;
                } = {
                    ready: isReady,
                    checks,
                    timestamp: new Date().toISOString(),
                };

                if (!envValid && envError) {
                    response.error = envError;
                    response.docs =
                        'https://github.com/Enflame-Media/happy-server-workers/blob/main/docs/SECRETS.md';
                }

                return c.json(response, isReady ? 200 : 503);
            });

            // Test with missing secret
            const res = await app.request('/ready', undefined, {
                DB: {} as D1Database,
            });
            const body = (await res.json()) as {
                ready: boolean;
                checks: { environment: boolean };
                error?: string;
                docs?: string;
            };

            expect(res.status).toBe(503);
            expect(body.ready).toBe(false);
            expect(body.checks.environment).toBe(false);
            expect(body.error).toContain('HAPPY_MASTER_SECRET is required');
            expect(body.docs).toContain('docs/SECRETS.md');
        });

        it('should return 200 from /ready with valid configuration', async () => {
            const app = new Hono<{
                Bindings: { HAPPY_MASTER_SECRET?: string; DB?: D1Database };
            }>();

            app.get('/ready', async (c) => {
                let envValid = true;
                try {
                    validateEnv(c.env);
                } catch {
                    envValid = false;
                }

                const checks = {
                    environment: envValid,
                    database: true,
                };

                const isReady = Object.values(checks).every(Boolean);

                return c.json(
                    {
                        ready: isReady,
                        checks,
                        timestamp: new Date().toISOString(),
                    },
                    isReady ? 200 : 503
                );
            });

            const res = await app.request('/ready', undefined, {
                HAPPY_MASTER_SECRET: 'test-secret-32-bytes',
                DB: {} as D1Database,
            });
            const body = (await res.json()) as {
                ready: boolean;
                checks: { environment: boolean };
            };

            expect(res.status).toBe(200);
            expect(body.ready).toBe(true);
            expect(body.checks.environment).toBe(true);
        });
    });
});
