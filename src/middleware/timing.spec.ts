/**
 * Tests for Timing Middleware
 *
 * Tests the Server-Timing header generation including:
 * - X-Response-Time header format
 * - Server-Timing header with total time
 * - Custom timing entries via addServerTiming helper
 * - formatTimingEntry with description escaping
 *
 * Mutation testing targets:
 * - ConditionalExpression: if (description), if (entries), if (entries && entries.length > 0)
 * - StringLiteral: 'serverTimingEntries', 'ms', 'total', header formats
 * - ArithmeticOperator: Date.now() - start, dur.toFixed(1)
 *
 * @module middleware/timing.spec
 * @see HAP-913 - Improve middleware test quality
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { timing, addServerTiming } from './timing';

describe('Timing Middleware', () => {
    let app: Hono;

    beforeEach(() => {
        app = new Hono();
        app.use('*', timing());
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('X-Response-Time Header', () => {
        it('should add X-Response-Time header with ms suffix', async () => {
            app.get('/test', (c) => c.json({ ok: true }));

            const res = await app.request('/test');

            expect(res.status).toBe(200);
            const responseTime = res.headers.get('X-Response-Time');
            expect(responseTime).toBeDefined();
            expect(responseTime).toMatch(/^\d+ms$/);
        });

        it('should measure actual request duration', async () => {
            // Use a route that takes measurable time
            app.get('/slow', async (c) => {
                await new Promise((resolve) => setTimeout(resolve, 10));
                return c.json({ ok: true });
            });

            const res = await app.request('/slow');

            const responseTime = res.headers.get('X-Response-Time');
            const duration = parseInt(responseTime!.replace('ms', ''), 10);
            // Should be at least 10ms (our delay)
            expect(duration).toBeGreaterThanOrEqual(10);
        });

        it('should return 0ms for instant requests', async () => {
            app.get('/instant', (c) => c.text('ok'));

            const res = await app.request('/instant');

            const responseTime = res.headers.get('X-Response-Time');
            expect(responseTime).toBeDefined();
            // Duration should be a number (0 or small positive)
            const duration = parseInt(responseTime!.replace('ms', ''), 10);
            expect(duration).toBeGreaterThanOrEqual(0);
        });
    });

    describe('Server-Timing Header', () => {
        it('should include total request time in Server-Timing', async () => {
            app.get('/test', (c) => c.json({ ok: true }));

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toBeDefined();
            // Should contain total;dur=X.X;desc="Total request time"
            expect(serverTiming).toMatch(/total;dur=\d+\.\d;desc="Total request time"/);
        });

        it('should format duration with one decimal place', async () => {
            app.get('/test', (c) => c.json({ ok: true }));

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Check format: dur=X.X (exactly one decimal place)
            expect(serverTiming).toMatch(/dur=\d+\.\d[;,]/);
        });

        it('should only have total entry when no custom timings added', async () => {
            app.get('/test', (c) => c.json({ ok: true }));

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Should only have the total entry, no comma-separated additional entries
            expect(serverTiming).toMatch(/^total;dur=\d+\.\d;desc="Total request time"$/);
        });
    });

    describe('addServerTiming Helper', () => {
        it('should add custom timing entries to Server-Timing header', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'db', 15.5, 'Database query');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('total;dur=');
            expect(serverTiming).toContain('db;dur=15.5;desc="Database query"');
        });

        it('should add timing entry without description', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'cache', 2.3);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Should have cache entry without desc
            expect(serverTiming).toContain('cache;dur=2.3');
            // Should NOT have desc for cache (no description provided)
            expect(serverTiming).not.toContain('cache;dur=2.3;desc=');
        });

        it('should handle multiple timing entries', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'db', 10.0, 'Database');
                addServerTiming(c, 'cache', 2.5, 'Cache lookup');
                addServerTiming(c, 'auth', 5.0, 'Auth check');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('db;dur=10.0;desc="Database"');
            expect(serverTiming).toContain('cache;dur=2.5;desc="Cache lookup"');
            expect(serverTiming).toContain('auth;dur=5.0;desc="Auth check"');
            // All should be comma-separated
            expect(serverTiming).toContain(', ');
        });

        it('should create entries array on first call', async () => {
            app.get('/test', (c) => {
                // First call should create the array
                addServerTiming(c, 'first', 1.0);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('first;dur=1.0');
        });

        it('should push to existing entries array on subsequent calls', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'first', 1.0);
                // Second call should push to existing array
                addServerTiming(c, 'second', 2.0);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('first;dur=1.0');
            expect(serverTiming).toContain('second;dur=2.0');
        });

        it('should handle zero duration', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'instant', 0);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('instant;dur=0.0');
        });

        it('should handle very large durations', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'slow', 99999.9);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('slow;dur=99999.9');
        });

        it('should handle fractional milliseconds', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'precise', 3.14159);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Should be rounded to one decimal place
            expect(serverTiming).toContain('precise;dur=3.1');
        });
    });

    describe('Description Escaping (formatTimingEntry)', () => {
        it('should escape backslashes in description', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'path', 5.0, 'C:\\Users\\data');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Backslashes should be escaped: \ -> \\
            expect(serverTiming).toContain('path;dur=5.0;desc="C:\\\\Users\\\\data"');
        });

        it('should escape double quotes in description', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'query', 10.0, 'SELECT "id" FROM users');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Quotes should be escaped: " -> \"
            expect(serverTiming).toContain('query;dur=10.0;desc="SELECT \\"id\\" FROM users"');
        });

        it('should handle description with both backslashes and quotes', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'complex', 7.5, 'Path: C:\\temp "file"');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('complex;dur=7.5;desc="Path: C:\\\\temp \\"file\\""');
        });

        it('should handle empty description string', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'empty', 1.0, '');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Empty string is falsy, so no desc should be added
            expect(serverTiming).not.toContain('empty;dur=1.0;desc=');
        });

        it('should handle description with special characters', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'special', 3.0, 'Query: SELECT * WHERE id=1; --comment');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Special characters other than \ and " should be preserved
            expect(serverTiming).toContain('special;dur=3.0;desc="Query: SELECT * WHERE id=1; --comment"');
        });

        it('should handle description with ASCII-safe special chars', async () => {
            // Note: HTTP headers only support ASCII (RFC 7230)
            // Unicode characters would cause a ByteString conversion error
            app.get('/test', (c) => {
                addServerTiming(c, 'query', 2.0, 'User lookup - fast');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('query;dur=2.0;desc="User lookup - fast"');
        });
    });

    describe('Edge Cases', () => {
        it('should handle POST requests', async () => {
            app.post('/test', (c) => c.json({ created: true }));

            const res = await app.request('/test', { method: 'POST' });

            expect(res.headers.get('X-Response-Time')).toBeDefined();
            expect(res.headers.get('Server-Timing')).toBeDefined();
        });

        it('should handle routes that throw errors', async () => {
            app.get('/error', () => {
                throw new Error('Test error');
            });

            app.onError((err, c) => {
                return c.json({ error: err.message }, 500);
            });

            const res = await app.request('/error');

            // Headers should still be added even with error
            expect(res.headers.get('X-Response-Time')).toBeDefined();
            expect(res.headers.get('Server-Timing')).toBeDefined();
        });

        it('should work with nested routes', async () => {
            const api = new Hono();
            api.get('/users', (c) => {
                addServerTiming(c, 'nested', 1.0);
                return c.json({ users: [] });
            });
            app.route('/api', api);

            const res = await app.request('/api/users');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('nested;dur=1.0');
        });

        it('should handle text responses', async () => {
            app.get('/text', (c) => c.text('Hello'));

            const res = await app.request('/text');

            expect(res.headers.get('X-Response-Time')).toMatch(/^\d+ms$/);
            expect(res.headers.get('Server-Timing')).toContain('total');
        });

        it('should handle redirect responses', async () => {
            app.get('/redirect', (c) => c.redirect('/elsewhere'));

            const res = await app.request('/redirect');

            expect(res.headers.get('X-Response-Time')).toBeDefined();
            expect(res.headers.get('Server-Timing')).toBeDefined();
        });

        it('should handle 204 No Content responses', async () => {
            app.delete('/resource', (c) => c.body(null, 204));

            const res = await app.request('/resource', { method: 'DELETE' });

            expect(res.status).toBe(204);
            expect(res.headers.get('X-Response-Time')).toBeDefined();
            expect(res.headers.get('Server-Timing')).toBeDefined();
        });
    });

    describe('Metric Name Validation', () => {
        it('should handle lowercase metric names', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'database', 5.0);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('database;dur=5.0');
        });

        it('should handle metric names with hyphens', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'cache-miss', 3.0);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('cache-miss;dur=3.0');
        });

        it('should handle metric names with underscores', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'db_query', 4.0);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            expect(serverTiming).toContain('db_query;dur=4.0');
        });
    });

    describe('Header Format Compliance', () => {
        it('should use semicolon separators within entries', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'test', 1.0, 'Test entry');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Format: name;dur=X.X;desc="Y"
            expect(serverTiming).toMatch(/test;dur=1\.0;desc="Test entry"/);
        });

        it('should use comma and space separators between entries', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'a', 1.0);
                addServerTiming(c, 'b', 2.0);
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Entries should be separated by ", "
            expect(serverTiming).toContain(', ');
        });

        it('should quote description values', async () => {
            app.get('/test', (c) => {
                addServerTiming(c, 'test', 1.0, 'A description');
                return c.json({ ok: true });
            });

            const res = await app.request('/test');

            const serverTiming = res.headers.get('Server-Timing');
            // Description should be in quotes
            expect(serverTiming).toContain('desc="A description"');
        });
    });
});
