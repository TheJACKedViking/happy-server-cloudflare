import type { Context, MiddlewareHandler } from 'hono';

/**
 * Context key for storing timing entries during request processing.
 * Route handlers can add timing entries via `addServerTiming()` helper.
 *
 * @example
 * ```typescript
 * // In a route handler:
 * addServerTiming(c, 'db', Date.now() - dbStart, 'Database query');
 * ```
 */
const TIMING_ENTRIES_KEY = 'serverTimingEntries';

/**
 * Represents a single Server-Timing metric entry.
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing}
 */
interface ServerTimingEntry {
    /** Metric name (lowercase, no spaces) */
    name: string;
    /** Duration in milliseconds */
    dur: number;
    /** Human-readable description (optional) */
    desc?: string;
}

/**
 * Add a timing entry to the Server-Timing header.
 *
 * @param c - Hono context
 * @param name - Metric name (e.g., 'db', 'cache', 'auth')
 * @param duration - Duration in milliseconds
 * @param description - Optional human-readable description
 *
 * @remarks
 * Call this from route handlers to add timing information for specific operations.
 * All entries will be collected and sent in the Server-Timing response header.
 *
 * @example
 * ```typescript
 * const dbStart = Date.now();
 * const result = await c.env.DB.prepare('SELECT * FROM users').first();
 * addServerTiming(c, 'db', Date.now() - dbStart, 'User lookup');
 * ```
 */
export function addServerTiming(
    c: Context,
    name: string,
    duration: number,
    description?: string
): void {
    const entries = c.get(TIMING_ENTRIES_KEY) as ServerTimingEntry[] | undefined;
    const entry: ServerTimingEntry = { name, dur: duration };
    if (description) {
        entry.desc = description;
    }
    if (entries) {
        entries.push(entry);
    } else {
        c.set(TIMING_ENTRIES_KEY, [entry]);
    }
}

/**
 * Format a Server-Timing entry to the header value format.
 *
 * @param entry - The timing entry to format
 * @returns Formatted string (e.g., 'db;dur=45.2;desc="Database query"')
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing}
 */
function formatTimingEntry(entry: ServerTimingEntry): string {
    let result = entry.name;
    result += `;dur=${entry.dur.toFixed(1)}`;
    if (entry.desc) {
        // Quote description if it contains special characters
        result += `;desc="${entry.desc.replace(/"/g, '\\"')}"`;
    }
    return result;
}

/**
 * Timing middleware for performance monitoring.
 *
 * @remarks
 * Adds standard performance timing headers to all responses:
 *
 * - `X-Response-Time`: Total request duration in milliseconds (e.g., "42.5ms")
 * - `Server-Timing`: Detailed breakdown of internal operations using W3C Server-Timing format
 *
 * The `Server-Timing` header is viewable in browser DevTools (Network tab > Timing),
 * making it excellent for debugging performance without exposing sensitive data.
 *
 * @returns Hono middleware handler
 *
 * @example
 * ```typescript
 * // In app initialization:
 * app.use('*', timing());
 *
 * // In route handlers, add timing entries:
 * import { addServerTiming } from '@/middleware/timing';
 *
 * app.get('/users/:id', async (c) => {
 *     const start = Date.now();
 *     const user = await db.query(...);
 *     addServerTiming(c, 'db', Date.now() - start, 'User fetch');
 *     return c.json(user);
 * });
 * ```
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing}
 * @see {@link https://w3c.github.io/server-timing/}
 */
export const timing = (): MiddlewareHandler => {
    return async (c, next) => {
        // Capture start time with high precision
        const start = Date.now();

        // Execute the request handler chain
        await next();

        // Calculate total response time
        const duration = Date.now() - start;

        // Add X-Response-Time header (widely supported, simple format)
        c.header('X-Response-Time', `${duration}ms`);

        // Collect all Server-Timing entries added during request processing
        const entries = c.get(TIMING_ENTRIES_KEY) as ServerTimingEntry[] | undefined;

        // Build Server-Timing header value
        const timingParts: string[] = [];

        // Always include total request time
        timingParts.push(`total;dur=${duration.toFixed(1)};desc="Total request time"`);

        // Add any entries from route handlers
        if (entries && entries.length > 0) {
            for (const entry of entries) {
                timingParts.push(formatTimingEntry(entry));
            }
        }

        // Add Server-Timing header (W3C standard, visible in browser DevTools)
        c.header('Server-Timing', timingParts.join(', '));
    };
};
