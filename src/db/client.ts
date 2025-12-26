/**
 * Database Client for D1
 *
 * Provides typed database access using Drizzle ORM with D1
 */

import { drizzle } from 'drizzle-orm/d1';
import { schema } from '@/db/schema';

/**
 * Create a typed Drizzle database client from D1 instance
 *
 * @param d1 - Cloudflare D1 database instance from environment bindings
 * @returns Typed Drizzle database client with relational query API
 *
 * @example
 * ```typescript
 * import { getDb } from '@/db/client';
 *
 * export default {
 *     async fetch(request: Request, env: Env) {
 *         const db = getDb(env.DB);
 *
 *         // Use relational queries
 *         const accounts = await db.query.accounts.findMany({
 *             with: {
 *                 sessions: true,
 *                 machines: true,
 *             },
 *         });
 *
 *         return Response.json(accounts);
 *     },
 * };
 * ```
 */
export function getDb(d1: D1Database) {
    return drizzle(d1, { schema });
}

/**
 * Database client type for use in function signatures
 */
export type DbClient = ReturnType<typeof getDb>;
