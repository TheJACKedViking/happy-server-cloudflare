/**
 * Worker-Compatible ID Generation
 *
 * This module provides ID generation that works within Cloudflare Workers.
 * Unlike @paralleldrive/cuid2, this implementation does NOT call crypto.getRandomValues()
 * at module initialization time, which would cause "Disallowed operation called within
 * global scope" errors in Workers.
 *
 * Uses crypto.randomUUID() which is available in handler context and produces
 * UUIDs that are:
 * - 36 characters (with hyphens) or 32 characters (without)
 * - Cryptographically random
 * - Compatible with database text columns
 *
 * @module utils/id
 */

/**
 * Generate a unique ID using crypto.randomUUID()
 *
 * This is a drop-in replacement for @paralleldrive/cuid2's createId().
 * The generated IDs are standard UUIDs without hyphens (32 characters).
 *
 * @example
 * ```typescript
 * import { createId } from '@/utils/id';
 *
 * const sessionId = createId(); // e.g., "a1b2c3d4e5f6789012345678901234ab"
 * ```
 *
 * @returns A unique 32-character hexadecimal string (UUID without hyphens)
 */
export function createId(): string {
    // crypto.randomUUID() is safe to call in handler context on Cloudflare Workers
    // It returns a UUID like "a1b2c3d4-e5f6-7890-1234-567890123456"
    // We remove hyphens for a cleaner 32-character ID
    return crypto.randomUUID().replace(/-/g, '');
}
