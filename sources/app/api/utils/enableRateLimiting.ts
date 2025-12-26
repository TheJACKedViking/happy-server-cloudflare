import fastifyRateLimit from "@fastify/rate-limit";
import { log } from "@/utils/log";
import { redis } from "@/storage/redis";
import { Fastify } from "../types";

/**
 * Rate limit tier configuration for endpoint protection.
 *
 * Tiers are based on endpoint cost analysis:
 * - CRITICAL: External paid APIs (ElevenLabs, RevenueCat) - strictest limits
 * - HIGH: Auth/crypto operations + database writes
 * - MEDIUM: List endpoints, paginated queries (global default)
 * - LOW: Simple reads, health checks
 *
 * @remarks
 * Each tier can be applied per-route via route config:
 * ```ts
 * app.get('/endpoint', {
 *   config: { rateLimit: RateLimitTiers.HIGH }
 * }, handler)
 * ```
 */
export const RateLimitTiers = {
    /** External paid APIs (5 req/min) - ElevenLabs voice tokens, etc. */
    CRITICAL: { max: 5, timeWindow: "1 minute" },
    /** Auth endpoints, DB writes (30 req/min) */
    HIGH: { max: 30, timeWindow: "1 minute" },
    /** List/pagination endpoints (60 req/min) - global default */
    MEDIUM: { max: 60, timeWindow: "1 minute" },
    /** Simple reads (120 req/min) */
    LOW: { max: 120, timeWindow: "1 minute" },
} as const;

/** Type for rate limit tier values */
export type RateLimitTier = (typeof RateLimitTiers)[keyof typeof RateLimitTiers];

/**
 * Enables distributed rate limiting with Redis backend.
 *
 * Features:
 * - Redis-backed for consistency across multiple server instances
 * - Custom key generator: uses userId for authenticated requests, IP fallback
 * - Graceful degradation: continues without rate limiting if Redis fails
 * - Standard rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, etc.)
 * - Monitoring callbacks for abuse detection
 *
 * @param app - Fastify instance
 */
export async function enableRateLimiting(app: Fastify) {
    // Skip rate limiting in test environment
    if (process.env.NODE_ENV === "test") {
        log({ module: "rate-limit" }, "Rate limiting disabled in test environment");
        return;
    }

    await app.register(fastifyRateLimit, {
        global: true,
        max: RateLimitTiers.MEDIUM.max, // Default: 60/min
        timeWindow: RateLimitTiers.MEDIUM.timeWindow,

        // Redis store for distributed rate limiting
        // Uses existing Redis connection from storage/redis.ts
        redis: redis,

        // Custom key generator: userId if authenticated, IP otherwise
        keyGenerator: (request) => {
            // Use userId from JWT if authenticated (set by enableAuthentication)
            if (request.userId) {
                return `user:${request.userId}`;
            }
            // Fall back to IP address for unauthenticated requests
            return request.ip;
        },

        // Skip rate limiting if Redis fails (graceful degradation)
        // This ensures API availability even during Redis outages
        skipOnError: true,

        // Enable IETF draft spec headers for standardization
        // Uses lowercase headers: x-ratelimit-limit, x-ratelimit-remaining, x-ratelimit-reset
        enableDraftSpec: true,

        // Add rate limit headers to responses approaching limit
        addHeadersOnExceeding: {
            "x-ratelimit-limit": true,
            "x-ratelimit-remaining": true,
            "x-ratelimit-reset": true,
        },

        // Add all headers when limit is reached/exceeded
        addHeaders: {
            "x-ratelimit-limit": true,
            "x-ratelimit-remaining": true,
            "x-ratelimit-reset": true,
            "retry-after": true,
        },

        // Monitoring callbacks for abuse detection and logging
        onExceeding: (request, key) => {
            log(
                { module: "rate-limit", level: "warn" },
                `Rate limit approaching for ${key}: ${request.method} ${request.url}`
            );
        },
        onExceeded: (request, key) => {
            log(
                { module: "rate-limit", level: "warn" },
                `Rate limit exceeded for ${key}: ${request.method} ${request.url}`
            );
        },

        // Custom 429 error response with clear retry guidance
        errorResponseBuilder: (_request, context) => ({
            statusCode: 429,
            error: "Too Many Requests",
            message: `Rate limit exceeded, retry in ${Math.ceil(context.ttl / 1000)} seconds`,
            retryAfter: Math.ceil(context.ttl / 1000),
        }),
    });

    log({ module: "rate-limit" }, "Rate limiting enabled (Redis-backed)");
}
