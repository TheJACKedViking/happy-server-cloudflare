import { z } from "zod";
import { type Fastify } from "../types";
import { db } from "@/storage/db";
import { redis } from "@/storage/redis";
import { s3client, s3bucket } from "@/storage/files";
import { checkEnv } from "@/utils/validateEnv";

/**
 * Health check response schema
 *
 * @remarks
 * Structured JSON response matching happy-server-workers format for consistency.
 * Includes per-dependency status and overall readiness.
 */
const HealthResponseSchema = z.object({
    status: z.enum(['healthy', 'unhealthy']),
    timestamp: z.string(),
    version: z.string(),
});

const ReadyResponseSchema = z.object({
    ready: z.boolean(),
    checks: z.object({
        environment: z.boolean(),
        database: z.boolean(),
        redis: z.boolean(),
        storage: z.boolean(),
    }),
    timestamp: z.string(),
    error: z.string().optional(),
});

/**
 * Health check routes for monitoring and load balancer integration
 *
 * Provides two endpoints:
 * - GET /health: Basic liveness check (always returns 200 if server is running)
 * - GET /ready: Readiness check with per-dependency status
 *
 * @remarks
 * These endpoints are unauthenticated to allow external monitoring systems
 * to verify service health without credentials.
 */
export function healthRoutes(app: Fastify) {
    /**
     * Basic liveness check
     *
     * Used by monitoring systems and load balancers to verify the service is running.
     * Always returns 200 if the server can respond to HTTP requests.
     *
     * @route GET /health
     */
    app.get('/health', {
        config: {
            rateLimit: false  // Health checks exempt from rate limiting for monitoring systems
        },
        schema: {
            response: {
                200: HealthResponseSchema
            }
        }
    }, async (_request, reply) => {
        reply.send({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            version: process.env.npm_package_version ?? '0.0.0',
        });
    });

    /**
     * Readiness check with dependency verification
     *
     * Checks all downstream dependencies to determine if the service is ready
     * to accept traffic. Returns 200 when all checks pass, 503 otherwise.
     *
     * Checks performed:
     * - environment: Configuration validation (required env vars)
     * - database: PostgreSQL connectivity via Prisma
     * - redis: Redis connectivity via ioredis
     * - storage: S3/MinIO bucket accessibility
     *
     * @route GET /ready
     */
    app.get('/ready', {
        config: {
            rateLimit: false  // Readiness checks exempt from rate limiting for orchestration
        },
        schema: {
            response: {
                200: ReadyResponseSchema,
                503: ReadyResponseSchema
            }
        }
    }, async (_request, reply) => {
        // Environment validation check
        const envResult = checkEnv();
        const envValid = envResult.valid;

        // Run all dependency checks in parallel for optimal latency
        const [dbResult, redisResult, storageResult] = await Promise.allSettled([
            // PostgreSQL health check via Prisma raw query
            db.$queryRaw`SELECT 1 as ok`,
            // Redis health check via PING command
            redis.ping(),
            // S3/MinIO health check via bucket existence
            s3client.bucketExists(s3bucket),
        ]);

        const checks = {
            environment: envValid,
            database: dbResult.status === 'fulfilled',
            redis: redisResult.status === 'fulfilled' && redisResult.value === 'PONG',
            storage: storageResult.status === 'fulfilled' && storageResult.value === true,
        };

        const isReady = Object.values(checks).every(Boolean);

        const response: z.infer<typeof ReadyResponseSchema> = {
            ready: isReady,
            checks,
            timestamp: new Date().toISOString(),
        };

        // Include error details if environment validation failed
        if (!envValid) {
            response.error = `Missing required environment variables: ${envResult.missingRequired.join(', ')}`;
        }

        reply.status(isReady ? 200 : 503).send(response);
    });
}
