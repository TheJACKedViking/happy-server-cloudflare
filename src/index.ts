import { OpenAPIHono } from '@hono/zod-openapi';
import { logger } from '@/middleware/logger';
import { cors } from '@/middleware/cors';
import { timing, addServerTiming } from '@/middleware/timing';
import { errorHandler } from '@/middleware/error';
import { initAuth } from '@/lib/auth';
import authRoutes from '@/routes/auth';
import testRoutes from '@/routes/test/privacy-kit-test';
import sessionsRoutes from '@/routes/sessions';
import machinesRoutes from '@/routes/machines';
import artifactsRoutes from '@/routes/artifacts';
import accessKeysRoutes from '@/routes/accessKeys';
import connectRoutes from '@/routes/connect';
import accountRoutes from '@/routes/account';
import userRoutes from '@/routes/user';
import feedRoutes from '@/routes/feed';
import versionRoutes from '@/routes/version';
import devRoutes from '@/routes/dev';
import voiceRoutes from '@/routes/voice';
import kvRoutes from '@/routes/kv';
import pushRoutes from '@/routes/push';
import websocketRoutes from '@/routes/websocket';
import uploadRoutes from '@/routes/uploads';
import usageRoutes from '@/routes/usage';

// Export Durable Object classes for Cloudflare Workers
// These must be exported from the main entry point for Wrangler to detect them
export { ConnectionManager } from '@/durable-objects';

/**
 * Environment bindings interface for Cloudflare Workers
 *
 * @remarks
 * Define all environment variables and secrets here for type safety.
 * Access via `c.env` in route handlers, not `process.env`.
 */
interface Env {
    /**
     * Current deployment environment
     * @default 'production'
     */
    ENVIRONMENT?: 'development' | 'staging' | 'production';

    /**
     * D1 Database binding
     * @required
     */
    DB: D1Database;

    /**
     * Master secret for token generation/verification
     * @required Must be set via wrangler secret in production
     */
    HANDY_MASTER_SECRET: string;

    /**
     * Test secret for privacy-kit integration tests
     * @optional Only used in test routes
     */
    TEST_AUTH_SECRET?: string;

    /**
     * ConnectionManager Durable Object namespace
     * @required for WebSocket functionality (HAP-16)
     */
    CONNECTION_MANAGER: DurableObjectNamespace;

    /**
     * R2 bucket for file uploads
     * @required for file storage functionality (HAP-5)
     */
    UPLOADS: R2Bucket;

    /**
     * KV namespace for rate limiting
     * @optional - rate limiting gracefully degrades if not configured (HAP-409)
     */
    RATE_LIMIT_KV?: KVNamespace;
}

/**
 * Application version (should match package.json)
 */
const APP_VERSION = '0.0.0';

/**
 * Main Hono application instance with OpenAPI support
 * Configured with typed environment bindings for Cloudflare Workers
 */
const app = new OpenAPIHono<{ Bindings: Env }>();

/*
 * Global Middleware
 * Applied in order: timing → logging → CORS → auth initialization → routes → error handling
 */
app.use('*', timing());
app.use('*', logger());
app.use('*', cors());

/*
 * Initialize auth module on every request
 * In Cloudflare Workers, we need to initialize per-request due to stateless nature
 * Skip initialization in test environments where HANDY_MASTER_SECRET might not be set
 */
app.use('*', async (c, next) => {
    const secret = c.env?.HANDY_MASTER_SECRET;
    if (secret) {
        // Debug: Log secret info (NOT the actual secret, just metadata)
        console.log('[Auth Init] Secret present, length:', secret.length, 'first 4 chars:', secret.substring(0, 4) + '...');
        await initAuth(secret);
    } else {
        console.error('[Auth Init] WARNING: HANDY_MASTER_SECRET is NOT SET!');
    }
    await next();
});

/*
 * API Routes
 */

// Mount authentication routes
app.route('/', authRoutes);

// Mount core API routes (HAP-13)
app.route('/', sessionsRoutes);
app.route('/', machinesRoutes);
app.route('/', artifactsRoutes);
app.route('/', accessKeysRoutes);
app.route('/', connectRoutes);

// Mount user profile and social routes (HAP-14)
app.route('/', accountRoutes);
app.route('/', userRoutes);
app.route('/', feedRoutes);

// Mount utility and specialized routes (HAP-15)
app.route('/', versionRoutes);
app.route('/', devRoutes);
app.route('/', voiceRoutes);
app.route('/', kvRoutes);
app.route('/', pushRoutes);

// Mount WebSocket routes (HAP-16: Durable Objects foundation)
// These routes handle WebSocket upgrades and forward to ConnectionManager DO
app.route('/', websocketRoutes);

// Mount file upload routes (HAP-5: R2 Storage)
app.route('/', uploadRoutes);

// Mount usage routes (HAP-302: Usage query endpoint)
app.route('/', usageRoutes);

// Mount test routes
app.route('/test', testRoutes);

/**
 * Root endpoint - API information
 * @route GET /
 * @returns API welcome message with version and environment
 */
app.get('/', (c) => {
    return c.json({
        message: 'Welcome to Happy Server on Cloudflare Workers!',
        version: APP_VERSION,
        environment: c.env?.ENVIRONMENT ?? 'production',
        timestamp: new Date().toISOString(),
    });
});

/**
 * Health check endpoint
 * @route GET /health
 * @returns Service health status
 *
 * @remarks
 * Used by monitoring systems and load balancers to verify service availability.
 * Should always return 200 if the service is running.
 */
app.get('/health', (c) => {
    return c.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: APP_VERSION,
    });
});

/**
 * Readiness check endpoint
 * @route GET /ready
 * @returns Service readiness status with per-dependency check results
 *
 * @remarks
 * Indicates whether the service is ready to accept traffic.
 * Different from /health - this checks actual dependencies.
 *
 * Checks performed (HAP-412, HAP-416):
 * - database: D1 database connectivity
 * - storage: R2 bucket accessibility
 * - durableObjects: ConnectionManager DO instantiation
 * - kv: Rate limit KV namespace (conditional, omitted if not configured)
 *
 * All checks run in parallel for optimal latency.
 * Returns 200 when all checks pass, 503 when any check fails.
 */
app.get('/ready', async (c) => {
    // Helper to wrap async operations with timing measurement
    const timed = async <T>(
        name: string,
        description: string,
        operation: () => Promise<T>
    ): Promise<T> => {
        const start = Date.now();
        try {
            return await operation();
        } finally {
            addServerTiming(c, name, Date.now() - start, description);
        }
    };

    // Durable Object health check (HAP-416)
    // Instantiate a dedicated health-check DO instance and call its /health endpoint
    // This verifies the DO namespace is functional without affecting real connections
    const doHealthCheck = async (): Promise<boolean> => {
        const doId = c.env.CONNECTION_MANAGER.idFromName('health-check');
        const stub = c.env.CONNECTION_MANAGER.get(doId);
        const response = await stub.fetch(new Request('http://internal/health'));
        return response.ok;
    };

    // KV health check (HAP-416) - conditional on KV being configured
    // Returns null if KV not configured (allows graceful degradation)
    const kvHealthCheck = async (): Promise<boolean | null> => {
        if (!c.env.RATE_LIMIT_KV) {
            return null; // KV not configured, skip check
        }
        // KV.get returns null for non-existent keys without throwing
        await c.env.RATE_LIMIT_KV.get('_health_check');
        return true;
    };

    // Run all checks in parallel using Promise.allSettled for fault isolation
    // Each check is timed and reported via Server-Timing header (HAP-476)
    const [dbResult, r2Result, doResult, kvResult] = await Promise.allSettled([
        timed('db', 'D1 database', () => c.env.DB.prepare('SELECT 1').first()),
        timed('r2', 'R2 storage', () => c.env.UPLOADS.list({ limit: 1 })),
        timed('do', 'Durable Objects', doHealthCheck),
        timed('kv', 'KV namespace', kvHealthCheck),
    ] as const);

    // Build checks object with all dependency statuses
    const checks: Record<string, boolean | null> = {
        database: dbResult.status === 'fulfilled',
        storage: r2Result.status === 'fulfilled',
        durableObjects: doResult.status === 'fulfilled' && doResult.value === true,
    };

    // KV check is null if not configured (graceful degradation)
    if (kvResult.status === 'fulfilled' && kvResult.value !== null) {
        checks.kv = kvResult.value === true;
    } else if (kvResult.status === 'rejected') {
        checks.kv = false;
    }
    // If kvResult.value is null, omit kv from checks (not configured)

    // Service is ready if all configured checks pass
    // null values (unconfigured dependencies) are excluded from readiness calculation
    const isReady = Object.values(checks)
        .filter((v): v is boolean => v !== null)
        .every(Boolean);

    return c.json(
        {
            ready: isReady,
            checks,
            timestamp: new Date().toISOString(),
        },
        isReady ? 200 : 503
    );
});

/*
 * Error Handling
 * Must be registered last to catch all errors from routes
 */
app.onError(errorHandler);

/*
 * 404 Handler
 * Catches all unmatched routes
 */
app.notFound((c) => {
    // Use flat error format for consistency with route handlers
    return c.json({ error: `Not found: ${c.req.path}` }, 404);
});

/*
 * OpenAPI 3.1 Documentation
 * Serves the complete API specification at /openapi.json
 */
app.doc('/openapi.json', {
    openapi: '3.1.0',
    info: {
        version: APP_VERSION,
        title: 'Happy Server API',
        description: 'Cloudflare Workers API for Happy - Remote Claude Code/Codex control with end-to-end encryption',
    },
    servers: [
        {
            url: 'https://api.happy.example.com',
            description: 'Production server',
        },
        {
            url: 'http://localhost:8787',
            description: 'Local development server',
        },
    ],
});

/**
 * Export the Hono app as default for Cloudflare Workers
 */
export default app;
