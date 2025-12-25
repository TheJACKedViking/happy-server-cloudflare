import { OpenAPIHono } from '@hono/zod-openapi';
import { logger } from '@/middleware/logger';
import { cors } from '@/middleware/cors';
import { timing, addServerTiming } from '@/middleware/timing';
import { errorHandler } from '@/middleware/error';
import { initAuth, cleanupExpiredTokens } from '@/lib/auth';
import { getMasterSecret, validateEnv } from '@/config/env';
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
import analyticsRoutes from '@/routes/analytics';

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
     * Master secret for token generation/verification (preferred)
     * @required Must be set via wrangler secret in production
     */
    HAPPY_MASTER_SECRET?: string;

    /**
     * Master secret for token generation/verification (deprecated)
     * @deprecated Use HAPPY_MASTER_SECRET instead. This will be removed in a future version.
     */
    HANDY_MASTER_SECRET?: string;

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

    /**
     * Analytics Engine dataset for sync metrics (HAP-546)
     * Used to store sync performance metrics for analysis
     * @optional - metrics are silently dropped if not configured
     */
    SYNC_METRICS?: AnalyticsEngineDataset;
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
 * Applied in order: timing → logging → CORS → env validation → auth initialization → routes → error handling
 */
app.use('*', timing());
app.use('*', logger());
app.use('*', cors());

/*
 * Environment validation middleware (HAP-523)
 * Validates required configuration before processing any routes.
 * Returns structured JSON error response with documentation link.
 * Skip validation for health endpoint (allows monitoring when misconfigured).
 */
app.use('*', async (c, next): Promise<Response | void> => {
    // Allow /health endpoint even without configuration (for basic liveness checks)
    if (c.req.path === '/health') {
        await next();
        return;
    }

    try {
        validateEnv(c.env);
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid environment configuration';
        console.error('[Config Error]', message);

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

/*
 * Initialize auth module on every request
 * In Cloudflare Workers, we need to initialize per-request due to stateless nature
 * Skip initialization in test environments where master secret might not be set
 */
app.use('*', async (c, next) => {
    const secret = getMasterSecret(c.env);
    if (secret) {
        // Debug: Log secret info (NOT the actual secret, just metadata)
        console.log('[Auth Init] Secret present, length:', secret.length, 'first 4 chars:', secret.substring(0, 4) + '...');
        await initAuth(secret);
    } else {
        console.error('[Auth Init] WARNING: HAPPY_MASTER_SECRET is NOT SET!');
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

// Mount analytics routes (HAP-546: Sync metrics ingestion)
app.route('/', analyticsRoutes);

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
 * Checks performed (HAP-412, HAP-416, HAP-523):
 * - environment: Configuration validation (HAPPY_MASTER_SECRET, DB binding)
 * - database: D1 database connectivity
 * - storage: R2 bucket accessibility
 * - durableObjects: ConnectionManager DO instantiation
 * - kv: Rate limit KV namespace (conditional, omitted if not configured)
 *
 * All checks run in parallel for optimal latency.
 * Returns 200 when all checks pass, 503 when any check fails.
 * When environment validation fails, includes error message and docs link.
 */
app.get('/ready', async (c) => {
    // Environment validation check (HAP-523)
    // Validates configuration before checking dependencies
    let envValid = true;
    let envError: string | null = null;
    try {
        validateEnv(c.env);
    } catch (error) {
        envValid = false;
        envError = error instanceof Error ? error.message : 'Invalid environment configuration';
        console.error('[Ready Check] Configuration validation failed:', envError);
    }

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

    // Build checks object with all dependency statuses (HAP-523: added environment check)
    const checks: Record<string, boolean | null> = {
        environment: envValid,
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

    // Build response with optional error details (HAP-523)
    const response: {
        ready: boolean;
        checks: Record<string, boolean | null>;
        timestamp: string;
        error?: string;
        docs?: string;
    } = {
        ready: isReady,
        checks,
        timestamp: new Date().toISOString(),
    };

    // Include error details if environment validation failed
    if (!envValid && envError) {
        response.error = envError;
        response.docs = 'https://github.com/Enflame-Media/happy-server-workers/blob/main/docs/SECRETS.md';
    }

    return c.json(response, isReady ? 200 : 503);
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
 * Export the Hono app for testing
 * Tests use `app.request()` which is a Hono convenience method
 */
export { app };

/**
 * Scheduled event handler for cron triggers
 * Runs daily at 2 AM UTC to clean up expired token blacklist entries
 *
 * @param event - Scheduled event from Cloudflare
 * @param env - Environment bindings
 * @param _ctx - Execution context (unused but required by Workers API)
 *
 * @see HAP-504 for implementation details
 * @see HAP-452 for token blacklist architecture
 */
async function scheduled(event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    console.log(`[Scheduled] Token blacklist cleanup triggered at ${new Date(event.scheduledTime).toISOString()}`);

    try {
        const deleted = await cleanupExpiredTokens(env.DB);
        console.log(`[Scheduled] Removed ${deleted} expired blacklist entries`);
    } catch (error) {
        console.error('[Scheduled] Token blacklist cleanup failed:', error);
        // Don't rethrow - let the worker complete gracefully
        // Failed cleanups will be retried on next cron run
    }
}

/**
 * Export the Worker with both fetch and scheduled handlers
 *
 * @remarks
 * Hono apps are compatible with Cloudflare Workers via their `fetch` method.
 * The scheduled handler runs token blacklist cleanup (HAP-504).
 */
export default {
    /**
     * HTTP request handler (Hono app)
     */
    fetch: app.fetch,

    /**
     * Scheduled event handler
     */
    scheduled,
};
