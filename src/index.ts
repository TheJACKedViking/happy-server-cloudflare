import { OpenAPIHono } from '@hono/zod-openapi';
import * as Sentry from '@sentry/cloudflare';
import { logger } from '@/middleware/logger';
import { cors } from '@/middleware/cors';
import { timing, addServerTiming } from '@/middleware/timing';
import { requestIdMiddleware } from '@/middleware/requestId';
import { errorHandler } from '@/middleware/error';
import { bodySizeLimits } from '@/middleware/bodySize';
import { securityHeadersMiddleware } from '@/middleware/securityHeaders';
import { initAuth, cleanupExpiredTokens } from '@/lib/auth';
import { cleanupEmptyArchivedSessions } from '@/lib/sessionCleanup';
import { cleanupExpiredInvitations } from '@/lib/invitationCleanup';
import { getMasterSecret, validateEnv } from '@/config/env';
import { buildSentryOptions } from '@/lib/sentry';
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
import sharingRoutes from '@/routes/sharing';
import ciMetricsRoutes from '@/routes/ciMetrics';
import clientMetricsRoutes from '@/routes/clientMetrics';
import healthRoutes from '@/routes/health';

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
    ENVIRONMENT?: 'development' | 'production';

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

    /**
     * Analytics Engine dataset for bundle size metrics (HAP-564)
     * Used to store CI/CD bundle size metrics for trend analysis
     * @optional - metrics are silently dropped if not configured
     */
    BUNDLE_METRICS?: AnalyticsEngineDataset;

    /**
     * Analytics Engine dataset for client-side metrics (HAP-577)
     * Used to store validation failure metrics from the mobile app
     * @optional - metrics are silently dropped if not configured
     */
    CLIENT_METRICS?: AnalyticsEngineDataset;

    /**
     * Analytics Engine dataset for WebSocket metrics (HAP-896)
     * Used to track connection times, broadcast latency, and errors
     * @optional - metrics are silently dropped if not configured
     */
    WS_METRICS?: AnalyticsEngineDataset;

    /**
     * API key for CI metrics ingestion (HAP-564)
     * Used to authenticate CI/CD systems sending bundle metrics
     * @optional - if not set, CI metrics endpoint is disabled
     */
    CI_METRICS_API_KEY?: string;

    /**
     * Sentry Data Source Name (DSN) for error monitoring
     * @required for Sentry integration
     */
    SENTRY_DSN?: string;

    /**
     * Cloudflare version metadata for Sentry release tracking
     * Automatically populated by Cloudflare Workers
     */
    CF_VERSION_METADATA?: { id: string };

    /**
     * Resend API key for sending transactional emails (HAP-805)
     * @optional - if not set, email sending is disabled in production
     * @see https://resend.com/api-keys
     */
    RESEND_API_KEY?: string;

    /**
     * Base URL for the Happy app (HAP-805)
     * Used for building invitation accept links in emails
     * @optional - defaults to https://happy.enflamemedia.com
     */
    HAPPY_APP_URL?: string;
}

/**
 * Application version (should match package.json)
 */
const APP_VERSION = '0.0.0';

/**
 * Main Hono application instance with OpenAPI support
 * Configured with typed environment bindings for Cloudflare Workers
 *
 * HAP-647: Uses defaultHook to sanitize Zod validation error messages.
 * Validation errors are returned with generic messages to prevent
 * exposing internal field paths and schema structure.
 */
const app = new OpenAPIHono<{ Bindings: Env }>({
    defaultHook: (result, c): Response | void => {
        if (!result.success) {
            // Get request ID for correlation (may not be set yet if validation fails early)
            // Use type assertion since requestId middleware sets this
            const requestId = (c.var as { requestId?: string })?.requestId || crypto.randomUUID().slice(0, 8);
            const isDevelopment = (c.env as { ENVIRONMENT?: string })?.ENVIRONMENT === 'development';

            // Log full validation details internally for debugging
            console.warn(`[${requestId}] Validation error:`, JSON.stringify(result.error.flatten()));

            // Return sanitized error response
            // In development, show field-level errors for debugging
            // In production, use generic message to prevent information leakage
            const errorMessage = isDevelopment
                ? `Validation failed: ${result.error.issues.map((e: { message: string }) => e.message).join(', ')}`
                : 'Invalid request data';

            return c.json(
                {
                    error: errorMessage,
                    code: 'VALIDATION_FAILED',
                    requestId,
                    timestamp: new Date().toISOString(),
                },
                400
            );
        }
        // When validation succeeds, return undefined to continue to the route handler
    },
});

/*
 * Global Middleware
 * Applied in order: timing → requestId → logging → CORS → security headers → body size → env validation → auth initialization → routes → error handling
 */
app.use('*', timing());
app.use('*', requestIdMiddleware());
app.use('*', logger());
app.use('*', cors());

/*
 * Security Headers Middleware (HAP-627)
 *
 * Adds standard security headers to all responses:
 * - Content-Security-Policy: Prevents XSS and data injection
 * - X-Frame-Options: Prevents clickjacking
 * - X-Content-Type-Options: Prevents MIME sniffing
 * - Strict-Transport-Security: Enforces HTTPS (production only)
 * - X-XSS-Protection: Legacy XSS protection
 * - Referrer-Policy: Controls referrer leakage
 * - Permissions-Policy: Restricts browser features
 */
app.use('*', securityHeadersMiddleware());

/*
 * Body size limiting (HAP-629)
 * Prevents DoS attacks via oversized request payloads.
 * Applied early to reject large payloads before authentication overhead.
 */
app.use('*', bodySizeLimits.sync()); // 10MB default for sync payloads

/*
 * Environment validation middleware (HAP-523)
 * Validates required configuration before processing any routes.
 * Returns structured JSON error response with documentation link.
 * Skip validation for health endpoints (allows monitoring when misconfigured).
 */
app.use('*', async (c, next): Promise<Response | void> => {
    // Allow health endpoints even without configuration (for monitoring checks)
    // HAP-587: Added /health/messages for deployment validation
    if (c.req.path === '/health' || c.req.path.startsWith('/health/')) {
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

// Mount session sharing routes (HAP-772: Session sharing API)
app.route('/', sharingRoutes);

// Mount usage routes (HAP-302: Usage query endpoint)
app.route('/', usageRoutes);

// Mount analytics routes (HAP-546: Sync metrics ingestion)
app.route('/', analyticsRoutes);

// Mount CI metrics routes (HAP-564: Bundle size metrics from GitHub Actions)
app.route('/', ciMetricsRoutes);

// Mount client metrics routes (HAP-577: Validation failure metrics from mobile app)
app.route('/', clientMetricsRoutes);

// Mount specialized health check routes (HAP-587: Deployment health validation)
app.route('/', healthRoutes);

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
 * Runs daily at 2 AM UTC for maintenance tasks:
 * - Clean up expired token blacklist entries (HAP-504)
 * - Delete empty archived sessions (sessions with no messages)
 * - Mark expired share invitations as 'expired' (HAP-824)
 *
 * Note: Sentry is automatically initialized by the withSentry wrapper for scheduled handlers.
 * Error capture and flushing is handled by the wrapper.
 *
 * @param event - Scheduled event from Cloudflare
 * @param env - Environment bindings
 * @param ctx - Execution context
 *
 * @see HAP-504 for token blacklist implementation
 * @see HAP-452 for token blacklist architecture
 * @see HAP-824 for invitation expiration implementation
 */
async function scheduled(event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    console.log(`[Scheduled] Maintenance triggered at ${new Date(event.scheduledTime).toISOString()}`);

    // Set Sentry context for this scheduled job
    Sentry.setTag('handler', 'scheduled');
    Sentry.setContext('scheduled', {
        scheduledTime: new Date(event.scheduledTime).toISOString(),
        cron: event.cron,
    });

    // Task 1: Token blacklist cleanup
    Sentry.setTag('task', 'token-blacklist-cleanup');
    try {
        const deleted = await cleanupExpiredTokens(env.DB);
        console.log(`[Scheduled] Removed ${deleted} expired blacklist entries`);
    } catch (error) {
        // Capture error to Sentry with additional context
        Sentry.captureException(error);
        console.error('[Scheduled] Token blacklist cleanup failed:', error);
        // Don't rethrow - continue with other tasks
    }

    // Task 2: Empty archived sessions cleanup
    Sentry.setTag('task', 'empty-sessions-cleanup');
    try {
        const deleted = await cleanupEmptyArchivedSessions(env.DB);
        console.log(`[Scheduled] Removed ${deleted} empty archived sessions`);
    } catch (error) {
        Sentry.captureException(error);
        console.error('[Scheduled] Empty sessions cleanup failed:', error);
        // Don't rethrow - let the worker complete gracefully
    }

    // Task 3: Expired share invitations cleanup (HAP-824)
    Sentry.setTag('task', 'expired-invitations-cleanup');
    try {
        const expired = await cleanupExpiredInvitations(env.DB);
        console.log(`[Scheduled] Marked ${expired} share invitations as expired`);
    } catch (error) {
        Sentry.captureException(error);
        console.error('[Scheduled] Expired invitations cleanup failed:', error);
        // Don't rethrow - let the worker complete gracefully
    }
    // Note: Sentry flush is handled automatically by withSentry wrapper
}

/**
 * Export the Worker with Sentry instrumentation
 *
 * @remarks
 * The worker is wrapped with Sentry.withSentry() for automatic error capture,
 * performance tracing, and context propagation. This provides:
 *
 * - Automatic exception capture from Hono's onError handler
 * - Performance tracing for all requests
 * - Request context attached to all Sentry events
 * - Automatic event flushing via waitUntil
 *
 * The scheduled handler is wrapped separately for cron job monitoring.
 *
 * @see https://docs.sentry.io/platforms/javascript/guides/cloudflare/
 */
export default Sentry.withSentry(
    (env: Env) => buildSentryOptions(env, {
        // Override tracesSampleRate based on environment
        // Production: 10% sampling to manage costs
        // Development: 100% sampling for debugging
        tracesSampleRate: env.ENVIRONMENT === 'development' ? 1.0 : 0.1,
    }),
    {
        /**
         * HTTP request handler (Hono app)
         */
        fetch: app.fetch,

        /**
         * Scheduled event handler
         */
        scheduled,
    } as ExportedHandler<Env>
);
