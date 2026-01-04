/**
 * Sentry Configuration for Cloudflare Workers
 *
 * This module provides centralized Sentry configuration for error monitoring,
 * performance tracing, logging, and metrics in happy-server-workers.
 *
 * Features:
 * - Error monitoring with automatic exception capture
 * - Performance tracing with configurable sample rates
 * - Release tracking via Cloudflare version metadata
 * - Environment-aware configuration (development vs production)
 * - PII scrubbing and data sanitization
 *
 * @module lib/sentry
 * @see https://docs.sentry.io/platforms/javascript/guides/cloudflare/
 */

import * as Sentry from '@sentry/cloudflare';

/**
 * Environment bindings required for Sentry configuration
 */
export interface SentryEnv {
    /** Sentry Data Source Name (DSN) */
    SENTRY_DSN?: string;

    /** Current deployment environment */
    ENVIRONMENT?: 'development' | 'staging' | 'production';

    /** Cloudflare version metadata for release tracking */
    CF_VERSION_METADATA?: { id: string };
}

/**
 * Sentry configuration options
 */
export interface SentryConfig {
    /** Sample rate for error events (0.0 - 1.0) */
    sampleRate?: number;

    /** Sample rate for performance traces (0.0 - 1.0) */
    tracesSampleRate?: number;

    /** Enable debug mode for Sentry SDK */
    debug?: boolean;
}

/**
 * Build Sentry options from environment bindings
 *
 * Creates a configuration object suitable for use with Sentry.withSentry()
 * or Sentry.init(). Adjusts sample rates based on environment.
 *
 * @param env - Environment bindings
 * @param overrides - Optional configuration overrides
 * @returns Sentry configuration options
 *
 * @example
 * ```typescript
 * const options = buildSentryOptions(c.env);
 * Sentry.init(options);
 * ```
 */
export function buildSentryOptions(
    env: SentryEnv,
    overrides?: SentryConfig
): Sentry.CloudflareOptions {
    const isDevelopment = env.ENVIRONMENT === 'development';

    return {
        dsn: env.SENTRY_DSN,
        environment: env.ENVIRONMENT ?? 'production',
        release: env.CF_VERSION_METADATA?.id,

        // Sample rates - higher in development for debugging
        sampleRate: overrides?.sampleRate ?? 1.0, // Capture all errors
        tracesSampleRate: overrides?.tracesSampleRate ?? (isDevelopment ? 1.0 : 0.1),

        // Enable debug logging in development
        debug: overrides?.debug ?? isDevelopment,

        // Attach stack traces to all messages
        attachStacktrace: true,

        // Normalize stack traces depth
        normalizeDepth: 10,

        // Before sending event - sanitize sensitive data
        beforeSend(event, hint) {
            // Skip certain known noisy errors in production
            if (!isDevelopment) {
                const error = hint?.originalException;
                if (error instanceof Error) {
                    // Skip WebSocket close events (expected behavior)
                    if (error.message?.includes('WebSocket is already in CLOSING')) {
                        return null;
                    }
                }
            }

            // Scrub sensitive headers
            if (event.request?.headers) {
                const sensitiveHeaders = ['authorization', 'cookie', 'x-auth-token'];
                for (const header of sensitiveHeaders) {
                    if (header in event.request.headers) {
                        event.request.headers[header] = '[Filtered]';
                    }
                }
            }

            return event;
        },

        // Before sending breadcrumb - filter sensitive data
        beforeBreadcrumb(breadcrumb) {
            // Filter out sensitive fetch breadcrumbs
            if (breadcrumb.category === 'fetch' && breadcrumb.data?.url) {
                const url = breadcrumb.data.url as string;
                // Redact auth-related URLs
                if (url.includes('/auth') || url.includes('token')) {
                    breadcrumb.data.url = '[Filtered Auth URL]';
                }
            }
            return breadcrumb;
        },

        // Integrations configuration
        integrations: [
            // Capture console.error/console.warn as breadcrumbs
            Sentry.consoleIntegration(),
        ],
    };
}

/**
 * Set user context for Sentry events
 *
 * Call this after user authentication to associate events with a user.
 *
 * @param userId - The authenticated user's ID
 * @param extras - Optional additional user information
 *
 * @example
 * ```typescript
 * setSentryUser(verifiedToken.userId, { clientType: 'mobile' });
 * ```
 */
export function setSentryUser(userId: string, extras?: Record<string, string>): void {
    Sentry.setUser({
        id: userId,
        ...extras,
    });
}

/**
 * Clear user context (e.g., on logout)
 */
export function clearSentryUser(): void {
    Sentry.setUser(null);
}

/**
 * Add context to Sentry events
 *
 * Use this to add structured context that will be attached to all subsequent events.
 *
 * @param name - Context name (e.g., 'request', 'session')
 * @param context - Context data
 *
 * @example
 * ```typescript
 * setSentryContext('request', {
 *     requestId: '123',
 *     path: '/v1/sessions',
 *     method: 'POST',
 * });
 * ```
 */
export function setSentryContext(name: string, context: Record<string, unknown>): void {
    Sentry.setContext(name, context);
}

/**
 * Set a tag on Sentry events
 *
 * Tags are indexed and searchable in Sentry.
 *
 * @param key - Tag key
 * @param value - Tag value
 *
 * @example
 * ```typescript
 * setSentryTag('error.code', 'AUTH_FAILED');
 * ```
 */
export function setSentryTag(key: string, value: string): void {
    Sentry.setTag(key, value);
}

/**
 * Capture an exception to Sentry
 *
 * Use this for explicit error capture with additional context.
 *
 * @param error - The error to capture
 * @param context - Optional additional context
 *
 * @example
 * ```typescript
 * try {
 *     await riskyOperation();
 * } catch (error) {
 *     captureException(error, {
 *         tags: { operation: 'riskyOperation' },
 *         extra: { attemptNumber: 3 },
 *     });
 * }
 * ```
 */
export function captureException(
    error: unknown,
    context?: {
        tags?: Record<string, string>;
        extra?: Record<string, unknown>;
        level?: Sentry.SeverityLevel;
    }
): string {
    return Sentry.captureException(error, {
        tags: context?.tags,
        extra: context?.extra,
        level: context?.level,
    });
}

/**
 * Capture a message to Sentry
 *
 * Use this for non-exception events that should still be tracked.
 *
 * @param message - The message to capture
 * @param level - Severity level (default: 'info')
 *
 * @example
 * ```typescript
 * captureMessage('User reached rate limit', 'warning');
 * ```
 */
export function captureMessage(
    message: string,
    level: Sentry.SeverityLevel = 'info'
): string {
    return Sentry.captureMessage(message, level);
}

/**
 * Add a breadcrumb for debugging
 *
 * Breadcrumbs are a trail of events that happened before an error.
 *
 * @param breadcrumb - Breadcrumb data
 *
 * @example
 * ```typescript
 * addBreadcrumb({
 *     category: 'websocket',
 *     message: 'Connection established',
 *     level: 'info',
 *     data: { connectionId: '123' },
 * });
 * ```
 */
export function addBreadcrumb(breadcrumb: Sentry.Breadcrumb): void {
    Sentry.addBreadcrumb(breadcrumb);
}

/**
 * Flush pending Sentry events
 *
 * Use this in Durable Objects with ctx.waitUntil() to ensure events are sent.
 *
 * @param timeout - Maximum time to wait in ms (default: 2000)
 * @returns Promise that resolves when flush completes or times out
 *
 * @example
 * ```typescript
 * // In Durable Object
 * this.ctx.waitUntil(flushSentry(2000));
 * ```
 */
export function flushSentry(timeout = 2000): Promise<boolean> {
    return Sentry.flush(timeout);
}

/**
 * Start a performance span
 *
 * Use this to measure the duration of operations.
 *
 * @param options - Span options
 * @param callback - Function to execute within the span
 * @returns The result of the callback
 *
 * @example
 * ```typescript
 * const result = await startSpan(
 *     { op: 'db.query', name: 'Fetch user sessions' },
 *     async () => {
 *         return await db.select().from(sessions);
 *     }
 * );
 * ```
 */
export async function startSpan<T>(
    options: { op: string; name: string; attributes?: Record<string, string | number | boolean> },
    callback: () => Promise<T> | T
): Promise<T> {
    return Sentry.startSpan(options, callback);
}

// Re-export Sentry for advanced usage
export { Sentry };

// Re-export instrumentDurableObjectWithSentry for Durable Object instrumentation
export { instrumentDurableObjectWithSentry } from '@sentry/cloudflare';
