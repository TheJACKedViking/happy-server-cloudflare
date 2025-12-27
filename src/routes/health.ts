import { createRoute, OpenAPIHono, z } from '@hono/zod-openapi';
import { addServerTiming } from '@/middleware/timing';
import { CreateSessionMessageRequestSchema } from '@/schemas/sessions';

/**
 * Environment bindings for health routes
 */
interface Env {
    DB: D1Database;
}

/**
 * Health check response schema for /health/messages
 *
 * @remarks
 * Provides detailed status for message-related functionality including
 * database connectivity and schema parsing validation.
 */
const MessageHealthResponseSchema = z
    .object({
        status: z.enum(['healthy', 'unhealthy']).openapi({
            description: 'Overall health status of message functionality',
            example: 'healthy',
        }),
        checks: z
            .object({
                database: z.enum(['ok', 'error']).openapi({
                    description: 'D1 database connectivity status',
                    example: 'ok',
                }),
                schema: z.enum(['ok', 'error']).openapi({
                    description: 'Message schema parsing status',
                    example: 'ok',
                }),
            })
            .openapi({
                description: 'Individual health check results',
            }),
        timestamp: z.string().openapi({
            description: 'ISO 8601 timestamp of health check',
            example: '2025-12-27T12:00:00.000Z',
        }),
        latencyMs: z.number().optional().openapi({
            description: 'Total health check latency in milliseconds',
            example: 45,
        }),
    })
    .openapi('MessageHealthResponse');

/**
 * Unhealthy response schema with error details
 */
const MessageHealthErrorResponseSchema = z
    .object({
        status: z.literal('unhealthy').openapi({
            description: 'Unhealthy status indicator',
            example: 'unhealthy',
        }),
        checks: z
            .object({
                database: z.enum(['ok', 'error']).openapi({
                    description: 'D1 database connectivity status',
                    example: 'error',
                }),
                schema: z.enum(['ok', 'error']).openapi({
                    description: 'Message schema parsing status',
                    example: 'ok',
                }),
            })
            .openapi({
                description: 'Individual health check results',
            }),
        error: z.string().openapi({
            description: 'Error message describing the failure',
            example: 'Database connection failed: no such table: sessions',
        }),
        timestamp: z.string().openapi({
            description: 'ISO 8601 timestamp of health check',
            example: '2025-12-27T12:00:00.000Z',
        }),
    })
    .openapi('MessageHealthErrorResponse');

/**
 * Health routes module (HAP-587)
 *
 * Implements specialized health check endpoints for deployment validation:
 * - GET /health/messages - Validates message endpoint functionality
 *
 * These endpoints are designed to be called post-deployment to verify
 * that critical functionality is working correctly.
 *
 * @remarks
 * Unlike /health (basic liveness) and /ready (full dependency check),
 * these endpoints focus on specific feature areas and include schema
 * validation to catch deployment regressions.
 */
const healthRoutes = new OpenAPIHono<{ Bindings: Env }>();

// ============================================================================
// GET /health/messages - Message Endpoint Health Check
// ============================================================================

const messageHealthRoute = createRoute({
    method: 'get',
    path: '/health/messages',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: MessageHealthResponseSchema,
                },
            },
            description: 'Message functionality is healthy',
        },
        503: {
            content: {
                'application/json': {
                    schema: MessageHealthErrorResponseSchema,
                },
            },
            description: 'Message functionality is unhealthy',
        },
    },
    tags: ['Health'],
    summary: 'Check message endpoint health',
    description: `Validates that message-related functionality is working correctly.

**Checks performed:**
1. **Database connectivity**: Verifies D1 database can be queried
2. **Schema validation**: Confirms message schemas can parse correctly

**Use cases:**
- Post-deployment validation in CI/CD pipelines
- Monitoring system health checks
- Debugging deployment regressions (like HAP-581)

**Response time target:** < 5 seconds`,
});

healthRoutes.openapi(messageHealthRoute, async (c) => {
    const startTime = Date.now();
    const errors: string[] = [];

    const checks = {
        database: 'ok' as 'ok' | 'error',
        schema: 'ok' as 'ok' | 'error',
    };

    // Check 1: D1 database connectivity
    // Uses a simple query to verify the database is accessible
    try {
        const dbStart = Date.now();
        await c.env.DB.prepare('SELECT 1 as health_check').first();
        addServerTiming(c, 'db', Date.now() - dbStart, 'D1 database check');
    } catch (error) {
        checks.database = 'error';
        const message = error instanceof Error ? error.message : 'Unknown database error';
        errors.push(`Database: ${message}`);
        console.error('[Health/Messages] Database check failed:', error);
    }

    // Check 2: Message schema parsing
    // Validates that the Zod schemas can parse a minimal valid message
    try {
        const schemaStart = Date.now();

        // Test message creation schema parsing with minimal valid payload
        const testMessage = {
            content: { type: 'health_check', data: 'test' },
        };

        // This will throw if the schema is broken
        CreateSessionMessageRequestSchema.parse(testMessage);

        addServerTiming(c, 'schema', Date.now() - schemaStart, 'Schema validation');
    } catch (error) {
        checks.schema = 'error';
        const message = error instanceof Error ? error.message : 'Unknown schema error';
        errors.push(`Schema: ${message}`);
        console.error('[Health/Messages] Schema check failed:', error);
    }

    const latencyMs = Date.now() - startTime;
    addServerTiming(c, 'total', latencyMs, 'Total health check');

    // Determine overall health status
    const isHealthy = checks.database === 'ok' && checks.schema === 'ok';

    if (isHealthy) {
        return c.json(
            {
                status: 'healthy' as const,
                checks,
                timestamp: new Date().toISOString(),
                latencyMs,
            },
            200
        );
    }

    return c.json(
        {
            status: 'unhealthy' as const,
            checks,
            error: errors.join('; '),
            timestamp: new Date().toISOString(),
        },
        503
    );
});

export default healthRoutes;
