import { createRoute, OpenAPIHono } from '@hono/zod-openapi';
import type { Context } from 'hono';
import { authMiddleware, type AuthVariables } from '@/middleware/auth';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';
import { eq, and, gte, lte } from 'drizzle-orm';
import {
    UsageQueryRequestSchema,
    UsageQueryResponseSchema,
    UnauthorizedErrorSchema,
    NotFoundErrorSchema,
    InternalErrorSchema,
    GetUsageLimitsResponseSchema,
} from '@/schemas/usage';

/**
 * Environment bindings for usage routes
 */
interface Env {
    DB: D1Database;
    CONNECTION_MANAGER?: DurableObjectNamespace;
}

/**
 * Usage routes module
 *
 * Implements usage endpoints for token/cost tracking:
 * - POST /v1/usage/query - Query aggregated usage data with optional filters
 * - GET /v1/usage/limits - Get cached plan limits from connected CLI sessions
 *
 * The endpoints support filtering by session, time range, and aggregation period.
 * All routes require authentication.
 */
const usageRoutes = new OpenAPIHono<{ Bindings: Env }>();

// Apply auth middleware to all usage routes
usageRoutes.use('/v1/usage/*', authMiddleware());

// ============================================================================
// POST /v1/usage/query - Query Usage Data
// ============================================================================

const queryUsageRoute = createRoute({
    method: 'post',
    path: '/v1/usage/query',
    request: {
        body: {
            content: {
                'application/json': {
                    schema: UsageQueryRequestSchema,
                },
            },
        },
    },
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: UsageQueryResponseSchema,
                },
            },
            description: 'Aggregated usage data',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        404: {
            content: {
                'application/json': {
                    schema: NotFoundErrorSchema,
                },
            },
            description: 'Session not found or not owned by user',
        },
        500: {
            content: {
                'application/json': {
                    schema: InternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Usage'],
    summary: 'Query usage data',
    description: 'Query aggregated usage data with optional filtering by session, time range, and grouping period. Returns token counts and costs aggregated by hour or day.',
});

/**
 * Usage report data structure as stored in the database.
 * The data field contains JSON with tokens and cost breakdowns.
 */
interface UsageReportData {
    tokens: Record<string, number>;
    cost: Record<string, number>;
}

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
usageRoutes.openapi(queryUsageRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');
    const { sessionId, startTime, endTime, groupBy } = c.req.valid('json');
    const actualGroupBy = groupBy || 'day';
    const db = getDb(c.env.DB);

    try {
        // If sessionId provided, verify it belongs to the user
        if (sessionId) {
            const session = await db.query.sessions.findFirst({
                where: (sessions, { eq, and }) =>
                    and(eq(sessions.id, sessionId), eq(sessions.accountId, userId)),
            });
            if (!session) {
                return c.json({ error: 'Session not found' }, 404);
            }
        }

        // Build query conditions
        const conditions = [eq(schema.usageReports.accountId, userId)];

        if (sessionId) {
            conditions.push(eq(schema.usageReports.sessionId, sessionId));
        }

        if (startTime) {
            // Convert seconds to milliseconds for timestamp_ms field
            conditions.push(gte(schema.usageReports.createdAt, new Date(startTime * 1000)));
        }

        if (endTime) {
            // Convert seconds to milliseconds for timestamp_ms field
            conditions.push(lte(schema.usageReports.createdAt, new Date(endTime * 1000)));
        }

        // Fetch usage reports with all conditions
        const reports = await db
            .select()
            .from(schema.usageReports)
            .where(and(...conditions))
            .orderBy(schema.usageReports.createdAt);

        // Aggregate data by time period
        const aggregated = new Map<
            string,
            {
                tokens: Record<string, number>;
                cost: Record<string, number>;
                count: number;
                timestamp: number;
            }
        >();

        for (const report of reports) {
            const data = report.data as UsageReportData;
            const date = report.createdAt;

            // Calculate timestamp based on groupBy
            let timestamp: number;
            if (actualGroupBy === 'hour') {
                // Round down to hour
                const hourDate = new Date(
                    date.getFullYear(),
                    date.getMonth(),
                    date.getDate(),
                    date.getHours(),
                    0,
                    0,
                    0
                );
                timestamp = Math.floor(hourDate.getTime() / 1000);
            } else {
                // Round down to day
                const dayDate = new Date(
                    date.getFullYear(),
                    date.getMonth(),
                    date.getDate(),
                    0,
                    0,
                    0,
                    0
                );
                timestamp = Math.floor(dayDate.getTime() / 1000);
            }

            const key = timestamp.toString();

            if (!aggregated.has(key)) {
                aggregated.set(key, {
                    tokens: {},
                    cost: {},
                    count: 0,
                    timestamp,
                });
            }

            const agg = aggregated.get(key)!;
            agg.count++;

            // Aggregate tokens
            if (data.tokens) {
                for (const [tokenKey, tokenValue] of Object.entries(data.tokens)) {
                    if (typeof tokenValue === 'number') {
                        agg.tokens[tokenKey] = (agg.tokens[tokenKey] || 0) + tokenValue;
                    }
                }
            }

            // Aggregate costs
            if (data.cost) {
                for (const [costKey, costValue] of Object.entries(data.cost)) {
                    if (typeof costValue === 'number') {
                        agg.cost[costKey] = (agg.cost[costKey] || 0) + costValue;
                    }
                }
            }
        }

        // Convert to array and sort by timestamp
        const result = Array.from(aggregated.values())
            .map((data) => ({
                timestamp: data.timestamp,
                tokens: data.tokens,
                cost: data.cost,
                reportCount: data.count,
            }))
            .sort((a, b) => a.timestamp - b.timestamp);

        return c.json({
            usage: result,
            groupBy: actualGroupBy,
            totalReports: reports.length,
        });
    } catch (error) {
        console.error('Failed to query usage reports:', error);
        return c.json({ error: 'Failed to query usage reports' }, 500);
    }
});

// ============================================================================
// GET /v1/usage/limits - Get Plan Limits
// ============================================================================

/**
 * Get cached usage limits from connected CLI sessions
 *
 * Returns plan limits data that was most recently received from an active CLI session.
 * The CLI polls the AI provider for usage limits and sends updates via WebSocket.
 * This endpoint retrieves the cached limits for the authenticated user.
 *
 * @see HAP-728 - Parent issue for usage limits feature
 * @see HAP-731 - This endpoint implementation
 */
const getUsageLimitsRoute = createRoute({
    method: 'get',
    path: '/v1/usage/limits',
    responses: {
        200: {
            content: {
                'application/json': {
                    schema: GetUsageLimitsResponseSchema,
                },
            },
            description: 'Plan limits data from connected CLI session',
        },
        401: {
            content: {
                'application/json': {
                    schema: UnauthorizedErrorSchema,
                },
            },
            description: 'Unauthorized',
        },
        500: {
            content: {
                'application/json': {
                    schema: InternalErrorSchema,
                },
            },
            description: 'Internal server error',
        },
    },
    tags: ['Usage'],
    summary: 'Get plan limits',
    description: 'Returns cached plan limits from connected CLI sessions. Returns limitsAvailable=false when no CLI is connected or no usage data is available.',
});

// @ts-expect-error - OpenAPI handler type inference doesn't carry Variables from middleware
usageRoutes.openapi(getUsageLimitsRoute, async (c) => {
    const userId = (c as unknown as Context<{ Bindings: Env; Variables: AuthVariables }>).get('userId');

    try {
        // Check if CONNECTION_MANAGER is configured
        if (!c.env.CONNECTION_MANAGER) {
            // Return unavailable response when Durable Objects not configured
            return c.json({
                limitsAvailable: false,
                weeklyLimits: [],
                lastUpdatedAt: Date.now(),
            });
        }

        // Get the user's Durable Object to check for cached limits
        const doId = c.env.CONNECTION_MANAGER.idFromName(userId);
        const stub = c.env.CONNECTION_MANAGER.get(doId);

        // Request usage limits from the Durable Object
        const response = await stub.fetch(new Request('https://do/usage-limits'));

        if (!response.ok) {
            // If DO returns non-OK (e.g., 404 for no data), return unavailable
            return c.json({
                limitsAvailable: false,
                weeklyLimits: [],
                lastUpdatedAt: Date.now(),
            });
        }

        // Parse and return the cached limits
        const limits = await response.json();

        // Validate the response has the expected shape
        if (limits && typeof limits === 'object' && 'limitsAvailable' in limits) {
            return c.json(limits);
        }

        // Fallback if response format is unexpected
        return c.json({
            limitsAvailable: false,
            weeklyLimits: [],
            lastUpdatedAt: Date.now(),
        });
    } catch (error) {
        console.error('Failed to get usage limits:', error);

        // Return unavailable on any error rather than 500
        // This provides a graceful degradation for the client
        return c.json({
            limitsAvailable: false,
            weeklyLimits: [],
            lastUpdatedAt: Date.now(),
        });
    }
});

export default usageRoutes;
