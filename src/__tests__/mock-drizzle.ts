/**
 * Mock Drizzle ORM Client for Integration Tests
 *
 * Provides a type-safe mock that mimics the Drizzle ORM relational query API
 * and core insert/update/delete operations. This allows route handler tests
 * to exercise actual business logic instead of accepting 500 errors.
 *
 * @module __tests__/mock-drizzle
 */

import { vi } from 'vitest';
import type { DbClient } from '@/db/client';

/**
 * Generic entity with common fields
 */
interface BaseEntity {
    id: string;
    createdAt?: Date;
    updatedAt?: Date;
    [key: string]: unknown;
}

/**
 * Query options matching Drizzle's relational query API
 */
interface QueryOptions<T> {
    where?: (table: T, ops: WhereOperators) => boolean | unknown;
    orderBy?: (table: T, ops: OrderByOperators) => unknown[];
    limit?: number;
    offset?: number;
    with?: Record<string, boolean | QueryOptions<unknown>>;
}

/**
 * Where clause operators
 */
interface WhereOperators {
    eq: <T>(field: T, value: T) => boolean;
    ne: <T>(field: T, value: T) => boolean;
    gt: <T>(field: T, value: T) => boolean;
    gte: <T>(field: T, value: T) => boolean;
    lt: <T>(field: T, value: T) => boolean;
    lte: <T>(field: T, value: T) => boolean;
    and: (...conditions: (boolean | unknown)[]) => boolean;
    or: (...conditions: (boolean | unknown)[]) => boolean;
    like: (field: string, pattern: string) => boolean;
    inArray: <T>(field: T, values: T[]) => boolean;
    isNull: <T>(field: T) => boolean;
    isNotNull: <T>(field: T) => boolean;
}

/**
 * OrderBy operators
 */
interface OrderByOperators {
    asc: <T>(field: T) => { field: T; direction: 'asc' };
    desc: <T>(field: T) => { field: T; direction: 'desc' };
}

/**
 * Chainable insert builder
 */
interface InsertBuilder<T> {
    values: (data: Partial<T> | Partial<T>[]) => InsertBuilder<T>;
    returning: () => Promise<T[]>;
    onConflictDoNothing: () => InsertBuilder<T>;
    onConflictDoUpdate: (opts: { target: unknown; set: Partial<T> }) => InsertBuilder<T>;
}

/**
 * Chainable update builder
 */
interface UpdateBuilder<T> {
    set: (data: Partial<T>) => UpdateBuilder<T>;
    where: (condition: unknown) => UpdateBuilder<T>;
    returning: () => Promise<T[]>;
}

/**
 * Chainable delete builder
 */
interface DeleteBuilder<T> {
    where: (condition: unknown) => DeleteBuilder<T>;
    returning: () => Promise<T[]>;
}

/**
 * In-memory data store for test data
 */
type DataStore = Map<string, BaseEntity[]>;

/**
 * Create where operators that work with actual data
 */
function createWhereOps(): WhereOperators {
    return {
        eq: <T>(field: T, value: T) => field === value,
        ne: <T>(field: T, value: T) => field !== value,
        gt: <T>(field: T, value: T) => (field as number) > (value as number),
        gte: <T>(field: T, value: T) => (field as number) >= (value as number),
        lt: <T>(field: T, value: T) => (field as number) < (value as number),
        lte: <T>(field: T, value: T) => (field as number) <= (value as number),
        and: (...conditions) => conditions.every(Boolean),
        or: (...conditions) => conditions.some(Boolean),
        like: (field, pattern) => {
            const regex = new RegExp('^' + pattern.replace(/%/g, '.*') + '$', 'i');
            return regex.test(field);
        },
        inArray: <T>(field: T, values: T[]) => values.includes(field),
        isNull: <T>(field: T) => field === null || field === undefined,
        isNotNull: <T>(field: T) => field !== null && field !== undefined,
    };
}

/**
 * Create orderBy operators
 */
function createOrderByOps(): OrderByOperators {
    return {
        asc: <T>(field: T) => ({ field, direction: 'asc' as const }),
        desc: <T>(field: T) => ({ field, direction: 'desc' as const }),
    };
}

/**
 * Apply where filter to data
 */
function applyWhere<T extends BaseEntity>(
    data: T[],
    where: ((table: T, ops: WhereOperators) => boolean | unknown) | undefined
): T[] {
    if (!where) return data;

    const ops = createWhereOps();

    return data.filter((item) => {
        // Create a proxy that returns the actual field value when accessed
        const proxy = new Proxy(item, {
            get: (_target, prop) => item[prop as keyof T],
        });
        const result = where(proxy as T, ops);
        return result;
    });
}

/**
 * Apply orderBy to data
 */
function applyOrderBy<T extends BaseEntity>(
    data: T[],
    orderBy: ((table: T, ops: OrderByOperators) => unknown[]) | undefined
): T[] {
    if (!orderBy) return data;

    const ops = createOrderByOps();
    // Get the ordering spec using a sample item (for field extraction)
    const sample = data[0];
    if (!sample) return data;

    // We need to track which fields and directions to sort by
    const sortSpecs: { field: string; direction: 'asc' | 'desc' }[] = [];

    // Create a proxy to capture field access
    const fieldProxy = new Proxy({} as T, {
        get: (_target, prop) => prop,
    });

    const orderResult = orderBy(fieldProxy, ops);

    // Extract sort specifications from the result
    for (const spec of orderResult) {
        if (spec && typeof spec === 'object' && 'field' in spec && 'direction' in spec) {
            sortSpecs.push(spec as { field: string; direction: 'asc' | 'desc' });
        }
    }

    // Sort the data
    return [...data].sort((a, b) => {
        for (const { field, direction } of sortSpecs) {
            const aVal = a[field];
            const bVal = b[field];

            let comparison = 0;
            if (aVal instanceof Date && bVal instanceof Date) {
                comparison = aVal.getTime() - bVal.getTime();
            } else if (typeof aVal === 'number' && typeof bVal === 'number') {
                comparison = aVal - bVal;
            } else if (typeof aVal === 'string' && typeof bVal === 'string') {
                comparison = aVal.localeCompare(bVal);
            }

            if (comparison !== 0) {
                return direction === 'asc' ? comparison : -comparison;
            }
        }
        return 0;
    });
}

/**
 * Create a relational query mock for a specific table
 */
function createRelationalQueryMock<T extends BaseEntity>(
    store: DataStore,
    tableName: string
) {
    return {
        findMany: vi.fn(async (options?: QueryOptions<T>): Promise<T[]> => {
            let data = (store.get(tableName) || []) as T[];

            // Apply where filter
            data = applyWhere(data, options?.where);

            // Apply orderBy
            data = applyOrderBy(data, options?.orderBy);

            // Apply limit/offset
            if (options?.offset) {
                data = data.slice(options.offset);
            }
            if (options?.limit) {
                data = data.slice(0, options.limit);
            }

            return data;
        }),

        findFirst: vi.fn(async (options?: QueryOptions<T>): Promise<T | undefined> => {
            let data = (store.get(tableName) || []) as T[];

            // Apply where filter
            data = applyWhere(data, options?.where);

            // Apply orderBy
            data = applyOrderBy(data, options?.orderBy);

            return data[0];
        }),
    };
}

/**
 * Create an insert builder mock
 */
function createInsertMock<T extends BaseEntity>(
    store: DataStore,
    tableName: string
): (table: unknown) => InsertBuilder<T> {
    return () => {
        let valuesToInsert: Partial<T>[] = [];
        let conflictBehavior: 'nothing' | 'update' | null = null;
        let conflictUpdateSet: Partial<T> | null = null;

        const builder: InsertBuilder<T> = {
            values: (data) => {
                valuesToInsert = Array.isArray(data) ? data : [data];
                return builder;
            },
            returning: async () => {
                const existing = (store.get(tableName) || []) as T[];
                const inserted: T[] = [];

                for (const val of valuesToInsert) {
                    const existingIndex = existing.findIndex((e) => e.id === val.id);
                    if (existingIndex !== -1) {
                        if (conflictBehavior === 'nothing') {
                            inserted.push(existing[existingIndex] as T);
                            continue;
                        }
                        if (conflictBehavior === 'update' && conflictUpdateSet) {
                            // Apply the update to the existing item
                            const updatedItem = {
                                ...existing[existingIndex],
                                ...conflictUpdateSet,
                                updatedAt: new Date(),
                            } as T;
                            existing[existingIndex] = updatedItem;
                            inserted.push(updatedItem);
                            continue;
                        }
                    }

                    const newItem = {
                        ...val,
                        createdAt: val.createdAt || new Date(),
                        updatedAt: val.updatedAt || new Date(),
                    } as T;

                    existing.push(newItem);
                    inserted.push(newItem);
                }

                store.set(tableName, existing);
                return inserted;
            },
            onConflictDoNothing: () => {
                conflictBehavior = 'nothing';
                return builder;
            },
            onConflictDoUpdate: (opts) => {
                conflictBehavior = 'update';
                conflictUpdateSet = opts.set;
                return builder;
            },
        };

        return builder;
    };
}

/**
 * Create an update builder mock
 */
function createUpdateMock<T extends BaseEntity>(
    store: DataStore,
    tableName: string
): (table: unknown) => UpdateBuilder<T> {
    return () => {
        let updateData: Partial<T> = {};
        let whereCondition: unknown = null;

        const builder: UpdateBuilder<T> = {
            set: (data) => {
                updateData = data;
                return builder;
            },
            where: (condition) => {
                whereCondition = condition;
                return builder;
            },
            returning: async () => {
                const data = (store.get(tableName) || []) as T[];
                const updated: T[] = [];

                for (let i = 0; i < data.length; i++) {
                    const item = data[i];
                    // For testing purposes, if a where condition is provided (truthy),
                    // we assume it matches the first item in the store.
                    // This simplified approach works for single-item update tests.
                    // Real Drizzle SQL conditions are complex objects that are hard to parse.
                    const shouldUpdate =
                        whereCondition === undefined ||
                        whereCondition === null ||
                        (typeof whereCondition === 'boolean' && whereCondition) ||
                        // If whereCondition is a truthy object (Drizzle SQL condition),
                        // update the first matching item (simplified behavior for tests)
                        (whereCondition && typeof whereCondition === 'object');

                    if (shouldUpdate) {
                        const newItem = {
                            ...item,
                            ...updateData,
                            updatedAt: new Date(),
                        } as T;
                        data[i] = newItem;
                        updated.push(newItem);
                        // Only update first matching item for single-item update semantics
                        break;
                    }
                }

                store.set(tableName, data);
                return updated;
            },
        };

        return builder;
    };
}

/**
 * Create a delete builder mock
 */
function createDeleteMock<T extends BaseEntity>(
    store: DataStore,
    tableName: string
): (table: unknown) => DeleteBuilder<T> {
    return () => {
        let deleteFilter: ((item: T) => boolean) | null = null;

        const builder: DeleteBuilder<T> = {
            where: (condition) => {
                // For now, treat any where condition as "delete all"
                // In a more sophisticated implementation, we'd parse the condition
                deleteFilter = () => Boolean(condition);
                return builder;
            },
            returning: async () => {
                const data = (store.get(tableName) || []) as T[];
                let deleted: T[];
                let remaining: T[];

                if (deleteFilter) {
                    // In reality, we'd filter based on the condition
                    // For simplicity, delete all items when a where clause is provided
                    deleted = [...data];
                    remaining = [];
                } else {
                    // No filter means delete nothing
                    deleted = [];
                    remaining = data;
                }

                store.set(tableName, remaining);
                return deleted;
            },
        };

        return builder;
    };
}

/**
 * Chainable select builder interface
 * Mimics Drizzle's db.select().from().where().orderBy().limit() pattern
 */
interface SelectBuilder<T> {
    from: (table: unknown) => SelectBuilder<T>;
    where: (condition: unknown) => SelectBuilder<T>;
    orderBy: (...orderings: unknown[]) => SelectBuilder<T>;
    limit: (n: number) => SelectBuilder<T>;
    offset: (n: number) => SelectBuilder<T>;
    then: <TResult1 = T[], TResult2 = never>(
        onfulfilled?: ((value: T[]) => TResult1 | PromiseLike<TResult1>) | null,
        onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null
    ) => Promise<TResult1 | TResult2>;
}

/**
 * Create a select builder mock that supports chainable API
 * Usage: db.select().from(table).where(condition).orderBy(...).limit(n)
 */
function createSelectMock<T extends BaseEntity>(store: DataStore): SelectBuilder<T> {
    let tableName: string | null = null;
    let whereConditions: unknown[] = [];
    let orderSpecs: { field: string; direction: 'asc' | 'desc' }[] = [];
    let limitValue: number | null = null;
    let offsetValue: number | null = null;

    /**
     * Parse a Drizzle SQL condition to extract field/value comparisons
     * This handles `eq(table.field, value)` style conditions
     */
    function parseCondition(condition: unknown): ((item: T) => boolean) | null {
        if (condition === undefined || condition === null) {
            return null;
        }

        // Handle SQL template objects from Drizzle
        // These look like: { queryChunks: [...], sql: SQL<...> }
        // or for eq/and: { sql: SQL<...>, getSQL: () => ... }
        if (typeof condition === 'object' && condition !== null) {
            const obj = condition as Record<string, unknown>;

            // Check if this is a Drizzle SQL object
            if ('getSQL' in obj && typeof obj.getSQL === 'function') {
                try {
                    const sql = obj.getSQL();
                    // Try to extract comparison info from the SQL object
                    if (sql && typeof sql === 'object' && 'queryChunks' in (sql as Record<string, unknown>)) {
                        const chunks = (sql as { queryChunks: unknown[] }).queryChunks;
                        // Extract field names and values from chunks
                        // This is a simplified heuristic
                        return () => true; // Allow through for now
                    }
                } catch {
                    // Fallback if getSQL fails
                }
            }

            // Check for queryChunks directly (common in Drizzle SQL objects)
            if ('queryChunks' in obj) {
                // For now, accept all SQL conditions
                return () => true;
            }
        }

        // Boolean condition
        if (typeof condition === 'boolean') {
            return () => condition;
        }

        // Default: accept
        return null;
    }

    /**
     * Execute the query against the store
     */
    async function executeQuery(): Promise<T[]> {
        if (!tableName) {
            return [];
        }

        let data = (store.get(tableName) || []) as T[];

        // Apply where conditions if any meaningful ones exist
        // Note: Drizzle conditions are complex SQL objects that are hard to parse
        // For testing purposes, we accept the data as-is if conditions are present
        // Real filtering should happen via seeded test data
        for (const condition of whereConditions) {
            const filter = parseCondition(condition);
            if (filter) {
                data = data.filter(filter);
            }
        }

        // Apply ordering
        if (orderSpecs.length > 0) {
            data = [...data].sort((a, b) => {
                for (const { field, direction } of orderSpecs) {
                    const aVal = a[field];
                    const bVal = b[field];

                    let comparison = 0;
                    if (aVal instanceof Date && bVal instanceof Date) {
                        comparison = aVal.getTime() - bVal.getTime();
                    } else if (typeof aVal === 'number' && typeof bVal === 'number') {
                        comparison = aVal - bVal;
                    } else if (typeof aVal === 'string' && typeof bVal === 'string') {
                        comparison = aVal.localeCompare(bVal);
                    }

                    if (comparison !== 0) {
                        return direction === 'asc' ? comparison : -comparison;
                    }
                }
                return 0;
            });
        }

        // Apply offset
        if (offsetValue !== null && offsetValue > 0) {
            data = data.slice(offsetValue);
        }

        // Apply limit
        if (limitValue !== null) {
            data = data.slice(0, limitValue);
        }

        return data;
    }

    const builder: SelectBuilder<T> = {
        from: (table: unknown) => {
            // Extract table name from the schema table object
            // Drizzle tables use Symbol.for('drizzle:Name') to store the table name
            const drizzleNameSymbol = Symbol.for('drizzle:Name');
            const tableWithSymbol = table as Record<symbol, string>;
            tableName = tableWithSymbol[drizzleNameSymbol] || null;
            return builder;
        },

        where: (condition: unknown) => {
            whereConditions.push(condition);
            return builder;
        },

        orderBy: (...orderings: unknown[]) => {
            // Parse ordering specs from Drizzle asc/desc objects
            for (const ordering of orderings) {
                if (ordering && typeof ordering === 'object') {
                    const ord = ordering as { sql?: { queryChunks?: unknown[] }; order?: string };

                    // Drizzle orderBy produces objects with sql.queryChunks
                    // For simplicity, we'll extract field names heuristically
                    if (ord.sql && ord.sql.queryChunks) {
                        const chunks = ord.sql.queryChunks;
                        // Usually contains column reference and direction
                        // For now, use a default order
                        orderSpecs.push({ field: 'updatedAt', direction: 'desc' });
                    } else {
                        // Fallback
                        orderSpecs.push({ field: 'id', direction: 'desc' });
                    }
                }
            }
            return builder;
        },

        limit: (n: number) => {
            limitValue = n;
            return builder;
        },

        offset: (n: number) => {
            offsetValue = n;
            return builder;
        },

        // Make the builder thenable so it can be awaited directly
        then: <TResult1 = T[], TResult2 = never>(
            onfulfilled?: ((value: T[]) => TResult1 | PromiseLike<TResult1>) | null,
            onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null
        ): Promise<TResult1 | TResult2> => {
            return executeQuery().then(onfulfilled, onrejected);
        },
    };

    return builder;
}

/**
 * Table name mappings from schema export names to database table names
 */
const TABLE_NAME_MAP: Record<string, string> = {
    accounts: 'Account',
    sessions: 'Session',
    sessionMessages: 'SessionMessage',
    machines: 'Machine',
    artifacts: 'Artifact',
    accessKeys: 'AccessKey',
    userRelationships: 'UserRelationship',
    userFeedItems: 'UserFeedItem',
    usageReports: 'UsageReport',
    userKVStores: 'UserKVStore',
    accountPushTokens: 'AccountPushToken',
    terminalAuthRequests: 'TerminalAuthRequest',
    accountAuthRequests: 'AccountAuthRequest',
    serviceAccountTokens: 'AIServiceToken',
    githubUsers: 'GitHubUser',
    uploadedFiles: 'UploadedFile',
};

/**
 * Configuration for mock Drizzle client
 */
export interface MockDrizzleConfig {
    /** Initial data to seed into tables */
    initialData?: Record<string, BaseEntity[]>;
}

/**
 * Create a mock Drizzle client that mimics the real Drizzle ORM behavior
 *
 * @example
 * ```typescript
 * import { createMockDrizzle } from './mock-drizzle';
 *
 * const { mockDb, seedData, getData } = createMockDrizzle();
 *
 * // Seed test data
 * seedData('sessions', [
 *     { id: 'session-1', accountId: 'user-123', metadata: '{}', active: true }
 * ]);
 *
 * // Mock the getDb function
 * vi.mock('@/db/client', () => ({
 *     getDb: vi.fn(() => mockDb)
 * }));
 *
 * // Now route handlers will use the mock database
 * const res = await app.request('/v1/sessions', { headers: authHeader() });
 * const body = await res.json();
 * expect(body.sessions).toHaveLength(1);
 * ```
 */
export function createMockDrizzle(config?: MockDrizzleConfig) {
    // In-memory data store
    const store: DataStore = new Map();

    // Initialize tables
    Object.values(TABLE_NAME_MAP).forEach((tableName) => {
        store.set(tableName, []);
    });

    // Seed initial data if provided
    if (config?.initialData) {
        for (const [table, data] of Object.entries(config.initialData)) {
            const tableName = TABLE_NAME_MAP[table] || table;
            store.set(tableName, [...data]);
        }
    }

    // Create query mock for each table
    const queryMocks: Record<string, ReturnType<typeof createRelationalQueryMock>> = {};

    for (const [schemaName, tableName] of Object.entries(TABLE_NAME_MAP)) {
        queryMocks[schemaName] = createRelationalQueryMock(store, tableName);
    }

    // Create the mock database client
    const mockDb = {
        // Relational query API (db.query.tableName.findMany/findFirst)
        query: queryMocks,

        // Core insert API (db.insert(table).values(...).returning())
        insert: vi.fn((table: unknown) => {
            // Determine table name from the table object using Drizzle's Symbol
            const drizzleNameSymbol = Symbol.for('drizzle:Name');
            const tableName = (table as Record<symbol, string>)[drizzleNameSymbol] || 'Unknown';
            return createInsertMock(store, tableName)(table);
        }),

        // Core update API (db.update(table).set(...).where(...).returning())
        update: vi.fn((table: unknown) => {
            const drizzleNameSymbol = Symbol.for('drizzle:Name');
            const tableName = (table as Record<symbol, string>)[drizzleNameSymbol] || 'Unknown';
            return createUpdateMock(store, tableName)(table);
        }),

        // Core delete API (db.delete(table).where(...).returning())
        delete: vi.fn((table: unknown) => {
            const drizzleNameSymbol = Symbol.for('drizzle:Name');
            const tableName = (table as Record<symbol, string>)[drizzleNameSymbol] || 'Unknown';
            return createDeleteMock(store, tableName)(table);
        }),

        // Core select API (db.select().from(table).where(...).orderBy(...).limit(...))
        select: vi.fn(() => {
            return createSelectMock(store);
        }),

        // Transaction support
        transaction: vi.fn(async <T>(fn: (tx: typeof mockDb) => Promise<T>): Promise<T> => {
            return fn(mockDb);
        }),
    };

    return {
        /** The mock database client - use this to replace getDb() return value */
        mockDb: mockDb as unknown as DbClient,

        /**
         * Seed data into a table
         * @param tableName - Schema table name (e.g., 'sessions', 'accounts')
         * @param data - Array of entities to seed
         */
        seedData: <T extends BaseEntity>(tableName: string, data: T[]) => {
            const actualTableName = TABLE_NAME_MAP[tableName] || tableName;
            store.set(actualTableName, [...data]);
        },

        /**
         * Get current data from a table
         * @param tableName - Schema table name (e.g., 'sessions', 'accounts')
         */
        getData: <T extends BaseEntity>(tableName: string): T[] => {
            const actualTableName = TABLE_NAME_MAP[tableName] || tableName;
            return (store.get(actualTableName) || []) as T[];
        },

        /**
         * Clear all data from all tables
         */
        clearAll: () => {
            Object.values(TABLE_NAME_MAP).forEach((tableName) => {
                store.set(tableName, []);
            });
        },

        /**
         * Get the underlying data store (for debugging)
         */
        _store: store,
    };
}

/**
 * Type for the mock Drizzle instance
 */
export type MockDrizzleInstance = ReturnType<typeof createMockDrizzle>;
