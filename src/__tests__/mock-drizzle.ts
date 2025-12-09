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
                    // Simple condition check - assumes it's checking id
                    if (
                        whereCondition === undefined ||
                        (typeof whereCondition === 'boolean' && whereCondition)
                    ) {
                        const newItem = {
                            ...item,
                            ...updateData,
                            updatedAt: new Date(),
                        } as T;
                        data[i] = newItem;
                        updated.push(newItem);
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
            // Determine table name from the table object
            const tableName = (table as { _: { name: string } })?._?.name || 'Unknown';
            return createInsertMock(store, tableName)(table);
        }),

        // Core update API (db.update(table).set(...).where(...).returning())
        update: vi.fn((table: unknown) => {
            const tableName = (table as { _: { name: string } })?._?.name || 'Unknown';
            return createUpdateMock(store, tableName)(table);
        }),

        // Core delete API (db.delete(table).where(...).returning())
        delete: vi.fn((table: unknown) => {
            const tableName = (table as { _: { name: string } })?._?.name || 'Unknown';
            return createDeleteMock(store, tableName)(table);
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
