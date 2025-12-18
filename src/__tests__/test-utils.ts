/**
 * Test Utilities for Integration Tests
 *
 * Provides mock infrastructure for testing Hono routes against Cloudflare Workers
 * environment without actual D1/R2/Durable Object dependencies.
 *
 * @module __tests__/test-utils
 */

import { vi } from 'vitest';

// Re-export mock-drizzle utilities for easy access
export { createMockDrizzle, type MockDrizzleInstance } from './mock-drizzle';

/**
 * Mock user ID used in authentication mocks
 */
export const TEST_USER_ID = 'test-user-123';

/**
 * Second test user for relationship/ownership tests
 */
export const TEST_USER_ID_2 = 'test-user-456';

/**
 * Valid auth token that passes mock verification
 */
export const VALID_TOKEN = 'valid-token';

/**
 * Invalid auth token that fails mock verification
 */
export const INVALID_TOKEN = 'invalid-token';

/**
 * Create authorization header for authenticated requests
 */
export function authHeader(token: string = VALID_TOKEN): Headers {
    return new Headers({
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
    });
}

/**
 * Create JSON body for POST/PUT requests
 */
export function jsonBody(data: unknown): string {
    return JSON.stringify(data);
}

/**
 * Type-safe JSON response parser
 */
export async function parseJson<T = unknown>(response: Response): Promise<T> {
    return (await response.json()) as T;
}

/**
 * Mock D1 Database for tests
 * Provides in-memory storage with basic query support
 */
export function createMockDb() {
    const storage = new Map<string, unknown[]>();

    // Initialize empty tables
    const tables = [
        'Account',
        'Session',
        'SessionMessage',
        'Machine',
        'Artifact',
        'AccessKey',
        'UserRelationship',
        'UserFeedItem',
        'UsageReport',
        'UserKVStore',
        'PushToken',
        'TerminalAuthRequest',
        'AIServiceToken',
        'GitHubUser',
        'UploadedFile',
    ];
    tables.forEach((table) => storage.set(table, []));

    return {
        prepare: vi.fn((_sql: string) => {
            const mockStatement = {
                bind: vi.fn(() => mockStatement),
                all: vi.fn(async () => ({
                    results: [],
                    success: true,
                })),
                first: vi.fn(async () => null),
                run: vi.fn(async () => ({
                    success: true,
                    meta: { changes: 1 },
                })),
            };
            return mockStatement;
        }),
        batch: vi.fn(async () => []),
        exec: vi.fn(async () => ({ count: 0, duration: 0 })),
        dump: vi.fn(async () => new ArrayBuffer(0)),

        // Test helpers
        _storage: storage,
        _seed: (table: string, data: unknown[]) => {
            storage.set(table, data);
        },
    };
}

/**
 * Mock R2 Bucket for tests
 */
export function createMockR2() {
    const files = new Map<string, { body: ArrayBuffer; customMetadata?: Record<string, string> }>();

    return {
        get: vi.fn(async (key: string) => {
            const file = files.get(key);
            if (!file) return null;
            return {
                body: new ReadableStream(),
                bodyUsed: false,
                arrayBuffer: async () => file.body,
                text: async () => new TextDecoder().decode(file.body),
                json: async () => JSON.parse(new TextDecoder().decode(file.body)),
                blob: async () => new Blob([file.body]),
                customMetadata: file.customMetadata,
                httpMetadata: {},
                key,
                size: file.body.byteLength,
                etag: 'mock-etag',
                uploaded: new Date(),
            };
        }),
        put: vi.fn(async (key: string, body: ArrayBuffer | ReadableStream, options?: object) => {
            let buffer: ArrayBuffer;
            if (body instanceof ArrayBuffer) {
                buffer = body;
            } else {
                buffer = new ArrayBuffer(0);
            }
            files.set(key, {
                body: buffer,
                customMetadata: (options as { customMetadata?: Record<string, string> })
                    ?.customMetadata,
            });
            return { key, etag: 'mock-etag' };
        }),
        delete: vi.fn(async (key: string) => {
            files.delete(key);
        }),
        list: vi.fn(async () => ({
            objects: Array.from(files.keys()).map((key) => ({
                key,
                size: files.get(key)!.body.byteLength,
                etag: 'mock-etag',
                uploaded: new Date(),
            })),
            truncated: false,
        })),

        // Test helpers
        _files: files,
    };
}

/**
 * Mock Durable Object Namespace
 */
export function createMockDurableObjectNamespace() {
    return {
        idFromName: vi.fn((name: string) => ({
            toString: () => `do-id-${name}`,
        })),
        get: vi.fn(() => ({
            fetch: vi.fn(async () => new Response(JSON.stringify({ success: true }))),
        })),
    };
}

/**
 * Create mock environment with all bindings
 */
export function createMockEnv() {
    return {
        ENVIRONMENT: 'development' as const,
        HANDY_MASTER_SECRET: 'test-secret-for-vitest-tests',
        DB: createMockDb(),
        UPLOADS: createMockR2(),
        CONNECTION_MANAGER: createMockDurableObjectNamespace(),
        TEST_AUTH_SECRET: 'test-auth-secret',
    };
}

/**
 * Generate unique test ID
 */
let idCounter = 0;
export function generateTestId(prefix: string = 'test'): string {
    idCounter++;
    return `${prefix}_${Date.now()}_${idCounter}`;
}

/**
 * Reset ID counter between test suites
 */
export function resetTestIds(): void {
    idCounter = 0;
}

/**
 * Assert successful JSON response
 */
export async function expectSuccess(
    response: Response,
    expectedStatus: number = 200
): Promise<void> {
    if (response.status !== expectedStatus) {
        const body = await response.text();
        throw new Error(
            `Expected status ${expectedStatus}, got ${response.status}. Body: ${body}`
        );
    }
}

/**
 * Assert error response
 */
export async function expectError(
    response: Response,
    expectedStatus: number,
    errorContains?: string
): Promise<void> {
    if (response.status !== expectedStatus) {
        const body = await response.text();
        throw new Error(
            `Expected status ${expectedStatus}, got ${response.status}. Body: ${body}`
        );
    }
    if (errorContains) {
        const body = await response.text();
        if (!body.includes(errorContains)) {
            throw new Error(`Expected error to contain "${errorContains}", got: ${body}`);
        }
    }
}


/**
 * Assert response is successful (2xx) and return parsed JSON body.
 * Use this instead of conditionally checking res.ok before parsing.
 *
 * @example
 * // Before (anti-pattern - expect may never run)
 * if (res.ok) {
 *     const body = await parseJson<{ sessions: unknown[] }>(res);
 *     expect(body).toHaveProperty('sessions');
 * }
 *
 * // After (fail fast, expect always runs)
 * const body = await expectOk<{ sessions: unknown[] }>(res);
 * expect(body).toHaveProperty('sessions');
 */
export async function expectOk<T>(response: Response): Promise<T> {
    if (!response.ok) {
        const body = await response.text();
        throw new Error(
            `Expected response.ok to be true, got status ${response.status}. Body: ${body}`
        );
    }
    return (await response.json()) as T;
}

/**
 * Assert response has specific status and return parsed JSON body.
 * Use this instead of conditionally checking res.status before parsing.
 *
 * @example
 * // Before (anti-pattern - expect may never run)
 * if (res.status === 200) {
 *     const body = await parseJson<{ success: boolean }>(res);
 *     expect(body.success).toBe(true);
 * }
 *
 * // After (fail fast, expect always runs)
 * const body = await expectStatus<{ success: boolean }>(res, 200);
 * expect(body.success).toBe(true);
 */
export async function expectStatus<T>(response: Response, status: number): Promise<T> {
    if (response.status !== status) {
        const body = await response.text();
        throw new Error(
            `Expected status ${status}, got ${response.status}. Body: ${body}`
        );
    }
    return (await response.json()) as T;
}

/**
 * Assert response status is one of expected statuses and return parsed JSON body.
 * Use this for tests where multiple success statuses are acceptable.
 *
 * @example
 * // Before (anti-pattern - expect may never run)
 * expect([200, 201, 500]).toContain(res.status);
 * if (res.status === 200 || res.status === 201) {
 *     const body = await parseJson<{ session: object }>(res);
 *     expect(body).toHaveProperty('session');
 * }
 *
 * // After (fail fast, expect always runs or test skips gracefully)
 * const body = await expectOneOfStatus<{ session: object }>(res, [200, 201], [500]);
 * if (body) {
 *     expect(body).toHaveProperty('session');
 * }
 */
export async function expectOneOfStatus<T>(
    response: Response,
    successStatuses: number[],
    acceptableFailureStatuses: number[] = []
): Promise<T | null> {
    const allAcceptable = [...successStatuses, ...acceptableFailureStatuses];
    if (!allAcceptable.includes(response.status)) {
        const body = await response.text();
        throw new Error(
            `Expected status to be one of [${allAcceptable.join(', ')}], got ${response.status}. Body: ${body}`
        );
    }
    if (acceptableFailureStatuses.includes(response.status)) {
        return null;
    }
    return (await response.json()) as T;
}

/**
 * Create test session data compatible with Drizzle ORM schema
 * Returns Date objects for timestamp fields as expected by the schema
 */
export function createTestSession(accountId: string, overrides: Partial<{
    id: string;
    tag: string;
    metadata: string;
    agentState: string;
    active: boolean;
    lastActiveAt: Date;
    createdAt: Date;
    updatedAt: Date;
}> = {}) {
    const now = new Date();
    return {
        id: overrides.id ?? generateTestId('session'),
        tag: overrides.tag ?? `test-tag-${Date.now()}`,
        accountId,
        metadata: overrides.metadata ?? '{"name":"Test Session"}',
        metadataVersion: 1,
        agentState: overrides.agentState ?? '{}',
        agentStateVersion: 1,
        dataEncryptionKey: Buffer.from('test-key'),
        seq: 0,
        active: overrides.active ?? true,
        lastActiveAt: overrides.lastActiveAt ?? now,
        createdAt: overrides.createdAt ?? now,
        updatedAt: overrides.updatedAt ?? now,
    };
}

/**
 * Create test machine data compatible with Drizzle ORM schema
 * Returns Date objects for timestamp fields as expected by the schema
 */
export function createTestMachine(accountId: string, overrides: Partial<{
    id: string;
    metadata: string;
    daemonState: string;
    active: boolean;
    lastActiveAt: Date;
    createdAt: Date;
    updatedAt: Date;
}> = {}) {
    const now = new Date();
    return {
        id: overrides.id ?? generateTestId('machine'),
        accountId,
        metadata: overrides.metadata ?? '{"hostname":"test-machine"}',
        metadataVersion: 1,
        daemonState: overrides.daemonState ?? '{}',
        daemonStateVersion: 1,
        dataEncryptionKey: Buffer.from('test-key'),
        seq: 0,
        active: overrides.active ?? false,
        lastActiveAt: overrides.lastActiveAt ?? now,
        createdAt: overrides.createdAt ?? now,
        updatedAt: overrides.updatedAt ?? now,
    };
}

/**
 * Create test artifact data compatible with Drizzle ORM schema
 * Returns Date objects for timestamp fields as expected by the schema
 */
export function createTestArtifact(accountId: string, overrides: Partial<{
    id: string;
    header: Buffer;
    body: Buffer;
    createdAt: Date;
    updatedAt: Date;
}> = {}) {
    const now = new Date();
    return {
        id: overrides.id ?? generateTestId('artifact'),
        accountId,
        header: overrides.header ?? Buffer.from('test-header'),
        headerVersion: 1,
        body: overrides.body ?? Buffer.from('test-body'),
        bodyVersion: 1,
        dataEncryptionKey: Buffer.from('test-key'),
        seq: 0,
        createdAt: overrides.createdAt ?? now,
        updatedAt: overrides.updatedAt ?? now,
    };
}

/**
 * Create test account data compatible with Drizzle ORM schema
 * Returns Date objects for timestamp fields as expected by the schema
 */
export function createTestAccount(overrides: Partial<{
    id: string;
    publicKey: string;
    firstName: string;
    lastName: string;
    username: string;
    seq: number;
    feedSeq: number;
    settings: string;
    settingsVersion: number;
    githubUserId: string | null;
    createdAt: Date;
    updatedAt: Date;
}> = {}) {
    const now = new Date();
    return {
        id: overrides.id ?? generateTestId('account'),
        publicKey: overrides.publicKey ?? `ed25519_pk_test_${Date.now()}`,
        seq: overrides.seq ?? 0,
        feedSeq: overrides.feedSeq ?? 0,
        firstName: overrides.firstName ?? 'Test',
        lastName: overrides.lastName ?? 'User',
        username: overrides.username ?? `testuser_${Date.now()}`,
        settings: overrides.settings ?? '{}',
        settingsVersion: overrides.settingsVersion ?? 1,
        githubUserId: overrides.githubUserId ?? null,
        createdAt: overrides.createdAt ?? now,
        updatedAt: overrides.updatedAt ?? now,
    };
}

/**
 * Create test access key data compatible with Drizzle ORM schema
 */
export function createTestAccessKey(accountId: string, sessionId: string, machineId: string, overrides: Partial<{
    id: string;
    data: string;
    dataVersion: number;
    createdAt: Date;
    updatedAt: Date;
}> = {}) {
    const now = new Date();
    return {
        id: overrides.id ?? generateTestId('accesskey'),
        accountId,
        sessionId,
        machineId,
        data: overrides.data ?? 'encrypted-access-key-data',
        dataVersion: overrides.dataVersion ?? 1,
        createdAt: overrides.createdAt ?? now,
        updatedAt: overrides.updatedAt ?? now,
    };
}
