/**
 * Drizzle ORM Schema for Happy Server (D1/SQLite)
 *
 * Migrated from Prisma/PostgreSQL schema
 * Reference: happy-server/prisma/schema.prisma
 *
 * Key Migrations:
 * - PostgreSQL Bytes → SQLite blob (buffer mode)
 * - PostgreSQL Json → SQLite text (json mode)
 * - PostgreSQL DateTime → SQLite integer (timestamp_ms mode)
 * - PostgreSQL BigInt → SQLite integer
 * - PostgreSQL Boolean → SQLite integer (boolean mode)
 * - PostgreSQL enums → SQLite text with CHECK constraints
 * - cuid() defaults → Application layer (using cuid2 package)
 * - @updatedAt → $onUpdate helper
 * - Account.avatar field → REMOVED (frontend-only avatars)
 */

import { relations, sql } from 'drizzle-orm';
import {
    sqliteTable,
    text,
    integer,
    blob,
    index,
    uniqueIndex,
    primaryKey,
    check,
} from 'drizzle-orm/sqlite-core';

// ============================================================================
// Account
// ============================================================================

export const accounts = sqliteTable(
    'Account',
    {
        id: text('id').primaryKey(),
        publicKey: text('publicKey').notNull().unique(),
        seq: integer('seq').notNull().default(0),
        feedSeq: integer('feedSeq').notNull().default(0),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
        settings: text('settings'),
        settingsVersion: integer('settingsVersion').notNull().default(0),
        githubUserId: text('githubUserId').unique(),

        // Profile (avatar field removed - frontend generates avatars)
        firstName: text('firstName'),
        lastName: text('lastName'),
        username: text('username').unique(),

        // Privacy settings (HAP-727)
        showOnlineStatus: integer('showOnlineStatus', { mode: 'boolean' })
            .notNull()
            .default(true),
    },
    (table) => ({
        publicKeyIdx: uniqueIndex('Account_publicKey_key').on(table.publicKey),
        usernameIdx: uniqueIndex('Account_username_key').on(table.username),
        githubUserIdIdx: uniqueIndex('Account_githubUserId_key').on(
            table.githubUserId
        ),
    })
);

export const accountsRelations = relations(accounts, ({ one, many }) => ({
    githubUser: one(githubUsers, {
        fields: [accounts.githubUserId],
        references: [githubUsers.id],
    }),
    sessions: many(sessions),
    pushTokens: many(accountPushTokens),
    terminalAuthRequests: many(terminalAuthRequests),
    accountAuthRequests: many(accountAuthRequests),
    usageReports: many(usageReports),
    machines: many(machines),
    uploadedFiles: many(uploadedFiles),
    serviceAccountTokens: many(serviceAccountTokens),
    relationshipsFrom: many(userRelationships, {
        relationName: 'RelationshipsFrom',
    }),
    relationshipsTo: many(userRelationships, { relationName: 'RelationshipsTo' }),
    artifacts: many(artifacts),
    accessKeys: many(accessKeys),
    feedItems: many(userFeedItems),
    kvStore: many(userKVStores),
}));

// ============================================================================
// Auth Requests
// ============================================================================

export const terminalAuthRequests = sqliteTable(
    'TerminalAuthRequest',
    {
        id: text('id').primaryKey(),
        publicKey: text('publicKey').notNull().unique(),
        supportsV2: integer('supportsV2', { mode: 'boolean' })
            .notNull()
            .default(false),
        response: text('response'),
        responseAccountId: text('responseAccountId'),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        publicKeyIdx: uniqueIndex('TerminalAuthRequest_publicKey_key').on(
            table.publicKey
        ),
    })
);

export const terminalAuthRequestsRelations = relations(
    terminalAuthRequests,
    ({ one }) => ({
        responseAccount: one(accounts, {
            fields: [terminalAuthRequests.responseAccountId],
            references: [accounts.id],
        }),
    })
);

export const accountAuthRequests = sqliteTable(
    'AccountAuthRequest',
    {
        id: text('id').primaryKey(),
        publicKey: text('publicKey').notNull().unique(),
        response: text('response'),
        responseAccountId: text('responseAccountId'),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        publicKeyIdx: uniqueIndex('AccountAuthRequest_publicKey_key').on(
            table.publicKey
        ),
    })
);

export const accountAuthRequestsRelations = relations(
    accountAuthRequests,
    ({ one }) => ({
        responseAccount: one(accounts, {
            fields: [accountAuthRequests.responseAccountId],
            references: [accounts.id],
        }),
    })
);

export const accountPushTokens = sqliteTable(
    'AccountPushToken',
    {
        id: text('id').primaryKey(),
        accountId: text('accountId').notNull(),
        token: text('token').notNull(),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        accountTokenIdx: uniqueIndex('AccountPushToken_accountId_token_key').on(
            table.accountId,
            table.token
        ),
    })
);

export const accountPushTokensRelations = relations(
    accountPushTokens,
    ({ one }) => ({
        account: one(accounts, {
            fields: [accountPushTokens.accountId],
            references: [accounts.id],
        }),
    })
);

// ============================================================================
// Sessions
// ============================================================================

export const sessions = sqliteTable(
    'Session',
    {
        id: text('id').primaryKey(),
        tag: text('tag').notNull(),
        accountId: text('accountId').notNull(),
        metadata: text('metadata').notNull(),
        metadataVersion: integer('metadataVersion').notNull().default(0),
        agentState: text('agentState'),
        agentStateVersion: integer('agentStateVersion').notNull().default(0),
        dataEncryptionKey: blob('dataEncryptionKey', { mode: 'buffer' }),
        seq: integer('seq').notNull().default(0),
        active: integer('active', { mode: 'boolean' }).notNull().default(true),
        lastActiveAt: integer('lastActiveAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        // Session state tracking for revival flow (HAP-734)
        stoppedAt: integer('stoppedAt', { mode: 'timestamp_ms' }),
        stoppedReason: text('stoppedReason'),
        archivedAt: integer('archivedAt', { mode: 'timestamp_ms' }),
        archiveReason: text('archiveReason'), // 'revival_failed' | 'user_requested' | 'timeout'
        archiveError: text('archiveError'), // Original error for debugging
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        accountTagIdx: uniqueIndex('Session_accountId_tag_key').on(
            table.accountId,
            table.tag
        ),
        accountUpdatedAtIdx: index('Session_accountId_updatedAt_idx').on(
            table.accountId,
            table.updatedAt
        ),
    })
);

export const sessionsRelations = relations(sessions, ({ one, many }) => ({
    account: one(accounts, {
        fields: [sessions.accountId],
        references: [accounts.id],
    }),
    messages: many(sessionMessages),
    usageReports: many(usageReports),
    accessKeys: many(accessKeys),
}));

export const sessionMessages = sqliteTable(
    'SessionMessage',
    {
        id: text('id').primaryKey(),
        sessionId: text('sessionId').notNull(),
        localId: text('localId'),
        seq: integer('seq').notNull(),
        content: text('content', { mode: 'json' }).notNull(),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        sessionLocalIdIdx: uniqueIndex('SessionMessage_sessionId_localId_key').on(
            table.sessionId,
            table.localId
        ),
        sessionSeqIdx: index('SessionMessage_sessionId_seq_idx').on(
            table.sessionId,
            table.seq
        ),
    })
);

export const sessionMessagesRelations = relations(sessionMessages, ({ one }) => ({
    session: one(sessions, {
        fields: [sessionMessages.sessionId],
        references: [sessions.id],
    }),
}));

// ============================================================================
// Github
// ============================================================================

export const githubUsers = sqliteTable('GithubUser', {
    id: text('id').primaryKey(),
    profile: text('profile', { mode: 'json' }).notNull(),
    token: blob('token', { mode: 'buffer' }),
    createdAt: integer('createdAt', { mode: 'timestamp_ms' })
        .notNull()
        .default(sql`(unixepoch() * 1000)`),
    updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
        .notNull()
        .default(sql`(unixepoch() * 1000)`)
        .$onUpdate(() => new Date()),
});

export const githubUsersRelations = relations(githubUsers, ({ many }) => ({
    accounts: many(accounts),
}));

export const githubOrganizations = sqliteTable('GithubOrganization', {
    id: text('id').primaryKey(),
    profile: text('profile', { mode: 'json' }).notNull(),
    createdAt: integer('createdAt', { mode: 'timestamp_ms' })
        .notNull()
        .default(sql`(unixepoch() * 1000)`),
    updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
        .notNull()
        .default(sql`(unixepoch() * 1000)`)
        .$onUpdate(() => new Date()),
});

// ============================================================================
// Utility Tables
// ============================================================================

export const globalLocks = sqliteTable('GlobalLock', {
    key: text('key').primaryKey(),
    value: text('value').notNull(),
    createdAt: integer('createdAt', { mode: 'timestamp_ms' })
        .notNull()
        .default(sql`(unixepoch() * 1000)`),
    updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
        .notNull()
        .default(sql`(unixepoch() * 1000)`)
        .$onUpdate(() => new Date()),
    expiresAt: integer('expiresAt', { mode: 'timestamp_ms' }).notNull(),
});

export const repeatKeys = sqliteTable('RepeatKey', {
    key: text('key').primaryKey(),
    value: text('value').notNull(),
    createdAt: integer('createdAt', { mode: 'timestamp_ms' })
        .notNull()
        .default(sql`(unixepoch() * 1000)`),
    expiresAt: integer('expiresAt', { mode: 'timestamp_ms' }).notNull(),
});

export const simpleCaches = sqliteTable('SimpleCache', {
    key: text('key').primaryKey(),
    value: text('value').notNull(),
    createdAt: integer('createdAt', { mode: 'timestamp_ms' })
        .notNull()
        .default(sql`(unixepoch() * 1000)`),
    updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
        .notNull()
        .default(sql`(unixepoch() * 1000)`)
        .$onUpdate(() => new Date()),
});

// ============================================================================
// Usage Reporting
// ============================================================================

export const usageReports = sqliteTable(
    'UsageReport',
    {
        id: text('id').primaryKey(),
        key: text('key').notNull(),
        accountId: text('accountId').notNull(),
        sessionId: text('sessionId'),
        data: text('data', { mode: 'json' }).notNull(),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        uniqueReportIdx: uniqueIndex('UsageReport_accountId_sessionId_key_key').on(
            table.accountId,
            table.sessionId,
            table.key
        ),
        accountIdx: index('UsageReport_accountId_idx').on(table.accountId),
        sessionIdx: index('UsageReport_sessionId_idx').on(table.sessionId),
    })
);

export const usageReportsRelations = relations(usageReports, ({ one }) => ({
    account: one(accounts, {
        fields: [usageReports.accountId],
        references: [accounts.id],
    }),
    session: one(sessions, {
        fields: [usageReports.sessionId],
        references: [sessions.id],
    }),
}));

// ============================================================================
// Machines
// ============================================================================

export const machines = sqliteTable(
    'Machine',
    {
        id: text('id').primaryKey(),
        accountId: text('accountId').notNull(),
        metadata: text('metadata').notNull(), // Encrypted
        metadataVersion: integer('metadataVersion').notNull().default(0),
        daemonState: text('daemonState'), // Encrypted
        daemonStateVersion: integer('daemonStateVersion').notNull().default(0),
        dataEncryptionKey: blob('dataEncryptionKey', { mode: 'buffer' }),
        seq: integer('seq').notNull().default(0),
        active: integer('active', { mode: 'boolean' }).notNull().default(true),
        lastActiveAt: integer('lastActiveAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        accountMachineIdx: uniqueIndex('Machine_accountId_id_key').on(
            table.accountId,
            table.id
        ),
        accountIdx: index('Machine_accountId_idx').on(table.accountId),
    })
);

export const machinesRelations = relations(machines, ({ one, many }) => ({
    account: one(accounts, {
        fields: [machines.accountId],
        references: [accounts.id],
    }),
    accessKeys: many(accessKeys),
}));

export const uploadedFiles = sqliteTable(
    'UploadedFile',
    {
        id: text('id').primaryKey(),
        accountId: text('accountId').notNull(),
        path: text('path').notNull(),
        width: integer('width'),
        height: integer('height'),
        thumbhash: text('thumbhash'),
        reuseKey: text('reuseKey'),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        accountPathIdx: uniqueIndex('UploadedFile_accountId_path_key').on(
            table.accountId,
            table.path
        ),
        accountIdx: index('UploadedFile_accountId_idx').on(table.accountId),
    })
);

export const uploadedFilesRelations = relations(uploadedFiles, ({ one }) => ({
    account: one(accounts, {
        fields: [uploadedFiles.accountId],
        references: [accounts.id],
    }),
}));

export const serviceAccountTokens = sqliteTable(
    'ServiceAccountToken',
    {
        id: text('id').primaryKey(),
        accountId: text('accountId').notNull(),
        vendor: text('vendor').notNull(),
        token: blob('token', { mode: 'buffer' }).notNull(), // Encrypted
        metadata: text('metadata', { mode: 'json' }),
        lastUsedAt: integer('lastUsedAt', { mode: 'timestamp_ms' }),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        accountVendorIdx: uniqueIndex(
            'ServiceAccountToken_accountId_vendor_key'
        ).on(table.accountId, table.vendor),
        accountIdx: index('ServiceAccountToken_accountId_idx').on(table.accountId),
    })
);

export const serviceAccountTokensRelations = relations(
    serviceAccountTokens,
    ({ one }) => ({
        account: one(accounts, {
            fields: [serviceAccountTokens.accountId],
            references: [accounts.id],
        }),
    })
);

// ============================================================================
// Artifacts
// ============================================================================

export const artifacts = sqliteTable(
    'Artifact',
    {
        id: text('id').primaryKey(), // UUID provided by client
        accountId: text('accountId').notNull(),
        header: blob('header', { mode: 'buffer' }).notNull(), // Encrypted
        headerVersion: integer('headerVersion').notNull().default(0),
        body: blob('body', { mode: 'buffer' }).notNull(), // Encrypted
        bodyVersion: integer('bodyVersion').notNull().default(0),
        dataEncryptionKey: blob('dataEncryptionKey', { mode: 'buffer' }).notNull(),
        seq: integer('seq').notNull().default(0),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        accountIdx: index('Artifact_accountId_idx').on(table.accountId),
        accountUpdatedAtIdx: index('Artifact_accountId_updatedAt_idx').on(
            table.accountId,
            table.updatedAt
        ),
    })
);

export const artifactsRelations = relations(artifacts, ({ one }) => ({
    account: one(accounts, {
        fields: [artifacts.accountId],
        references: [accounts.id],
    }),
}));

// ============================================================================
// Access Keys
// ============================================================================

export const accessKeys = sqliteTable(
    'AccessKey',
    {
        id: text('id').primaryKey(),
        accountId: text('accountId').notNull(),
        machineId: text('machineId').notNull(),
        sessionId: text('sessionId').notNull(),
        data: text('data').notNull(), // Encrypted
        dataVersion: integer('dataVersion').notNull().default(0),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        accountMachineSessionIdx: uniqueIndex(
            'AccessKey_accountId_machineId_sessionId_key'
        ).on(table.accountId, table.machineId, table.sessionId),
        accountIdx: index('AccessKey_accountId_idx').on(table.accountId),
        sessionIdx: index('AccessKey_sessionId_idx').on(table.sessionId),
        machineIdx: index('AccessKey_machineId_idx').on(table.machineId),
    })
);

export const accessKeysRelations = relations(accessKeys, ({ one }) => ({
    account: one(accounts, {
        fields: [accessKeys.accountId],
        references: [accounts.id],
    }),
    machine: one(machines, {
        fields: [accessKeys.accountId, accessKeys.machineId],
        references: [machines.accountId, machines.id],
    }),
    session: one(sessions, {
        fields: [accessKeys.sessionId],
        references: [sessions.id],
    }),
}));

// ============================================================================
// Social Network - Relationships
// ============================================================================

// RelationshipStatus enum implemented as CHECK constraint
export const userRelationships = sqliteTable(
    'UserRelationship',
    {
        fromUserId: text('fromUserId').notNull(),
        toUserId: text('toUserId').notNull(),
        status: text('status')
            .notNull()
            .default('pending')
            .$type<'none' | 'requested' | 'pending' | 'friend' | 'rejected'>(),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
        acceptedAt: integer('acceptedAt', { mode: 'timestamp_ms' }),
        lastNotifiedAt: integer('lastNotifiedAt', { mode: 'timestamp_ms' }),
    },
    (table) => ({
        pk: primaryKey({ columns: [table.fromUserId, table.toUserId] }),
        toUserStatusIdx: index('UserRelationship_toUserId_status_idx').on(
            table.toUserId,
            table.status
        ),
        fromUserStatusIdx: index('UserRelationship_fromUserId_status_idx').on(
            table.fromUserId,
            table.status
        ),
        // CHECK constraint for enum values
        statusCheck: check('UserRelationship_status_check', sql`status IN ('none', 'requested', 'pending', 'friend', 'rejected')`),
    })
);

export const userRelationshipsRelations = relations(
    userRelationships,
    ({ one }) => ({
        fromUser: one(accounts, {
            fields: [userRelationships.fromUserId],
            references: [accounts.id],
            relationName: 'RelationshipsFrom',
        }),
        toUser: one(accounts, {
            fields: [userRelationships.toUserId],
            references: [accounts.id],
            relationName: 'RelationshipsTo',
        }),
    })
);

// ============================================================================
// Feed
// ============================================================================

export const userFeedItems = sqliteTable(
    'UserFeedItem',
    {
        id: text('id').primaryKey(),
        userId: text('userId').notNull(),
        counter: integer('counter').notNull(),
        repeatKey: text('repeatKey'),
        body: text('body', { mode: 'json' }).notNull(),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        userCounterIdx: uniqueIndex('UserFeedItem_userId_counter_key').on(
            table.userId,
            table.counter
        ),
        userRepeatKeyIdx: uniqueIndex('UserFeedItem_userId_repeatKey_key').on(
            table.userId,
            table.repeatKey
        ),
        userCounterDescIdx: index('UserFeedItem_userId_counter_idx').on(
            table.userId,
            table.counter
        ),
    })
);

export const userFeedItemsRelations = relations(userFeedItems, ({ one }) => ({
    user: one(accounts, {
        fields: [userFeedItems.userId],
        references: [accounts.id],
    }),
}));

// ============================================================================
// Key-Value Storage
// ============================================================================

export const userKVStores = sqliteTable(
    'UserKVStore',
    {
        id: text('id').primaryKey(),
        accountId: text('accountId').notNull(),
        key: text('key').notNull(), // Unencrypted for indexing
        value: blob('value', { mode: 'buffer' }), // Encrypted, null when deleted
        version: integer('version').notNull().default(0),
        createdAt: integer('createdAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        updatedAt: integer('updatedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`)
            .$onUpdate(() => new Date()),
    },
    (table) => ({
        accountKeyIdx: uniqueIndex('UserKVStore_accountId_key_key').on(
            table.accountId,
            table.key
        ),
        accountIdx: index('UserKVStore_accountId_idx').on(table.accountId),
    })
);

export const userKVStoresRelations = relations(userKVStores, ({ one }) => ({
    account: one(accounts, {
        fields: [userKVStores.accountId],
        references: [accounts.id],
    }),
}));

// ============================================================================
// Token Revocation (Distributed Blacklist)
// ============================================================================

/**
 * Revoked tokens table for distributed token invalidation.
 *
 * Cloudflare Workers run globally distributed - each edge location has its own
 * instance with its own in-memory cache. This table provides a durable,
 * globally-consistent blacklist that all Workers can check.
 *
 * @see HAP-452 for implementation details
 */
export const revokedTokens = sqliteTable(
    'RevokedToken',
    {
        id: text('id').primaryKey(),
        /** SHA-256 hash of the token (never store actual tokens) */
        tokenHash: text('tokenHash').notNull(),
        /** User ID for bulk invalidation (e.g., logout all devices) */
        userId: text('userId').notNull(),
        /** Reason for revocation */
        reason: text('reason').$type<'logout' | 'security' | 'password_change' | 'manual'>(),
        /** When the token was revoked */
        revokedAt: integer('revokedAt', { mode: 'timestamp_ms' })
            .notNull()
            .default(sql`(unixepoch() * 1000)`),
        /**
         * When this blacklist entry can be cleaned up.
         * Set to revokedAt + 30 days by default.
         * After this time, the entry can be deleted since the token
         * would have been rejected anyway due to age.
         */
        expiresAt: integer('expiresAt', { mode: 'timestamp_ms' }),
    },
    (table) => ({
        /** Fast lookup by token hash */
        tokenHashIdx: uniqueIndex('RevokedToken_tokenHash_key').on(table.tokenHash),
        /** For bulk invalidation queries */
        userIdIdx: index('RevokedToken_userId_idx').on(table.userId),
        /** For cleanup of expired entries */
        expiresAtIdx: index('RevokedToken_expiresAt_idx').on(table.expiresAt),
    })
);

export const revokedTokensRelations = relations(revokedTokens, ({ one }) => ({
    user: one(accounts, {
        fields: [revokedTokens.userId],
        references: [accounts.id],
    }),
}));

// ============================================================================
// Schema Exports
// ============================================================================

export const schema = {
    // Account tables
    accounts,
    terminalAuthRequests,
    accountAuthRequests,
    accountPushTokens,

    // Session tables
    sessions,
    sessionMessages,

    // Github tables
    githubUsers,
    githubOrganizations,

    // Utility tables
    globalLocks,
    repeatKeys,
    simpleCaches,

    // Usage tables
    usageReports,

    // Machine tables
    machines,
    uploadedFiles,
    serviceAccountTokens,

    // Artifact tables
    artifacts,

    // Access tables
    accessKeys,

    // Social tables
    userRelationships,

    // Feed tables
    userFeedItems,

    // KV tables
    userKVStores,

    // Token revocation tables
    revokedTokens,

    // Relations
    accountsRelations,
    terminalAuthRequestsRelations,
    accountAuthRequestsRelations,
    accountPushTokensRelations,
    sessionsRelations,
    sessionMessagesRelations,
    githubUsersRelations,
    usageReportsRelations,
    machinesRelations,
    uploadedFilesRelations,
    serviceAccountTokensRelations,
    artifactsRelations,
    accessKeysRelations,
    userRelationshipsRelations,
    userFeedItemsRelations,
    userKVStoresRelations,
    revokedTokensRelations,
};
