/**
 * Database Seed Script
 *
 * Generates test data for development and testing
 * Run with: yarn db:seed
 */

import { createId } from '@/utils/id';

/**
 * Generate mock encrypted data (for Bytes fields)
 * In production, this would use actual TweetNaCl encryption
 */
function mockEncrypted(data: string): Buffer {
    return Buffer.from(data, 'utf-8');
}

/**
 * Generate seed data for all tables
 * Returns SQL INSERT statements for D1
 */
function generateSeedData(): string[] {
    const statements: string[] = [];
    const now = Date.now();

    // Create test accounts
    const accountId1 = createId();
    const accountId2 = createId();

    statements.push(`
        INSERT INTO Account (id, publicKey, seq, feedSeq, createdAt, updatedAt, settings, settingsVersion, firstName, lastName, username)
        VALUES (
            '${accountId1}',
            'ed25519_pk_test_alice_${createId()}',
            0,
            0,
            ${now},
            ${now},
            '{"theme":"dark","notifications":true}',
            1,
            'Alice',
            'Developer',
            'alice_dev'
        );
    `);

    statements.push(`
        INSERT INTO Account (id, publicKey, seq, feedSeq, createdAt, updatedAt, settings, settingsVersion, firstName, lastName, username)
        VALUES (
            '${accountId2}',
            'ed25519_pk_test_bob_${createId()}',
            0,
            0,
            ${now},
            ${now},
            '{"theme":"light","notifications":false}',
            1,
            'Bob',
            'Tester',
            'bob_test'
        );
    `);

    // Create test sessions
    const sessionId1 = createId();
    const sessionId2 = createId();

    statements.push(`
        INSERT INTO Session (id, tag, accountId, metadata, metadataVersion, dataEncryptionKey, seq, active, lastActiveAt, createdAt, updatedAt)
        VALUES (
            '${sessionId1}',
            'main',
            '${accountId1}',
            '{"name":"Main Session","device":"laptop"}',
            1,
            X'${mockEncrypted('encryption_key_1').toString('hex')}',
            0,
            1,
            ${now},
            ${now},
            ${now}
        );
    `);

    statements.push(`
        INSERT INTO Session (id, tag, accountId, metadata, metadataVersion, seq, active, lastActiveAt, createdAt, updatedAt)
        VALUES (
            '${sessionId2}',
            'work',
            '${accountId2}',
            '{"name":"Work Session","device":"desktop"}',
            1,
            0,
            1,
            ${now},
            ${now},
            ${now}
        );
    `);

    // Create test machines
    const machineId1 = createId();
    const machineId2 = createId();

    statements.push(`
        INSERT INTO Machine (id, accountId, metadata, metadataVersion, dataEncryptionKey, seq, active, lastActiveAt, createdAt, updatedAt)
        VALUES (
            '${machineId1}',
            '${accountId1}',
            '{"hostname":"laptop-01","os":"macOS"}',
            1,
            X'${mockEncrypted('machine_key_1').toString('hex')}',
            0,
            1,
            ${now},
            ${now},
            ${now}
        );
    `);

    statements.push(`
        INSERT INTO Machine (id, accountId, metadata, metadataVersion, seq, active, lastActiveAt, createdAt, updatedAt)
        VALUES (
            '${machineId2}',
            '${accountId2}',
            '{"hostname":"desktop-01","os":"Windows"}',
            1,
            0,
            1,
            ${now},
            ${now},
            ${now}
        );
    `);

    // Create session messages
    const messageId1 = createId();

    statements.push(`
        INSERT INTO SessionMessage (id, sessionId, localId, seq, content, createdAt, updatedAt)
        VALUES (
            '${messageId1}',
            '${sessionId1}',
            'local_${createId()}',
            1,
            '{"type":"user","text":"Hello, this is a test message"}',
            ${now},
            ${now}
        );
    `);

    // Create artifacts
    const artifactId1 = createId();

    statements.push(`
        INSERT INTO Artifact (id, accountId, header, headerVersion, body, bodyVersion, dataEncryptionKey, seq, createdAt, updatedAt)
        VALUES (
            '${artifactId1}',
            '${accountId1}',
            X'${mockEncrypted('artifact_header').toString('hex')}',
            1,
            X'${mockEncrypted('artifact_body_content').toString('hex')}',
            1,
            X'${mockEncrypted('artifact_encryption_key').toString('hex')}',
            0,
            ${now},
            ${now}
        );
    `);

    // Create user relationship
    statements.push(`
        INSERT INTO UserRelationship (fromUserId, toUserId, status, createdAt, updatedAt)
        VALUES (
            '${accountId1}',
            '${accountId2}',
            'friend',
            ${now},
            ${now}
        );
    `);

    // Create feed items
    const feedId1 = createId();

    statements.push(`
        INSERT INTO UserFeedItem (id, userId, counter, body, createdAt, updatedAt)
        VALUES (
            '${feedId1}',
            '${accountId1}',
            1,
            '{"type":"session_created","sessionId":"${sessionId1}"}',
            ${now},
            ${now}
        );
    `);

    // Create usage report
    const usageId1 = createId();

    statements.push(`
        INSERT INTO UsageReport (id, key, accountId, sessionId, data, createdAt, updatedAt)
        VALUES (
            '${usageId1}',
            'token_usage_${now}',
            '${accountId1}',
            '${sessionId1}',
            '{"inputTokens":100,"outputTokens":200}',
            ${now},
            ${now}
        );
    `);

    // Create access key
    const accessKeyId1 = createId();

    statements.push(`
        INSERT INTO AccessKey (id, accountId, machineId, sessionId, data, dataVersion, createdAt, updatedAt)
        VALUES (
            '${accessKeyId1}',
            '${accountId1}',
            '${machineId1}',
            '${sessionId1}',
            '{"encryptedAccessKey":"mock_encrypted_key"}',
            1,
            ${now},
            ${now}
        );
    `);

    // Create KV store entry
    const kvId1 = createId();

    statements.push(`
        INSERT INTO UserKVStore (id, accountId, key, value, version, createdAt, updatedAt)
        VALUES (
            '${kvId1}',
            '${accountId1}',
            'user_preference_theme',
            X'${mockEncrypted('{"theme":"dark"}').toString('hex')}',
            1,
            ${now},
            ${now}
        );
    `);

    return statements;
}

/**
 * Main seed function
 * Prints SQL statements to stdout for use with wrangler d1 execute
 */
function main() {
    console.log('-- Database Seed Script');
    console.log('-- Generated at:', new Date().toISOString());
    console.log('--');
    console.log('-- Run with: wrangler d1 execute happy-db --local --command="$(yarn db:seed)"');
    console.log('');

    // Enable foreign keys
    console.log('PRAGMA foreign_keys = ON;');
    console.log('');

    const statements = generateSeedData();

    statements.forEach((stmt) => {
        console.log(stmt.trim());
        console.log('');
    });

    console.log('-- Seed complete!');
    console.log(
        `-- Created: 2 accounts, 2 sessions, 2 machines, 1 message, 1 artifact, 1 relationship, 1 feed item, 1 usage report, 1 access key, 1 KV entry`
    );
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main();
}

export { generateSeedData };
