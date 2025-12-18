import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Context } from '@/context';

// Mock all dependencies before importing the function under test
vi.mock('@/storage/db', () => ({
    db: {
        account: {
            findUnique: vi.fn(),
        },
        $transaction: vi.fn(),
    },
}));

vi.mock('@/utils/log', () => ({
    log: vi.fn(),
}));

vi.mock('@/storage/seq', () => ({
    allocateUserSeq: vi.fn(),
}));

vi.mock('@/app/events/eventRouter', () => ({
    buildUpdateAccountUpdate: vi.fn(),
    eventRouter: {
        emitUpdate: vi.fn(),
    },
}));

vi.mock('@/utils/randomKeyNaked', () => ({
    randomKeyNaked: vi.fn().mockReturnValue('mock-random-key'),
}));

import { githubDisconnect } from './githubDisconnect';
import { db } from '@/storage/db';
import { allocateUserSeq } from '@/storage/seq';
import { buildUpdateAccountUpdate, eventRouter } from '@/app/events/eventRouter';

const TEST_USER_ID = 'test-user-123';
const TEST_GITHUB_USER_ID = 'github-user-456';

describe('githubDisconnect', () => {
    const mockContext: Context = {
        uid: TEST_USER_ID,
    } as Context;

    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('when user has GitHub connected', () => {
        beforeEach(() => {
            // Setup: User has GitHub connected
            vi.mocked(db.account.findUnique).mockResolvedValue({
                githubUserId: TEST_GITHUB_USER_ID,
            } as any);

            // Mock transaction to execute the callback
            vi.mocked(db.$transaction).mockImplementation(async (callback: any) => {
                const mockTx = {
                    account: {
                        update: vi.fn().mockResolvedValue({}),
                    },
                    githubInstallation: {
                        updateMany: vi.fn().mockResolvedValue({ count: 0 }),
                    },
                    githubUser: {
                        delete: vi.fn().mockResolvedValue({}),
                    },
                };
                return callback(mockTx);
            });

            // Mock sequence allocation
            vi.mocked(allocateUserSeq).mockResolvedValue(42);

            // Mock event payload builder
            vi.mocked(buildUpdateAccountUpdate).mockReturnValue({
                type: 'update-account',
                data: { github: null, username: null },
            } as any);
        });

        it('should clear GitHub connection from account', async () => {
            await githubDisconnect(mockContext);

            expect(db.account.findUnique).toHaveBeenCalledWith({
                where: { id: TEST_USER_ID },
                select: { githubUserId: true },
            });

            expect(db.$transaction).toHaveBeenCalled();
        });

        it('should emit update-account event with github: null', async () => {
            await githubDisconnect(mockContext);

            // Verify sequence was allocated
            expect(allocateUserSeq).toHaveBeenCalledWith(TEST_USER_ID);

            // Verify event payload was built with github: null
            expect(buildUpdateAccountUpdate).toHaveBeenCalledWith(
                TEST_USER_ID,
                { github: null, username: null },
                42, // sequence number
                'mock-random-key'
            );

            // Verify event was emitted to all user connections
            expect(eventRouter.emitUpdate).toHaveBeenCalledWith({
                userId: TEST_USER_ID,
                payload: expect.objectContaining({
                    type: 'update-account',
                    data: { github: null, username: null },
                }),
                recipientFilter: { type: 'all-user-authenticated-connections' },
            });
        });

        it('should increment sequence number for event', async () => {
            await githubDisconnect(mockContext);

            expect(allocateUserSeq).toHaveBeenCalledTimes(1);
            expect(allocateUserSeq).toHaveBeenCalledWith(TEST_USER_ID);
        });
    });

    describe('when user has no GitHub connected', () => {
        beforeEach(() => {
            // Setup: User has no GitHub connected
            vi.mocked(db.account.findUnique).mockResolvedValue({
                githubUserId: null,
            } as any);
        });

        it('should return early without error', async () => {
            await expect(githubDisconnect(mockContext)).resolves.toBeUndefined();
        });

        it('should not run transaction', async () => {
            await githubDisconnect(mockContext);

            expect(db.$transaction).not.toHaveBeenCalled();
        });

        it('should not emit any event', async () => {
            await githubDisconnect(mockContext);

            expect(eventRouter.emitUpdate).not.toHaveBeenCalled();
            expect(allocateUserSeq).not.toHaveBeenCalled();
        });
    });

    describe('when user account not found', () => {
        beforeEach(() => {
            // Setup: User doesn't exist
            vi.mocked(db.account.findUnique).mockResolvedValue(null);
        });

        it('should return early without error', async () => {
            await expect(githubDisconnect(mockContext)).resolves.toBeUndefined();
        });

        it('should not run transaction or emit event', async () => {
            await githubDisconnect(mockContext);

            expect(db.$transaction).not.toHaveBeenCalled();
            expect(eventRouter.emitUpdate).not.toHaveBeenCalled();
        });
    });
});
