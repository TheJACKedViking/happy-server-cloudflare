import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createTestApp, authHeader, TEST_USER_ID, TEST_USER_ID_2 } from './__test__/testUtils';
import { userRoutes } from './userRoutes';
import type { Fastify } from '../types';

// Define RelationshipStatus enum locally to avoid Prisma client dependency
const RelationshipStatus = {
    none: 'none',
    requested: 'requested',
    pending: 'pending',
    friend: 'friend',
    rejected: 'rejected',
} as const;

// Mock @prisma/client before any imports that depend on it
vi.mock('@prisma/client', () => ({
    RelationshipStatus: {
        none: 'none',
        requested: 'requested',
        pending: 'pending',
        friend: 'friend',
        rejected: 'rejected',
    },
}));

// Mock external dependencies
vi.mock('@/storage/db', () => ({
    db: {
        account: {
            findUnique: vi.fn(),
            findMany: vi.fn(),
        },
        userRelationship: {
            findFirst: vi.fn(),
        },
    },
}));

vi.mock('@/storage/files', () => ({
    getPublicUrl: vi.fn((path: string) => `https://cdn.example.com/${path}`),
}));

vi.mock('@/app/social/friendAdd', () => ({
    friendAdd: vi.fn(),
}));

vi.mock('@/app/social/friendRemove', () => ({
    friendRemove: vi.fn(),
}));

vi.mock('@/app/social/friendList', () => ({
    friendList: vi.fn(),
}));

import { db } from '@/storage/db';
import { friendAdd } from '@/app/social/friendAdd';
import { friendRemove } from '@/app/social/friendRemove';
import { friendList } from '@/app/social/friendList';

describe('userRoutes', () => {
    let app: Fastify;

    beforeEach(async () => {
        app = createTestApp();
        await userRoutes(app);
        await app.ready();
        vi.clearAllMocks();
    });

    afterEach(async () => {
        await app.close();
    });

    describe('GET /v1/user/:id', () => {
        it('should return user profile with relationship status', async () => {
            const mockUser = {
                id: TEST_USER_ID_2,
                firstName: 'Jane',
                lastName: 'Smith',
                username: 'janesmith',
                avatar: { path: 'avatars/456.jpg', width: 100, height: 100 },
                githubUser: { profile: { login: 'janesmith', bio: 'Engineer' } },
            };
            vi.mocked(db.account.findUnique).mockResolvedValue(mockUser as any);
            vi.mocked(db.userRelationship.findFirst).mockResolvedValue({
                status: RelationshipStatus.friend,
            } as any);

            const response = await app.inject({
                method: 'GET',
                url: `/v1/user/${TEST_USER_ID_2}`,
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.user).toBeDefined();
            expect(body.user.id).toBe(TEST_USER_ID_2);
            expect(body.user.firstName).toBe('Jane');
            expect(body.user.status).toBe('friend');
        });

        it('should return 404 when user not found', async () => {
            vi.mocked(db.account.findUnique).mockResolvedValue(null);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/user/non-existent-user',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(404);
            const body = JSON.parse(response.payload);
            expect(body.error).toBe('User not found');
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'GET',
                url: `/v1/user/${TEST_USER_ID_2}`,
            });

            expect(response.statusCode).toBe(401);
        });

        it('should return none status when no relationship exists', async () => {
            const mockUser = {
                id: TEST_USER_ID_2,
                firstName: 'Stranger',
                lastName: null,
                username: 'stranger',
                avatar: null,
                githubUser: null,
            };
            vi.mocked(db.account.findUnique).mockResolvedValue(mockUser as any);
            vi.mocked(db.userRelationship.findFirst).mockResolvedValue(null);

            const response = await app.inject({
                method: 'GET',
                url: `/v1/user/${TEST_USER_ID_2}`,
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.user.status).toBe('none');
        });
    });

    describe('GET /v1/user/search', () => {
        it('should return matching users by username prefix', async () => {
            const mockUsers = [
                {
                    id: 'user-1',
                    firstName: 'John',
                    lastName: 'Doe',
                    username: 'johndoe',
                    avatar: null,
                    githubUser: null,
                },
                {
                    id: 'user-2',
                    firstName: 'Johnny',
                    lastName: 'Appleseed',
                    username: 'johnnyapple',
                    avatar: null,
                    githubUser: null,
                },
            ];
            vi.mocked(db.account.findMany).mockResolvedValue(mockUsers as any);
            vi.mocked(db.userRelationship.findFirst).mockResolvedValue(null);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/user/search?query=john',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.users).toHaveLength(2);
            expect(body.users[0].username).toBe('johndoe');
            expect(body.users[1].username).toBe('johnnyapple');
        });

        it('should return empty array when no users match', async () => {
            vi.mocked(db.account.findMany).mockResolvedValue([]);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/user/search?query=xyz123',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.users).toHaveLength(0);
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/user/search?query=test',
            });

            expect(response.statusCode).toBe(401);
        });

        it('should include relationship status for each user', async () => {
            const mockUsers = [
                {
                    id: 'friend-user',
                    firstName: 'Friend',
                    lastName: null,
                    username: 'friend',
                    avatar: null,
                    githubUser: null,
                },
            ];
            vi.mocked(db.account.findMany).mockResolvedValue(mockUsers as any);
            vi.mocked(db.userRelationship.findFirst).mockResolvedValue({
                status: RelationshipStatus.friend,
            } as any);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/user/search?query=friend',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.users[0].status).toBe('friend');
        });
    });

    describe('POST /v1/friends/add', () => {
        it('should add friend successfully', async () => {
            const mockProfile = {
                id: TEST_USER_ID_2,
                firstName: 'New',
                lastName: 'Friend',
                username: 'newfriend',
                avatar: null,
                bio: null,
                status: RelationshipStatus.requested,
            };
            vi.mocked(friendAdd).mockResolvedValue(mockProfile);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/friends/add',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    uid: TEST_USER_ID_2,
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.user).toBeDefined();
            expect(body.user.id).toBe(TEST_USER_ID_2);
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/friends/add',
                headers: {
                    'Content-Type': 'application/json',
                },
                payload: {
                    uid: TEST_USER_ID_2,
                },
            });

            expect(response.statusCode).toBe(401);
        });
    });

    describe('POST /v1/friends/remove', () => {
        it('should remove friend successfully', async () => {
            const mockProfile = {
                id: TEST_USER_ID_2,
                firstName: 'Ex',
                lastName: 'Friend',
                username: 'exfriend',
                avatar: null,
                bio: null,
                status: RelationshipStatus.none,
            };
            vi.mocked(friendRemove).mockResolvedValue(mockProfile);

            const response = await app.inject({
                method: 'POST',
                url: '/v1/friends/remove',
                headers: {
                    ...authHeader(),
                    'Content-Type': 'application/json',
                },
                payload: {
                    uid: TEST_USER_ID_2,
                },
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.user).toBeDefined();
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'POST',
                url: '/v1/friends/remove',
                headers: {
                    'Content-Type': 'application/json',
                },
                payload: {
                    uid: TEST_USER_ID_2,
                },
            });

            expect(response.statusCode).toBe(401);
        });
    });

    describe('GET /v1/friends', () => {
        it('should return list of friends', async () => {
            const mockFriends = [
                {
                    id: 'friend-1',
                    firstName: 'Friend',
                    lastName: 'One',
                    username: 'friend1',
                    avatar: null,
                    bio: null,
                    status: RelationshipStatus.friend,
                },
                {
                    id: 'friend-2',
                    firstName: 'Friend',
                    lastName: 'Two',
                    username: 'friend2',
                    avatar: null,
                    bio: null,
                    status: RelationshipStatus.friend,
                },
            ];
            vi.mocked(friendList).mockResolvedValue(mockFriends);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/friends',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.friends).toHaveLength(2);
        });

        it('should return empty array when user has no friends', async () => {
            vi.mocked(friendList).mockResolvedValue([]);

            const response = await app.inject({
                method: 'GET',
                url: '/v1/friends',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.friends).toHaveLength(0);
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/friends',
            });

            expect(response.statusCode).toBe(401);
        });
    });
});
