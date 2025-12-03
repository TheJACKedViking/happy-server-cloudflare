import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createTestApp, authHeader, TEST_USER_ID } from './__test__/testUtils';
import { feedRoutes } from './feedRoutes';
import type { Fastify } from '../types';

// Mock external dependencies
vi.mock('@/storage/db', () => ({
    db: {
        userFeedItem: {
            findMany: vi.fn(),
        },
    },
}));

vi.mock('@/app/feed/feedGet', () => ({
    feedGet: vi.fn(),
}));

import { feedGet } from '@/app/feed/feedGet';

describe('feedRoutes', () => {
    let app: Fastify;

    beforeEach(async () => {
        app = createTestApp();
        feedRoutes(app);
        await app.ready();
        vi.clearAllMocks();
    });

    afterEach(async () => {
        await app.close();
    });

    describe('GET /v1/feed', () => {
        it('should return feed items for authenticated user', async () => {
            const mockItems = [
                {
                    id: 'feed-1',
                    body: { kind: 'friend_request', uid: 'user-1' },
                    repeatKey: null,
                    cursor: '0-100',
                    createdAt: Date.now(),
                },
                {
                    id: 'feed-2',
                    body: { kind: 'text', text: 'Welcome!' },
                    repeatKey: 'welcome',
                    cursor: '0-99',
                    createdAt: Date.now() - 1000,
                },
            ];
            vi.mocked(feedGet).mockResolvedValue({
                items: mockItems,
                hasMore: false,
            });

            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.items).toHaveLength(2);
            expect(body.hasMore).toBe(false);
            expect(body.items[0].body.kind).toBe('friend_request');
        });

        it('should return 401 without authorization', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed',
            });

            expect(response.statusCode).toBe(401);
        });

        it('should return empty feed when user has no items', async () => {
            vi.mocked(feedGet).mockResolvedValue({
                items: [],
                hasMore: false,
            });

            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.items).toHaveLength(0);
            expect(body.hasMore).toBe(false);
        });

        it('should pass before cursor for pagination', async () => {
            vi.mocked(feedGet).mockResolvedValue({
                items: [],
                hasMore: false,
            });

            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed?before=0-50',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            expect(vi.mocked(feedGet)).toHaveBeenCalledWith(
                expect.anything(),
                expect.anything(),
                expect.objectContaining({
                    cursor: expect.objectContaining({
                        before: '0-50',
                    }),
                })
            );
        });

        it('should pass after cursor for pagination', async () => {
            vi.mocked(feedGet).mockResolvedValue({
                items: [],
                hasMore: false,
            });

            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed?after=0-100',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            expect(vi.mocked(feedGet)).toHaveBeenCalledWith(
                expect.anything(),
                expect.anything(),
                expect.objectContaining({
                    cursor: expect.objectContaining({
                        after: '0-100',
                    }),
                })
            );
        });

        it('should pass custom limit', async () => {
            vi.mocked(feedGet).mockResolvedValue({
                items: [],
                hasMore: false,
            });

            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed?limit=25',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            expect(vi.mocked(feedGet)).toHaveBeenCalledWith(
                expect.anything(),
                expect.anything(),
                expect.objectContaining({
                    limit: 25,
                })
            );
        });

        it('should return hasMore true when more items exist', async () => {
            const mockItems = Array(50).fill(null).map((_, i) => ({
                id: `feed-${i}`,
                body: { kind: 'text' as const, text: `Item ${i}` },
                repeatKey: null,
                cursor: `0-${100 - i}`,
                createdAt: Date.now() - i * 1000,
            }));
            vi.mocked(feedGet).mockResolvedValue({
                items: mockItems,
                hasMore: true,
            });

            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed?limit=50',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.items).toHaveLength(50);
            expect(body.hasMore).toBe(true);
        });

        it('should handle friend_accepted feed item type', async () => {
            vi.mocked(feedGet).mockResolvedValue({
                items: [
                    {
                        id: 'feed-accept',
                        body: { kind: 'friend_accepted', uid: 'user-accepted' },
                        repeatKey: null,
                        cursor: '0-200',
                        createdAt: Date.now(),
                    },
                ],
                hasMore: false,
            });

            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(200);
            const body = JSON.parse(response.payload);
            expect(body.items[0].body.kind).toBe('friend_accepted');
            expect(body.items[0].body.uid).toBe('user-accepted');
        });

        it('should enforce maximum limit of 200', async () => {
            vi.mocked(feedGet).mockResolvedValue({
                items: [],
                hasMore: false,
            });

            // Request with limit above max (200)
            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed?limit=500',
                headers: authHeader(),
            });

            // Should return validation error
            expect(response.statusCode).toBe(400);
        });

        it('should reject limit less than 1', async () => {
            const response = await app.inject({
                method: 'GET',
                url: '/v1/feed?limit=0',
                headers: authHeader(),
            });

            expect(response.statusCode).toBe(400);
        });
    });
});
