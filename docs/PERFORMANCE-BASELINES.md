# Performance Baselines - Happy Server Workers

This document establishes performance baselines for the Happy Server Workers API. These baselines serve as acceptance criteria for HAP-19 and ongoing performance monitoring.

## Overview

Happy Server Workers is designed to run on Cloudflare's global edge network, providing low-latency API access worldwide. The performance characteristics are fundamentally different from traditional server deployments.

### Key Performance Characteristics

- **Cold Start**: ~5-15ms (Cloudflare Workers cold start)
- **Global Distribution**: Edge nodes in 300+ cities worldwide
- **Concurrency**: No practical limit per-region (Workers scale automatically)
- **Memory**: 128MB per request
- **CPU Time**: 50ms per request (paid), 10ms (free)

## Performance Requirements (HAP-19)

### Primary Acceptance Criteria

| Metric | Target | Critical |
|--------|--------|----------|
| Concurrent Users | 100+ sustained | Yes |
| Request Rate | 1,000+ req/min | Yes |
| P95 Response Time | < 500ms | Yes |
| P99 Response Time | < 1000ms | Yes |
| Error Rate | < 1% | Yes |

### Endpoint-Specific Baselines

#### Health & Status Endpoints (No Auth)

| Endpoint | Method | P50 | P95 | P99 | Notes |
|----------|--------|-----|-----|-----|-------|
| `/health` | GET | 10ms | 30ms | 50ms | No DB access |
| `/ready` | GET | 10ms | 30ms | 50ms | No DB access |
| `/` | GET | 10ms | 30ms | 50ms | No DB access |
| `/openapi.json` | GET | 20ms | 50ms | 100ms | Static generation |

#### Authentication Endpoints

| Endpoint | Method | P50 | P95 | P99 | Notes |
|----------|--------|-----|-----|-----|-------|
| `/v1/auth` | POST | 50ms | 150ms | 300ms | Crypto operations |
| `/v1/auth/request` | POST | 30ms | 100ms | 200ms | DB write |
| `/v1/auth/request/status` | GET | 20ms | 80ms | 150ms | DB read |
| `/v1/auth/response` | POST | 50ms | 150ms | 300ms | DB write + crypto |

#### Session Endpoints (Protected)

| Endpoint | Method | P50 | P95 | P99 | Notes |
|----------|--------|-----|-----|-----|-------|
| `/v1/sessions` | GET | 50ms | 150ms | 300ms | DB read, limit 150 |
| `/v2/sessions` | GET | 40ms | 120ms | 250ms | Paginated, optimized |
| `/v2/sessions/active` | GET | 30ms | 100ms | 200ms | Filtered query |
| `/v1/sessions` | POST | 60ms | 180ms | 350ms | DB write |
| `/v1/sessions/:id` | GET | 30ms | 100ms | 200ms | Single record |
| `/v1/sessions/:id` | DELETE | 40ms | 120ms | 250ms | Soft delete |
| `/v1/sessions/:id/messages` | POST | 50ms | 150ms | 300ms | DB write |

#### Machine Endpoints (Protected)

| Endpoint | Method | P50 | P95 | P99 | Notes |
|----------|--------|-----|-----|-----|-------|
| `/v1/machines` | GET | 40ms | 120ms | 250ms | DB read |
| `/v1/machines` | POST | 50ms | 150ms | 300ms | DB upsert |
| `/v1/machines/:id` | GET | 30ms | 100ms | 200ms | Single record |
| `/v1/machines/:id/status` | PUT | 40ms | 120ms | 250ms | DB update |

#### Artifact Endpoints (Protected)

| Endpoint | Method | P50 | P95 | P99 | Notes |
|----------|--------|-----|-----|-----|-------|
| `/v1/artifacts` | GET | 50ms | 150ms | 300ms | Headers only |
| `/v1/artifacts` | POST | 80ms | 250ms | 500ms | Blob write |
| `/v1/artifacts/:id` | GET | 60ms | 180ms | 350ms | Full artifact |
| `/v1/artifacts/:id` | POST | 70ms | 200ms | 400ms | Update with lock |
| `/v1/artifacts/:id` | DELETE | 40ms | 120ms | 250ms | DB delete |

#### KV Store Endpoints (Protected)

| Endpoint | Method | P50 | P95 | P99 | Notes |
|----------|--------|-----|-----|-----|-------|
| `/v1/kv/:key` | GET | 20ms | 80ms | 150ms | Single key |
| `/v1/kv` | GET | 40ms | 120ms | 250ms | List with filter |
| `/v1/kv/bulk` | POST | 50ms | 150ms | 300ms | Multi-key get |
| `/v1/kv` | POST | 60ms | 180ms | 350ms | Batch mutations |

#### WebSocket Endpoints (Protected)

| Endpoint | Method | P50 | P95 | P99 | Notes |
|----------|--------|-----|-----|-----|-------|
| `/v1/websocket/stats` | GET | 30ms | 100ms | 200ms | DO state read |
| `/v1/websocket/broadcast` | POST | 50ms | 150ms | 300ms | DO messaging |
| `/v1/updates` | GET (WS) | 100ms | 300ms | 500ms | WS handshake |

#### Other Endpoints (Protected)

| Endpoint | Method | P50 | P95 | P99 | Notes |
|----------|--------|-----|-----|-----|-------|
| `/v1/account` | GET | 30ms | 100ms | 200ms | Single record |
| `/v1/account` | PUT | 40ms | 120ms | 250ms | DB update |
| `/v1/feed` | GET | 60ms | 180ms | 350ms | Paginated feed |
| `/v1/users/search` | GET | 50ms | 150ms | 300ms | Search query |
| `/v1/version` | POST | 20ms | 80ms | 150ms | Version check |

## Load Test Scenarios

### Scenario 1: Smoke Test
- **VUs**: 1
- **Duration**: 30s
- **Purpose**: Verify basic functionality
- **Expected**: 100% success rate, all P95 within baseline

### Scenario 2: Average Load
- **VUs**: 100
- **Duration**: 2 minutes
- **Purpose**: Simulate normal production load
- **Expected**: >99% success rate, P95 within 2x baseline

### Scenario 3: Stress Test
- **VUs**: 200
- **Duration**: 6 minutes
- **Purpose**: Find breaking points
- **Expected**: >95% success rate, graceful degradation

### Scenario 4: Spike Test
- **VUs**: 200 (sudden spike)
- **Duration**: 1 minute
- **Purpose**: Test auto-scaling behavior
- **Expected**: Recovery within 10s of spike

### Scenario 5: Endurance Test
- **VUs**: 50
- **Duration**: 10 minutes
- **Purpose**: Detect memory leaks, connection issues
- **Expected**: Stable performance throughout

## Database Performance

### D1 (SQLite) Baselines

| Operation | Baseline | Notes |
|-----------|----------|-------|
| Simple SELECT | 5-15ms | Single row by ID |
| SELECT with JOIN | 15-30ms | 2-3 table join |
| INDEX scan | 10-25ms | List with filter |
| INSERT | 10-20ms | Single row |
| UPDATE | 10-20ms | Single row |
| Batch operations | 30-100ms | Transaction with 5-10 ops |

### Query Optimization Guidelines

1. **Always use indexes**: Primary keys, foreign keys, frequently filtered columns
2. **Limit result sets**: Use pagination, avoid `SELECT *` on large tables
3. **Batch operations**: Use transactions for multiple writes
4. **Avoid N+1**: Use JOINs or batch queries instead of loops

## Durable Objects Performance

### WebSocket Connection Baselines

| Metric | Baseline | Notes |
|--------|----------|-------|
| Connection time | 50-100ms | WebSocket handshake |
| Message latency | 5-20ms | DO in same region |
| Broadcast (10 clients) | 20-50ms | Fan-out to connections |
| Hibernation wake | 50-100ms | Cold start from hibernation |

### DO Limits

- **Connections per DO**: 32,768 concurrent WebSockets
- **Memory per DO**: 128MB
- **Storage per DO**: 50GB (with KV)
- **Requests per second**: No hard limit (auto-scales)

## R2 Storage Performance

| Operation | Baseline | Notes |
|-----------|----------|-------|
| PUT (< 100KB) | 50-100ms | Small files |
| PUT (1MB) | 100-200ms | Medium files |
| GET (< 100KB) | 20-50ms | Cached edge |
| GET (1MB) | 50-150ms | From origin |
| DELETE | 30-80ms | Single object |
| LIST | 50-150ms | 1000 objects |

## Response Timing Headers (HAP-476)

All API responses include timing headers for performance monitoring and debugging:

### X-Response-Time

Simple header showing total request duration:

```
X-Response-Time: 42ms
```

**Usage**: Check this header for quick performance assessment. Widely supported by monitoring tools, reverse proxies, and log aggregators.

### Server-Timing

W3C standard header with detailed breakdown of internal operations:

```
Server-Timing: total;dur=42.3;desc="Total request time", db;dur=15.2;desc="D1 database", r2;dur=8.1;desc="R2 storage"
```

**Usage**: Visible in browser DevTools (Network tab → select request → Timing). Provides granular metrics for debugging slow requests.

### Adding Timing Metrics to Routes

Route handlers can add custom timing entries:

```typescript
import { addServerTiming } from '@/middleware/timing';

app.get('/v1/users/:id', async (c) => {
    const start = Date.now();
    const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?')
        .bind(c.req.param('id'))
        .first();
    addServerTiming(c, 'db', Date.now() - start, 'User lookup');

    return c.json(user);
});
```

### Example: /ready Endpoint Timing

The `/ready` endpoint demonstrates timing all health checks:

```
Server-Timing: total;dur=45.2;desc="Total request time",
               db;dur=12.1;desc="D1 database",
               r2;dur=8.3;desc="R2 storage",
               do;dur=18.5;desc="Durable Objects",
               kv;dur=5.2;desc="KV namespace"
```

### CORS Configuration

Both headers are exposed to browser clients via CORS:

```typescript
exposeHeaders: ['X-Response-Time', 'Server-Timing', ...]
```

## Monitoring & Alerting

### Key Metrics to Monitor

1. **Request duration** (P50, P95, P99)
2. **Error rate** (by endpoint)
3. **Request volume** (by endpoint)
4. **WebSocket connections** (active count)
5. **D1 query duration**
6. **Durable Object CPU time**

### Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| P95 latency | 2x baseline | 3x baseline |
| Error rate | > 1% | > 5% |
| DO CPU time | > 30ms avg | > 50ms avg |
| Memory usage | > 80% | > 95% |

## Performance Testing Commands

```bash
# Run all integration tests
cd happy-server-workers
yarn test:integration

# Run with coverage
yarn test:coverage

# Run k6 smoke test
k6 run load-tests/scenarios/health-check.js

# Run k6 average load test
k6 run --env AUTH_TOKEN=your-token load-tests/scenarios/full-api.js

# Run k6 stress test
k6 run --vus 200 --duration 5m load-tests/scenarios/full-api.js
```

## Baseline Update Process

1. Run baseline tests monthly on staging environment
2. Document any significant changes (>20% variance)
3. Update baselines after major infrastructure changes
4. Archive historical baselines for trend analysis

## Version History

| Date | Version | Changes |
|------|---------|---------|
| 2024-12-03 | 1.0.0 | Initial baselines (HAP-19) |
