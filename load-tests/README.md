# Load Testing for Happy Server Workers

This directory contains k6 load testing scripts for validating the Happy Server Workers API under load.

## Prerequisites

Install k6:

```bash
# macOS
brew install k6

# Linux (Debian/Ubuntu)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Docker
docker pull grafana/k6
```

## Test Scenarios

### 1. Health Check (`health-check.js`)
Quick smoke test for health endpoints. Very fast response time expectations.

```bash
k6 run load-tests/scenarios/health-check.js
```

### 2. Sessions API (`sessions-api.js`)
Tests session CRUD operations including listing, creation, messages, and deletion.

```bash
k6 run --env AUTH_TOKEN=your-token load-tests/scenarios/sessions-api.js
```

### 3. WebSocket (`websocket.js`)
Tests WebSocket-related HTTP endpoints (stats, broadcast). Note: k6 has limited native WebSocket support.

```bash
k6 run --env AUTH_TOKEN=your-token load-tests/scenarios/websocket.js
```

### 4. Full API (`full-api.js`)
Comprehensive mixed workload test covering all major API endpoints with weighted distribution.

```bash
k6 run --env AUTH_TOKEN=your-token load-tests/scenarios/full-api.js
```

### 5. WebSocket Performance (`websocket-performance.js`) - HAP-263
**Tests 100+ concurrent WebSocket connections** as required by HAP-17 acceptance criteria.

This test validates:
- Scale Test: Connect 100+ WebSocket clients to a single ConnectionManager DO
- Broadcast Test: Broadcast message to all connections, measure delivery time
- Filter Test: Broadcast with filters (user-scoped-only, session-specific), verify correct routing
- Sustained Load: Keep connections active for 5+ minutes, verify stability
- Reconnection Test: Disconnect 10% of connections, verify reconnection handling

**Test Modes (via npm scripts):**

```bash
# Quick smoke test (default) - 10 VUs, 30s
yarn load-test:smoke

# Scale test - 100+ concurrent connections
yarn load-test:scale

# Sustained load test - 5+ minutes at 100 connections
yarn load-test:sustained

# Stress test - 200+ connections
yarn load-test:stress

# Against dev environment (requires AUTH_TOKEN)
AUTH_TOKEN=your-token yarn load-test:dev

# Against production (requires AUTH_TOKEN)
AUTH_TOKEN=your-token yarn load-test:prod
```

**Direct k6 commands:**

```bash
# Quick smoke test (default) - 10 VUs, 30s
k6 run --env AUTH_TOKEN=your-token load-tests/scenarios/websocket-performance.js

# Scale test - 100+ concurrent connections
k6 run --env AUTH_TOKEN=your-token --env TEST_MODE=scale load-tests/scenarios/websocket-performance.js

# Sustained load test - 5+ minutes at 100 connections
k6 run --env AUTH_TOKEN=your-token --env TEST_MODE=sustained load-tests/scenarios/websocket-performance.js

# Stress test - 200+ connections
k6 run --env AUTH_TOKEN=your-token --env TEST_MODE=stress load-tests/scenarios/websocket-performance.js
```

**Success Criteria (HAP-263):**

| Criterion | Target |
|-----------|--------|
| Concurrent connections | 100+ established successfully |
| Broadcast delivery time | < 500ms (P95) |
| Connection success rate | > 95% |
| Sustained load stability | No connection drops in 5+ minutes |
| Memory usage | Remains stable |

### 6. Extreme Load Test - HAP-894

**Tests 500+ concurrent WebSocket connections** to identify Durable Object scaling limits.

This test mode validates:
- Connection limits per Durable Object
- Memory pressure thresholds
- Graceful degradation behavior
- Horizontal scaling requirements

**Extreme Test Modes:**

| Mode | Peak VUs | Duration | Purpose |
|------|----------|----------|---------|
| `extreme` | 750 | ~10min | Gradual ramp to find DO limits |
| `spikeExtreme` | 600 | ~5min | Sudden burst to test burst capacity |

**Commands:**

```bash
# Extreme load test - gradual ramp to 750 connections
k6 run --env AUTH_TOKEN=your-token \
       --env BASE_URL=https://staging.example.com \
       --env TEST_MODE=extreme \
       load-tests/scenarios/websocket-performance.js

# Spike extreme test - sudden burst to 600 connections
k6 run --env AUTH_TOKEN=your-token \
       --env BASE_URL=https://staging.example.com \
       --env TEST_MODE=spikeExtreme \
       load-tests/scenarios/websocket-performance.js
```

**Extreme Test Metrics (HAP-894):**

| Metric | Description | Target |
|--------|-------------|--------|
| `do_connections_total` | Peak DO connections | Track max |
| `do_connections_rejected` | Connection rejections | < 20% |
| `do_connection_rejection_rate` | Rejection rate | < 0.20 |
| `do_response_time` | DO stats response | p95 < 5s |
| `do_memory_usage_bytes` | DO memory (if available) | Monitor |

**Important Notes:**
- Only run extreme tests against staging, never production
- Tests may trigger DO rate limits or evictions
- Results help establish capacity planning limits
- See [WEBSOCKET-CAPACITY-PLANNING.md](../../../../docs/WEBSOCKET-CAPACITY-PLANNING.md) for full documentation

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BASE_URL` | API server URL | `http://localhost:8787` |
| `AUTH_TOKEN` | Authentication token | `test-auth-token` |

### Test Profiles

The `k6-config.js` file defines standard test profiles:

| Profile | Description | Duration |
|---------|-------------|----------|
| `smoke` | Quick validation | 30s with 1 VU |
| `average` | Normal load (100 users) | ~2 min ramp |
| `stress` | High load (200+ users) | ~6 min |
| `spike` | Sudden traffic spike | ~1 min |
| `endurance` | Sustained load | ~12 min |

## Running Tests

### Local Development

```bash
# Start the dev server
cd happy-server-workers
yarn dev

# Run smoke test
k6 run load-tests/scenarios/health-check.js

# Run with custom URL
k6 run --env BASE_URL=http://localhost:8787 load-tests/scenarios/full-api.js
```

### Against Staging

```bash
# Get auth token from staging
AUTH_TOKEN=$(curl -s -X POST https://staging.example.com/v1/auth \
  -H 'Content-Type: application/json' \
  -d '{"publicKey":"...", "challenge":"...", "signature":"..."}' \
  | jq -r '.token')

# Run full API test
k6 run \
  --env BASE_URL=https://staging.example.com \
  --env AUTH_TOKEN=$AUTH_TOKEN \
  load-tests/scenarios/full-api.js
```

### With Custom VUs and Duration

```bash
# Quick test with 10 VUs for 1 minute
k6 run --vus 10 --duration 1m load-tests/scenarios/sessions-api.js

# Stress test with 200 VUs
k6 run --vus 200 --duration 5m --env AUTH_TOKEN=your-token load-tests/scenarios/full-api.js
```

### Output to JSON

```bash
k6 run --out json=results.json load-tests/scenarios/health-check.js
```

## Performance Baselines

### Acceptance Criteria (HAP-19)

| Metric | Target |
|--------|--------|
| Concurrent Users | 100+ sustained |
| Request Rate | 1,000+ req/min |
| P95 Response Time | < 500ms |
| P99 Response Time | < 1000ms |
| Error Rate | < 1% |

### Expected Results by Endpoint

| Endpoint | P95 Latency | P99 Latency |
|----------|-------------|-------------|
| `/health` | < 50ms | < 100ms |
| `/v1/sessions` (list) | < 200ms | < 400ms |
| `/v1/sessions` (create) | < 300ms | < 500ms |
| `/v1/machines` (list) | < 200ms | < 400ms |
| `/v1/artifacts` (list) | < 200ms | < 400ms |
| `/v1/websocket/stats` | < 100ms | < 200ms |
| `/v1/websocket/broadcast` | < 200ms | < 400ms |

### WebSocket Performance Metrics (HAP-263)

| Metric | Target |
|--------|--------|
| WebSocket Connection Time (P95) | < 2000ms |
| WebSocket Connection Time (P99) | < 5000ms |
| Message Latency (P95) | < 100ms |
| Message Latency (P99) | < 200ms |
| Broadcast Delivery Time (P95) | < 500ms |
| Broadcast Delivery Time (P99) | < 1000ms |
| Connection Error Rate | < 5% |
| Broadcast Success Rate | > 95% |

### Extreme Load Test Metrics (HAP-894)

These metrics have relaxed thresholds as the goal is to find limits, not meet SLOs:

| Metric | Target (Extreme) | Purpose |
|--------|------------------|---------|
| WebSocket Connection Time (P95) | < 5000ms | Degradation acceptable |
| WebSocket Connection Time (P99) | < 10000ms | Under extreme load |
| Message Latency (P95) | < 500ms | Relaxed for capacity |
| Broadcast Delivery Time (P95) | < 2000ms | Finding limits |
| Connection Rejection Rate | < 20% | Track DO capacity |
| DO Response Time (P95) | < 1000ms | Monitor DO health |
| HTTP Error Rate | < 10% | Allow degradation |

## Interpreting Results

k6 outputs summary statistics after each run:

```
     checks.........................: 98.5% ✓ 12340 ✗ 186
     data_received..................: 5.2 MB 87 kB/s
     data_sent......................: 1.8 MB 30 kB/s
     http_req_blocked...............: avg=1.23ms   min=1µs    p(90)=3.21ms p(95)=5.67ms
     http_req_connecting............: avg=812µs    min=0s     p(90)=2.01ms p(95)=3.45ms
     http_req_duration..............: avg=156.23ms min=12ms   p(90)=312ms  p(95)=423ms
     http_req_failed................: 0.15%  ✓ 23    ✗ 15317
     http_req_receiving.............: avg=234µs    min=10µs   p(90)=567µs  p(95)=890µs
     http_req_sending...............: avg=45µs     min=5µs    p(90)=89µs   p(95)=123µs
     http_reqs......................: 15340  255.67/s
     iteration_duration.............: avg=391.45ms min=112ms  p(90)=612ms  p(95)=789ms
     iterations.....................: 5113   85.22/s
     vus............................: 100    min=1   max=100
     vus_max........................: 100    min=100 max=100
```

Key metrics:
- **http_req_duration**: Response time (p95 and p99 are most important)
- **http_req_failed**: Error rate (should be < 1%)
- **http_reqs**: Total requests and rate
- **checks**: Assertion pass rate

## CI/CD Integration (HAP-891)

The WebSocket performance tests are integrated into the CI/CD pipeline for automated regression detection.

### Automated Test Triggers

| Trigger | Test Mode | Environment | Description |
|---------|-----------|-------------|-------------|
| PR with WebSocket changes | Smoke | Dev | Quick validation on PRs touching `src/durable-objects/`, `src/routes/websocket.ts`, or load test files |
| Post-deployment | Scale | Dev | Full 100+ connection test after deployment to dev environment |
| Manual dispatch | Configurable | Dev/Prod | On-demand testing for debugging |

### GitHub Actions Workflow

The workflow is defined in `.github/workflows/websocket-load-test.yml` and includes:

1. **PR Smoke Test**: Runs on PRs affecting WebSocket code
   - 10 VUs for 30 seconds
   - Posts results as PR comment
   - Fails PR if regression detected

2. **Staging Scale Test**: Runs after deployment
   - 100+ concurrent connections
   - 3-minute scale test
   - Creates GitHub step summary
   - Alerts on regression (non-blocking)

3. **Manual Test**: On-demand via workflow dispatch
   - Choose test mode: smoke, scale, sustained, stress
   - Choose environment: dev or prod

### Regression Thresholds

The CI pipeline uses these thresholds (20% buffer over HAP-263 baselines):

| Metric | HAP-263 Baseline | CI Threshold |
|--------|------------------|--------------|
| Connection Time (P95) | < 2000ms | < 2400ms |
| Broadcast Delivery (P95) | < 500ms | < 600ms |
| Error Rate | < 5% | < 5% |

### Required Secrets

Configure these in GitHub repository secrets:

| Secret | Description |
|--------|-------------|
| `LOAD_TEST_TOKEN` | Valid auth token for the target environment |

### Viewing Results

- **PR Comments**: Smoke test results posted as PR comment
- **Step Summary**: Scale test results in GitHub Actions step summary
- **Artifacts**: Full JSON results stored as workflow artifacts (30-90 day retention)

### Running Manually

```bash
# Via GitHub Actions UI
# Go to Actions > WebSocket Load Tests > Run workflow

# Or via GitHub CLI
gh workflow run websocket-load-test.yml \
  --ref main \
  -f test_mode=scale \
  -f environment=dev
```

## Documentation

For comprehensive performance baseline documentation and regression threshold guidelines, see:

- **[PERFORMANCE-BASELINES.md](../../../../docs/PERFORMANCE-BASELINES.md)** - Detailed performance baselines, regression thresholds, and historical tracking

## Troubleshooting

### High Error Rates
- Check if auth token is valid
- Verify BASE_URL is correct
- Check server logs for errors

### Slow Response Times
- Check if database is under load
- Verify Durable Object limits
- Check for rate limiting

### Connection Errors
- Verify server is running
- Check firewall rules
- Verify DNS resolution
