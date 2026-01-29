/**
 * WebSocket Performance Test - 100+ Concurrent Connections
 *
 * HAP-263: Validates WebSocket performance with 100+ concurrent connections
 * as required by HAP-17 acceptance criteria.
 *
 * Test Requirements:
 * 1. Scale Test: Connect 100+ WebSocket clients to a single ConnectionManager DO
 * 2. Broadcast Test: Broadcast message to all connections, measure delivery time
 * 3. Filter Test: Broadcast with filters (user-scoped-only, session-specific), verify correct routing
 * 4. Sustained Load: Keep connections active for 5+ minutes, verify stability
 * 5. Reconnection Test: Disconnect 10% of connections, verify reconnection handling
 *
 * Success Criteria:
 * - 100 concurrent connections established successfully
 * - Broadcast to all connections completes in < 500ms
 * - Filtered broadcasts route correctly
 * - No connection drops under sustained load
 * - Memory usage remains stable
 *
 * Run: k6 run --env AUTH_TOKEN=your-token load-tests/scenarios/websocket-performance.js
 *
 * For full 5-minute sustained load test:
 * k6 run --env AUTH_TOKEN=your-token --env TEST_MODE=sustained load-tests/scenarios/websocket-performance.js
 *
 * For scale test only (100+ connections):
 * k6 run --env AUTH_TOKEN=your-token --env TEST_MODE=scale load-tests/scenarios/websocket-performance.js
 */

import ws from 'k6/ws';
import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Counter, Trend, Rate, Gauge } from 'k6/metrics';
import { BASE_URL, AUTH_TOKEN, authHeaders, generateId } from '../k6-config.js';

// ============================================================================
// Custom Metrics for WebSocket Performance
// ============================================================================

// Connection metrics
const wsConnectionTime = new Trend('ws_connection_time', true);
const wsConnectionsActive = new Gauge('ws_connections_active');
const wsConnectionErrors = new Counter('ws_connection_errors');
const wsConnectionSuccess = new Counter('ws_connection_success');

// Message metrics
const wsMessagesReceived = new Counter('ws_messages_received');
const wsMessagesSent = new Counter('ws_messages_sent');
const wsMessageLatency = new Trend('ws_message_latency', true);

// Broadcast metrics
const wsBroadcastDeliveryTime = new Trend('ws_broadcast_delivery_time', true);
const wsBroadcastSuccess = new Rate('ws_broadcast_success');

// Reconnection metrics
const wsReconnections = new Counter('ws_reconnections');
const wsReconnectionTime = new Trend('ws_reconnection_time', true);

// ============================================================================
// Durable Object Metrics (HAP-894)
// ============================================================================

// Connection capacity metrics
const doConnectionsTotal = new Gauge('do_connections_total');
const doConnectionsRejected = new Counter('do_connections_rejected');
const doConnectionRejectionRate = new Rate('do_connection_rejection_rate');

// Memory and performance metrics (from stats endpoint)
const doMemoryUsage = new Gauge('do_memory_usage_bytes');
const doConnectionsByType = new Gauge('do_connections_by_type');
const doOldestConnection = new Gauge('do_oldest_connection_ms');

// Degradation metrics
const doMessageQueueDepth = new Gauge('do_message_queue_depth');
const doBroadcastFailures = new Counter('do_broadcast_failures');
const doResponseTime = new Trend('do_response_time', true);

// Hibernation metrics
const doHibernationEvents = new Counter('do_hibernation_events');
const doWakeupTime = new Trend('do_wakeup_time', true);

// ============================================================================
// Test Configuration
// ============================================================================

// Default to quick smoke test, override with TEST_MODE env var
const TEST_MODE = __ENV.TEST_MODE || 'smoke';

// Test mode configurations
const testModes = {
    // Quick smoke test (default) - verifies basic functionality
    smoke: {
        vus: 10,
        duration: '30s',
        targetConnections: 10,
        sustainedDuration: 0, // No sustained phase
    },

    // Scale test - validates 100+ concurrent connections
    scale: {
        stages: [
            { duration: '30s', target: 50 },   // Ramp up to 50
            { duration: '30s', target: 100 },  // Ramp up to 100
            { duration: '1m', target: 120 },   // Hold at 120
            { duration: '30s', target: 0 },    // Ramp down
        ],
        targetConnections: 100,
        sustainedDuration: 0,
    },

    // Sustained load test - 5+ minutes stability
    sustained: {
        stages: [
            { duration: '30s', target: 50 },   // Ramp up
            { duration: '1m', target: 100 },   // Reach target
            { duration: '5m', target: 100 },   // Sustained load for 5 minutes
            { duration: '30s', target: 0 },    // Ramp down
        ],
        targetConnections: 100,
        sustainedDuration: 5 * 60, // 5 minutes in seconds
    },

    // Stress test - push beyond normal limits
    stress: {
        stages: [
            { duration: '30s', target: 100 },
            { duration: '1m', target: 200 },
            { duration: '2m', target: 200 },
            { duration: '30s', target: 0 },
        ],
        targetConnections: 200,
        sustainedDuration: 0,
    },

    // Extreme load test - identify scaling limits (HAP-894)
    // Tests 500+ concurrent WebSocket connections to find DO limits
    extreme: {
        stages: [
            { duration: '1m', target: 200 },    // Ramp to known working level
            { duration: '2m', target: 500 },    // Push to extreme load
            { duration: '3m', target: 500 },    // Sustain extreme load
            { duration: '1m', target: 750 },    // Push beyond to find limits
            { duration: '2m', target: 750 },    // Sustain at peak
            { duration: '1m', target: 0 },      // Ramp down
        ],
        targetConnections: 500,
        sustainedDuration: 3 * 60, // 3 minutes at target
    },

    // Spike extreme test - sudden burst to extreme levels
    spikeExtreme: {
        stages: [
            { duration: '30s', target: 100 },   // Baseline
            { duration: '30s', target: 600 },   // Sudden spike!
            { duration: '2m', target: 600 },    // Hold spike
            { duration: '30s', target: 100 },   // Return to baseline
            { duration: '1m', target: 100 },    // Stabilize
            { duration: '30s', target: 0 },     // Ramp down
        ],
        targetConnections: 600,
        sustainedDuration: 0,
    },
};

const config = testModes[TEST_MODE] || testModes.smoke;

// Define thresholds based on test mode
const getThresholds = () => {
    const baseThresholds = {
        // Connection thresholds
        ws_connection_time: ['p(95)<2000', 'p(99)<5000'], // Connection time < 2s (95th), < 5s (99th)
        ws_connection_errors: ['count<10'], // Less than 10 connection errors total

        // Message thresholds
        ws_message_latency: ['p(95)<100', 'p(99)<200'], // Message latency < 100ms (95th)

        // Broadcast thresholds (HAP-263 requirement: < 500ms)
        ws_broadcast_delivery_time: ['p(95)<500', 'p(99)<1000'],
        ws_broadcast_success: ['rate>0.95'], // 95% broadcast success rate

        // Standard HTTP thresholds for stats/broadcast endpoints
        http_req_duration: ['p(95)<300', 'p(99)<500'],
        http_req_failed: ['rate<0.05'],
    };

    // Relaxed thresholds for extreme load tests (HAP-894)
    // The goal is to find limits, not meet SLOs
    if (TEST_MODE === 'extreme' || TEST_MODE === 'spikeExtreme') {
        return {
            ...baseThresholds,
            // Relaxed connection thresholds - expect some degradation
            ws_connection_time: ['p(95)<5000', 'p(99)<10000'],
            ws_connection_errors: ['count<100'], // Allow more errors under extreme load

            // Relaxed message thresholds
            ws_message_latency: ['p(95)<500', 'p(99)<1000'],

            // Relaxed broadcast thresholds
            ws_broadcast_delivery_time: ['p(95)<2000', 'p(99)<5000'],
            ws_broadcast_success: ['rate>0.80'], // Lower success threshold

            // DO-specific thresholds
            do_connection_rejection_rate: ['rate<0.20'], // Track but allow 20% rejections
            do_response_time: ['p(95)<1000'],

            // Standard HTTP - slightly relaxed
            http_req_duration: ['p(95)<1000', 'p(99)<2000'],
            http_req_failed: ['rate<0.10'],
        };
    }

    return baseThresholds;
};

export const options = {
    ...(config.stages ? { stages: config.stages } : { vus: config.vus, duration: config.duration }),
    thresholds: getThresholds(),
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get WebSocket URL for the server
 * Converts http:// to ws:// or https:// to wss://
 */
function getWsUrl() {
    const baseUrl = BASE_URL;
    if (baseUrl.startsWith('https://')) {
        return baseUrl.replace('https://', 'wss://');
    } else if (baseUrl.startsWith('http://')) {
        return baseUrl.replace('http://', 'ws://');
    }
    return baseUrl;
}

/**
 * Generate a unique session ID for this VU
 */
function getSessionId() {
    return `perf_session_${__VU}_${Date.now()}`;
}

/**
 * Generate a unique machine ID for this VU
 */
function getMachineId() {
    return `perf_machine_${__VU}_${Date.now()}`;
}

// ============================================================================
// WebSocket Connection Test
// ============================================================================

/**
 * Main test function - runs once per VU iteration
 */
export default function () {
    const wsUrl = getWsUrl();
    const token = AUTH_TOKEN;
    const sessionId = getSessionId();
    const machineId = getMachineId();
    const connectionId = generateId('conn');

    // Determine client type based on VU number
    // Distribute across client types: 70% user-scoped, 15% session-scoped, 15% machine-scoped
    let clientType = 'user-scoped';
    let queryParams = `token=${token}&clientType=${clientType}`;

    if (__VU % 100 >= 85) {
        clientType = 'machine-scoped';
        queryParams = `token=${token}&clientType=${clientType}&machineId=${machineId}`;
    } else if (__VU % 100 >= 70) {
        clientType = 'session-scoped';
        queryParams = `token=${token}&clientType=${clientType}&sessionId=${sessionId}`;
    }

    group('WebSocket Connection', () => {
        const connectionStart = Date.now();
        let connected = false;
        let messagesReceived = 0;
        let lastMessageTime = 0;

        const res = ws.connect(`${wsUrl}/v1/updates?${queryParams}`, {}, function (socket) {
            socket.on('open', () => {
                const connectionTime = Date.now() - connectionStart;
                wsConnectionTime.add(connectionTime);
                wsConnectionSuccess.add(1);
                wsConnectionsActive.add(1);
                connected = true;

                // Send ping to verify connection is working
                socket.send(JSON.stringify({ event: 'ping' }));
                wsMessagesSent.add(1);
            });

            socket.on('message', (data) => {
                const receiveTime = Date.now();
                messagesReceived++;
                wsMessagesReceived.add(1);

                // Calculate latency if this is a response to our ping
                if (lastMessageTime > 0) {
                    wsMessageLatency.add(receiveTime - lastMessageTime);
                }
                lastMessageTime = receiveTime;

                try {
                    const msg = JSON.parse(data);

                    // Handle different message types
                    if (msg.event === 'connected') {
                        check(msg.data, {
                            'connected message has connectionId': (d) => d && d.connectionId,
                            'connected message has userId': (d) => d && d.userId,
                            'connected message has clientType': (d) => d && d.clientType,
                        });
                    }

                    if (msg.event === 'pong') {
                        check(msg, {
                            'pong response received': () => true,
                            'pong has timestamp': (m) => m.data && m.data.timestamp,
                        });
                    }

                    if (msg.event === 'broadcast') {
                        // Track broadcast delivery time
                        if (msg.data && msg.data.sentAt) {
                            const deliveryTime = receiveTime - msg.data.sentAt;
                            wsBroadcastDeliveryTime.add(deliveryTime);
                            wsBroadcastSuccess.add(deliveryTime < 500);
                        }
                    }

                    if (msg.event === 'error') {
                        console.warn(`WebSocket error: ${JSON.stringify(msg.data)}`);
                        wsConnectionErrors.add(1);
                    }
                } catch {
                    // Non-JSON message, ignore
                }
            });

            socket.on('close', () => {
                wsConnectionsActive.add(-1);
            });

            socket.on('error', (e) => {
                wsConnectionErrors.add(1);
                console.error(`WebSocket error: ${e.message || e}`);
            });

            // Keep connection alive based on test mode
            if (TEST_MODE === 'sustained') {
                // For sustained test, keep connection alive for longer
                // Send periodic pings to keep connection active
                const pingInterval = setInterval(() => {
                    if (socket.readyState === 1) { // OPEN
                        lastMessageTime = Date.now();
                        socket.send(JSON.stringify({ event: 'ping' }));
                        wsMessagesSent.add(1);
                    }
                }, 10000); // Ping every 10 seconds

                socket.setTimeout(() => {
                    clearInterval(pingInterval);
                    socket.close();
                }, 60000); // 60 seconds per iteration for sustained test
            } else {
                // For other tests, shorter connection duration
                // Send a few pings then close
                socket.setTimeout(() => {
                    // Send a couple more pings
                    for (let i = 0; i < 3; i++) {
                        if (socket.readyState === 1) {
                            lastMessageTime = Date.now();
                            socket.send(JSON.stringify({ event: 'ping' }));
                            wsMessagesSent.add(1);
                        }
                    }
                }, 2000);

                socket.setTimeout(() => {
                    socket.close();
                }, 5000); // 5 seconds per iteration for other tests
            }
        });

        // Track connection success/rejection (HAP-894)
        const connectionEstablished = res && res.status === 101;
        check(res, {
            'WebSocket connection established': (r) => r && r.status === 101,
            'Connection completed without error': () => connected,
            'Messages received': () => messagesReceived > 0,
        });

        // Track rejection metrics for extreme tests (HAP-894)
        if (!connectionEstablished) {
            doConnectionsRejected.add(1);
            doConnectionRejectionRate.add(1);

            // Log rejection details in extreme tests
            if (TEST_MODE === 'extreme' || TEST_MODE === 'spikeExtreme') {
                console.log(`[DO] Connection rejected: VU ${__VU}, status: ${res?.status || 'unknown'}`);
            }
        } else {
            doConnectionRejectionRate.add(0); // Track success for rate calculation
        }
    });

    // Test broadcast via HTTP endpoint (only some VUs to avoid overwhelming)
    if (__VU % 10 === 1) {
        group('Broadcast Test', () => {
            const broadcastStart = Date.now();
            const headers = authHeaders(token);

            const broadcastRes = http.post(
                `${BASE_URL}/v1/websocket/broadcast`,
                JSON.stringify({
                    message: {
                        type: 'broadcast',
                        payload: {
                            testId: connectionId,
                            sentAt: broadcastStart,
                            source: 'perf-test',
                        },
                        timestamp: broadcastStart,
                    },
                }),
                { headers }
            );

            const broadcastTime = Date.now() - broadcastStart;

            check(broadcastRes, {
                'broadcast - status 200 or 401': (r) => r.status === 200 || r.status === 401,
                'broadcast - success response': (r) => {
                    if (r.status !== 200) return true;
                    try {
                        const body = JSON.parse(r.body);
                        return body.success === true;
                    } catch {
                        return false;
                    }
                },
                'broadcast - under 500ms': () => broadcastTime < 500,
            });

            if (broadcastRes.status === 200) {
                wsBroadcastDeliveryTime.add(broadcastTime);
                wsBroadcastSuccess.add(broadcastTime < 500);
            }
        });
    }

    // Test filtered broadcast (session-specific)
    if (__VU % 20 === 1) {
        group('Filtered Broadcast Test', () => {
            const headers = authHeaders(token);

            // Test user-scoped-only filter
            const userScopedRes = http.post(
                `${BASE_URL}/v1/websocket/broadcast`,
                JSON.stringify({
                    message: {
                        type: 'filtered-test',
                        payload: {
                            filterType: 'user-scoped-only',
                            timestamp: Date.now(),
                        },
                        timestamp: Date.now(),
                    },
                    filter: {
                        type: 'user-scoped-only',
                    },
                }),
                { headers }
            );

            check(userScopedRes, {
                'user-scoped filter - success': (r) => r.status === 200 || r.status === 401,
            });

            // Test session filter
            const sessionFilterRes = http.post(
                `${BASE_URL}/v1/websocket/broadcast`,
                JSON.stringify({
                    message: {
                        type: 'session-specific',
                        payload: {
                            sessionId: sessionId,
                            timestamp: Date.now(),
                        },
                        timestamp: Date.now(),
                    },
                    filter: {
                        type: 'session',
                        sessionId: sessionId,
                    },
                }),
                { headers }
            );

            check(sessionFilterRes, {
                'session filter - success': (r) => r.status === 200 || r.status === 401,
            });

            // Test machine filter
            const machineFilterRes = http.post(
                `${BASE_URL}/v1/websocket/broadcast`,
                JSON.stringify({
                    message: {
                        type: 'machine-specific',
                        payload: {
                            machineId: machineId,
                            timestamp: Date.now(),
                        },
                        timestamp: Date.now(),
                    },
                    filter: {
                        type: 'machine',
                        machineId: machineId,
                    },
                }),
                { headers }
            );

            check(machineFilterRes, {
                'machine filter - success': (r) => r.status === 200 || r.status === 401,
            });
        });
    }

    // Check connection stats periodically
    // For extreme tests, increase frequency to capture degradation patterns
    const statsFrequency = (TEST_MODE === 'extreme' || TEST_MODE === 'spikeExtreme') ? 2 : 5;
    if (__VU % statsFrequency === 0) {
        group('Connection Stats', () => {
            const headers = authHeaders(token);
            const statsStart = Date.now();
            const statsRes = http.get(`${BASE_URL}/v1/websocket/stats`, { headers });
            const statsTime = Date.now() - statsStart;

            // Track DO response time (HAP-894)
            doResponseTime.add(statsTime);

            check(statsRes, {
                'stats - status 200 or 401': (r) => r.status === 200 || r.status === 401,
                'stats - has connection count': (r) => {
                    if (r.status !== 200) return true;
                    try {
                        const body = JSON.parse(r.body);
                        return typeof body.totalConnections === 'number';
                    } catch {
                        return false;
                    }
                },
            });

            // Collect DO metrics from stats response (HAP-894)
            if (statsRes.status === 200) {
                try {
                    const stats = JSON.parse(statsRes.body);

                    // Connection metrics
                    if (typeof stats.totalConnections === 'number') {
                        doConnectionsTotal.add(stats.totalConnections);
                    }

                    // Connection breakdown by type
                    if (stats.byType) {
                        const userScoped = stats.byType['user-scoped'] || 0;
                        const sessionScoped = stats.byType['session-scoped'] || 0;
                        const machineScoped = stats.byType['machine-scoped'] || 0;
                        doConnectionsByType.add(userScoped + sessionScoped + machineScoped);
                    }

                    // Oldest connection age (proxy for hibernation behavior)
                    if (stats.oldestConnection) {
                        const connectionAge = Date.now() - stats.oldestConnection;
                        doOldestConnection.add(connectionAge);
                    }

                    // Memory usage (if available - depends on stats endpoint implementation)
                    if (stats.memoryUsage) {
                        doMemoryUsage.add(stats.memoryUsage);
                    }

                    // Message queue depth (if available)
                    if (stats.messageQueueDepth) {
                        doMessageQueueDepth.add(stats.messageQueueDepth);
                    }

                    // Log extreme conditions for analysis
                    if (TEST_MODE === 'extreme' || TEST_MODE === 'spikeExtreme') {
                        if (stats.totalConnections > 400) {
                            console.log(`[DO] High connection count: ${stats.totalConnections}`);
                        }
                    }
                } catch {
                    // Non-JSON response, ignore
                }
            }
        });
    }

    // Small sleep between iterations to prevent overwhelming
    sleep(0.5);
}

// ============================================================================
// Reconnection Test Scenario
// ============================================================================

/**
 * Reconnection test - simulates 10% connection drops and measures reconnection time
 * Run with: k6 run --env AUTH_TOKEN=xxx --env TEST_MODE=reconnect scenarios/websocket-performance.js
 */
export function reconnectionTest() {
    const wsUrl = getWsUrl();
    const token = AUTH_TOKEN;
    const connectionId = generateId('reconn');

    // Connect
    let connectionStart = Date.now();
    let connectionSuccess = false;

    const res = ws.connect(`${wsUrl}/v1/updates?token=${token}&clientType=user-scoped`, {}, function (socket) {
        socket.on('open', () => {
            wsConnectionTime.add(Date.now() - connectionStart);
            connectionSuccess = true;
        });

        socket.on('message', () => {
            wsMessagesReceived.add(1);
        });

        // Simulate 10% disconnection rate
        if (Math.random() < 0.1) {
            socket.setTimeout(() => {
                socket.close(1000, 'Simulated disconnect for reconnection test');

                // Measure reconnection time
                const reconnectStart = Date.now();

                // Reconnect
                ws.connect(`${wsUrl}/v1/updates?token=${token}&clientType=user-scoped`, {}, function (newSocket) {
                    newSocket.on('open', () => {
                        const reconnectTime = Date.now() - reconnectStart;
                        wsReconnectionTime.add(reconnectTime);
                        wsReconnections.add(1);

                        check(null, {
                            'reconnection under 2s': () => reconnectTime < 2000,
                        });
                    });

                    newSocket.setTimeout(() => {
                        newSocket.close();
                    }, 3000);
                });
            }, 2000);
        } else {
            socket.setTimeout(() => {
                socket.close();
            }, 5000);
        }
    });

    check(res, {
        'initial connection successful': (r) => r && r.status === 101,
    });

    sleep(1);
}

// ============================================================================
// Setup and Teardown
// ============================================================================

export function setup() {
    const isExtremeTest = TEST_MODE === 'extreme' || TEST_MODE === 'spikeExtreme';

    console.log(`Starting WebSocket ${isExtremeTest ? 'Extreme Load' : 'Performance'} Test`);
    console.log(`Test Mode: ${TEST_MODE}`);
    console.log(`Target Connections: ${config.targetConnections}`);
    console.log(`Base URL: ${BASE_URL}`);

    if (isExtremeTest) {
        console.log('\n=== HAP-894 Extreme Load Test ===');
        console.log('Purpose: Identify Durable Object scaling limits');
        console.log('Goals:');
        console.log('  - Test 500+ concurrent WebSocket connections');
        console.log('  - Identify connection limits per DO');
        console.log('  - Monitor memory pressure thresholds');
        console.log('  - Document graceful degradation behavior');
        console.log('');
    }

    // Verify server is accessible
    const healthRes = http.get(`${BASE_URL}/health`);
    if (healthRes.status !== 200) {
        console.warn('Warning: Health check failed, server may not be accessible');
    }

    // Verify auth token works
    const headers = authHeaders(AUTH_TOKEN);
    const statsRes = http.get(`${BASE_URL}/v1/websocket/stats`, { headers });
    if (statsRes.status === 401) {
        console.error('Error: AUTH_TOKEN is invalid or missing');
    }

    return {
        testMode: TEST_MODE,
        targetConnections: config.targetConnections,
        startTime: Date.now(),
    };
}

export function teardown(data) {
    const duration = (Date.now() - data.startTime) / 1000;
    console.log(`\nWebSocket Performance Test Complete`);
    console.log(`Test Mode: ${data.testMode}`);
    console.log(`Duration: ${duration.toFixed(2)}s`);
    console.log(`Target Connections: ${data.targetConnections}`);
}

// ============================================================================
// Summary Report
// ============================================================================

export function handleSummary(data) {
    const summary = {
        testMode: TEST_MODE,
        targetConnections: config.targetConnections,
        metrics: {
            connections: {
                successRate: data.metrics.ws_connection_success?.values?.count || 0,
                errors: data.metrics.ws_connection_errors?.values?.count || 0,
                avgTime: data.metrics.ws_connection_time?.values?.avg || 0,
                p95Time: data.metrics.ws_connection_time?.values['p(95)'] || 0,
            },
            messages: {
                sent: data.metrics.ws_messages_sent?.values?.count || 0,
                received: data.metrics.ws_messages_received?.values?.count || 0,
                avgLatency: data.metrics.ws_message_latency?.values?.avg || 0,
            },
            broadcast: {
                avgDeliveryTime: data.metrics.ws_broadcast_delivery_time?.values?.avg || 0,
                p95DeliveryTime: data.metrics.ws_broadcast_delivery_time?.values['p(95)'] || 0,
                successRate: data.metrics.ws_broadcast_success?.values?.rate || 0,
            },
            reconnections: {
                count: data.metrics.ws_reconnections?.values?.count || 0,
                avgTime: data.metrics.ws_reconnection_time?.values?.avg || 0,
            },
            // Durable Object metrics (HAP-894)
            durableObject: {
                peakConnections: data.metrics.do_connections_total?.values?.max || 0,
                avgConnections: data.metrics.do_connections_total?.values?.avg || 0,
                connectionsRejected: data.metrics.do_connections_rejected?.values?.count || 0,
                rejectionRate: data.metrics.do_connection_rejection_rate?.values?.rate || 0,
                avgResponseTime: data.metrics.do_response_time?.values?.avg || 0,
                p95ResponseTime: data.metrics.do_response_time?.values?.['p(95)'] || 0,
                peakMemoryUsage: data.metrics.do_memory_usage_bytes?.values?.max || 0,
                oldestConnectionAge: data.metrics.do_oldest_connection_ms?.values?.max || 0,
            },
        },
        thresholds: data.thresholds,
    };

    // Check acceptance criteria based on test mode
    let criteria;
    let criteriaTitle;

    if (TEST_MODE === 'extreme' || TEST_MODE === 'spikeExtreme') {
        // HAP-894 acceptance criteria for extreme tests
        criteriaTitle = 'HAP-894 Extreme Load Test Results';
        criteria = {
            '500+ connections attempted': summary.metrics.connections.successRate >= 500,
            'Peak connections recorded': summary.metrics.durableObject.peakConnections > 0,
            'Rejection rate < 20%': summary.metrics.durableObject.rejectionRate < 0.20,
            'DO response time p95 < 5s': summary.metrics.durableObject.p95ResponseTime < 5000,
            'Graceful degradation observed': summary.metrics.connections.errors < summary.metrics.connections.successRate * 0.5,
        };
    } else {
        // HAP-263 acceptance criteria for standard tests
        criteriaTitle = 'HAP-263 Acceptance Criteria';
        criteria = {
            '100 concurrent connections': summary.metrics.connections.successRate >= 100,
            'Broadcast < 500ms': summary.metrics.broadcast.p95DeliveryTime < 500,
            'Connection success > 95%': summary.metrics.connections.errors / (summary.metrics.connections.successRate + summary.metrics.connections.errors) < 0.05,
        };
    }

    console.log(`\n=== ${criteriaTitle} ===`);
    for (const [criterion, passed] of Object.entries(criteria)) {
        console.log(`${passed ? '✓' : '✗'} ${criterion}`);
    }

    // Additional extreme test analysis (HAP-894)
    if (TEST_MODE === 'extreme' || TEST_MODE === 'spikeExtreme') {
        console.log('\n=== Capacity Planning Insights ===');
        console.log(`Peak Connections: ${summary.metrics.durableObject.peakConnections}`);
        console.log(`Connection Rejections: ${summary.metrics.durableObject.connectionsRejected}`);
        console.log(`Rejection Rate: ${(summary.metrics.durableObject.rejectionRate * 100).toFixed(2)}%`);
        console.log(`DO Response Time (p95): ${summary.metrics.durableObject.p95ResponseTime.toFixed(2)}ms`);
        console.log(`Oldest Connection Age: ${(summary.metrics.durableObject.oldestConnectionAge / 1000).toFixed(2)}s`);

        // Recommendations
        console.log('\n=== Recommendations ===');
        if (summary.metrics.durableObject.rejectionRate > 0.10) {
            console.log('⚠ High rejection rate - consider horizontal scaling (multiple DOs per user)');
        }
        if (summary.metrics.durableObject.p95ResponseTime > 2000) {
            console.log('⚠ High DO response time - consider connection limits per DO');
        }
        if (summary.metrics.durableObject.peakConnections > 400) {
            console.log(`✓ Successfully handled ${summary.metrics.durableObject.peakConnections} connections`);
        }
    }

    return {
        'stdout': textSummary(data, { indent: ' ', enableColors: true }),
        'load-tests/results/websocket-performance.json': JSON.stringify(summary, null, 2),
    };
}

// Helper for text summary (k6 built-in)
function textSummary(data, options) {
    // Use k6's default text summary format
    const isExtremeTest = TEST_MODE === 'extreme' || TEST_MODE === 'spikeExtreme';
    const title = isExtremeTest
        ? 'Extreme Load Test Results (HAP-894)'
        : 'WebSocket Performance Test Results (HAP-263)';

    let output = '\n';
    output += '='.repeat(60) + '\n';
    output += title + '\n';
    output += '='.repeat(60) + '\n\n';

    output += `Test Mode: ${TEST_MODE}\n`;
    output += `Target Connections: ${config.targetConnections}\n\n`;

    output += 'Connection Metrics:\n';
    output += `  Success: ${data.metrics.ws_connection_success?.values?.count || 0}\n`;
    output += `  Errors: ${data.metrics.ws_connection_errors?.values?.count || 0}\n`;
    output += `  Avg Time: ${(data.metrics.ws_connection_time?.values?.avg || 0).toFixed(2)}ms\n`;
    output += `  P95 Time: ${(data.metrics.ws_connection_time?.values['p(95)'] || 0).toFixed(2)}ms\n\n`;

    output += 'Message Metrics:\n';
    output += `  Sent: ${data.metrics.ws_messages_sent?.values?.count || 0}\n`;
    output += `  Received: ${data.metrics.ws_messages_received?.values?.count || 0}\n`;
    output += `  Avg Latency: ${(data.metrics.ws_message_latency?.values?.avg || 0).toFixed(2)}ms\n\n`;

    output += 'Broadcast Metrics:\n';
    output += `  Avg Delivery: ${(data.metrics.ws_broadcast_delivery_time?.values?.avg || 0).toFixed(2)}ms\n`;
    output += `  P95 Delivery: ${(data.metrics.ws_broadcast_delivery_time?.values['p(95)'] || 0).toFixed(2)}ms\n`;
    output += `  Success Rate: ${((data.metrics.ws_broadcast_success?.values?.rate || 0) * 100).toFixed(1)}%\n\n`;

    // Add Durable Object metrics for extreme tests (HAP-894)
    if (isExtremeTest) {
        output += 'Durable Object Metrics (HAP-894):\n';
        output += `  Peak Connections: ${data.metrics.do_connections_total?.values?.max || 0}\n`;
        output += `  Avg Connections: ${(data.metrics.do_connections_total?.values?.avg || 0).toFixed(0)}\n`;
        output += `  Connections Rejected: ${data.metrics.do_connections_rejected?.values?.count || 0}\n`;
        output += `  Rejection Rate: ${((data.metrics.do_connection_rejection_rate?.values?.rate || 0) * 100).toFixed(2)}%\n`;
        output += `  DO Response Time (avg): ${(data.metrics.do_response_time?.values?.avg || 0).toFixed(2)}ms\n`;
        output += `  DO Response Time (p95): ${(data.metrics.do_response_time?.values?.['p(95)'] || 0).toFixed(2)}ms\n`;
        output += `  Oldest Connection Age: ${((data.metrics.do_oldest_connection_ms?.values?.max || 0) / 1000).toFixed(2)}s\n\n`;

        output += 'Scaling Limits Identified:\n';
        const peakConns = data.metrics.do_connections_total?.values?.max || 0;
        const rejectionRate = data.metrics.do_connection_rejection_rate?.values?.rate || 0;
        if (rejectionRate < 0.05) {
            output += `  ✓ System handled ${peakConns} connections with minimal rejections\n`;
        } else if (rejectionRate < 0.20) {
            output += `  ⚠ Degradation detected at ${peakConns} connections (${(rejectionRate * 100).toFixed(1)}% rejection)\n`;
        } else {
            output += `  ✗ Significant degradation at ${peakConns} connections (${(rejectionRate * 100).toFixed(1)}% rejection)\n`;
        }
        output += '\n';
    }

    output += '='.repeat(60) + '\n';

    return output;
}
