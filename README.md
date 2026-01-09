# Happy Server Workers

A Cloudflare Workers implementation of the Happy backend API - enabling remote control and session sharing for Claude Code and Codex across devices with end-to-end encryption.

## Overview

Happy Server Workers is the edge-native successor to the traditional Node.js happy-server. It provides:

- **Global Edge Distribution**: API runs on Cloudflare's 300+ edge locations
- **Real-time WebSocket**: Native WebSocket support via Durable Objects
- **SQLite Database**: D1 for relational data storage
- **Object Storage**: R2 for file uploads and artifacts
- **End-to-End Encryption**: Zero-knowledge architecture - server cannot decrypt user data

## Quick Start

### Prerequisites

- Node.js 18+
- Yarn package manager
- Wrangler CLI (`npm install -g wrangler`)

### Setup

```bash
# Clone and install dependencies
cd happy-server-workers
yarn install

# Configure local secrets
cp .dev.vars.example .dev.vars
# Edit .dev.vars and add your HAPPY_MASTER_SECRET

# Start local development server
yarn dev
```

The server runs at `http://localhost:8787`.

### Verify Setup

```bash
# Health check
curl http://localhost:8787/health

# OpenAPI spec
curl http://localhost:8787/openapi.json
```

## Project Structure

```
apps/server/workers/
├── src/
│   ├── index.ts              # Main entry point
│   ├── routes/               # API route handlers
│   │   ├── auth/             # Authentication routes
│   │   ├── sessions.ts       # Session management
│   │   ├── machines.ts       # Machine registration
│   │   ├── websocket.ts      # WebSocket upgrades
│   │   └── ...
│   ├── db/
│   │   ├── schema.ts         # Drizzle ORM schema
│   │   └── client.ts         # Database client
│   ├── durable-objects/
│   │   └── ConnectionManager.ts  # WebSocket handling
│   ├── middleware/           # Hono middleware
│   ├── lib/                  # Utilities
│   └── storage/              # R2 storage utilities
├── drizzle/
│   └── migrations/           # Database migrations
├── docs/                     # Additional documentation
├── scripts/                  # Deployment and setup scripts
├── load-tests/               # Performance testing
├── wrangler.toml             # Cloudflare configuration
└── CLAUDE.md                 # Comprehensive dev guidelines
```

## Key Features

### Authentication

Ed25519 public key authentication with QR code pairing:

```typescript
// Direct authentication
POST /v1/auth { publicKey, challenge, signature }

// Terminal pairing (CLI -> Mobile)
POST /v1/auth/request { publicKey, supportsV2 }
GET  /v1/auth/request/status?publicKey=xxx
POST /v1/auth/response { publicKey, response }
```

### Sessions

Encrypted session management with real-time sync:

```typescript
GET    /v1/sessions              // List sessions
GET    /v2/sessions              // Paginated list
POST   /v1/sessions              // Create session
GET    /v1/sessions/:id          // Get session
DELETE /v1/sessions/:id          // Soft delete
POST   /v1/sessions/:id/messages // Add message
```

### WebSocket

Real-time updates via Durable Objects:

```typescript
// Connect with token
GET /v1/updates?token=xxx&clientType=user-scoped

// Connection types
- user-scoped    // Mobile app - receives all user events
- session-scoped // Session viewer - specific session events
- machine-scoped // CLI daemon - specific machine events
```

### File Storage

R2-backed uploads with image optimization:

```typescript
POST   /v1/uploads         // Upload file
POST   /v1/uploads/avatar  // Upload avatar (image only)
GET    /v1/uploads/:id     // Get metadata
GET    /v1/uploads/:id/download  // Download file
DELETE /v1/uploads/:id     // Delete file
```

## Development Commands

```bash
# Local development
yarn dev              # Start local server (http://localhost:8787)

# Type checking and linting
yarn typecheck        # TypeScript type check
yarn lint             # ESLint + Oxlint
yarn lint:fix         # Auto-fix lint issues

# Testing
yarn test             # Run all tests
yarn test:watch       # Watch mode

# Database
yarn db:generate      # Generate migrations from schema changes
yarn db:migrate       # Apply migrations to local D1
yarn db:migrate:remote # Apply to dev environment
yarn db:migrate:prod  # Apply to production
yarn db:studio        # Open Drizzle Studio GUI

# Deployment
yarn deploy:dev       # Deploy to development
yarn deploy:prod      # Deploy to production
```

## Deployment

### Environments

| Environment | Worker Name | URL |
|-------------|-------------|-----|
| Development | `happy-server-workers-dev` | `happy-api-dev.enflamemedia.com` |
| Production | `happy-server-workers-prod` | `happy-api.enflamemedia.com` |

### Deploy to Production

```bash
# 1. Set secrets (first time only)
wrangler secret put HAPPY_MASTER_SECRET --env prod

# 2. Deploy
yarn deploy:prod

# 3. Verify
curl https://happy-api.enflamemedia.com/health
```

See [docs/DEPLOYMENT-RUNBOOK.md](docs/DEPLOYMENT-RUNBOOK.md) for detailed deployment procedures.

## Documentation

| Document | Purpose |
|----------|---------|
| [CLAUDE.md](CLAUDE.md) | Comprehensive development guidelines |
| [docs/CLOUDFLARE_SETUP.md](docs/CLOUDFLARE_SETUP.md) | Initial Cloudflare infrastructure setup |
| [docs/SECRETS.md](docs/SECRETS.md) | Secrets management guide |
| [docs/DEPLOYMENT-RUNBOOK.md](docs/DEPLOYMENT-RUNBOOK.md) | Deployment procedures and checklist |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [docs/MIGRATION-GUIDE.md](docs/MIGRATION-GUIDE.md) | Migration from happy-server |
| [docs/CLIENT-COMPATIBILITY.md](docs/CLIENT-COMPATIBILITY.md) | Client compatibility validation |
| [docs/PERFORMANCE-BASELINES.md](docs/PERFORMANCE-BASELINES.md) | Performance metrics and baselines |

## API Documentation

The API is documented using OpenAPI 3.1. Access the specification:

- **Development**: http://localhost:8787/openapi.json
- **Production**: https://happy-api.enflamemedia.com/openapi.json

All routes are defined using `@hono/zod-openapi` for type-safe request/response validation.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Cloudflare Edge Network                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                   Hono Web Server                     │  │
│  │  • OpenAPI 3.1 with Zod validation                   │  │
│  │  • Auth, CORS, Error handling middleware             │  │
│  │  • Route handlers for REST API                       │  │
│  └──────────────────────────────────────────────────────┘  │
│           │                    │                    │        │
│           ▼                    ▼                    ▼        │
│  ┌────────────┐    ┌─────────────────┐    ┌────────────┐   │
│  │    D1      │    │ Durable Objects │    │     R2     │   │
│  │ (SQLite)   │    │  (WebSocket)    │    │  (Files)   │   │
│  └────────────┘    └─────────────────┘    └────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology |
|-----------|------------|
| Runtime | Cloudflare Workers |
| Framework | Hono v4 |
| Database | D1 (SQLite) + Drizzle ORM |
| WebSocket | Durable Objects with Hibernation API |
| File Storage | R2 (S3-compatible) |
| Authentication | Privacy-kit (Ed25519 tokens) |
| Encryption | TweetNaCl (E2E encryption) |
| Testing | Vitest |
| API Docs | OpenAPI 3.1 |

## Security

- **End-to-End Encryption**: All user data (sessions, messages, artifacts) is encrypted client-side before transmission
- **Zero-Knowledge**: Server cannot decrypt user content - acts as encrypted relay
- **Ed25519 Authentication**: Cryptographic signatures, no passwords
- **Server-side Encryption**: AI vendor tokens encrypted at rest using TweetNaCl secretbox

## License

Proprietary - Enflame Media

## Contributing

See [CLAUDE.md](CLAUDE.md) for development guidelines and coding conventions.
