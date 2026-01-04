# Happy Server Workers - Development Guidelines

> **📍 Part of the Happy monorepo** — See root [`CLAUDE.md`](../CLAUDE.md) for overall architecture and cross-project guidelines.

---

This document contains development guidelines for the Happy Server on Cloudflare Workers. This guide OVERRIDES any default behaviors and MUST be followed exactly.

## Project Overview

**Name**: happy-server-workers
**Purpose**: Cloudflare Workers implementation of Happy Server
**Framework**: Hono with OpenAPI 3.1 (via @hono/zod-openapi)
**Runtime**: Cloudflare Workers
**Language**: TypeScript (strict mode)

## Core Technology Stack

- **Runtime**: Cloudflare Workers
- **Framework**: Hono v4+
- **Language**: TypeScript with strict mode
- **Testing**: Vitest
- **Development Tool**: Wrangler CLI v3+
- **Package Manager**: Yarn (not npm)

## Architecture

This is a serverless implementation of Happy Server, designed to run on Cloudflare's global edge network. It replaces the traditional Node.js/Fastify server with a Workers-based architecture.

### Key Differences from happy-server

| Aspect | happy-server | happy-server-workers |
|--------|--------------|----------------------|
| Runtime | Node.js | Cloudflare Workers |
| Framework | Fastify | Hono |
| Database | PostgreSQL + Prisma | D1 + Drizzle ORM |
| WebSockets | Socket.io | Durable Objects (future) |
| File Storage | MinIO/S3 | R2 |
| Deployment | Traditional server | Serverless edge |

## Development Workflow

### Commands

```bash
# Install dependencies
yarn install

# Start local development server
yarn dev

# Type checking
yarn typecheck

# Linting
yarn lint
yarn lint:fix

# Code formatting
yarn format

# Run tests
yarn test
yarn test:watch

# Deploy to Cloudflare Workers
yarn deploy
```

### Local Development

The `yarn dev` command starts Wrangler's local development server on port 8787:

```bash
yarn dev
# Server runs at http://localhost:8787
```

Access the development server:

- Root: <http://localhost:8787/>
- Health check: <http://localhost:8787/health>

## Code Style and Structure

### General Principles

- Use **4 spaces** for indentation (matching happy-server convention)
- Write concise, technical TypeScript code with accurate examples
- Use functional and declarative programming patterns
- Prefer iteration and modularization over code duplication
- Use descriptive variable names with auxiliary verbs
- **Always use absolute imports** with `@/*` prefix
- Prefer interfaces over types
- Avoid enums; use const objects or unions instead
- Use TypeScript strict mode

### Folder Structure

```
/src
├── /middleware        # Hono middleware
│   ├── logger.ts     # Request logging
│   ├── error.ts      # Error handling
│   └── cors.ts       # CORS configuration
├── /routes           # API routes (future)
├── /utils            # Utility functions
└── index.ts          # Main entry point
```

### Naming Conventions

- Use lowercase with dashes for directories (e.g., `api-routes`)
- File and function names should match for utilities
- Test files use `.spec.ts` suffix

## Linting

This project uses **oxlint** exclusively (no ESLint). The configuration is in `oxlint.json`.

### Key Features

- **JS Plugins**: Custom rules from `@happy/lint-rules` package
- **Performance**: oxlint is 50-100x faster than ESLint

### Configuration (`oxlint.json`)

```json
{
    "plugins": ["eslint", "typescript", "oxc", "vitest", "unicorn"],
    "jsPlugins": ["@happy/lint-rules"],
    "rules": {
        "happy/github-casing": "warn",
        "happy/protocol-helpers": "warn"
    }
}
```

### Custom Rules

- `happy/github-casing`: Enforces "GitHub" (not "Github") in PascalCase identifiers (HAP-502)
- `happy/protocol-helpers`: Enforces `getSessionId()`/`getMachineId()` helpers (HAP-658)

### Dependencies

- `oxlint`: Core linter (v1.36.0+)
- `oxlint-tsgolint`: Type-aware linting support (v0.10.1+)
- `@happy/lint-rules`: Custom rules (workspace package)

## Environment Variables & Secrets

**See `docs/SECRETS.md` for comprehensive secrets management documentation.**

### Quick Start

1. Copy the template:

   ```bash
   cp .dev.vars.example .dev.vars
   ```

2. Generate a master secret:

   ```bash
   openssl rand -hex 32
   ```

3. Add it to `.dev.vars`:

   ```bash
   HAPPY_MASTER_SECRET=your-generated-secret-here
   ```

4. Start development:

   ```bash
   yarn dev
   ```

### Required Secrets

| Secret | Purpose | Generation |
|--------|---------|------------|
| `HAPPY_MASTER_SECRET` | Auth token generation | `openssl rand -hex 32` |

### Local Development (.dev.vars)

Environment variables for local development are stored in `.dev.vars`:

```bash
ENVIRONMENT=development
HAPPY_MASTER_SECRET=your-32-byte-hex-secret
```

⚠️ **IMPORTANT**: Never commit `.dev.vars` to version control - it's gitignored by default.

### Accessing Environment Variables

In Workers, access environment variables via the context:

```typescript
app.get('/example', (c) => {
    const env = c.env.ENVIRONMENT;
    const secret = c.env.HAPPY_MASTER_SECRET; // Required
    return c.json({ env });
});
```

**NOT** via `process.env` (that's Node.js specific).

### Production Secrets (Wrangler)

For production, use Wrangler secrets (never put secrets in `wrangler.toml`):

```bash
# Set required secret for production
wrangler secret put HAPPY_MASTER_SECRET --env prod

# Set required secret for development (remote)
wrangler secret put HAPPY_MASTER_SECRET --env dev

# List all secrets
wrangler secret list --env prod

# Delete a secret
wrangler secret delete SECRET_NAME --env prod
```

### Secret Rotation

See `happy-server/docs/SECRET-ROTATION.md` for detailed rotation procedures.

**Warning:** Rotating `HAPPY_MASTER_SECRET` invalidates all existing auth tokens.

## Middleware

### Order Matters

Middleware is applied in the order defined:

```typescript
app.use('*', logger());      // 1. Log request
app.use('*', cors());        // 2. Handle CORS
// Routes here
app.onError(errorHandler);   // Last: Error handling
```

### Creating Custom Middleware

```typescript
import type { MiddlewareHandler } from 'hono';

export const myMiddleware = (): MiddlewareHandler => {
    return async (c, next) => {
        // Before request
        await next();
        // After request
    };
};
```

## Routing

### Basic Routes

```typescript
// GET route
app.get('/users', (c) => {
    return c.json({ users: [] });
});

// POST route with body
app.post('/users', async (c) => {
    const body = await c.req.json();
    return c.json({ created: body }, 201);
});

// Route with parameters
app.get('/users/:id', (c) => {
    const id = c.req.param('id');
    return c.json({ id });
});
```

### Nested Routes

```typescript
// Create a sub-app
const apiRoutes = new Hono();

apiRoutes.get('/users', (c) => c.json({ users: [] }));
apiRoutes.get('/posts', (c) => c.json({ posts: [] }));

// Mount to main app
app.route('/api/v1', apiRoutes);
```

## TypeScript Configuration

### Path Aliases

The project uses `@/*` path aliases for cleaner imports:

```typescript
// ✅ Good
import { logger } from '@/middleware/logger';

// ❌ Bad
import { logger } from '../middleware/logger';
```

### Strict Mode

TypeScript strict mode is enabled with additional checks:

- `noUnusedLocals`: Error on unused variables
- `noUnusedParameters`: Error on unused parameters
- `noImplicitReturns`: All code paths must return
- `noFallthroughCasesInSwitch`: No fallthrough in switch

## Testing

### Writing Tests

```typescript
import { describe, it, expect } from 'vitest';
import app from '@/index';

describe('GET /', () => {
    it('returns welcome message', async () => {
        const res = await app.request('/');
        const json = await res.json();

        expect(res.status).toBe(200);
        expect(json.message).toContain('Welcome');
    });
});
```

### Running Tests

```bash
# Run once
yarn test

# Watch mode
yarn test:watch
```

## Deployment

### Prerequisites

1. Cloudflare account with Workers enabled
2. Wrangler CLI authenticated:

```bash
wrangler login
```

### Deploy to Production

```bash
# Deploy to production
yarn deploy

# Deploy to specific environment
wrangler deploy --env staging
```

### Deployment Checklist

- [ ] All tests passing (`yarn test`)
- [ ] Type checks passing (`yarn typecheck`)
- [ ] Linting passing (`yarn lint`)
- [ ] Environment variables set via `wrangler secret`
- [ ] `wrangler.toml` configured correctly

## Cloudflare Workers Specifics

### Compatibility Date

The project uses `compatibility_date = "2025-01-08"` in `wrangler.toml`. This determines which Workers runtime features are available.

### Compatibility Flags

- `nodejs_compat`: Enables Node.js compatibility layer for APIs like `Buffer`, `process`, etc.

### Limitations

Cloudflare Workers have specific limitations:

- **CPU Time**: 10ms for free tier, 50ms for paid (can be extended with [Unbound](https://developers.cloudflare.com/workers/platform/pricing/#workers))
- **Memory**: 128 MB
- **Request Size**: 100 MB
- **Response Size**: Unlimited
- **Subrequests**: 50 per request (free), 1000 (paid)

Design your application within these constraints.

## Migration Guide

This Workers implementation is Phase 1 of migrating from happy-server. Future phases will add:

- **Phase 2**: Database migration (PostgreSQL → D1)
- **Phase 3**: API routes migration
- **Phase 4**: WebSocket/real-time (Durable Objects)
- **Phase 5**: File storage (R2) - IMPLEMENTED (HAP-5)
- **Phase 6**: Testing and production deployment

## Common Patterns

### Error Handling

```typescript
import { HTTPException } from 'hono/http-exception';

app.get('/protected', (c) => {
    if (!c.req.header('Authorization')) {
        throw new HTTPException(401, {
            message: 'Unauthorized',
        });
    }
    return c.json({ data: 'sensitive' });
});
```

### Type-Safe Environment

```typescript
interface Env {
    DATABASE_URL: string;
    API_KEY: string;
}

const app = new Hono<{ Bindings: Env }>();

app.get('/data', async (c) => {
    // c.env is now typed!
    const dbUrl = c.env.DATABASE_URL;
    return c.json({ dbUrl });
});
```

## Important Reminders

1. **Use 4 spaces** for indentation (not 2)
2. **Use yarn**, not npm
3. **Always use `@/*` imports** for src files
4. **Never commit `.dev.vars`** (contains secrets)
5. **Test locally with `yarn dev`** before deploying
6. **Workers ≠ Node.js** - some Node APIs not available
7. **Access env via `c.env`**, not `process.env`

## Database (D1 + Drizzle ORM)

### Overview

The database has been migrated from Prisma/PostgreSQL to Drizzle ORM/D1 (Cloudflare's SQLite database). This migration maintains 100% schema parity with 20+ tables while adapting to SQLite's constraints.

### Schema Location

- **Schema Definition**: `src/db/schema.ts` (complete Drizzle schema for all tables)
- **Database Client**: `src/db/client.ts` (typed database access)
- **Migrations**: `drizzle/migrations/` (generated SQL migrations)
- **Configuration**: `drizzle.config.ts` (Drizzle Kit config)

### PostgreSQL → SQLite Type Mappings

| Prisma (PostgreSQL) | Drizzle (SQLite) | Notes |
|---------------------|------------------|-------|
| `Bytes` | `blob({ mode: 'buffer' })` | For encryption (TweetNaCl) |
| `Json` | `text({ mode: 'json' })` | Auto JSON serialization |
| `DateTime` | `integer({ mode: 'timestamp_ms' })` | Unix timestamps in ms |
| `BigInt` | `integer()` | SQLite 64-bit integers |
| `Boolean` | `integer({ mode: 'boolean' })` | 0 = false, 1 = true |
| `cuid()` default | Application layer | Use `@/utils/id` (Worker-safe) |
| `@updatedAt` | `$onUpdate(() => new Date())` | Drizzle auto-update |
| Enum types | `text()` + CHECK constraint | SQL-level validation |

### Database Commands

```bash
# Generate migrations from schema changes
yarn db:generate

# Apply migrations to local D1 database
yarn db:migrate

# Apply migrations to remote dev database
yarn db:migrate:remote

# Apply migrations to remote production database
yarn db:migrate:prod

# Create remote dev D1 database (first time only)
yarn db:create

# Create remote prod D1 database (first time only)
yarn db:create:prod

# Show local database status (tables and row counts)
yarn db:status

# Reset local database (DESTRUCTIVE - deletes all data)
yarn db:reset

# Open Drizzle Studio (database GUI)
yarn db:studio

# Seed test data
yarn db:seed

# Validate schema parity with Prisma
yarn db:compare
```

### D1 Database Setup

#### Initial Setup (One-time per environment)

1. **Create the D1 database:**

   ```bash
   # Development database
   yarn db:create

   # Production database
   yarn db:create:prod
   ```

2. **Update wrangler.toml** with the database ID printed by the create command:

   ```toml
   [[env.dev.d1_databases]]
   binding = "DB"
   database_name = "happy-dev"
   database_id = "YOUR_ACTUAL_DATABASE_ID"  # From yarn db:create output
   ```

3. **Apply migrations:**

   ```bash
   # Local development (auto-created by wrangler dev)
   yarn db:migrate

   # Remote dev database
   yarn db:migrate:remote

   # Remote production database
   yarn db:migrate:prod
   ```

#### Development Workflow

1. **Start local development** (D1 is auto-created locally):

   ```bash
   yarn dev
   ```

2. **Make schema changes** in `src/db/schema.ts`

3. **Generate new migration:**

   ```bash
   yarn db:generate
   ```

4. **Apply migration locally:**

   ```bash
   yarn db:migrate
   ```

5. **Test changes, then apply to remote:**

   ```bash
   yarn db:migrate:remote  # dev environment
   yarn db:migrate:prod    # production (after testing)
   ```

#### Idempotent Migration Application

Migrations are idempotent:

- Running `yarn db:migrate` multiple times is safe
- The script applies each migration file in order
- D1 tracks which migrations have been applied via the drizzle `_journal`

#### Environment-Specific Configuration

| Environment | Database Name | Binding | Usage |
|-------------|---------------|---------|-------|
| Local | auto-created | DB | `wrangler dev` |
| dev | happy-dev | DB | `wrangler deploy --env dev` |
| prod | happy-prod | DB | `wrangler deploy --env prod` |

### Key Schema Changes from Prisma

1. **Account.avatar field REMOVED**
   - Frontend generates avatars dynamically (initials/placeholders)
   - Eliminates server-side image processing complexity
   - No database storage needed for avatar images

2. **RelationshipStatus enum**
   - PostgreSQL native enum → SQLite TEXT with CHECK constraint
   - Values: `'none' | 'requested' | 'pending' | 'friend' | 'rejected'`
   - Enforced at database level: `CHECK (status IN (...))`

3. **Composite Primary Keys**
   - UserRelationship uses `primaryKey({ columns: [fromUserId, toUserId] })`
   - SQLite doesn't support `@@id` directive like Prisma

4. **ID Generation**
   - Prisma `@default(cuid())` → Application-layer using `createId()` from `@/utils/id` (Worker-safe)
   - No database-level default for IDs

5. **Encryption Fields**
   - All `Bytes` fields (dataEncryptionKey, token, etc.) → `blob({ mode: 'buffer' })`
   - Preserves binary data integrity for TweetNaCl encryption

### Usage Examples

#### Basic Query

```typescript
import { getDb } from '@/db/client';

export default {
    async fetch(request: Request, env: Env) {
        const db = getDb(env.DB);

        // Query accounts
        const accounts = await db.select().from(schema.accounts);

        return Response.json(accounts);
    },
};
```

#### Relational Query

```typescript
import { getDb } from '@/db/client';

export default {
    async fetch(request: Request, env: Env) {
        const db = getDb(env.DB);

        // Query with relations using Drizzle Relational API
        const accountWithSessions = await db.query.accounts.findFirst({
            where: (accounts, { eq }) => eq(accounts.id, 'account_id_here'),
            with: {
                sessions: true,
                machines: true,
                artifacts: true,
            },
        });

        return Response.json(accountWithSessions);
    },
};
```

#### Insert with Generated ID

```typescript
import { createId } from '@/utils/id';
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';

export default {
    async fetch(request: Request, env: Env) {
        const db = getDb(env.DB);

        const newAccount = await db.insert(schema.accounts).values({
            id: createId(), // Application-layer ID generation
            publicKey: 'ed25519_pk_...',
            seq: 0,
            feedSeq: 0,
            // ... other fields
        }).returning();

        return Response.json(newAccount);
    },
};
```

#### Transaction Example

```typescript
import { getDb } from '@/db/client';
import { schema } from '@/db/schema';

export default {
    async fetch(request: Request, env: Env) {
        const db = getDb(env.DB);

        const result = await db.transaction(async (tx) => {
            // Insert account
            const [account] = await tx.insert(schema.accounts).values({
                id: createId(),
                publicKey: 'pk_...',
            }).returning();

            // Insert session for that account
            const [session] = await tx.insert(schema.sessions).values({
                id: createId(),
                accountId: account.id,
                tag: 'main',
                metadata: JSON.stringify({ device: 'web' }),
            }).returning();

            return { account, session };
        });

        return Response.json(result);
    },
};
```

### Migration Best Practices

1. **Always generate migrations**: Don't manually edit migration files
2. **Test locally first**: Use local D1 database before production
3. **Validate schema parity**: Run `yarn db:compare` after changes
4. **Backup before migration**: D1 doesn't support automatic rollbacks
5. **Handle breaking changes**: Create new migrations, don't edit existing ones

### Schema Validation

The `src/db/comparison-tool.ts` validates 100% parity with the original Prisma schema:

- Table count (20 tables)
- Expected table names
- Key field presence (Account, Session, etc.)
- Relation definitions
- Schema adjustments (avatar removal, enum conversions)

Run validation:

```bash
yarn db:compare
```

### Troubleshooting

**Error: "Table already exists"**

- Drop and recreate local D1 database: `wrangler d1 execute DB --local --command="DROP TABLE IF EXISTS ..."`

**Error: "Foreign key constraint failed"**

- Ensure `PRAGMA foreign_keys = ON` in migration files
- Check that referenced records exist before inserting

**Error: "No such table"**

- Run migrations: `yarn db:migrate`
- Verify D1 database exists: `wrangler d1 list`

**Type errors in queries**

- Regenerate schema: `yarn db:generate`
- Ensure `@/*` path aliases working in tsconfig.json

## Authentication & OpenAPI

### Overview

The authentication system uses **privacy-kit** for token generation/verification, preserving the exact same auth flow as happy-server. **Better-Auth integration was deferred to HAP-29** due to HAP-10 (POC) not being completed.

### OpenAPI 3.1 Specification

The server uses `@hono/zod-openapi` to automatically generate OpenAPI 3.1 documentation from Zod schemas.

**Access the OpenAPI spec:**

```bash
curl http://localhost:8787/openapi.json
```

**Key features:**

- All routes defined with `createRoute()` from `@hono/zod-openapi`
- Request/response validation via Zod schemas
- Automatic OpenAPI documentation generation
- OpenAPI 3.1 compliant (not 3.0 or Swagger 2.0)

### Auth Module (Privacy-Kit)

**Location:** `src/lib/auth.ts`

**Initialization:**

```typescript
import { initAuth } from '@/lib/auth';

// Initialize with master secret (done automatically in middleware)
await initAuth(env.HAPPY_MASTER_SECRET);
```

**Token Generation:**

```typescript
import { createToken } from '@/lib/auth';

const token = await createToken(userId, { session: 'session_id' });
// Returns: JWT-style token string
```

**Token Verification:**

```typescript
import { verifyToken } from '@/lib/auth';

const verified = await verifyToken(token);
if (verified) {
    console.log(verified.userId);    // User ID
    console.log(verified.extras);    // Optional extras (e.g., session ID)
}
```

**Cache Management:**

```typescript
import { invalidateUserTokens, invalidateToken, getCacheStats } from '@/lib/auth';

// Invalidate all tokens for a user (e.g., on logout)
invalidateUserTokens(userId);

// Invalidate specific token
invalidateToken(token);

// Get cache statistics
const stats = getCacheStats();
console.log(`Cache size: ${stats.size} tokens`);
```

### Auth Middleware

**Location:** `src/middleware/auth.ts`

**Protecting Routes:**

```typescript
import { authMiddleware } from '@/middleware/auth';

// Apply to specific route
app.get('/v1/sessions', authMiddleware(), async (c) => {
    const userId = c.get('userId');              // Always defined after middleware
    const extras = c.get('sessionExtras');       // Optional extras from token
    // ... fetch user's data
});

// Apply to route prefix
app.use('/v1/sessions/*', authMiddleware());
```

**Optional Authentication:**

```typescript
import { optionalAuthMiddleware } from '@/middleware/auth';

app.get('/v1/public/data', optionalAuthMiddleware(), async (c) => {
    const userId = c.get('userId');  // May be undefined
    if (userId) {
        // Show personalized data
    } else {
        // Show public data
    }
});
```

### Auth Routes

**Location:** `src/routes/auth/index.ts`

All auth routes are OpenAPI-documented and use Zod validation.

#### POST /v1/auth - Direct Public Key Authentication

**Use case:** Client has Ed25519 keypair and wants to authenticate directly.

**Request:**

```json
{
    "publicKey": "base64-encoded-ed25519-public-key",
    "challenge": "base64-encoded-challenge",
    "signature": "base64-encoded-ed25519-signature"
}
```

**Response (200):**

```json
{
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Flow:**

1. Client generates Ed25519 keypair
2. Server sends challenge (not implemented yet - client generates challenge)
3. Client signs challenge with private key
4. Server verifies signature with public key
5. Server creates/updates account in database
6. Server generates authentication token

#### POST /v1/auth/request - Terminal Pairing (CLI → Mobile)

**Use case:** happy-cli wants to pair with happy-app.

**Request:**

```json
{
    "publicKey": "base64-encoded-x25519-public-key",
    "supportsV2": true
}
```

**Response (200) - Pending:**

```json
{
    "state": "requested"
}
```

**Response (200) - Already Authorized:**

```json
{
    "state": "authorized",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "response": "base64-encoded-encrypted-response"
}
```

**Flow:**

1. CLI generates X25519 keypair
2. CLI displays QR code with public key
3. CLI calls POST /v1/auth/request (creates pending request)
4. CLI polls GET /v1/auth/request/status until approved
5. Mobile scans QR and calls POST /v1/auth/response
6. CLI receives token and encrypted response

#### GET /v1/auth/request/status - Check Pairing Status

**Query Parameters:**

- `publicKey`: Base64-encoded public key to check

**Response:**

```json
{
    "status": "not_found" | "pending" | "authorized",
    "supportsV2": true
}
```

#### POST /v1/auth/response - Approve Terminal Pairing 🔒

**Auth Required:** Yes (Bearer token)

**Request:**

```json
{
    "publicKey": "base64-encoded-public-key-of-terminal",
    "response": "base64-encoded-encrypted-approval-response"
}
```

**Response (200):**

```json
{
    "success": true
}
```

**Flow:**

1. Mobile app is already authenticated (has token)
2. Mobile scans CLI's QR code (gets public key)
3. Mobile approves pairing via this endpoint
4. Server updates terminal auth request with response and mobile's user ID
5. CLI's next poll receives token and response

#### POST /v1/auth/account/request - Account Pairing (Mobile → Mobile)

**Use case:** happy-app wants to pair with another happy-app.

**Same flow as terminal pairing, but for mobile-to-mobile pairing.**

#### POST /v1/auth/account/response - Approve Account Pairing 🔒

**Auth Required:** Yes (Bearer token)

**Same as POST /v1/auth/response, but for account pairing.**

### Security Considerations

**Token Security:**

- Tokens are generated using privacy-kit persistent tokens (cryptographically signed)
- Tokens are cached in-memory for fast verification
- No expiration implemented yet (privacy-kit tokens can be configured with TTL)

**Public Key Cryptography:**

- Ed25519 for signature verification (direct auth)
- X25519 for encryption (pairing flows)
- TweetNaCl library used for all crypto operations

**Database Storage:**

- Public keys stored as hex strings
- No private keys ever stored on server
- Auth requests store encrypted responses (server cannot decrypt)

**Best Practices:**

- Always use HTTPS in production
- Set HAPPY_MASTER_SECRET via `wrangler secret` (never commit)
- Validate public key lengths before processing
- Rate limit auth endpoints to prevent brute force

### Server-Side Encryption Architecture

The server uses **TweetNaCl secretbox** (XSalsa20-Poly1305) for encrypting server-managed secrets. This is intentionally different from the client-side E2E encryption (which uses AES-256-GCM).

**See `/docs/ENCRYPTION-ARCHITECTURE.md` for comprehensive documentation.**

#### What Server-Side Encryption Protects

| Data | Encrypted? | Purpose |
|------|-----------|---------|
| AI vendor tokens (OpenAI, Anthropic) | Yes | Protect API keys at rest |
| OAuth tokens | Yes | Protect third-party credentials |
| User session data | No (E2E encrypted by clients) | Server stores encrypted blobs |
| User messages | No (E2E encrypted by clients) | Server cannot read |

#### Key Points for Server Development

1. **Algorithm**: TweetNaCl secretbox (XSalsa20-Poly1305)
2. **Key Derivation**: HKDF with path-based context (e.g., `['user', userId, 'vendors', 'openai', 'token']`)
3. **Key Cache**: Up to 1000 derived keys cached for performance
4. **Location**: `src/lib/encryption.ts`

#### Usage Example

```typescript
import { encryptString, decryptString } from '@/lib/encryption';

// Encrypt an AI vendor token
const encrypted = await encryptString(
    ['user', userId, 'vendors', 'openai', 'token'],
    'sk-...'
);

// Decrypt when needed
const token = await decryptString(
    ['user', userId, 'vendors', 'openai', 'token'],
    encrypted
);
```

#### Why TweetNaCl (not AES-GCM like clients)?

- **Simplicity**: No key versioning needed for server secrets
- **Audited**: TweetNaCl is a widely audited, secure-by-default library
- **Sufficient**: Server secrets don't need cross-platform compatibility
- **Different trust model**: Server encryption protects secrets the server needs to use

**Important**: Server-side encryption and E2E encryption are completely separate systems. The server cannot decrypt user data (sessions, messages) because those use client-side E2E encryption with user-controlled keys.

### Future Migration to Better-Auth

**Status:** Deferred to HAP-29 (blocked by HAP-10 POC)

Once HAP-10 (Better-Auth Custom Provider POC) is complete and proves Better-Auth can support public key authentication, the migration path is:

1. Complete HAP-10 POC validation
2. Implement Better-Auth custom provider for Ed25519 auth
3. Migrate privacy-kit auth to Better-Auth (HAP-29)
4. Update all auth routes to use Better-Auth sessions
5. Handle token migration (privacy-kit → Better-Auth format)

**Current state:** privacy-kit auth is production-ready and fully functional. Better-Auth migration is an optimization, not a blocker.

## Core API Routes (HAP-13)

The following routes handle the core business logic for sessions, machines, artifacts, access keys, and third-party integrations. All routes use OpenAPI documentation and Zod validation schemas.

### Session Routes

**Location:** `src/routes/sessions.ts`

Sessions track Claude Code/Codex work sessions with encrypted metadata and message history.

#### GET /v1/sessions - List Sessions (Legacy)

**Auth Required:** Yes (Bearer token)

Returns up to 150 sessions ordered by most recent. Use v2 endpoint for pagination.

**Response (200):**

```json
{
  "sessions": [{
    "id": "session_id",
    "seq": 0,
    "createdAt": 1701432000000,
    "updatedAt": 1701432000000,
    "active": true,
    "activeAt": 1701432000000,
    "metadata": "encrypted_metadata_string",
    "metadataVersion": 1,
    "agentState": "encrypted_agent_state",
    "agentStateVersion": 1,
    "dataEncryptionKey": "base64_encoded_key",
    "lastMessage": null
  }]
}
```

#### GET /v2/sessions - List Sessions with Pagination

**Auth Required:** Yes (Bearer token)

**Query Parameters:**

- `cursor`: Pagination cursor (format: `cursor_v1_{sessionId}`)
- `limit`: Results per page (default: 50, max: 200)
- `changedSince`: ISO timestamp to filter by update time

**Response (200):**

```json
{
  "sessions": [...],
  "nextCursor": "cursor_v1_abc123"
}
```

#### GET /v2/sessions/active - List Active Sessions

**Auth Required:** Yes (Bearer token)

Returns sessions active in the last 15 minutes, ordered by most recent activity.

**Query Parameters:**

- `limit`: Max results (default: 150)

#### POST /v1/sessions - Create Session

**Auth Required:** Yes (Bearer token)

Creates a new session with tag-based deduplication. If a session with the same tag exists, returns the existing session.

**Request:**

```json
{
  "tag": "unique_session_tag",
  "metadata": "encrypted_metadata_string",
  "agentState": "encrypted_agent_state",
  "dataEncryptionKey": "base64_encoded_key"
}
```

**Response (200):**

```json
{
  "session": { ... }
}
```

#### GET /v1/sessions/:id - Get Session

**Auth Required:** Yes (Bearer token)

Returns a single session by ID. User must own the session.

**Response (200/404):**

```json
{
  "session": { ... }
}
```

#### DELETE /v1/sessions/:id - Delete Session (Soft Delete)

**Auth Required:** Yes (Bearer token)

Soft deletes a session by setting `active=false`. User must own the session.

**Response (200):**

```json
{
  "success": true
}
```

#### POST /v1/sessions/:id/messages - Create Session Message

**Auth Required:** Yes (Bearer token)

Creates a new message in a session. User must own the session.

**Request:**

```json
{
  "localId": "optional_client_id",
  "content": { "encrypted": "message_content" }
}
```

**Response (200):**

```json
{
  "message": {
    "id": "message_id",
    "sessionId": "session_id",
    "localId": "client_id",
    "seq": 0,
    "content": { ... },
    "createdAt": 1701432000000
  }
}
```

### Machine Routes

**Location:** `src/routes/machines.ts`

Machines represent CLI devices (terminals) that connect to the Happy platform.

#### POST /v1/machines - Register Machine

**Auth Required:** Yes (Bearer token)

Registers a new machine or returns existing machine with same ID. Composite key: (accountId + machineId).

**Request:**

```json
{
  "id": "machine_uuid",
  "metadata": "encrypted_metadata",
  "daemonState": "encrypted_daemon_state",
  "dataEncryptionKey": "base64_encoded_key"
}
```

**Response (200):**

```json
{
  "machine": {
    "id": "machine_uuid",
    "accountId": "user_id",
    "metadata": "encrypted_metadata",
    "metadataVersion": 1,
    "daemonState": "encrypted_daemon_state",
    "daemonStateVersion": 1,
    "dataEncryptionKey": "base64_encoded_key",
    "seq": 0,
    "active": false,
    "lastActiveAt": 1701432000000,
    "createdAt": 1701432000000,
    "updatedAt": 1701432000000
  }
}
```

#### GET /v1/machines - List Machines

**Auth Required:** Yes (Bearer token)

**Query Parameters:**

- `limit`: Max results (default: 50)
- `activeOnly`: Filter to active machines only (default: false)

#### GET /v1/machines/:id - Get Machine

**Auth Required:** Yes (Bearer token)

Returns a single machine by ID. User must own the machine.

#### PUT /v1/machines/:id/status - Update Machine Status

**Auth Required:** Yes (Bearer token)

Updates machine status, metadata, or daemon state. Always updates `lastActiveAt`.

**Request:**

```json
{
  "active": true,
  "metadata": "new_encrypted_metadata",
  "daemonState": "new_encrypted_daemon_state"
}
```

### Artifact Routes

**Location:** `src/routes/artifacts.ts`

Artifacts store encrypted files/outputs from Claude Code sessions.

#### GET /v1/artifacts - List Artifacts

**Auth Required:** Yes (Bearer token)

Returns artifact headers (without body content) ordered by most recent.

**Response (200):**

```json
{
  "artifacts": [{
    "id": "artifact_id",
    "header": "base64_encrypted_header",
    "headerVersion": 1,
    "dataEncryptionKey": "base64_encoded_key",
    "seq": 0,
    "createdAt": 1701432000000,
    "updatedAt": 1701432000000
  }]
}
```

#### GET /v1/artifacts/:id - Get Artifact

**Auth Required:** Yes (Bearer token)

Returns full artifact including body content. User must own the artifact.

**Response (200):**

```json
{
  "artifact": {
    "id": "artifact_id",
    "header": "base64_encrypted_header",
    "headerVersion": 1,
    "body": "base64_encrypted_body",
    "bodyVersion": 1,
    "dataEncryptionKey": "base64_encoded_key",
    "seq": 0,
    "createdAt": 1701432000000,
    "updatedAt": 1701432000000
  }
}
```

#### POST /v1/artifacts - Create Artifact

**Auth Required:** Yes (Bearer token)

Creates a new artifact. Idempotent by ID - returns existing artifact if ID matches for same user.

**Request:**

```json
{
  "id": "artifact_id",
  "header": "base64_encrypted_header",
  "body": "base64_encrypted_body",
  "dataEncryptionKey": "base64_encoded_key"
}
```

**Response (200/409):**

- 200: Artifact created or existing returned
- 409: Artifact ID exists for different user

#### POST /v1/artifacts/:id - Update Artifact

**Auth Required:** Yes (Bearer token)

Updates artifact header and/or body with optimistic locking.

**Request:**

```json
{
  "header": "new_base64_encrypted_header",
  "expectedHeaderVersion": 1,
  "body": "new_base64_encrypted_body",
  "expectedBodyVersion": 1
}
```

**Response (200):**

```json
{
  "success": true,
  "headerVersion": 2,
  "bodyVersion": 2
}
```

Or on version mismatch:

```json
{
  "success": false,
  "error": "version-mismatch",
  "currentHeaderVersion": 2,
  "currentHeader": "base64_current_header"
}
```

#### DELETE /v1/artifacts/:id - Delete Artifact

**Auth Required:** Yes (Bearer token)

Permanently deletes an artifact. User must own the artifact.

### Access Key Routes

**Location:** `src/routes/accessKeys.ts`

Access keys store encrypted session-machine access credentials.

#### GET /v1/access-keys/:sessionId/:machineId - Get Access Key

**Auth Required:** Yes (Bearer token)

Returns access key for a session-machine pair, or null if not found.

**Response (200):**

```json
{
  "accessKey": {
    "data": "encrypted_access_data",
    "dataVersion": 1,
    "createdAt": 1701432000000,
    "updatedAt": 1701432000000
  }
}
```

Or if not found:

```json
{
  "accessKey": null
}
```

#### POST /v1/access-keys/:sessionId/:machineId - Create Access Key

**Auth Required:** Yes (Bearer token)

Creates a new access key. Fails if key already exists.

**Request:**

```json
{
  "data": "encrypted_access_data"
}
```

**Response (200/409):**

- 200: Access key created
- 409: Access key already exists

#### PUT /v1/access-keys/:sessionId/:machineId - Update Access Key

**Auth Required:** Yes (Bearer token)

Updates access key with optimistic locking.

**Request:**

```json
{
  "data": "new_encrypted_access_data",
  "expectedVersion": 1
}
```

**Response (200):**

```json
{
  "success": true,
  "version": 2
}
```

### Connect Routes

**Location:** `src/routes/connect.ts`

Connect routes handle third-party integrations (GitHub OAuth, AI service tokens).

**Note:** Device pairing (CLI ↔ Mobile) is handled by auth routes (`/v1/auth/request`, `/v1/auth/response`), not connect routes.

#### GitHub OAuth Integration

##### GET /v1/connect/github/params 🔒

**Auth Required:** Yes

Returns GitHub OAuth authorization URL with state token.

**Response (200):**

```json
{
  "url": "https://github.com/login/oauth/authorize?client_id=...&state=..."
}
```

##### GET /v1/connect/github/callback

Handles GitHub OAuth redirect. Exchanges code for token and stores user data.

##### POST /v1/connect/github/webhook

Receives GitHub webhook events. Verifies signature and processes events.

##### DELETE /v1/connect/github 🔒

**Auth Required:** Yes

Disconnects user's GitHub account and clears stored tokens.

#### AI Service Token Management

Stores encrypted API tokens for AI services (OpenAI, Anthropic, Gemini).

##### POST /v1/connect/:vendor/register 🔒

**Auth Required:** Yes

**Path Parameters:**

- `vendor`: `openai` | `anthropic` | `gemini`

**Request:**

```json
{
  "token": "sk-..."
}
```

**Response (200):**

```json
{
  "success": true
}
```

##### GET /v1/connect/:vendor/token 🔒

**Auth Required:** Yes

Returns decrypted token for the specified vendor, or null if not registered.

**Response (200):**

```json
{
  "token": "sk-..."
}
```

##### DELETE /v1/connect/:vendor 🔒

**Auth Required:** Yes

Removes the stored token for the specified vendor.

##### GET /v1/connect/tokens 🔒

**Auth Required:** Yes

Lists all registered AI service tokens for the user.

**Response (200):**

```json
{
  "tokens": [
    { "vendor": "openai", "token": "sk-..." },
    { "vendor": "anthropic", "token": "sk-ant-..." }
  ]
}
```

### Common Error Responses

All routes follow consistent error response patterns:

**401 Unauthorized:**

```json
{
  "error": "Unauthorized"
}
```

**404 Not Found:**

```json
{
  "error": "Session not found"
}
```

**400 Bad Request:**

```json
{
  "error": "Invalid cursor format"
}
```

**409 Conflict:**

```json
{
  "error": "Access key already exists"
}
```

## User Profile & Social Routes (HAP-14)

The following routes handle user profile management, user discovery, and activity feeds. All routes require authentication and use OpenAPI documentation with Zod validation schemas.

### Account Routes

**Location:** `src/routes/account.ts`

Account routes manage the current user's profile and preferences.

#### GET /v1/account - Get User Profile

**Auth Required:** Yes (Bearer token)

Returns the current user's profile including connected services.

**Response (200):**

```json
{
  "id": "user_id",
  "timestamp": 1701432000000,
  "firstName": "John",
  "lastName": "Doe",
  "username": "johndoe",
  "github": { "login": "johndoe", "avatar_url": "..." },
  "connectedServices": ["openai", "anthropic"]
}
```

#### PUT /v1/account - Update User Profile

**Auth Required:** Yes (Bearer token)

Updates the current user's profile fields.

**Request:**

```json
{
  "firstName": "John",
  "lastName": "Doe",
  "username": "johndoe"
}
```

**Response (200):**

```json
{
  "success": true,
  "profile": { ... }
}
```

**Response (409) - Username Taken:**

```json
{
  "success": false,
  "error": "username-taken"
}
```

#### GET /v1/account/preferences - Get Account Preferences

**Auth Required:** Yes (Bearer token)

Returns encrypted account settings with version for optimistic concurrency.

**Response (200):**

```json
{
  "settings": "{\"theme\":\"dark\"}",
  "settingsVersion": 5
}
```

#### PUT /v1/account/preferences - Update Account Preferences

**Auth Required:** Yes (Bearer token)

Updates account settings with optimistic locking.

**Request:**

```json
{
  "settings": "{\"theme\":\"light\"}",
  "expectedVersion": 5
}
```

**Response (200) - Success:**

```json
{
  "success": true,
  "version": 6
}
```

**Response (200) - Version Mismatch:**

```json
{
  "success": false,
  "error": "version-mismatch",
  "currentVersion": 6,
  "currentSettings": "{\"theme\":\"dark\"}"
}
```

### User Routes

**Location:** `src/routes/user.ts`

User routes enable user discovery and profile viewing.

#### GET /v1/users/search - Search Users

**Auth Required:** Yes (Bearer token)

Search for users by username prefix (case-insensitive).

**Query Parameters:**

- `query`: Search string (username prefix)
- `limit`: Maximum results (1-50, default 10)

**Response (200):**

```json
{
  "users": [
    {
      "id": "user_id",
      "firstName": "Jane",
      "lastName": "Smith",
      "username": "janesmith",
      "status": "none"
    }
  ]
}
```

**Status values:** `none`, `requested`, `pending`, `friend`, `rejected`

#### GET /v1/users/:id - Get User Profile

**Auth Required:** Yes (Bearer token)

Returns a user's profile by ID with relationship status.

**Response (200):**

```json
{
  "user": {
    "id": "user_id",
    "firstName": "Jane",
    "lastName": "Smith",
    "username": "janesmith",
    "status": "friend"
  }
}
```

**Response (404):**

```json
{
  "error": "User not found"
}
```

### Feed Routes

**Location:** `src/routes/feed.ts`

Feed routes provide activity feed with cursor-based pagination.

#### GET /v1/feed - Get Activity Feed

**Auth Required:** Yes (Bearer token)

Returns user's activity feed with cursor-based pagination.

**Query Parameters:**

- `before`: Cursor for older items (e.g., `cursor_42`)
- `after`: Cursor for newer items
- `limit`: Maximum items (1-200, default 50)

**Response (200):**

```json
{
  "items": [
    {
      "id": "feed_abc123",
      "body": { "type": "session-created", ... },
      "repeatKey": "session_created_xyz",
      "cursor": "cursor_42",
      "createdAt": 1701432000000
    }
  ],
  "hasMore": true
}
```

**Pagination:**

- Use `before` cursor to get older items
- Use `after` cursor to get newer items
- Cursors are in format `cursor_{counter}`

## Utility & Specialized Routes (HAP-15)

The following routes provide utility functions: version checking, development logging, voice synthesis integration, key-value storage, and push notifications.

### Version Routes

**Location:** `src/routes/version.ts`

#### POST /v1/version - Check App Version

Check if the client app version requires an update.

**Request:**

```json
{
    "platform": "ios",
    "version": "1.4.0",
    "app_id": "com.ex3ndr.happy"
}
```

**Response (200):**

```json
{
    "updateUrl": "https://apps.apple.com/us/app/happy-claude-code-client/id6748571505"
}
```

Returns `null` for `updateUrl` if the version is up to date.

### Dev Routes

**Location:** `src/routes/dev.ts`

#### POST /logs-combined-from-cli-and-mobile-for-simple-ai-debugging

Combined logging endpoint for debugging. Only enabled when `DANGEROUSLY_LOG_TO_SERVER_FOR_AI_AUTO_DEBUGGING` environment variable is set.

**Request:**

```json
{
    "timestamp": "2024-01-15T10:30:00.000Z",
    "level": "info",
    "message": "User action completed",
    "source": "mobile",
    "platform": "ios"
}
```

**Response (200):**

```json
{
    "success": true
}
```

### Voice Routes

**Location:** `src/routes/voice.ts`

#### POST /v1/voice/token 🔒

**Auth Required:** Yes (Bearer token)

Get an ElevenLabs conversation token for voice synthesis. In production, requires RevenueCat subscription verification.

**Request:**

```json
{
    "agentId": "agent_abc123",
    "revenueCatPublicKey": "appl_XYZ789"
}
```

**Response (200) - Success:**

```json
{
    "allowed": true,
    "token": "xi_token_...",
    "agentId": "agent_abc123"
}
```

**Response (200) - Denied (no subscription):**

```json
{
    "allowed": false,
    "agentId": "agent_abc123"
}
```

### KV Routes

**Location:** `src/routes/kv.ts`

Key-value storage with optimistic locking. All routes require authentication.

#### GET /v1/kv/:key 🔒

Get a single key-value pair.

**Response (200):**

```json
{
    "key": "settings:theme",
    "value": "base64EncodedEncryptedValue",
    "version": 1
}
```

#### GET /v1/kv 🔒

List key-value pairs with optional prefix filter.

**Query Parameters:**

- `prefix`: Filter by key prefix (e.g., `settings:`)
- `limit`: Maximum items (1-1000, default: 100)

**Response (200):**

```json
{
    "items": [
        { "key": "settings:theme", "value": "...", "version": 1 }
    ]
}
```

#### POST /v1/kv/bulk 🔒

Bulk get multiple keys.

**Request:**

```json
{
    "keys": ["settings:theme", "settings:notifications"]
}
```

**Response (200):**

```json
{
    "values": [
        { "key": "settings:theme", "value": "...", "version": 1 }
    ]
}
```

#### POST /v1/kv 🔒

Atomic batch mutation (create/update/delete). Uses optimistic locking with version numbers.

**Request:**

```json
{
    "mutations": [
        { "key": "settings:theme", "value": "newBase64Value", "version": 1 },
        { "key": "settings:old", "value": null, "version": 2 }
    ]
}
```

- `version: -1` for new keys
- `value: null` to delete

**Response (200) - Success:**

```json
{
    "success": true,
    "results": [
        { "key": "settings:theme", "version": 2 }
    ]
}
```

**Response (409) - Version Mismatch:**

```json
{
    "success": false,
    "errors": [
        { "key": "settings:theme", "error": "version-mismatch", "version": 3, "value": "currentValue" }
    ]
}
```

### Push Routes

**Location:** `src/routes/push.ts`

Push notification token management. All routes require authentication.

#### POST /v1/push-tokens 🔒

Register a push notification token. Idempotent - updates timestamp if token already exists.

**Request:**

```json
{
    "token": "ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]"
}
```

**Response (200):**

```json
{
    "success": true
}
```

#### DELETE /v1/push-tokens/:token 🔒

Delete a push notification token.

**Response (200):**

```json
{
    "success": true
}
```

#### GET /v1/push-tokens 🔒

List all push tokens for the authenticated user.

**Response (200):**

```json
{
    "tokens": [
        {
            "id": "cld123abc",
            "token": "ExponentPushToken[xxx]",
            "createdAt": 1701432000000,
            "updatedAt": 1701432000000
        }
    ]
}
```

## WebSocket & Durable Objects (HAP-16)

### Overview

Real-time WebSocket connections are managed using Cloudflare Durable Objects with the WebSocket Hibernation API. This replaces the Socket.io + Redis architecture from happy-server.

**Location:** `src/durable-objects/`

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Cloudflare Edge                        │
├──────────────────────────────────────────────────────────┤
│  Worker (fetch) → /v1/updates or /v1/websocket           │
│         ↓                                                 │
│  Auth verification (privacy-kit token)                    │
│         ↓                                                 │
│  Get/Create ConnectionManager DO (by userId)              │
│         ↓                                                 │
│  ┌─────────────────────────────────────────────────────┐ │
│  │           ConnectionManager Durable Object           │ │
│  │                                                      │ │
│  │  - acceptWebSocket() with hibernation support        │ │
│  │  - Connection metadata via serializeAttachment       │ │
│  │  - Auto ping/pong during hibernation                 │ │
│  │  - Filtered message broadcasting                     │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### Connection Types

Three client types supported (matching happy-server Socket.io):

| Type | Description | Required Params |
|------|-------------|-----------------|
| `user-scoped` | Mobile app - receives all user events | token |
| `session-scoped` | Session viewer - specific session events | token, sessionId |
| `machine-scoped` | CLI daemon - specific machine events | token, machineId |

### WebSocket Endpoints

#### GET /v1/updates (or /v1/websocket)

WebSocket upgrade endpoint with multiple authentication methods.

**Authentication Methods (HAP-360, HAP-375):**

For security, auth tokens should NOT be passed in URL query strings. The server supports three auth methods:

| Method | Client | Flow |
|--------|--------|------|
| **Ticket Auth** (recommended) | Mobile (happy-app) | POST `/v1/websocket/ticket` → connect with `?ticket=xxx` |
| **Header Auth** | CLI (happy-cli) | Connect with `Authorization: Bearer <token>` header |
| **Message Auth** (fallback) | Mobile | Connect without token → send auth message on open |

**Query Parameters:**

- `ticket`: Short-lived auth ticket (from POST `/v1/websocket/ticket`)
- `clientType`: `user-scoped` | `session-scoped` | `machine-scoped` (default: user-scoped)
- `sessionId`: Required for session-scoped connections
- `machineId`: Required for machine-scoped connections
- `correlationId`: Optional request tracing ID

**Headers (for CLI/Node.js clients):**

- `Authorization: Bearer <token>`
- `X-Client-Type: <type>`
- `X-Session-Id: <id>`
- `X-Machine-Id: <id>`

**Message Auth Flow (HAP-360):**

If connecting without ticket or header auth, send auth message immediately after `onopen`:

```javascript
ws.onopen = () => {
    ws.send(JSON.stringify({
        event: 'auth',
        data: {
            token: authToken,
            clientType: 'user-scoped'
        }
    }));
};
```

Server responds with `{ event: 'connected' }` on success or `{ event: 'auth-error' }` on failure.
Connections that don't authenticate within 5 seconds are closed.

**Example (Mobile client with ticket auth):**

```javascript
// Step 1: Fetch short-lived ticket
const ticketRes = await fetch('/v1/websocket/ticket', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` }
});
const { ticket } = await ticketRes.json();

// Step 2: Connect with ticket (no long-lived token in URL)
const ws = new WebSocket(
    `wss://api.example.com/v1/updates?ticket=${ticket}&clientType=user-scoped`
);

ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.event === 'connected') {
        console.log('Authenticated!');
    }
};
```

**Example (CLI client with header auth):**

```javascript
// Node.js WebSocket supports headers
const ws = new WebSocket('wss://api.example.com/v1/updates', {
    headers: {
        'Authorization': `Bearer ${token}`,
        'X-Client-Type': 'machine-scoped',
        'X-Machine-Id': machineId
    }
});
```

#### GET /v1/websocket/stats (Protected)

Returns connection statistics for the authenticated user.

**Response:**

```json
{
    "totalConnections": 3,
    "byType": {
        "user-scoped": 1,
        "session-scoped": 1,
        "machine-scoped": 1
    },
    "activeSessions": 1,
    "activeMachines": 1,
    "oldestConnection": 1699500000000
}
```

#### POST /v1/websocket/broadcast (Protected)

Send a message to user's WebSocket connections with optional filtering.

**Request:**

```json
{
    "message": {
        "type": "session-update",
        "payload": { "sessionId": "xyz", "status": "active" },
        "timestamp": 1699500000000
    },
    "filter": {
        "type": "user-scoped-only"
    }
}
```

**Filter Types:**

- `{ type: "all" }` - All connections
- `{ type: "user-scoped-only" }` - Only mobile apps
- `{ type: "session", sessionId: "xxx" }` - Specific session
- `{ type: "machine", machineId: "xxx" }` - Specific machine
- `{ type: "exclude", connectionId: "xxx" }` - All except one

### Message Protocol

All WebSocket messages are JSON with this structure:

```typescript
interface WebSocketMessage {
    type: 'ping' | 'pong' | 'connected' | 'error' | 'broadcast' | ...;
    payload?: unknown;
    timestamp: number;
    messageId?: string;
}
```

**Built-in Message Types:**

- `ping` / `pong`: Keep-alive (auto-handled during hibernation)
- `connected`: Sent after successful connection with connectionId
- `error`: Error notification with code and message
- `broadcast`: Generic broadcast message

### Close Codes

Standard WebSocket codes plus custom application codes:

| Code | Constant | Meaning |
|------|----------|---------|
| 1000 | NORMAL | Clean disconnect |
| 1001 | GOING_AWAY | DO being evicted |
| 4001 | AUTH_FAILED | Invalid token |
| 4002 | INVALID_HANDSHAKE | Missing handshake data |
| 4003 | MISSING_SESSION_ID | Session-scoped without sessionId |
| 4004 | MISSING_MACHINE_ID | Machine-scoped without machineId |
| 4005 | CONNECTION_LIMIT_EXCEEDED | User has too many connections |

### Hibernation & Cost Optimization

The WebSocket Hibernation API allows Durable Objects to be evicted from memory while keeping WebSocket connections open:

- **Auto-response**: Ping/pong handled without waking DO
- **State restoration**: Connection metadata restored via `deserializeAttachment`
- **Tags**: Connections tagged for efficient filtering without iterating all

This significantly reduces costs for long-lived, mostly-idle WebSocket connections.

### Testing

```bash
# Run WebSocket/DO tests
yarn test src/durable-objects/

# Note: Tests mock cloudflare:workers since it's edge-only
```

### Files

- `src/durable-objects/types.ts` - Type definitions
- `src/durable-objects/ConnectionManager.ts` - Main DO class
- `src/durable-objects/index.ts` - Exports
- `src/routes/websocket.ts` - HTTP routes for WebSocket upgrade
- `wrangler.toml` - DO bindings configuration

## R2 Storage (HAP-5)

### Overview

File storage is implemented using Cloudflare R2 (S3-compatible object storage). The implementation provides:

- File upload/download with authentication
- Support for avatars, documents, and general files
- Proper content-type validation
- Size limits per category
- Integration with D1 database for file metadata

### Configuration

R2 bucket is configured in `wrangler.toml`:

```toml
# Development
[[env.dev.r2_buckets]]
binding = "UPLOADS"
bucket_name = "happy-dev-uploads"

# Production
[[env.prod.r2_buckets]]
binding = "UPLOADS"
bucket_name = "happy-prod-uploads"
```

### Storage Abstraction

**Location:** `src/storage/r2.ts`

The R2Storage class provides typed utilities for file operations:

```typescript
import { createR2Storage } from '@/storage/r2';

const r2 = createR2Storage(c.env.UPLOADS);

// Upload a file
const result = await r2.upload(path, body, metadata);

// Upload an avatar (with image validation)
const avatar = await r2.uploadAvatar(userId, body, 'image/jpeg', 'photo.jpg');

// Download a file
const file = await r2.get(path);

// Delete a file
await r2.delete(path);
```

### Supported File Types

**Images:**

- `image/jpeg`, `image/png`, `image/gif`, `image/webp`, `image/svg+xml`

**Documents:**

- `application/pdf`, `text/plain`, `application/json`, `text/markdown`

### Size Limits

| Category | Max Size |
|----------|----------|
| Avatar | 5 MB |
| Document | 50 MB |
| General | 100 MB |

### Upload Routes

**Location:** `src/routes/uploads.ts`

All routes require authentication (Bearer token).

#### POST /v1/uploads - Upload File

Upload a file to R2 storage.

**Request:** `multipart/form-data`

- `file`: File content (required)
- `category`: `avatars` | `documents` | `files` (optional, default: `files`)
- `reuseKey`: Deduplication key (optional)

**Response (200):**

```json
{
    "success": true,
    "file": {
        "id": "clm8z0xyz000008l5g1h9e2ab",
        "path": "documents/user123/clm8z0xyz000008l5g1h9e2ab.pdf",
        "originalName": "document.pdf",
        "contentType": "application/pdf",
        "size": 245678,
        "createdAt": 1705010400000,
        "updatedAt": 1705010400000
    }
}
```

#### GET /v1/uploads - List Files

List uploaded files for the authenticated user.

**Query Parameters:**

- `category`: Filter by category (optional)
- `limit`: Max results (1-200, default: 50)
- `cursor`: Pagination cursor (optional)

#### GET /v1/uploads/:id - Get File Metadata

Get metadata for a specific file.

#### GET /v1/uploads/:id/download - Download File

Download file content. Returns the file with appropriate Content-Type header.

#### DELETE /v1/uploads/:id - Delete File

Delete an uploaded file from both R2 and the database.

#### POST /v1/uploads/avatar - Upload Avatar

Convenience endpoint for avatar uploads. Automatically:

- Validates image type (JPEG, PNG, GIF, WebP only)
- Enforces 5MB size limit
- Replaces existing avatar (using `profile-avatar` reuseKey)

**Request:** `multipart/form-data`

- `file`: Image file (required)

**Response (200):**

```json
{
    "success": true,
    "avatar": {
        "id": "clm8z0xyz000008l5g1h9e2ab",
        "path": "avatars/user123/clm8z0xyz000008l5g1h9e2ab.jpg",
        "contentType": "image/jpeg",
        "size": 102400
    }
}
```

### Database Schema

The `uploadedFiles` table stores file metadata:

```typescript
uploadedFiles = sqliteTable('UploadedFile', {
    id: text('id').primaryKey(),
    accountId: text('accountId').notNull(),
    path: text('path').notNull(),           // R2 storage path
    width: integer('width'),                 // Image dimensions
    height: integer('height'),
    thumbhash: text('thumbhash'),           // Placeholder image
    reuseKey: text('reuseKey'),             // Deduplication key
    createdAt: integer('createdAt', { mode: 'timestamp_ms' }),
    updatedAt: integer('updatedAt', { mode: 'timestamp_ms' }),
});
```

### Usage Examples

#### Upload Avatar from Frontend

```typescript
const formData = new FormData();
formData.append('file', imageFile);

const response = await fetch('https://api.example.com/v1/uploads/avatar', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${token}`,
    },
    body: formData,
});

const { avatar } = await response.json();
console.log('Avatar uploaded:', avatar.path);
```

#### Upload Document

```typescript
const formData = new FormData();
formData.append('file', pdfFile);
formData.append('category', 'documents');

const response = await fetch('https://api.example.com/v1/uploads', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${token}`,
    },
    body: formData,
});

const { file } = await response.json();
```

#### Download File

```typescript
const response = await fetch(`https://api.example.com/v1/uploads/${fileId}/download`, {
    headers: {
        'Authorization': `Bearer ${token}`,
    },
});

const blob = await response.blob();
```

## Resources

- [Hono Documentation](https://hono.dev/)
- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Wrangler CLI Reference](https://developers.cloudflare.com/workers/wrangler/)
- [D1 Documentation](https://developers.cloudflare.com/d1/)
- [Drizzle ORM Documentation](https://orm.drizzle.team/)
- [Drizzle with D1 Guide](https://orm.drizzle.team/docs/get-started-sqlite#cloudflare-d1)
- [Durable Objects](https://developers.cloudflare.com/workers/learning/using-durable-objects/)
- [WebSocket Hibernation API](https://developers.cloudflare.com/durable-objects/best-practices/websockets/)
- [R2 Storage](https://developers.cloudflare.com/r2/)
