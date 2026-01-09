# Secrets Management for Happy Server Workers

This document describes how to configure and manage secrets for the Cloudflare Workers deployment.

## Overview

Happy Server Workers requires cryptographic secrets for:
- **Authentication**: Token generation and verification via privacy-kit
- **Encryption**: Server-side encryption operations
- **Integrations**: Third-party services (ElevenLabs, GitHub)

## Required Secrets

| Secret | Purpose | Required |
|--------|---------|----------|
| `HAPPY_MASTER_SECRET` | Master key for auth token generation | **Yes** |
| `ELEVENLABS_API_KEY` | Voice synthesis API | No |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth login | No |
| `GITHUB_WEBHOOK_SECRET` | Webhook signature verification | No |

## Secret Generation

### Using the Script

From the `happy-server` directory:

```bash
# Generate secrets for development
./scripts/generate-secrets.sh

# Generate secrets for production
./scripts/generate-secrets.sh --env production
```

### Manual Generation

```bash
# Generate HAPPY_MASTER_SECRET (32 bytes = 64 hex characters)
openssl rand -hex 32

# Example output:
# a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890
```

## Environment-Specific Configuration

### Local Development

1. Copy the template:
   ```bash
   cd happy-server-workers
   cp .dev.vars.example .dev.vars
   ```

2. Edit `.dev.vars` with your development secrets:
   ```bash
   ENVIRONMENT=development
   HAPPY_MASTER_SECRET=your-generated-secret-here
   ```

3. Start local development:
   ```bash
   yarn dev
   ```

**Note:** `.dev.vars` is gitignored and should never be committed.

### Development Environment (Remote)

Set secrets for the dev environment:

```bash
cd happy-server-workers

# Set required secret
wrangler secret put HAPPY_MASTER_SECRET --env dev
# Paste secret when prompted

# Optional: Set additional secrets
wrangler secret put ELEVENLABS_API_KEY --env dev
```

Deploy to dev:
```bash
wrangler deploy --env dev
```

### Production Environment

Set secrets for production:

```bash
cd happy-server-workers

# Set required secret
wrangler secret put HAPPY_MASTER_SECRET --env prod
# Paste secret when prompted

# Optional: Set additional secrets
wrangler secret put ELEVENLABS_API_KEY --env prod
wrangler secret put GITHUB_CLIENT_SECRET --env prod
wrangler secret put GITHUB_WEBHOOK_SECRET --env prod
```

Deploy to production:
```bash
wrangler deploy --env prod
```

## Wrangler Secret Commands Reference

```bash
# List all secrets for an environment
wrangler secret list --env prod

# Set a secret (interactive, prompts for value)
wrangler secret put SECRET_NAME --env prod

# Delete a secret
wrangler secret delete SECRET_NAME --env prod
```

## Security Best Practices

### Do's

1. **Generate unique secrets per environment** - Never share secrets between dev/staging/prod
2. **Use the generation script** - Ensures cryptographically secure random values
3. **Rotate quarterly** - Regular rotation reduces exposure window
4. **Use Cloudflare Secrets** - Never put production secrets in `wrangler.toml`
5. **Store secrets securely** - Use a password manager or vault for backup copies

### Don'ts

1. **Never commit secrets** - `.dev.vars` and all env files with real values are gitignored
2. **Never log secrets** - Be careful with debug logging in production
3. **Never share via chat/email** - Use secure channels for secret sharing
4. **Never use development secrets in production** - The test values are publicly visible

## Secret Rotation

See `apps/server/docker/docs/SECRET-ROTATION.md` for detailed rotation procedures.

### Quick Rotation Steps

1. **Generate new secret:**
   ```bash
   openssl rand -hex 32
   ```

2. **Update in Cloudflare:**
   ```bash
   wrangler secret put HAPPY_MASTER_SECRET --env prod
   ```

3. **Deploy (optional but recommended):**
   ```bash
   wrangler deploy --env prod
   ```

**Warning:** Rotating `HAPPY_MASTER_SECRET` invalidates all existing authentication tokens. Users will need to re-authenticate.

## Troubleshooting

### "HAPPY_MASTER_SECRET is required" Error

The worker requires this secret to start. Ensure it's set:

```bash
# Check if secret exists
wrangler secret list --env dev

# Set if missing
wrangler secret put HAPPY_MASTER_SECRET --env dev
```

### "Invalid token" Errors After Rotation

This is expected behavior. When `HAPPY_MASTER_SECRET` changes:
- All existing tokens become invalid
- Users must re-authenticate
- CLI devices must re-pair with mobile app

### Local Development Not Using Secrets

Ensure `.dev.vars` exists and has the correct format:
- No quotes around values
- No spaces around `=`
- File is in the project root (same level as `wrangler.toml`)

```bash
# Verify file exists
ls -la .dev.vars

# Verify format
cat .dev.vars
```
