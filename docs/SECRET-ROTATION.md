# Secret Rotation Procedures

This document describes the procedures for rotating secrets in the Happy platform.

## Overview

Secret rotation should be performed:
- **Immediately** if a secret is compromised or suspected of being compromised
- **Quarterly** as a security best practice
- **When team members leave** who had access to production secrets

## Secret Inventory

| Secret | Location | Rotation Impact |
|--------|----------|-----------------|
| `HANDY_MASTER_SECRET` | Server, Workers | High - invalidates all tokens |
| `DATABASE_URL` | Server | Low - database credentials |
| `REDIS_URL` | Server | Low - cache connection |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | Server | Low - storage credentials |
| `ELEVENLABS_API_KEY` | Server, Workers | Low - voice API |
| `GITHUB_CLIENT_SECRET` | Server, Workers | Medium - breaks OAuth flow |
| `GITHUB_WEBHOOK_SECRET` | Server, Workers | Low - webhook verification |

## Rotation Procedures

### 1. HANDY_MASTER_SECRET (High Impact)

⚠️ **WARNING**: Rotating this secret will invalidate all existing authentication tokens. All users will need to re-authenticate.

#### Preparation
1. Schedule maintenance window
2. Notify users of upcoming re-authentication requirement
3. Generate new secret: `openssl rand -hex 32`

#### For happy-server (Traditional)
```bash
# 1. Update .env with new secret
cd happy-server
# Edit .env and replace HANDY_MASTER_SECRET

# 2. Restart server
pm2 restart happy-server  # or your process manager
```

#### For happy-server-workers (Cloudflare)
```bash
# 1. Set new secret
cd happy-server-workers
wrangler secret put HANDY_MASTER_SECRET --env prod
# Paste new secret when prompted

# 2. Deploy to apply (secrets are applied immediately, but good practice)
wrangler deploy --env prod
```

#### Post-Rotation
1. Verify server is responding to authenticated requests (new logins)
2. Monitor error rates for authentication failures
3. Old tokens will fail - this is expected

### 2. DATABASE_URL (Low Impact)

#### Preparation
1. Create new database credentials in your database admin panel
2. Test new credentials locally first

#### Procedure
```bash
# 1. Update credentials in database admin (PostgreSQL)
# 2. Update .env with new DATABASE_URL
# 3. Restart server

# Test connection
cd happy-server
yarn prisma db pull  # Verify connection works
```

### 3. S3/R2 Storage Credentials (Low Impact)

#### For AWS S3
```bash
# 1. Create new IAM access key in AWS Console
# 2. Update .env with new S3_ACCESS_KEY and S3_SECRET_KEY
# 3. Delete old access key after verifying new one works
```

#### For Cloudflare R2
R2 uses API tokens managed in the Cloudflare dashboard:
1. Go to R2 > Manage R2 API Tokens
2. Create new token with appropriate permissions
3. Update credentials
4. Delete old token

### 4. ELEVENLABS_API_KEY (Low Impact)

```bash
# 1. Generate new API key in ElevenLabs dashboard
# 2. Update secret
wrangler secret put ELEVENLABS_API_KEY --env prod
# 3. Delete old key from ElevenLabs dashboard
```

### 5. GitHub OAuth Secrets (Medium Impact)

⚠️ Rotating `GITHUB_CLIENT_SECRET` will temporarily break GitHub OAuth login.

```bash
# 1. In GitHub Developer Settings, regenerate client secret
# 2. Immediately update the secret
wrangler secret put GITHUB_CLIENT_SECRET --env prod

# 3. Verify OAuth flow works
```

### 6. GITHUB_WEBHOOK_SECRET (Low Impact)

```bash
# 1. Generate new secret
openssl rand -hex 32

# 2. Update in GitHub webhook settings (repository settings)
# 3. Update server secret
wrangler secret put GITHUB_WEBHOOK_SECRET --env prod

# 4. Verify webhook deliveries are succeeding
```

## TweetNaCl Encryption Keys

Client-side encryption keys are stored on user devices and are **not** server-managed. Each client generates its own keypair:

- **CLI**: Keys stored in `~/.happy/access.key`
- **Mobile App**: Keys stored in secure device storage

### Forcing Key Rotation for Clients

If you need all clients to regenerate keys (security incident):

1. Revoke all tokens (rotate `HANDY_MASTER_SECRET`)
2. Users will need to re-pair devices
3. New keypairs are generated during re-pairing

## Emergency Rotation Checklist

If a secret is compromised:

- [ ] 1. Immediately generate new secret
- [ ] 2. Update production secrets
- [ ] 3. Restart/redeploy services
- [ ] 4. Revoke/disable old credentials where possible
- [ ] 5. Review access logs for suspicious activity
- [ ] 6. Document incident and rotation in security log
- [ ] 7. Notify affected users if personal data was at risk

## Cloudflare Secrets Commands Reference

```bash
# List all secrets for an environment
wrangler secret list --env prod

# Set a secret (prompts for value)
wrangler secret put SECRET_NAME --env prod

# Delete a secret
wrangler secret delete SECRET_NAME --env prod

# Bulk update from .env file (careful with this!)
cat .env.prod | while IFS='=' read -r key value; do
  [[ $key =~ ^# ]] && continue  # Skip comments
  [[ -z $key ]] && continue     # Skip empty lines
  echo "$value" | wrangler secret put "$key" --env prod
done
```

## Audit Log

Maintain a log of secret rotations:

| Date | Secret | Reason | Performed By |
|------|--------|--------|--------------|
| YYYY-MM-DD | HANDY_MASTER_SECRET | Quarterly rotation | @username |
| ... | ... | ... | ... |

Keep this log in a secure, access-controlled location (not in the repository).
