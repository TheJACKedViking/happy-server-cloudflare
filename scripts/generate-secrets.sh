#!/bin/bash
# Happy Secrets Generation Script
#
# This script generates cryptographic secrets for the Happy platform.
# Run this when setting up a new environment or rotating keys.
#
# SECURITY NOTES:
# - Store generated secrets securely (password manager, Cloudflare Secrets, etc.)
# - Use different secrets for each environment (dev, staging, production)
# - Never commit generated secrets to version control
#
# Usage:
#   ./scripts/generate-secrets.sh
#   ./scripts/generate-secrets.sh --env production

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ENV_NAME="${1:-development}"
if [[ "$1" == "--env" ]]; then
    ENV_NAME="${2:-development}"
fi

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Happy Secrets Generator - ${ENV_NAME}${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to generate a hex secret
generate_hex_secret() {
    local bytes=$1
    openssl rand -hex $bytes
}

# Function to generate a base64 secret
generate_base64_secret() {
    local bytes=$1
    openssl rand -base64 $bytes | tr -d '\n'
}

# Function to generate TweetNaCl keypair (32-byte secret key)
generate_nacl_keypair() {
    # TweetNaCl uses 32-byte (256-bit) keys
    echo "$(generate_hex_secret 32)"
}

echo -e "${GREEN}1. HANDY_MASTER_SECRET${NC} (32 bytes / 64 hex chars)"
echo -e "   Used for: JWT signing, server-side encryption"
MASTER_SECRET=$(generate_hex_secret 32)
echo -e "   ${YELLOW}HANDY_MASTER_SECRET=${MASTER_SECRET}${NC}"
echo ""

echo -e "${GREEN}2. S3_ACCESS_KEY${NC} (20 chars)"
echo -e "   Used for: S3/MinIO/R2 access"
echo -e "   ${YELLOW}Note: Use credentials from your S3 provider${NC}"
echo ""

echo -e "${GREEN}3. S3_SECRET_KEY${NC} (40 chars)"
echo -e "   Used for: S3/MinIO/R2 secret"
echo -e "   ${YELLOW}Note: Use credentials from your S3 provider${NC}"
echo ""

echo -e "${GREEN}4. GITHUB_WEBHOOK_SECRET${NC} (32 bytes / 64 hex chars)"
echo -e "   Used for: Verifying GitHub webhook signatures"
WEBHOOK_SECRET=$(generate_hex_secret 32)
echo -e "   ${YELLOW}GITHUB_WEBHOOK_SECRET=${WEBHOOK_SECRET}${NC}"
echo ""

echo -e "${GREEN}5. TweetNaCl Ed25519 Signing Key${NC} (32 bytes / 64 hex chars)"
echo -e "   Used for: Client-side encryption keypairs"
NACL_KEY=$(generate_nacl_keypair)
echo -e "   ${YELLOW}SIGNING_SECRET_KEY=${NACL_KEY}${NC}"
echo ""

echo -e "${GREEN}6. Session Encryption Key${NC} (32 bytes / 64 hex chars)"
echo -e "   Used for: End-to-end session encryption"
SESSION_KEY=$(generate_hex_secret 32)
echo -e "   ${YELLOW}SESSION_ENCRYPTION_KEY=${SESSION_KEY}${NC}"
echo ""

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Cloudflare Workers specific
echo -e "${GREEN}CLOUDFLARE WORKERS COMMANDS:${NC}"
echo ""
echo "# Set production secrets (run from happy-server-workers/):"
echo -e "${YELLOW}wrangler secret put HANDY_MASTER_SECRET --env prod${NC}"
echo -e "${YELLOW}wrangler secret put ELEVENLABS_API_KEY --env prod${NC}"
echo -e "${YELLOW}wrangler secret put GITHUB_WEBHOOK_SECRET --env prod${NC}"
echo ""
echo "# List all secrets:"
echo -e "${YELLOW}wrangler secret list --env prod${NC}"
echo ""

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${RED}⚠️  SECURITY REMINDERS:${NC}"
echo "   • Store these secrets in a password manager or secure vault"
echo "   • Use DIFFERENT secrets for each environment"
echo "   • Never commit secrets to version control"
echo "   • Rotate secrets periodically (see docs/SECRET-ROTATION.md)"
echo "   • For production, use Cloudflare Secrets (wrangler secret)"
echo ""

echo -e "${GREEN}✓ Secrets generated successfully for ${ENV_NAME}${NC}"
