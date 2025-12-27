#!/bin/bash

##############################################################################
# Cloudflare Workers Deployment Script
#
# This script handles deployment to Cloudflare Workers for all environments.
#
# Usage:
#   ./scripts/deploy.sh [environment]
#
# Environments:
#   dev     Deploy to development environment
#   prod    Deploy to production environment
#
# Examples:
#   ./scripts/deploy.sh dev           # Deploy to development
#   ./scripts/deploy.sh prod          # Deploy to production
#   yarn deploy:dev                   # Via npm script
#   yarn deploy:prod                  # Via npm script
##############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

##############################################################################
# Helper Functions
##############################################################################

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

show_usage() {
    echo ""
    echo -e "${CYAN}Happy Server Workers - Deployment${NC}"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "Usage: $0 [environment]"
    echo ""
    echo "Environments:"
    echo "  dev     Deploy to development environment"
    echo "  prod    Deploy to production environment"
    echo ""
    echo "Options:"
    echo "  --help, -h    Show this help message"
    echo "  --dry-run     Show what would be deployed without deploying"
    echo ""
    echo "Examples:"
    echo "  $0 dev              # Deploy to development"
    echo "  $0 prod             # Deploy to production"
    echo "  $0 dev --dry-run    # Dry run for development"
    echo ""
}

get_worker_name() {
    case "$1" in
        dev)
            echo "happy-server-workers-dev"
            ;;
        prod)
            echo "happy-server-workers-prod"
            ;;
        *)
            echo ""
            ;;
    esac
}

##############################################################################
# Pre-deployment Checks
##############################################################################

check_prerequisites() {
    local env="$1"

    log_info "Running pre-deployment checks..."

    # Check if wrangler is available
    if ! command -v wrangler &> /dev/null; then
        log_error "wrangler CLI not found. Install with: npm install -g wrangler"
        exit 1
    fi

    # Check if logged in to Cloudflare
    if ! wrangler whoami &> /dev/null; then
        log_error "Not logged in to Cloudflare. Run: wrangler login"
        exit 1
    fi

    # Run type checking
    log_info "Running type check..."
    if ! yarn typecheck; then
        log_error "Type check failed. Fix errors before deploying."
        exit 1
    fi

    log_success "Pre-deployment checks passed"
}

##############################################################################
# Deployment
##############################################################################

deploy() {
    local env="$1"
    local dry_run="$2"
    local worker_name=$(get_worker_name "$env")

    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo -e "  ${CYAN}Deploying to: $env${NC}"
    echo "  Worker: $worker_name"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    if [ "$dry_run" = true ]; then
        log_warn "DRY RUN: Would deploy to $env environment"
        log_info "Command that would run: wrangler deploy --env $env"
        return 0
    fi

    # Production deployment confirmation
    if [ "$env" = "prod" ]; then
        echo ""
        log_warn "You are about to deploy to PRODUCTION!"
        echo ""
        read -p "Type 'yes' to confirm: " confirm
        if [ "$confirm" != "yes" ]; then
            log_info "Deployment cancelled."
            exit 0
        fi
        echo ""
    fi

    log_info "Starting deployment..."

    # Run wrangler deploy
    if wrangler deploy --env "$env"; then
        echo ""
        log_success "Deployment to $env completed successfully!"
        echo ""

        # Show worker URL
        case "$env" in
            dev)
                log_info "Worker URL: https://happy-server-workers-dev.<your-subdomain>.workers.dev"
                ;;
            prod)
                log_info "Worker URL: https://happy-server-workers-prod.<your-subdomain>.workers.dev"
                log_info "Custom domain: Configure in Cloudflare dashboard"
                ;;
        esac

        # Run post-deployment health check (HAP-587)
        echo ""
        log_info "Running post-deployment health check..."
        if [ -x "$SCRIPT_DIR/post-deploy-health-check.sh" ]; then
            if "$SCRIPT_DIR/post-deploy-health-check.sh" "$env"; then
                log_success "Post-deployment health check passed"
            else
                log_warn "Post-deployment health check failed - deployment may be unhealthy"
                log_warn "Run: ./scripts/post-deploy-health-check.sh $env --verbose"
                # Don't exit with error - let user decide if rollback is needed
            fi
        else
            log_warn "Health check script not found or not executable"
        fi
    else
        log_error "Deployment failed!"
        exit 1
    fi
}

##############################################################################
# Parse Arguments
##############################################################################

ENVIRONMENT=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        dev|prod)
            ENVIRONMENT="$1"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown argument: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate environment
if [ -z "$ENVIRONMENT" ]; then
    log_error "No environment specified"
    show_usage
    exit 1
fi

if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "prod" ]]; then
    log_error "Invalid environment: $ENVIRONMENT (must be 'dev' or 'prod')"
    exit 1
fi

# Change to project root
cd "$PROJECT_ROOT"

##############################################################################
# Execute Deployment
##############################################################################

check_prerequisites "$ENVIRONMENT"
deploy "$ENVIRONMENT" "$DRY_RUN"
