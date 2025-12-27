#!/bin/bash

##############################################################################
# Post-Deployment Health Check Script (HAP-587)
#
# This script validates that a Cloudflare Workers deployment is healthy
# by calling the /health/messages endpoint and verifying the response.
#
# Usage:
#   ./scripts/post-deploy-health-check.sh [environment]
#
# Environments:
#   dev     Check development environment
#   prod    Check production environment
#   local   Check local development server (localhost:8787)
#
# Exit Codes:
#   0 - Health check passed
#   1 - Health check failed (unhealthy response)
#   2 - Health check timeout (> 5 seconds)
#   3 - Network error (cannot reach endpoint)
#   4 - Invalid arguments
#
# Examples:
#   ./scripts/post-deploy-health-check.sh dev
#   ./scripts/post-deploy-health-check.sh prod
#   WORKERS_URL=http://localhost:8787 ./scripts/post-deploy-health-check.sh local
##############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TIMEOUT_SECONDS=5
MAX_RETRIES=3
RETRY_DELAY_SECONDS=2

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    echo -e "${CYAN}Happy Server Workers - Post-Deployment Health Check${NC}"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "Usage: $0 [environment]"
    echo ""
    echo "Environments:"
    echo "  dev     Check development environment"
    echo "  prod    Check production environment"
    echo "  local   Check local development server"
    echo ""
    echo "Options:"
    echo "  --help, -h    Show this help message"
    echo "  --verbose     Show detailed response information"
    echo ""
    echo "Environment Variables:"
    echo "  WORKERS_URL   Override the API URL (useful for local testing)"
    echo ""
    echo "Examples:"
    echo "  $0 dev                          # Check dev deployment"
    echo "  $0 prod                         # Check prod deployment"
    echo "  WORKERS_URL=http://localhost:8787 $0 local"
    echo ""
}

get_api_url() {
    case "$1" in
        dev)
            echo "https://happy-api-dev.enflamemedia.com"
            ;;
        prod)
            echo "https://happy-api.enflamemedia.com"
            ;;
        local)
            echo "${WORKERS_URL:-http://localhost:8787}"
            ;;
        *)
            echo ""
            ;;
    esac
}

##############################################################################
# Health Check Function
##############################################################################

check_health() {
    local url="$1"
    local endpoint="${url}/health/messages"
    local attempt=1

    log_info "Checking health at: $endpoint"
    log_info "Timeout: ${TIMEOUT_SECONDS}s, Max retries: $MAX_RETRIES"
    echo ""

    while [ $attempt -le $MAX_RETRIES ]; do
        log_info "Attempt $attempt of $MAX_RETRIES..."

        # Make the request with timeout
        # -f: Fail silently on HTTP errors (allows us to capture the response)
        # -s: Silent mode
        # -S: Show errors
        # -w: Write out format (for HTTP code)
        # --max-time: Timeout in seconds
        local response
        local http_code
        local start_time
        local end_time
        local duration

        start_time=$(date +%s%3N 2>/dev/null || date +%s)000

        # Use a temporary file for the response body
        local tmp_file=$(mktemp)
        trap "rm -f $tmp_file" EXIT

        http_code=$(curl -s -S \
            --max-time "$TIMEOUT_SECONDS" \
            -w "%{http_code}" \
            -o "$tmp_file" \
            "$endpoint" 2>/dev/null) || {
            local exit_code=$?
            rm -f "$tmp_file"

            if [ $exit_code -eq 28 ]; then
                log_error "Request timed out after ${TIMEOUT_SECONDS}s"
                if [ $attempt -lt $MAX_RETRIES ]; then
                    log_info "Retrying in ${RETRY_DELAY_SECONDS}s..."
                    sleep $RETRY_DELAY_SECONDS
                    ((attempt++))
                    continue
                fi
                echo ""
                log_error "Health check failed: Timeout exceeded"
                return 2
            else
                log_error "Network error (curl exit code: $exit_code)"
                if [ $attempt -lt $MAX_RETRIES ]; then
                    log_info "Retrying in ${RETRY_DELAY_SECONDS}s..."
                    sleep $RETRY_DELAY_SECONDS
                    ((attempt++))
                    continue
                fi
                echo ""
                log_error "Health check failed: Cannot reach endpoint"
                return 3
            fi
        }

        response=$(cat "$tmp_file")
        rm -f "$tmp_file"

        end_time=$(date +%s%3N 2>/dev/null || date +%s)000
        duration=$((end_time - start_time))

        # Show verbose output if requested
        if [ "$VERBOSE" = true ]; then
            echo ""
            log_info "Response (HTTP $http_code):"
            echo "$response" | jq . 2>/dev/null || echo "$response"
            echo ""
        fi

        # Check HTTP status code
        if [ "$http_code" = "200" ]; then
            # Parse response for health status
            local status
            status=$(echo "$response" | jq -r '.status' 2>/dev/null)

            if [ "$status" = "healthy" ]; then
                echo ""
                log_success "Health check passed!"
                log_info "Response time: ${duration}ms"

                # Show checks summary
                local db_status schema_status
                db_status=$(echo "$response" | jq -r '.checks.database' 2>/dev/null)
                schema_status=$(echo "$response" | jq -r '.checks.schema' 2>/dev/null)

                echo ""
                echo "Checks:"
                echo -e "  Database: ${GREEN}$db_status${NC}"
                echo -e "  Schema:   ${GREEN}$schema_status${NC}"
                echo ""
                return 0
            else
                log_error "Health check returned unhealthy status"
                local error_msg
                error_msg=$(echo "$response" | jq -r '.error' 2>/dev/null)
                if [ -n "$error_msg" ] && [ "$error_msg" != "null" ]; then
                    log_error "Error: $error_msg"
                fi
                return 1
            fi
        elif [ "$http_code" = "503" ]; then
            # Service unhealthy
            log_error "Service is unhealthy (HTTP 503)"

            local error_msg
            error_msg=$(echo "$response" | jq -r '.error' 2>/dev/null)
            if [ -n "$error_msg" ] && [ "$error_msg" != "null" ]; then
                log_error "Error: $error_msg"
            fi

            # Show checks summary
            local db_status schema_status
            db_status=$(echo "$response" | jq -r '.checks.database' 2>/dev/null)
            schema_status=$(echo "$response" | jq -r '.checks.schema' 2>/dev/null)

            echo ""
            echo "Checks:"
            [ "$db_status" = "ok" ] && echo -e "  Database: ${GREEN}$db_status${NC}" || echo -e "  Database: ${RED}$db_status${NC}"
            [ "$schema_status" = "ok" ] && echo -e "  Schema:   ${GREEN}$schema_status${NC}" || echo -e "  Schema:   ${RED}$schema_status${NC}"
            echo ""

            return 1
        else
            log_error "Unexpected HTTP status: $http_code"
            if [ $attempt -lt $MAX_RETRIES ]; then
                log_info "Retrying in ${RETRY_DELAY_SECONDS}s..."
                sleep $RETRY_DELAY_SECONDS
                ((attempt++))
                continue
            fi
            return 1
        fi
    done

    log_error "Max retries exceeded"
    return 1
}

##############################################################################
# Parse Arguments
##############################################################################

ENVIRONMENT=""
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        dev|prod|local)
            ENVIRONMENT="$1"
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown argument: $1"
            show_usage
            exit 4
            ;;
    esac
done

# Validate environment
if [ -z "$ENVIRONMENT" ]; then
    log_error "No environment specified"
    show_usage
    exit 4
fi

API_URL=$(get_api_url "$ENVIRONMENT")
if [ -z "$API_URL" ]; then
    log_error "Invalid environment: $ENVIRONMENT"
    exit 4
fi

##############################################################################
# Execute Health Check
##############################################################################

echo ""
echo "═══════════════════════════════════════════════════════════"
echo -e "  ${CYAN}Post-Deployment Health Check${NC}"
echo "  Environment: $ENVIRONMENT"
echo "  API URL: $API_URL"
echo "═══════════════════════════════════════════════════════════"
echo ""

check_health "$API_URL"
exit_code=$?

echo "═══════════════════════════════════════════════════════════"
if [ $exit_code -eq 0 ]; then
    echo -e "  ${GREEN}DEPLOYMENT HEALTHY${NC}"
else
    echo -e "  ${RED}DEPLOYMENT UNHEALTHY${NC}"
fi
echo "═══════════════════════════════════════════════════════════"
echo ""

exit $exit_code
