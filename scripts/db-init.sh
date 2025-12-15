#!/bin/bash

##############################################################################
# D1 Database Initialization Script
#
# This script handles D1 database creation and migration for all environments.
# It supports both local development and remote (Cloudflare) databases.
#
# Usage:
#   ./scripts/db-init.sh [command] [options]
#
# Commands:
#   create    Create D1 database (remote only)
#   migrate   Apply migrations to database
#   status    Check database status
#   reset     Drop and recreate database (local only, DESTRUCTIVE)
#
# Options:
#   --env dev|prod    Target environment (default: dev)
#   --local           Use local database (wrangler dev)
#   --remote          Use remote Cloudflare database
#
# Examples:
#   ./scripts/db-init.sh create --env dev
#   ./scripts/db-init.sh migrate --local
#   ./scripts/db-init.sh migrate --env prod --remote
#   ./scripts/db-init.sh status --local
##############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MIGRATIONS_DIR="$PROJECT_ROOT/drizzle/migrations"

# Default values
COMMAND=""
ENVIRONMENT="dev"
USE_LOCAL=true
USE_REMOTE=false

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
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  create    Create D1 database (remote only)"
    echo "  migrate   Apply migrations to database"
    echo "  status    Check database status"
    echo "  reset     Drop and recreate database (local only, DESTRUCTIVE)"
    echo ""
    echo "Options:"
    echo "  --env dev|prod    Target environment (default: dev)"
    echo "  --local           Use local database (wrangler dev)"
    echo "  --remote          Use remote Cloudflare database"
    echo ""
    echo "Examples:"
    echo "  $0 create --env dev           # Create remote dev database"
    echo "  $0 migrate --local            # Apply migrations to local database"
    echo "  $0 migrate --env prod --remote  # Apply migrations to production"
    echo "  $0 status --local             # Check local database status"
}

get_database_name() {
    case "$ENVIRONMENT" in
        dev)
            echo "happy-dev"
            ;;
        prod)
            echo "happy-prod"
            ;;
        *)
            log_error "Unknown environment: $ENVIRONMENT"
            exit 1
            ;;
    esac
}

# Get migration files in order
get_migration_files() {
    if [ -d "$MIGRATIONS_DIR" ]; then
        find "$MIGRATIONS_DIR" -name "*.sql" -type f | sort
    else
        echo ""
    fi
}

##############################################################################
# Commands
##############################################################################

cmd_create() {
    local db_name=$(get_database_name)

    if [ "$USE_LOCAL" = true ]; then
        log_error "Cannot create local database explicitly. It's auto-created by wrangler dev."
        log_info "Run 'yarn dev' to start local development server with D1."
        exit 1
    fi

    log_info "Creating D1 database: $db_name"

    # Check if database already exists
    if wrangler d1 list 2>&1 | grep -q "$db_name"; then
        log_warn "Database '$db_name' already exists"
        DB_ID=$(wrangler d1 list 2>&1 | grep "$db_name" | awk '{print $1}' | head -1)
        log_info "Database ID: $DB_ID"
        log_info "Update wrangler.toml env.$ENVIRONMENT.d1_databases with this ID"
        return 0
    fi

    # Create the database
    wrangler d1 create "$db_name"

    # Get the new database ID
    DB_ID=$(wrangler d1 list 2>&1 | grep "$db_name" | awk '{print $1}' | head -1)

    log_success "Database '$db_name' created successfully!"
    echo ""
    log_info "Database ID: $DB_ID"
    echo ""
    log_warn "IMPORTANT: Update wrangler.toml with the database ID:"
    echo ""
    echo "  [[env.${ENVIRONMENT}.d1_databases]]"
    echo "  binding = \"DB\""
    echo "  database_name = \"$db_name\""
    echo "  database_id = \"$DB_ID\""
    echo ""
}

cmd_migrate() {
    local db_name=$(get_database_name)
    local migration_files=$(get_migration_files)

    if [ -z "$migration_files" ]; then
        log_warn "No migration files found in $MIGRATIONS_DIR"
        log_info "Run 'yarn db:generate' to generate migrations from schema"
        exit 0
    fi

    log_info "Applying migrations to $db_name..."

    # Build wrangler flags - always include --env for D1 binding resolution
    local wrangler_flags="--env $ENVIRONMENT"
    if [ "$USE_LOCAL" = true ]; then
        wrangler_flags="$wrangler_flags --local"
        log_info "Target: Local database (env: $ENVIRONMENT)"
    else
        wrangler_flags="$wrangler_flags --remote"
        log_info "Target: Remote ($ENVIRONMENT) database"
    fi

    # Ensure migrations tracking table exists
    log_info "Ensuring migration tracking table exists..."
    wrangler d1 execute "$db_name" $wrangler_flags --command="CREATE TABLE IF NOT EXISTS _drizzle_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT NOT NULL UNIQUE, created_at INTEGER DEFAULT (unixepoch()));" 2>&1 > /dev/null

    # Get list of already applied migrations
    local applied_migrations=$(wrangler d1 execute "$db_name" $wrangler_flags --command="SELECT hash FROM _drizzle_migrations;" 2>&1 | grep -oE '"hash": "[^"]+"' | sed 's/"hash": "//g' | sed 's/"//g' || echo "")

    # Apply each migration file in order (if not already applied)
    local count=0
    local skipped=0
    for migration_file in $migration_files; do
        local filename=$(basename "$migration_file")
        local hash="${filename%.sql}"

        # Check if already applied
        if echo "$applied_migrations" | grep -q "^${hash}$"; then
            log_info "Skipping (already applied): $filename"
            skipped=$((skipped + 1))
            continue
        fi

        log_info "Applying: $filename"

        if wrangler d1 execute "$db_name" $wrangler_flags --file="$migration_file" 2>&1; then
            # Record the migration as applied
            wrangler d1 execute "$db_name" $wrangler_flags --command="INSERT INTO _drizzle_migrations (hash) VALUES ('${hash}');" 2>&1 > /dev/null
            log_success "Applied: $filename"
            count=$((count + 1))
        else
            log_error "Failed to apply: $filename"
            exit 1
        fi
    done

    if [ $count -eq 0 ] && [ $skipped -gt 0 ]; then
        log_success "Database is up to date ($skipped migration(s) already applied)"
    else
        log_success "Applied $count new migration(s), skipped $skipped already applied"
    fi
}

cmd_status() {
    local db_name=$(get_database_name)

    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  D1 Database Status: $db_name"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    # Build wrangler flags - always include --env for D1 binding resolution
    local wrangler_flags="--env $ENVIRONMENT"
    if [ "$USE_LOCAL" = true ]; then
        wrangler_flags="$wrangler_flags --local"
        log_info "Checking: Local database (env: $ENVIRONMENT)"
    else
        wrangler_flags="$wrangler_flags --remote"
        log_info "Checking: Remote ($ENVIRONMENT) database"
    fi

    # List tables
    log_info "Tables in database:"
    echo ""
    if wrangler d1 execute "$db_name" $wrangler_flags --command="SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;" 2>&1; then
        echo ""
    else
        log_error "Failed to query database. Is it initialized?"
        exit 1
    fi

    # Count rows in key tables
    log_info "Row counts:"
    echo ""
    for table in Account Session Machine Artifact; do
        local count=$(wrangler d1 execute "$db_name" $wrangler_flags --command="SELECT COUNT(*) as count FROM $table;" 2>&1 | grep -oE '[0-9]+' | tail -1 || echo "0")
        echo "  $table: $count rows"
    done
    echo ""
}

cmd_reset() {
    local db_name=$(get_database_name)

    if [ "$USE_LOCAL" = false ]; then
        log_error "Reset is only allowed for local databases!"
        log_error "For remote databases, use wrangler d1 delete and recreate."
        exit 1
    fi

    log_warn "This will DELETE all data in the local $db_name database!"
    read -p "Are you sure? (yes/no): " confirm

    if [ "$confirm" != "yes" ]; then
        log_info "Aborted."
        exit 0
    fi

    # Remove local D1 database files
    local wrangler_dir="$PROJECT_ROOT/.wrangler"
    if [ -d "$wrangler_dir" ]; then
        log_info "Removing local D1 database..."
        rm -rf "$wrangler_dir/state/v3/d1"
        log_success "Local database removed"
    fi

    log_info "Re-applying migrations..."
    cmd_migrate

    log_success "Database reset complete!"
}

##############################################################################
# Parse Arguments
##############################################################################

# Get command (first argument)
if [ $# -gt 0 ]; then
    COMMAND="$1"
    shift
fi

# Parse remaining options
while [[ $# -gt 0 ]]; do
    case $1 in
        --env)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --local)
            USE_LOCAL=true
            USE_REMOTE=false
            shift
            ;;
        --remote)
            USE_LOCAL=false
            USE_REMOTE=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate environment
if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "prod" ]]; then
    log_error "Invalid environment: $ENVIRONMENT (must be 'dev' or 'prod')"
    exit 1
fi

# Change to project root
cd "$PROJECT_ROOT"

##############################################################################
# Execute Command
##############################################################################

case "$COMMAND" in
    create)
        cmd_create
        ;;
    migrate)
        cmd_migrate
        ;;
    status)
        cmd_status
        ;;
    reset)
        cmd_reset
        ;;
    "")
        log_error "No command specified"
        show_usage
        exit 1
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac
