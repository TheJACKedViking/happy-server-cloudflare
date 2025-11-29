/**
 * Environment variable validation
 *
 * Validates required environment variables at startup and provides
 * clear error messages for missing configuration.
 */

interface EnvConfig {
    /** Variable name */
    name: string;
    /** Whether the variable is required for startup */
    required: boolean;
    /** Description shown in error messages */
    description: string;
    /** Feature group (for optional variables that are required together) */
    group?: string;
}

const envConfig: EnvConfig[] = [
    // Database
    { name: 'DATABASE_URL', required: true, description: 'PostgreSQL connection string (used by Prisma)' },

    // Redis
    { name: 'REDIS_URL', required: true, description: 'Redis connection URL for pub/sub and caching' },

    // S3 Storage
    { name: 'S3_HOST', required: true, description: 'S3-compatible storage hostname' },
    { name: 'S3_ACCESS_KEY', required: true, description: 'S3 access key' },
    { name: 'S3_SECRET_KEY', required: true, description: 'S3 secret key' },
    { name: 'S3_BUCKET', required: true, description: 'S3 bucket name' },
    { name: 'S3_PUBLIC_URL', required: true, description: 'Public URL for S3 assets' },
    { name: 'S3_PORT', required: false, description: 'S3 port (optional, defaults to standard ports)' },
    { name: 'S3_USE_SSL', required: false, description: 'Use SSL for S3 connections (default: true)' },

    // Security
    { name: 'HANDY_MASTER_SECRET', required: true, description: 'Master secret for authentication and encryption' },

    // Server
    { name: 'PORT', required: false, description: 'HTTP server port (default: 3005)' },
    { name: 'NODE_ENV', required: false, description: 'Node environment (development/production)' },

    // Monitoring
    { name: 'METRICS_ENABLED', required: false, description: 'Enable Prometheus metrics (default: true)' },
    { name: 'METRICS_PORT', required: false, description: 'Prometheus metrics port (default: 9090)' },

    // GitHub Integration (optional feature)
    { name: 'GITHUB_APP_ID', required: false, description: 'GitHub App ID', group: 'github' },
    { name: 'GITHUB_PRIVATE_KEY', required: false, description: 'GitHub App private key', group: 'github' },
    { name: 'GITHUB_CLIENT_ID', required: false, description: 'GitHub OAuth client ID', group: 'github' },
    { name: 'GITHUB_CLIENT_SECRET', required: false, description: 'GitHub OAuth client secret', group: 'github' },
    { name: 'GITHUB_REDIRECT_URI', required: false, description: 'GitHub OAuth redirect URI', group: 'github' },
    { name: 'GITHUB_WEBHOOK_SECRET', required: false, description: 'GitHub webhook secret', group: 'github' },
    { name: 'GITHUB_REDIRECT_URL', required: false, description: 'GitHub OAuth redirect URL (alternative)', group: 'github' },

    // Voice Integration (optional feature)
    { name: 'ELEVENLABS_API_KEY', required: false, description: 'ElevenLabs API key for voice synthesis', group: 'voice' },

    // Debug
    { name: 'DANGEROUSLY_LOG_TO_SERVER_FOR_AI_AUTO_DEBUGGING', required: false, description: 'Enable debug logging endpoint (dangerous in production)' },
];

interface ValidationResult {
    valid: boolean;
    missingRequired: string[];
    missingOptional: string[];
    partialGroups: { group: string; present: string[]; missing: string[] }[];
}

/**
 * Validates environment variables and returns detailed results
 */
export function checkEnv(): ValidationResult {
    const missingRequired: string[] = [];
    const missingOptional: string[] = [];
    const groupStatus: Record<string, { present: string[]; missing: string[] }> = {};

    for (const config of envConfig) {
        const value = process.env[config.name];
        const isSet = value !== undefined && value !== '';

        if (config.required && !isSet) {
            missingRequired.push(config.name);
        } else if (!config.required && !isSet) {
            missingOptional.push(config.name);
        }

        // Track group status
        if (config.group) {
            if (!groupStatus[config.group]) {
                groupStatus[config.group] = { present: [], missing: [] };
            }
            if (isSet) {
                groupStatus[config.group].present.push(config.name);
            } else {
                groupStatus[config.group].missing.push(config.name);
            }
        }
    }

    // Find partially configured groups
    const partialGroups = Object.entries(groupStatus)
        .filter(([, status]) => status.present.length > 0 && status.missing.length > 0)
        .map(([group, status]) => ({ group, ...status }));

    return {
        valid: missingRequired.length === 0,
        missingRequired,
        missingOptional,
        partialGroups,
    };
}

/**
 * Validates required environment variables at startup.
 * Exits the process with error code 1 if required variables are missing.
 */
export function validateEnv(): void {
    const result = checkEnv();

    if (!result.valid) {
        console.error('\n========================================');
        console.error('  MISSING REQUIRED ENVIRONMENT VARIABLES');
        console.error('========================================\n');

        for (const name of result.missingRequired) {
            const config = envConfig.find(c => c.name === name);
            console.error(`  - ${name}`);
            if (config) {
                console.error(`    ${config.description}`);
            }
            console.error('');
        }

        console.error('Please set these variables in your .env file or environment.\n');
        console.error('See .env.example for a complete list of available variables.\n');

        process.exit(1);
    }

    // Warn about partially configured feature groups
    for (const partial of result.partialGroups) {
        console.warn(`\n[WARN] ${partial.group.toUpperCase()} feature is partially configured:`);
        console.warn(`  Present: ${partial.present.join(', ')}`);
        console.warn(`  Missing: ${partial.missing.join(', ')}`);
        console.warn(`  This feature will be disabled until all variables are set.\n`);
    }
}

/**
 * Gets a typed environment variable with optional default
 */
export function getEnv(name: string, defaultValue?: string): string | undefined {
    return process.env[name] ?? defaultValue;
}

/**
 * Gets a required environment variable or throws
 */
export function requireEnv(name: string): string {
    const value = process.env[name];
    if (value === undefined || value === '') {
        throw new Error(`Required environment variable ${name} is not set`);
    }
    return value;
}
