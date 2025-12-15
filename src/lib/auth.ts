import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';

/**
 * Token extras type - additional data embedded in tokens
 */
export type TokenExtras = Record<string, unknown>;

/**
 * Token cache entry interface
 */
interface TokenCacheEntry {
    userId: string;
    extras?: TokenExtras;
    cachedAt: number;
}

/**
 * Auth state interface for persistent and ephemeral token management
 */
interface AuthState {
    persistentKey: CryptoKey;
    persistentPublicKey: string;
    ephemeralKey: CryptoKey;
    ephemeralPublicKey: string;
    ephemeralTtl: number;
}

/**
 * Authentication module for Cloudflare Workers using jose
 *
 * Replaces privacy-kit (which is incompatible with Workers due to
 * createRequire(import.meta.url) usage) with jose, which explicitly
 * supports Cloudflare Workers and Web Crypto API.
 *
 * @remarks
 * Token format is designed to be compatible with happy-server's privacy-kit tokens:
 * - Service identifier in issuer claim
 * - User ID in 'user' claim
 * - Optional extras in 'extras' claim
 *
 * Key differences from privacy-kit version:
 * - Uses jose SignJWT/jwtVerify instead of privacy-kit generators
 * - Derives Ed25519 keys from seed using Web Crypto API (HKDF)
 * - Persistent tokens have no expiration (match privacy-kit behavior)
 * - Ephemeral tokens have configurable TTL
 *
 * @see HAP-264 for implementation details
 * @see HAP-26 for discovery of privacy-kit incompatibility
 */

let authState: AuthState | null = null;
const tokenCache = new Map<string, TokenCacheEntry>();

// Service identifier for token issuer (matches happy-server)
const SERVICE_NAME = 'handy';
const EPHEMERAL_SERVICE_NAME = 'github-happy';
const DEFAULT_EPHEMERAL_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Ed25519 PKCS8 prefix for wrapping a 32-byte private key seed
 *
 * This is the ASN.1 DER encoding for:
 * SEQUENCE {
 *   INTEGER 0 (version)
 *   SEQUENCE { OID 1.3.101.112 (Ed25519) }
 *   OCTET STRING containing OCTET STRING of 32-byte seed
 * }
 *
 * The prefix is 16 bytes, followed by the 32-byte seed = 48 bytes total
 */
const ED25519_PKCS8_PREFIX = new Uint8Array([
    0x30, 0x2e, // SEQUENCE, 46 bytes
    0x02, 0x01, 0x00, // INTEGER 0 (version)
    0x30, 0x05, // SEQUENCE, 5 bytes (AlgorithmIdentifier)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22, // OCTET STRING, 34 bytes
    0x04, 0x20, // OCTET STRING, 32 bytes (the actual key seed)
]);

/**
 * Wrap a 32-byte Ed25519 seed in PKCS8 format
 *
 * Cloudflare Workers doesn't support raw import of Ed25519 private keys,
 * but does support PKCS8 format. This function wraps the seed in the
 * correct ASN.1 DER structure.
 *
 * @param seed - 32-byte Ed25519 private key seed
 * @returns PKCS8-formatted key (48 bytes)
 */
function wrapEd25519SeedAsPkcs8(seed: Uint8Array): Uint8Array {
    if (seed.length !== 32) {
        throw new Error(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
    }
    const pkcs8 = new Uint8Array(48);
    pkcs8.set(ED25519_PKCS8_PREFIX);
    pkcs8.set(seed, 16);
    return pkcs8;
}

/**
 * Derive a deterministic Ed25519 key pair from a seed string
 *
 * Uses HKDF to derive key material from the seed, then imports as Ed25519 key.
 * This ensures the same seed always produces the same key pair.
 *
 * Note: Cloudflare Workers doesn't support raw import of Ed25519 private keys,
 * so we wrap the derived seed in PKCS8 format before importing.
 *
 * @param seed - The master secret seed
 * @param salt - Salt for key derivation (uses service name for domain separation)
 * @returns Promise resolving to CryptoKeyPair
 */
async function deriveKeyPair(seed: string, salt: string): Promise<CryptoKeyPair> {
    // Import seed as raw key material for HKDF
    const seedBytes = new TextEncoder().encode(seed);
    const baseKey = await crypto.subtle.importKey('raw', seedBytes, 'HKDF', false, [
        'deriveBits',
    ]);

    // Derive 32 bytes for Ed25519 seed using HKDF
    const saltBytes = new TextEncoder().encode(salt);
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: saltBytes,
            info: new TextEncoder().encode('ed25519-key'),
        },
        baseKey,
        256
    );

    // Wrap the 32-byte seed in PKCS8 format
    // Cloudflare Workers doesn't support raw import of Ed25519 private keys
    const pkcs8Key = wrapEd25519SeedAsPkcs8(new Uint8Array(derivedBits));

    // Import as Ed25519 private key using PKCS8 format
    const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        pkcs8Key,
        { name: 'Ed25519' },
        true, // extractable - needed to derive public key
        ['sign']
    );

    // Export and re-import as public key
    const publicKeyJwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
    // Remove private key component to get public key only
    delete publicKeyJwk.d;
    publicKeyJwk.key_ops = ['verify'];

    const publicKey = await crypto.subtle.importKey(
        'jwk',
        publicKeyJwk,
        { name: 'Ed25519' },
        true,
        ['verify']
    );

    return { privateKey, publicKey };
}

/**
 * Export public key as base64url-encoded string for sharing
 *
 * @param publicKey - CryptoKey to export
 * @returns Base64url-encoded public key (JWK 'x' parameter)
 */
async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
    const jwk = (await crypto.subtle.exportKey('jwk', publicKey)) as JsonWebKey;
    return jwk.x ?? '';
}

/**
 * Initialize the auth module with master secret
 *
 * Must be called once during Worker initialization with the HANDY_MASTER_SECRET.
 * Derives deterministic Ed25519 keys from the seed for persistent token generation.
 *
 * @param masterSecret - The master secret for token generation (from env.HANDY_MASTER_SECRET)
 * @param ephemeralTtl - TTL for ephemeral tokens in milliseconds (default: 5 minutes)
 * @returns Promise that resolves when initialization is complete
 *
 * @example
 * ```typescript
 * // In your worker handler
 * export default {
 *     async fetch(request: Request, env: Env) {
 *         await initAuth(env.HANDY_MASTER_SECRET);
 *         // ... rest of your handler
 *     }
 * }
 * ```
 */
export async function initAuth(
    masterSecret: string,
    ephemeralTtl: number = DEFAULT_EPHEMERAL_TTL
): Promise<void> {
    if (authState) {
        console.log('[Auth] Already initialized, public key:', authState.persistentPublicKey.substring(0, 10) + '...');
        return; // Already initialized
    }

    console.log('[Auth] Initializing with secret length:', masterSecret.length);

    // Derive persistent key pair for main authentication tokens
    const persistentKeyPair = await deriveKeyPair(masterSecret, SERVICE_NAME);
    const persistentPublicKey = await exportPublicKey(persistentKeyPair.publicKey);

    console.log('[Auth] Derived persistent public key:', persistentPublicKey.substring(0, 10) + '...');

    // Derive ephemeral key pair for short-lived tokens (GitHub OAuth, etc.)
    const ephemeralKeyPair = await deriveKeyPair(masterSecret, EPHEMERAL_SERVICE_NAME);
    const ephemeralPublicKey = await exportPublicKey(ephemeralKeyPair.publicKey);

    authState = {
        persistentKey: persistentKeyPair.privateKey,
        persistentPublicKey,
        ephemeralKey: ephemeralKeyPair.privateKey,
        ephemeralPublicKey,
        ephemeralTtl,
    };

    console.log('[Auth] Initialization complete');
}

/**
 * Get the public key for persistent tokens
 *
 * Useful for sharing with other services that need to verify tokens.
 *
 * @returns Base64url-encoded public key string
 * @throws Error if auth module is not initialized
 */
export function getPublicKey(): string {
    if (!authState) {
        throw new Error('Auth module not initialized - call initAuth() first');
    }
    return authState.persistentPublicKey;
}

/**
 * Get the public key for ephemeral tokens
 *
 * @returns Base64url-encoded public key string
 * @throws Error if auth module is not initialized
 */
export function getEphemeralPublicKey(): string {
    if (!authState) {
        throw new Error('Auth module not initialized - call initAuth() first');
    }
    return authState.ephemeralPublicKey;
}

/**
 * Create a new authentication token for a user
 *
 * Generates a persistent JWT signed with Ed25519 that can be verified later.
 * Tokens are automatically cached for fast verification.
 *
 * @param userId - The user ID to embed in the token
 * @param extras - Optional additional data to embed in the token (e.g., session ID)
 * @returns Promise resolving to the generated token string
 * @throws Error if auth module is not initialized
 *
 * @example
 * ```typescript
 * const token = await createToken('user_abc123', { session: 'session_xyz' });
 * // Returns: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."
 * ```
 */
export async function createToken(userId: string, extras?: TokenExtras): Promise<string> {
    if (!authState) {
        throw new Error('Auth module not initialized - call initAuth() first');
    }

    console.log('[Auth] Creating token for user:', userId, 'with public key:', authState.persistentPublicKey.substring(0, 10) + '...');

    const builder = new SignJWT({
        user: userId,
        ...(extras && { extras }),
    })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
        .setIssuer(SERVICE_NAME)
        .setIssuedAt();

    // Persistent tokens don't expire (match privacy-kit behavior)
    const token = await builder.sign(authState.persistentKey);

    console.log('[Auth] Token created, first 20 chars:', token.substring(0, 20) + '...');

    // Cache the token immediately for fast verification
    tokenCache.set(token, {
        userId,
        extras,
        cachedAt: Date.now(),
    });

    return token;
}

/**
 * Verify an authentication token
 *
 * Checks if a token is valid and returns the embedded user ID and extras.
 * Uses in-memory cache for fast verification of recently seen tokens.
 *
 * @param token - The token string to verify
 * @returns Promise resolving to user data if valid, null if invalid
 * @throws Error if auth module is not initialized
 *
 * @example
 * ```typescript
 * const verified = await verifyToken(token);
 * if (verified) {
 *     console.log(`User ID: ${verified.userId}`);
 *     if (verified.extras?.session) {
 *         console.log(`Session: ${verified.extras.session}`);
 *     }
 * } else {
 *     console.log('Invalid token');
 * }
 * ```
 */
export async function verifyToken(
    token: string
): Promise<{ userId: string; extras?: TokenExtras } | null> {
    console.log('[Auth] Verifying token, first 20 chars:', token.substring(0, 20) + '...');

    // Check cache first for fast path
    const cached = tokenCache.get(token);
    if (cached) {
        console.log('[Auth] Token found in cache for user:', cached.userId);
        return {
            userId: cached.userId,
            extras: cached.extras,
        };
    }

    console.log('[Auth] Token not in cache, verifying cryptographically...');

    // Cache miss - verify token cryptographically
    if (!authState) {
        console.error('[Auth] ERROR: Auth module not initialized!');
        throw new Error('Auth module not initialized - call initAuth() first');
    }

    console.log('[Auth] Using public key:', authState.persistentPublicKey.substring(0, 10) + '...');

    try {
        // Derive public key from private key for verification
        const publicKeyJwk = (await crypto.subtle.exportKey(
            'jwk',
            authState.persistentKey
        )) as JsonWebKey;
        delete publicKeyJwk.d;
        publicKeyJwk.key_ops = ['verify'];

        const publicKey = await crypto.subtle.importKey(
            'jwk',
            publicKeyJwk,
            { name: 'Ed25519' },
            false,
            ['verify']
        );

        const { payload } = await jwtVerify(token, publicKey, {
            issuer: SERVICE_NAME,
        });

        const userId = payload.user as string;
        const extras = payload.extras as TokenExtras | undefined;

        console.log('[Auth] Token verified successfully for user:', userId);

        // Cache the result for future fast verification
        tokenCache.set(token, {
            userId,
            extras,
            cachedAt: Date.now(),
        });

        return { userId, extras };
    } catch (error) {
        // Handle jose-specific errors gracefully
        if (
            error instanceof joseErrors.JWTExpired ||
            error instanceof joseErrors.JWTInvalid ||
            error instanceof joseErrors.JWSSignatureVerificationFailed ||
            error instanceof joseErrors.JWTClaimValidationFailed
        ) {
            console.log('[Auth] Token verification failed:', error instanceof Error ? error.message : String(error));
            return null;
        }
        console.error('[Auth] Token verification error:', error);
        return null;
    }
}

/**
 * Create an ephemeral token with TTL (for OAuth flows like GitHub)
 *
 * Ephemeral tokens automatically expire after the configured TTL.
 * Use these for temporary authorization flows.
 *
 * @param userId - The user ID to embed in the token
 * @param purpose - Purpose identifier (e.g., 'github-oauth')
 * @returns Promise resolving to the generated token string
 * @throws Error if auth module is not initialized
 *
 * @example
 * ```typescript
 * const token = await createEphemeralToken('user_123', 'github-oauth');
 * // Token expires after 5 minutes (default TTL)
 * ```
 */
export async function createEphemeralToken(userId: string, purpose: string): Promise<string> {
    if (!authState) {
        throw new Error('Auth module not initialized - call initAuth() first');
    }

    const expirationTime = Math.floor((Date.now() + authState.ephemeralTtl) / 1000);

    const token = await new SignJWT({
        user: userId,
        purpose,
    })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
        .setIssuer(EPHEMERAL_SERVICE_NAME)
        .setIssuedAt()
        .setExpirationTime(expirationTime)
        .sign(authState.ephemeralKey);

    return token;
}

/**
 * Verify an ephemeral token (for OAuth flows)
 *
 * Ephemeral tokens are validated including expiration check.
 * Returns null if the token is expired or invalid.
 *
 * @param token - The token string to verify
 * @returns Promise resolving to user data if valid, null if invalid or expired
 * @throws Error if auth module is not initialized
 */
export async function verifyEphemeralToken(
    token: string
): Promise<{ userId: string; purpose?: string } | null> {
    if (!authState) {
        throw new Error('Auth module not initialized - call initAuth() first');
    }

    try {
        // Derive public key from private key for verification
        const publicKeyJwk = (await crypto.subtle.exportKey(
            'jwk',
            authState.ephemeralKey
        )) as JsonWebKey;
        delete publicKeyJwk.d;
        publicKeyJwk.key_ops = ['verify'];

        const publicKey = await crypto.subtle.importKey(
            'jwk',
            publicKeyJwk,
            { name: 'Ed25519' },
            false,
            ['verify']
        );

        const { payload } = await jwtVerify(token, publicKey, {
            issuer: EPHEMERAL_SERVICE_NAME,
        });

        return {
            userId: payload.user as string,
            purpose: payload.purpose as string | undefined,
        };
    } catch (error) {
        // Expired or invalid tokens return null
        if (
            error instanceof joseErrors.JWTExpired ||
            error instanceof joseErrors.JWTInvalid ||
            error instanceof joseErrors.JWSSignatureVerificationFailed ||
            error instanceof joseErrors.JWTClaimValidationFailed
        ) {
            return null;
        }
        console.error('Ephemeral token verification failed:', error);
        return null;
    }
}

/**
 * Invalidate all tokens for a specific user
 *
 * Removes all cached tokens for a user. Useful when a user logs out or
 * their account is compromised and you need to force re-authentication.
 *
 * Note: This only clears the cache in this Worker instance. Tokens remain
 * cryptographically valid. For true revocation, implement a token blacklist.
 *
 * @param userId - The user ID whose tokens should be invalidated
 *
 * @example
 * ```typescript
 * // User logs out or changes password
 * invalidateUserTokens('user_abc123');
 * ```
 */
export function invalidateUserTokens(userId: string): void {
    for (const [token, entry] of tokenCache.entries()) {
        if (entry.userId === userId) {
            tokenCache.delete(token);
        }
    }
}

/**
 * Invalidate a specific token
 *
 * Removes a token from the cache, forcing re-verification on next use.
 *
 * @param token - The token string to invalidate
 */
export function invalidateToken(token: string): void {
    tokenCache.delete(token);
}

/**
 * Get token cache statistics
 *
 * Returns information about the current cache state for monitoring and debugging.
 *
 * @returns Object with cache size and oldest entry timestamp
 */
export function getCacheStats(): { size: number; oldestEntry: number | null } {
    if (tokenCache.size === 0) {
        return { size: 0, oldestEntry: null };
    }

    let oldest = Date.now();
    for (const entry of tokenCache.values()) {
        if (entry.cachedAt < oldest) {
            oldest = entry.cachedAt;
        }
    }

    return {
        size: tokenCache.size,
        oldestEntry: oldest,
    };
}

/**
 * Reset auth state (primarily for testing)
 *
 * Clears all cached tokens and resets the auth state.
 * This should generally not be used in production.
 */
export function resetAuth(): void {
    authState = null;
    tokenCache.clear();
}
