/**
 * Error utilities for standardized error management in happy-server-workers.
 *
 * This module re-exports the shared AppError from @happy/errors for consistent
 * error handling across the Cloudflare Workers project.
 *
 * @module utils/errors
 *
 * @example Basic usage
 * ```typescript
 * import { AppError, ErrorCodes } from '@/utils/errors';
 *
 * // Throw a standardized error
 * throw new AppError(ErrorCodes.NOT_FOUND, 'Session not found');
 *
 * // Throw with retry capability
 * throw new AppError(ErrorCodes.FETCH_FAILED, 'Network error', { canTryAgain: true });
 *
 * // Wrap an unknown error safely
 * try {
 *   await dbOperation();
 * } catch (error) {
 *   throw AppError.fromUnknown(
 *     ErrorCodes.INTERNAL_ERROR,
 *     'Database operation failed',
 *     error
 *   );
 * }
 * ```
 */

// Re-export AppError, ErrorCodes, and types from shared package
export { AppError, ErrorCodes } from '@happy/errors';
export type { AppErrorOptions, AppErrorJSON, ErrorCode } from '@happy/errors';
