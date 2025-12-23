/**
 * Error utilities for standardized error management in happy-server.
 *
 * This module re-exports the shared AppError from @happy/errors and provides
 * server-specific error codes.
 *
 * @module utils/errors
 *
 * @example Basic usage
 * ```typescript
 * import { AppError, ErrorCodes } from '@/utils/errors';
 *
 * // Throw a standardized error
 * throw new AppError(ErrorCodes.INVALID_INPUT, 'Invalid cursor format');
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

// ErrorCodes and ErrorCode type are now imported from @happy/errors above.
// This provides unified error codes across all Happy projects (CLI, App, Server).
