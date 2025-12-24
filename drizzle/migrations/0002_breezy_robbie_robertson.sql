CREATE TABLE `RevokedToken` (
	`id` text PRIMARY KEY NOT NULL,
	`tokenHash` text NOT NULL,
	`userId` text NOT NULL,
	`reason` text,
	`revokedAt` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`expiresAt` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `RevokedToken_tokenHash_key` ON `RevokedToken` (`tokenHash`);--> statement-breakpoint
CREATE INDEX `RevokedToken_userId_idx` ON `RevokedToken` (`userId`);--> statement-breakpoint
CREATE INDEX `RevokedToken_expiresAt_idx` ON `RevokedToken` (`expiresAt`);