ALTER TABLE `Session` ADD `stoppedAt` integer;--> statement-breakpoint
ALTER TABLE `Session` ADD `stoppedReason` text;--> statement-breakpoint
ALTER TABLE `Session` ADD `archivedAt` integer;--> statement-breakpoint
ALTER TABLE `Session` ADD `archiveReason` text;--> statement-breakpoint
ALTER TABLE `Session` ADD `archiveError` text;