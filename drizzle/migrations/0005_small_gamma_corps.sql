ALTER TABLE `Account` ADD `profileVisibility` text DEFAULT 'public' NOT NULL;--> statement-breakpoint
ALTER TABLE `Account` ADD `friendRequestPermission` text DEFAULT 'anyone' NOT NULL;