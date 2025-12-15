PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_UserRelationship` (
	`fromUserId` text NOT NULL,
	`toUserId` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`createdAt` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updatedAt` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`acceptedAt` integer,
	`lastNotifiedAt` integer,
	PRIMARY KEY(`fromUserId`, `toUserId`),
	CONSTRAINT "UserRelationship_status_check" CHECK(status IN ('none', 'requested', 'pending', 'friend', 'rejected'))
);
--> statement-breakpoint
INSERT INTO `__new_UserRelationship`("fromUserId", "toUserId", "status", "createdAt", "updatedAt", "acceptedAt", "lastNotifiedAt") SELECT "fromUserId", "toUserId", "status", "createdAt", "updatedAt", "acceptedAt", "lastNotifiedAt" FROM `UserRelationship`;--> statement-breakpoint
DROP TABLE `UserRelationship`;--> statement-breakpoint
ALTER TABLE `__new_UserRelationship` RENAME TO `UserRelationship`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `UserRelationship_toUserId_status_idx` ON `UserRelationship` (`toUserId`,`status`);--> statement-breakpoint
CREATE INDEX `UserRelationship_fromUserId_status_idx` ON `UserRelationship` (`fromUserId`,`status`);