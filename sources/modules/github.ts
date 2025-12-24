import { App } from "octokit";
import { Webhooks } from "@octokit/webhooks";
import type { EmitterWebhookEvent } from "@octokit/webhooks";
import { log } from "@/utils/log";
import { db } from "@/storage/db";

let app: App | null = null;
let webhooks: Webhooks | null = null;

export async function initGitHub() {
    if (
        process.env.GITHUB_APP_ID &&
        process.env.GITHUB_PRIVATE_KEY &&
        process.env.GITHUB_CLIENT_ID &&
        process.env.GITHUB_CLIENT_SECRET &&
        process.env.GITHUB_REDIRECT_URI &&
        process.env.GITHUB_WEBHOOK_SECRET
    ) {
        app = new App({
            appId: process.env.GITHUB_APP_ID,
            privateKey: process.env.GITHUB_PRIVATE_KEY,
            webhooks: {
                secret: process.env.GITHUB_WEBHOOK_SECRET
            }
        });
        
        // Initialize standalone webhooks handler for type-safe event processing
        webhooks = new Webhooks({
            secret: process.env.GITHUB_WEBHOOK_SECRET
        });
        
        // Register type-safe event handlers
        registerWebhookHandlers();
    }
}

/**
 * Registers type-safe webhook event handlers.
 *
 * Handles GitHub App installation events, repository events, and general activity.
 * All events are logged for debugging; installation events trigger state updates.
 */
function registerWebhookHandlers() {
    if (!webhooks) return;

    // Installation events - App installed/uninstalled/suspended
    webhooks.on("installation", async ({ id, name, payload }: EmitterWebhookEvent<"installation">) => {
        const { action, installation, sender, repositories } = payload;
        const account = installation.account;
        const accountLogin = account && 'login' in account ? account.login : account?.name ?? 'unknown';
        const accountType = account && 'type' in account ? account.type : 'Enterprise';
        const installationId = installation.id.toString();

        log({ module: 'github-webhook', event: 'installation' },
            `GitHub App ${action}: installation ${installation.id} by ${sender.login}`, {
                deliveryId: id,
                action,
                installationId: installation.id,
                accountLogin,
                accountType,
                repositoryCount: repositories?.length ?? 0
            });

        // Persist installation state to database
        if (action === 'created') {
            await db.githubInstallation.upsert({
                where: { id: installationId },
                update: {
                    accountLogin,
                    accountType,
                    status: 'active',
                    repositoryCount: repositories?.length ?? 0
                },
                create: {
                    id: installationId,
                    accountLogin,
                    accountType,
                    status: 'active',
                    repositoryCount: repositories?.length ?? 0
                }
            });
        } else if (action === 'deleted') {
            await db.githubInstallation.update({
                where: { id: installationId },
                data: { status: 'deleted' }
            }).catch(() => {
                // Installation may not exist if webhook arrived before creation was processed
            });
        } else if (action === 'suspend') {
            await db.githubInstallation.update({
                where: { id: installationId },
                data: { status: 'suspended' }
            }).catch(() => {});
        } else if (action === 'unsuspend') {
            await db.githubInstallation.update({
                where: { id: installationId },
                data: { status: 'active' }
            }).catch(() => {});
        }
    });

    // Installation repositories events - Repos added/removed from installation
    webhooks.on("installation_repositories", async ({ id, name, payload }: EmitterWebhookEvent<"installation_repositories">) => {
        const { action, installation, sender, repositories_added, repositories_removed, repository_selection } = payload;
        const account = installation.account;
        const accountLogin = account && 'login' in account ? account.login : account?.name ?? 'unknown';
        const installationId = installation.id.toString();

        log({ module: 'github-webhook', event: 'installation_repositories' },
            `Repositories ${action}: ${repositories_added.length} added, ${repositories_removed.length} removed`, {
                deliveryId: id,
                action,
                installationId: installation.id,
                accountLogin,
                repositoriesAdded: repositories_added.map(r => r.full_name),
                repositoriesRemoved: repositories_removed.map(r => r.full_name)
            });

        // Update repository count in database
        // Use the repository_selection count if available, otherwise calculate delta
        const existingInstallation = await db.githubInstallation.findUnique({
            where: { id: installationId },
            select: { repositoryCount: true }
        });

        if (existingInstallation) {
            const newCount = existingInstallation.repositoryCount + repositories_added.length - repositories_removed.length;
            await db.githubInstallation.update({
                where: { id: installationId },
                data: { repositoryCount: Math.max(0, newCount) }
            });
        }
    });

    // Push events - Code pushed to repository
    webhooks.on("push", async ({ id, name, payload }: EmitterWebhookEvent<"push">) => {
        log({ module: 'github-webhook', event: 'push' },
            `Push to ${payload.repository.full_name} by ${payload.pusher.name}`, {
                deliveryId: id,
                ref: payload.ref,
                commits: payload.commits.length
            });
    });

    // Pull request events
    webhooks.on("pull_request", async ({ id, name, payload }: EmitterWebhookEvent<"pull_request">) => {
        log({ module: 'github-webhook', event: 'pull_request' },
            `PR ${payload.action} on ${payload.repository.full_name}: #${payload.pull_request.number} - ${payload.pull_request.title}`, {
                deliveryId: id,
                action: payload.action,
                number: payload.pull_request.number
            });
    });

    // Issue events
    webhooks.on("issues", async ({ id, name, payload }: EmitterWebhookEvent<"issues">) => {
        log({ module: 'github-webhook', event: 'issues' },
            `Issue ${payload.action} on ${payload.repository.full_name}: #${payload.issue.number} - ${payload.issue.title}`, {
                deliveryId: id,
                action: payload.action,
                number: payload.issue.number
            });
    });

    // Star events
    webhooks.on(["star.created", "star.deleted"], async ({ id, name, payload }: EmitterWebhookEvent<"star.created" | "star.deleted">) => {
        const action = payload.action === 'created' ? 'starred' : 'unstarred';
        log({ module: 'github-webhook', event: 'star' },
            `Repository ${action}: ${payload.repository.full_name} by ${payload.sender.login}`, {
                deliveryId: id
            });
    });

    // Repository events
    webhooks.on("repository", async ({ id, name, payload }: EmitterWebhookEvent<"repository">) => {
        log({ module: 'github-webhook', event: 'repository' },
            `Repository ${payload.action}: ${payload.repository.full_name}`, {
                deliveryId: id,
                action: payload.action
            });
    });

    // Member events - Collaborator changes
    webhooks.on("member", async ({ id, name, payload }: EmitterWebhookEvent<"member">) => {
        const memberLogin = payload.member?.login ?? 'unknown';
        log({ module: 'github-webhook', event: 'member' },
            `Collaborator ${payload.action} on ${payload.repository.full_name}: ${memberLogin}`, {
                deliveryId: id,
                action: payload.action,
                member: memberLogin
            });
    });

    // Catch-all for unhandled events (logged at debug level to avoid noise)
    webhooks.onAny(async ({ id, name, payload }: EmitterWebhookEvent) => {
        log({ module: 'github-webhook', event: name as string },
            `Received webhook event: ${name}`, { deliveryId: id });
    });

    webhooks.onError((error: any) => {
        log({ module: 'github-webhook', level: 'error' },
            `Webhook handler error: ${error.event?.name}`, {
                error: error.message,
                event: error.event?.name,
                deliveryId: error.event?.id
            });
    });
}

export function getWebhooks(): Webhooks | null {
    return webhooks;
}

export function getApp(): App | null {
    return app;
}