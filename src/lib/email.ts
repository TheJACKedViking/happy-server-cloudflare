/**
 * Email utility module for sending transactional emails (HAP-805)
 *
 * Uses Resend API for email delivery (https://resend.com/).
 * Resend is lightweight, has excellent Cloudflare Workers compatibility,
 * and provides a simple API for sending transactional emails.
 *
 * @remarks
 * - Requires RESEND_API_KEY environment variable to be set
 * - Uses HAPPY_APP_URL for building invitation accept links
 * - Do not log invitation tokens or recipient emails in plaintext
 */

/**
 * Email sending result
 */
export interface EmailResult {
    success: boolean;
    messageId?: string;
    error?: string;
}

/**
 * Configuration for sending invitation emails
 */
export interface InvitationEmailConfig {
    /** Recipient email address */
    recipientEmail: string;
    /** Invitation token for the accept link */
    invitationToken: string;
    /** Name of the person who sent the invitation (for email personalization) */
    inviterName?: string;
    /** Session name/title if available */
    sessionName?: string;
    /** Permission level granted */
    permission: 'view_only' | 'view_and_chat';
    /** Expiration date for the invitation */
    expiresAt: Date;
}

/**
 * Environment bindings needed for email sending
 */
export interface EmailEnv {
    /** Resend API key for sending emails */
    RESEND_API_KEY?: string;
    /** Base URL for the Happy app (for building links) */
    HAPPY_APP_URL?: string;
    /** Current environment (development/production) */
    ENVIRONMENT?: string;
}

/**
 * Resend API response type
 */
interface ResendResponse {
    id?: string;
    error?: {
        message: string;
        name: string;
    };
}

/**
 * Default sender email address
 * In production, this should be a verified domain in Resend
 */
const DEFAULT_SENDER = 'Happy <noreply@enflamemedia.com>';

/**
 * Send an invitation email to a recipient
 *
 * @param env - Environment bindings containing API keys and configuration
 * @param config - Invitation email configuration
 * @returns Result indicating success or failure
 *
 * @remarks
 * - Returns success: false with error message if email cannot be sent
 * - Does not throw exceptions - caller should check result.success
 * - Logs errors to console for debugging (without sensitive data)
 */
export async function sendInvitationEmail(
    env: EmailEnv,
    config: InvitationEmailConfig
): Promise<EmailResult> {
    // Check if email sending is configured
    if (!env.RESEND_API_KEY) {
        console.warn('[Email] RESEND_API_KEY not configured, skipping email send');
        // In development, treat missing API key as success to not block testing
        if (env.ENVIRONMENT === 'development') {
            console.log('[Email] Development mode: Would have sent invitation email to recipient');
            return { success: true, messageId: 'dev-mode-skip' };
        }
        return {
            success: false,
            error: 'Email service not configured',
        };
    }

    // Build the accept invitation URL
    const baseUrl = env.HAPPY_APP_URL ?? 'https://happy.enflamemedia.com';
    const acceptUrl = `${baseUrl}/invite/${config.invitationToken}`;

    // Format expiration date for display
    const expiresFormatted = config.expiresAt.toLocaleDateString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
    });

    // Build permission description
    const permissionText =
        config.permission === 'view_and_chat'
            ? 'view and chat'
            : 'view only';

    // Build email subject and body
    const subject = config.inviterName
        ? `${config.inviterName} shared a Happy session with you`
        : 'You\'ve been invited to a Happy session';

    const sessionContext = config.sessionName
        ? `the session "${config.sessionName}"`
        : 'a Happy session';

    const inviterContext = config.inviterName
        ? `${config.inviterName} has`
        : 'Someone has';

    // Build HTML email content
    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${subject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Happy Session Invitation</h1>
    </div>

    <div style="background: #f9fafb; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 10px 10px;">
        <p style="font-size: 16px; margin-bottom: 20px;">
            ${inviterContext} invited you to ${sessionContext} on Happy.
        </p>

        <p style="font-size: 14px; color: #666; margin-bottom: 20px;">
            You'll have <strong>${permissionText}</strong> access to this session.
        </p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="${acceptUrl}"
               style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; padding: 14px 28px; border-radius: 8px; font-weight: 600; font-size: 16px;">
                Accept Invitation
            </a>
        </div>

        <p style="font-size: 13px; color: #888; margin-top: 30px;">
            This invitation expires on ${expiresFormatted}.
        </p>

        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">

        <p style="font-size: 12px; color: #999; margin: 0;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="${acceptUrl}" style="color: #667eea; word-break: break-all;">${acceptUrl}</a>
        </p>
    </div>

    <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
        <p style="margin: 0;">
            Sent by Happy - Remote Claude Code Client<br>
            <a href="https://happy.enflamemedia.com" style="color: #667eea;">happy.enflamemedia.com</a>
        </p>
    </div>
</body>
</html>
    `.trim();

    // Build plain text alternative
    const textContent = `
${subject}

${inviterContext} invited you to ${sessionContext} on Happy.

You'll have ${permissionText} access to this session.

Accept the invitation by visiting:
${acceptUrl}

This invitation expires on ${expiresFormatted}.

---
Sent by Happy - Remote Claude Code Client
https://happy.enflamemedia.com
    `.trim();

    try {
        // Send email via Resend API
        const response = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${env.RESEND_API_KEY}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                from: DEFAULT_SENDER,
                to: [config.recipientEmail],
                subject: subject,
                html: htmlContent,
                text: textContent,
            }),
        });

        const result = await response.json() as ResendResponse;

        if (!response.ok || result.error) {
            const errorMessage = result.error?.message ?? `HTTP ${response.status}`;
            console.error('[Email] Failed to send invitation email:', errorMessage);
            return {
                success: false,
                error: `Failed to send email: ${errorMessage}`,
            };
        }

        console.log('[Email] Invitation email sent successfully, messageId:', result.id);
        return {
            success: true,
            messageId: result.id,
        };
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.error('[Email] Exception while sending email:', errorMessage);
        return {
            success: false,
            error: `Email sending failed: ${errorMessage}`,
        };
    }
}
