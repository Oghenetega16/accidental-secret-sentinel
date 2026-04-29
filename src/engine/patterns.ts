import type { Pattern } from '../shared/types';

/**
 * Curated library of secret patterns.
 *
 * Organised by provider. Each pattern has:
 *  - A stable ID (never change once shipped — used in suppression storage)
 *  - A human name shown in the popup
 *  - A regex that matches the raw secret value
 *  - A severity rating
 *  - Optional entropyMin to filter low-entropy false positives
 *  - Optional contextBoost headers that raise confidence
 *
 * To add new patterns: append to the array and add a test in patterns.test.ts.
 * Never modify an existing `id` — suppressions are keyed to it.
 */
export const PATTERNS: Pattern[] = [

  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    severity: 'critical',
    entropyMin: 3.5,
    description: 'AWS IAM access key — grants API access to AWS services.',
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    regex: /(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws[_\-\s]?secret)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})/i,
    severity: 'critical',
    entropyMin: 4.0,
    contextBoost: ['Authorization', 'X-Amz-Security-Token'],
    description: 'AWS IAM secret key — used to sign API requests.',
  },
  {
    id: 'aws-session-token',
    name: 'AWS Session Token',
    regex: /(?:aws[_\-\s]?session[_\-\s]?token)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{100,})/i,
    severity: 'critical',
    entropyMin: 4.0,
    description: 'Temporary AWS session credential.',
  },

  // ── GitHub ────────────────────────────────────────────────────────────────
  {
    id: 'github-pat-classic',
    name: 'GitHub Personal Access Token (classic)',
    regex: /\bghp_[A-Za-z0-9]{36}\b/,
    severity: 'critical',
    description: 'GitHub classic PAT — grants repo/org access.',
  },
  {
    id: 'github-pat-fine-grained',
    name: 'GitHub Fine-Grained PAT',
    regex: /\bgithub_pat_[A-Za-z0-9_]{82}\b/,
    severity: 'critical',
    description: 'GitHub fine-grained PAT.',
  },
  {
    id: 'github-oauth-token',
    name: 'GitHub OAuth Token',
    regex: /\bgho_[A-Za-z0-9]{36}\b/,
    severity: 'critical',
  },
  {
    id: 'github-app-token',
    name: 'GitHub App Token',
    regex: /\bghs_[A-Za-z0-9]{36}\b/,
    severity: 'critical',
  },
  {
    id: 'github-refresh-token',
    name: 'GitHub Refresh Token',
    regex: /\bghr_[A-Za-z0-9]{76}\b/,
    severity: 'critical',
  },

  // ── Stripe ────────────────────────────────────────────────────────────────
  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret Key',
    regex: /\bsk_(live|test)_[A-Za-z0-9]{24,99}\b/,
    severity: 'critical',
    description: 'Stripe secret key — full API access including charges.',
  },
  {
    id: 'stripe-restricted-key',
    name: 'Stripe Restricted Key',
    regex: /\brk_(live|test)_[A-Za-z0-9]{24,99}\b/,
    severity: 'warning',
    description: 'Stripe restricted key — limited API access.',
  },
  {
    id: 'stripe-webhook-secret',
    name: 'Stripe Webhook Secret',
    regex: /\bwhsec_[A-Za-z0-9]{32,99}\b/,
    severity: 'warning',
  },

  // ── Google / GCP ──────────────────────────────────────────────────────────
  {
    id: 'google-api-key',
    name: 'Google API Key',
    regex: /\bAIza[0-9A-Za-z_\-]{35}\b/,
    severity: 'warning',
    description: 'Google API key — scope depends on enabled APIs.',
  },
  {
    id: 'google-oauth-client-secret',
    name: 'Google OAuth Client Secret',
    regex: /GOCSPX-[A-Za-z0-9_\-]{28}/,
    severity: 'critical',
  },
  {
    id: 'google-service-account-key',
    name: 'Google Service Account Key',
    regex: /"type"\s*:\s*"service_account"/,
    severity: 'critical',
    description: 'GCP service account key — full GCP access per IAM roles.',
  },

  // ── Slack ─────────────────────────────────────────────────────────────────
  {
    id: 'slack-bot-token',
    name: 'Slack Bot Token',
    regex: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b/,
    severity: 'critical',
    description: 'Slack bot token — can post messages and read channels.',
  },
  {
    id: 'slack-user-token',
    name: 'Slack User Token',
    regex: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b/,
    severity: 'critical',
  },
  {
    id: 'slack-workspace-token',
    name: 'Slack Workspace Token',
    regex: /\bxoxa-2-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{64}\b/,
    severity: 'critical',
  },
  {
    id: 'slack-webhook-url',
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8}\/B[A-Za-z0-9_]{8,}\/[A-Za-z0-9_]{24}/,
    severity: 'warning',
  },

  // ── Twilio ────────────────────────────────────────────────────────────────
  {
    id: 'twilio-account-sid',
    name: 'Twilio Account SID',
    regex: /\bAC[a-z0-9]{32}\b/,
    severity: 'warning',
    description: 'Twilio Account SID — identifies the account.',
  },
  {
    id: 'twilio-auth-token',
    name: 'Twilio Auth Token',
    regex: /(?:twilio[_\-\s]?auth[_\-\s]?token|TWILIO_AUTH_TOKEN)[\"'\s]*[:=][\"'\s]*([a-z0-9]{32})/i,
    severity: 'critical',
    entropyMin: 3.5,
  },

  // ── SendGrid ──────────────────────────────────────────────────────────────
  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API Key',
    regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/,
    severity: 'critical',
  },

  // ── OpenAI ────────────────────────────────────────────────────────────────
  {
    id: 'openai-api-key',
    name: 'OpenAI API Key',
    regex: /\bsk-[A-Za-z0-9]{48}\b/,
    severity: 'critical',
    description: 'OpenAI API key — grants model API access and incurs billing.',
  },
  {
    id: 'openai-org-id',
    name: 'OpenAI Organisation ID',
    regex: /\borg-[A-Za-z0-9]{24}\b/,
    severity: 'info',
  },

  // ── Anthropic ─────────────────────────────────────────────────────────────
  {
    id: 'anthropic-api-key',
    name: 'Anthropic API Key',
    regex: /\bsk-ant-[A-Za-z0-9\-_]{95,}\b/,
    severity: 'critical',
    description: 'Anthropic Claude API key.',
  },

  // ── Azure ─────────────────────────────────────────────────────────────────
  {
    id: 'azure-storage-account-key',
    name: 'Azure Storage Account Key',
    regex: /AccountKey=[A-Za-z0-9+/]{88}==/,
    severity: 'critical',
  },
  {
    id: 'azure-sas-token',
    name: 'Azure SAS Token',
    regex: /sig=[A-Za-z0-9%]{43,}/,
    severity: 'warning',
    entropyMin: 3.5,
  },
  {
    id: 'azure-ad-client-secret',
    name: 'Azure AD Client Secret',
    regex: /(?:client[_\-\s]?secret)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9~._\-]{34,40})/i,
    severity: 'critical',
    entropyMin: 3.8,
  },

  // ── JWT ───────────────────────────────────────────────────────────────────
  {
    id: 'jwt-token',
    name: 'JSON Web Token (JWT)',
    regex: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/,
    severity: 'warning',
    contextBoost: ['Authorization', 'X-Auth-Token'],
    description: 'JWT — may carry sensitive claims or auth grants.',
  },

  // ── Private Keys ──────────────────────────────────────────────────────────
  {
    id: 'rsa-private-key',
    name: 'RSA Private Key',
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
    severity: 'critical',
  },
  {
    id: 'openssh-private-key',
    name: 'OpenSSH Private Key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    severity: 'critical',
  },
  {
    id: 'ec-private-key',
    name: 'EC Private Key',
    regex: /-----BEGIN EC PRIVATE KEY-----/,
    severity: 'critical',
  },
  {
    id: 'pgp-private-key',
    name: 'PGP Private Key Block',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    severity: 'critical',
  },

  // ── npm ───────────────────────────────────────────────────────────────────
  {
    id: 'npm-access-token',
    name: 'npm Access Token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/,
    severity: 'critical',
  },

  // ── Mailgun ───────────────────────────────────────────────────────────────
  {
    id: 'mailgun-api-key',
    name: 'Mailgun API Key',
    regex: /\bkey-[A-Za-z0-9]{32}\b/,
    severity: 'critical',
    entropyMin: 3.5,
  },

  // ── Shopify ───────────────────────────────────────────────────────────────
  {
    id: 'shopify-private-app-password',
    name: 'Shopify Private App Password',
    regex: /\bshppa_[A-Za-z0-9]{32}\b/,
    severity: 'critical',
  },
  {
    id: 'shopify-shared-secret',
    name: 'Shopify Shared Secret',
    regex: /\bshpss_[A-Za-z0-9]{32}\b/,
    severity: 'critical',
  },

  // ── Okta ─────────────────────────────────────────────────────────────────
  {
    id: 'okta-api-token',
    name: 'Okta API Token',
    regex: /00[A-Za-z0-9\-_]{40}/,
    severity: 'critical',
    contextBoost: ['Authorization', 'X-Okta-User-Agent-Extended'],
    entropyMin: 4.0,
  },

  // ── Generic high-entropy secrets ──────────────────────────────────────────
  {
    id: 'generic-secret-assignment',
    name: 'Generic Secret Assignment',
    regex: /(?:secret|api[_\-]?key|auth[_\-]?token|access[_\-]?token|private[_\-]?key)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/=_\-]{32,88})/i,
    severity: 'info',
    entropyMin: 4.2,
    description: 'High-entropy string assigned to a secret-like variable name.',
  },
  {
    id: 'generic-bearer-token',
    name: 'Bearer Token',
    regex: /Bearer\s+([A-Za-z0-9\-_=+/]{32,})/,
    severity: 'warning',
    contextBoost: ['Authorization'],
    entropyMin: 3.8,
  },
];

/** Quick lookup by pattern ID */
export const PATTERN_MAP = new Map<string, Pattern>(
  PATTERNS.map(p => [p.id, p])
);