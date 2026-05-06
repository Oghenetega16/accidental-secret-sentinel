// ─── Core domain types ────────────────────────────────────────────────────────

export type Severity = 'critical' | 'warning' | 'info';

export type SourceType =
  | 'request-header'
  | 'request-body'
  | 'response-header'
  | 'response-body'
  | 'js-bundle'
  | 'html-source'
  | 'url-param';

export interface Pattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  /** Minimum Shannon entropy score (0–8). Filters low-entropy false positives. */
  entropyMin?: number;
  /** Request/response header names that boost confidence if the match appears in them. */
  contextBoost?: string[];
  /** Human-readable description shown in the popup. */
  description?: string;
}

export interface Finding {
  id: string;               // UUID
  patternId: string;
  patternName: string;
  severity: Severity;
  sourceType: SourceType;
  url: string;
  tabId: number;
  /** Partially redacted matched value, e.g. "AKIA***************XYZ" */
  redactedValue: string;
  /** SHA-256 hash of the raw matched value — used for suppression */
  valueHash: string;
  timestamp: number;        // Date.now()
  entropy: number;
}

// ─── Suppression types ────────────────────────────────────────────────────────

export type SuppressionKind = 'value-hash' | 'domain' | 'pattern';

export interface Suppression {
  id: string;
  kind: SuppressionKind;
  /** The value that was suppressed — hash, domain, or patternId */
  value: string;
  /** Human label shown in the suppression list */
  label: string;
  createdAt: number;
}

// ─── Storage schema ───────────────────────────────────────────────────────────

export interface SessionFindings {
  /** tabId → Finding[] */
  [tabId: string]: Finding[];
}

export interface StorageLocal {
  findings: SessionFindings;
}

export interface StorageSync {
  suppressions: Suppression[];
  customPatterns: Pattern[];
  disabledDomains: string[];
  /** Global on/off toggle */
  enabled: boolean;
}

// ─── IPC messages ─────────────────────────────────────────────────────────────

export type MessageType =
  | 'FINDING_DETECTED'
  | 'GET_FINDINGS'
  | 'GET_FINDINGS_RESPONSE'
  | 'SUPPRESS'
  | 'CLEAR_FINDINGS'
  | 'GET_SETTINGS'
  | 'GET_SETTINGS_RESPONSE'
  | 'UPDATE_SETTINGS'
  | 'GET_TAB_ID'
  | 'GET_TAB_ID_RESPONSE'
  | 'REMOVE_SUPPRESSION'
  | 'SUPPRESSION_ADDED';

export interface BaseMessage {
  type: MessageType;
}

export interface FindingDetectedMessage extends BaseMessage {
  type: 'FINDING_DETECTED';
  finding: Finding;
}

export interface GetFindingsMessage extends BaseMessage {
  type: 'GET_FINDINGS';
  tabId: number;
}

export interface GetFindingsResponseMessage extends BaseMessage {
  type: 'GET_FINDINGS_RESPONSE';
  findings: Finding[];
}

export interface SuppressMessage extends BaseMessage {
  type: 'SUPPRESS';
  suppression: Omit<Suppression, 'id' | 'createdAt'>;
}

export interface ClearFindingsMessage extends BaseMessage {
  type: 'CLEAR_FINDINGS';
  tabId: number;
}

export interface GetSettingsMessage extends BaseMessage {
  type: 'GET_SETTINGS';
}

export interface GetSettingsResponseMessage extends BaseMessage {
  type: 'GET_SETTINGS_RESPONSE';
  settings: StorageSync;
}

export interface UpdateSettingsMessage extends BaseMessage {
  type: 'UPDATE_SETTINGS';
  settings: Partial<StorageSync>;
}

export interface GetTabIdMessage extends BaseMessage {
  type: 'GET_TAB_ID';
}

export interface GetTabIdResponseMessage extends BaseMessage {
  type: 'GET_TAB_ID_RESPONSE';
  tabId: number;
}

export interface RemoveSuppressionMessage extends BaseMessage {
  type: 'REMOVE_SUPPRESSION';
  suppressionId: string;
}

export interface SuppressionAddedMessage extends BaseMessage {
  type: 'SUPPRESSION_ADDED';
  suppression: Suppression;
}

export type Message =
  | FindingDetectedMessage
  | GetFindingsMessage
  | GetFindingsResponseMessage
  | SuppressMessage
  | ClearFindingsMessage
  | GetSettingsMessage
  | GetSettingsResponseMessage
  | UpdateSettingsMessage
  | GetTabIdMessage
  | GetTabIdResponseMessage
  | RemoveSuppressionMessage
  | SuppressionAddedMessage;