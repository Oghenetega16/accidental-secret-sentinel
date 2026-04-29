import type {
  Message,
  FindingDetectedMessage,
  GetFindingsMessage,
  GetFindingsResponseMessage,
  SuppressMessage,
  ClearFindingsMessage,
  GetSettingsMessage,
  GetSettingsResponseMessage,
  UpdateSettingsMessage,
} from './types';

// ─── Message type constants ───────────────────────────────────────────────────
// Single source of truth for all IPC message type strings.
// Import these instead of using raw strings anywhere in the codebase.

export const MSG = {
  FINDING_DETECTED:       'FINDING_DETECTED',
  GET_FINDINGS:           'GET_FINDINGS',
  GET_FINDINGS_RESPONSE:  'GET_FINDINGS_RESPONSE',
  SUPPRESS:               'SUPPRESS',
  CLEAR_FINDINGS:         'CLEAR_FINDINGS',
  GET_SETTINGS:           'GET_SETTINGS',
  GET_SETTINGS_RESPONSE:  'GET_SETTINGS_RESPONSE',
  UPDATE_SETTINGS:        'UPDATE_SETTINGS',
  GET_TAB_ID:             'GET_TAB_ID',
  GET_TAB_ID_RESPONSE:    'GET_TAB_ID_RESPONSE',
} as const;

export type MsgType = typeof MSG[keyof typeof MSG];

// ─── Type guards ──────────────────────────────────────────────────────────────
// Use these when receiving messages from chrome.runtime.onMessage to safely
// narrow the type before accessing message-specific fields.

export function isFindingDetected(m: Message): m is FindingDetectedMessage {
  return m.type === MSG.FINDING_DETECTED;
}

export function isGetFindings(m: Message): m is GetFindingsMessage {
  return m.type === MSG.GET_FINDINGS;
}

export function isGetFindingsResponse(m: Message): m is GetFindingsResponseMessage {
  return m.type === MSG.GET_FINDINGS_RESPONSE;
}

export function isSuppress(m: Message): m is SuppressMessage {
  return m.type === MSG.SUPPRESS;
}

export function isClearFindings(m: Message): m is ClearFindingsMessage {
  return m.type === MSG.CLEAR_FINDINGS;
}

export function isGetSettings(m: Message): m is GetSettingsMessage {
  return m.type === MSG.GET_SETTINGS;
}

export function isGetSettingsResponse(m: Message): m is GetSettingsResponseMessage {
  return m.type === MSG.GET_SETTINGS_RESPONSE;
}

export function isUpdateSettings(m: Message): m is UpdateSettingsMessage {
  return m.type === MSG.UPDATE_SETTINGS;
}

// ─── Message factories ────────────────────────────────────────────────────────
// Typed constructors so call sites never have to spell out `type` manually.

export const createMessage = {
  findingDetected: (
    finding: FindingDetectedMessage['finding']
  ): FindingDetectedMessage => ({
    type: MSG.FINDING_DETECTED,
    finding,
  }),

  getFindings: (tabId: number): GetFindingsMessage => ({
    type: MSG.GET_FINDINGS,
    tabId,
  }),

  getFindingsResponse: (
    findings: GetFindingsResponseMessage['findings']
  ): GetFindingsResponseMessage => ({
    type: MSG.GET_FINDINGS_RESPONSE,
    findings,
  }),

  suppress: (
    suppression: SuppressMessage['suppression']
  ): SuppressMessage => ({
    type: MSG.SUPPRESS,
    suppression,
  }),

  clearFindings: (tabId: number): ClearFindingsMessage => ({
    type: MSG.CLEAR_FINDINGS,
    tabId,
  }),

  getSettings: (): GetSettingsMessage => ({
    type: MSG.GET_SETTINGS,
  }),

  getSettingsResponse: (
    settings: GetSettingsResponseMessage['settings']
  ): GetSettingsResponseMessage => ({
    type: MSG.GET_SETTINGS_RESPONSE,
    settings,
  }),

  updateSettings: (
    settings: UpdateSettingsMessage['settings']
  ): UpdateSettingsMessage => ({
    type: MSG.UPDATE_SETTINGS,
    settings,
  }),
} as const;

// ─── Safe sendMessage wrapper ─────────────────────────────────────────────────
// Wraps chrome.runtime.sendMessage in a typed promise that swallows the
// "no receiving end" error thrown when popup or devtools panel is closed.

export function sendMessage<TResponse = unknown>(
  message: Message
): Promise<TResponse | null> {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage(message, (response: TResponse) => {
        if (chrome.runtime.lastError) {
          // Suppress "Could not establish connection" — expected when
          // the popup/devtools panel isn't open.
          resolve(null);
          return;
        }
        resolve(response ?? null);
      });
    } catch {
      resolve(null);
    }
  });
}

// ─── Safe tab message sender ──────────────────────────────────────────────────
// For messages from background → content script on a specific tab.

export function sendTabMessage<TResponse = unknown>(
  tabId: number,
  message: Message
): Promise<TResponse | null> {
  return new Promise(resolve => {
    try {
      chrome.tabs.sendMessage(tabId, message, (response: TResponse) => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(response ?? null);
      });
    } catch {
      resolve(null);
    }
  });
}