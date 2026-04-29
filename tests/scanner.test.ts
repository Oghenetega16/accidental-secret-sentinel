import { describe, it, expect } from 'vitest';
import { scan } from '../src/engine/scanner';
import type { ScanContext } from '../src/shared/types';

describe('Scan Engine', () => {
  const mockContext: ScanContext = { 
    url: 'https://api.example.com/v1/users', 
    tabId: 1, 
    sourceType: 'request-body' 
  };

  it('detects a known secret pattern within a larger payload', () => {
    const payload = JSON.stringify({
      user: "dev",
      // Mock GitHub PAT structure
      token: "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD" 
    });

    const findings = scan(payload, mockContext);
    
    expect(findings.length).toBe(1);
    expect(findings[0].patternName).toContain('GitHub');
    expect(findings[0].sourceType).toBe('request-body');
    // Ensure the value is properly redacted before emitting
    expect(findings[0].redactedValue).toContain('ghp_***'); 
  });

  it('ignores benign payloads without secrets', () => {
    const payload = JSON.stringify({ status: "ok", count: 42 });
    const findings = scan(payload, mockContext);
    
    expect(findings.length).toBe(0);
  });
});