import { describe, it, expect, afterEach } from 'vitest';
import {
  describeRequestOptionsForLog,
  describeShapeForLog,
  redactSensitive,
  redactionEnabled,
} from '../src/lib/log-redactor.js';

describe('redactSensitive', () => {
  const JWT =
    'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.s9Zf-dummy_signature123';

  it('redacts JWTs', () => {
    const out = redactSensitive(`token acquired: ${JWT} done`);
    expect(out).toBe('token acquired: [REDACTED_JWT] done');
    expect(out).not.toContain('eyJ');
  });

  it('redacts Bearer authorization headers', () => {
    expect(redactSensitive('Authorization: Bearer abc.DEF-123_xyz=')).toBe(
      'Authorization: Bearer [REDACTED]'
    );
  });

  it('redacts OAuth token fields in query strings', () => {
    const out = redactSensitive('POST /token?code=A1b2C3&client_secret=sup3r-s3cret');
    expect(out).toContain('code=[REDACTED]');
    expect(out).toContain('client_secret=[REDACTED]');
    expect(out).not.toContain('A1b2C3');
    expect(out).not.toContain('sup3r-s3cret');
  });

  it('redacts OAuth token fields in JSON bodies', () => {
    const out = redactSensitive('{"refresh_token": "0.AAA-refresh-value", "expires_in": 3600}');
    expect(out).toContain('[REDACTED]');
    expect(out).not.toContain('0.AAA-refresh-value');
    // Non-sensitive fields survive
    expect(out).toContain('expires_in');
    expect(out).toContain('3600');
  });

  it('redacts email addresses / UPNs', () => {
    expect(redactSensitive('login failed for alice.smith@contoso.com')).toBe(
      'login failed for [REDACTED_EMAIL]'
    );
  });

  it('leaves non-sensitive text untouched', () => {
    const msg = 'Microsoft 365 MCP Server starting on port 3000';
    expect(redactSensitive(msg)).toBe(msg);
  });

  it('leaves HTTP status codes and error codes untouched', () => {
    const statusMsg = 'Graph API request failed: statusCode: 401';
    expect(redactSensitive(statusMsg)).toBe(statusMsg);

    const errMsg = 'fetch failed { code: ENOTFOUND }';
    expect(redactSensitive(errMsg)).toBe(errMsg);

    const jsonErr = '{"statusCode":401,"code":"ECONNRESET"}';
    expect(redactSensitive(jsonErr)).toBe(jsonErr);
  });

  it('still redacts authorization codes in query strings', () => {
    const out = redactSensitive('redirect to /callback?code=AQABAAIAAAD.0.abc-123&state=xyz');
    expect(out).toBe('redirect to /callback?code=[REDACTED]&state=xyz');
  });

  it('handles multiple secrets in one message', () => {
    const out = redactSensitive(`Bearer ${'x'.repeat(20)} for user bob@example.org`);
    expect(out).toBe('Bearer [REDACTED] for user [REDACTED_EMAIL]');
  });
});

describe('redactionEnabled', () => {
  const prev = process.env.MS365_MCP_REDACT_PII;
  afterEach(() => {
    if (prev === undefined) delete process.env.MS365_MCP_REDACT_PII;
    else process.env.MS365_MCP_REDACT_PII = prev;
  });

  it('is on by default', () => {
    delete process.env.MS365_MCP_REDACT_PII;
    expect(redactionEnabled()).toBe(true);
  });

  it('is on for "true" and "1"', () => {
    process.env.MS365_MCP_REDACT_PII = 'true';
    expect(redactionEnabled()).toBe(true);
    process.env.MS365_MCP_REDACT_PII = '1';
    expect(redactionEnabled()).toBe(true);
  });

  it('is off for "false" and "0"', () => {
    process.env.MS365_MCP_REDACT_PII = 'false';
    expect(redactionEnabled()).toBe(false);
    process.env.MS365_MCP_REDACT_PII = '0';
    expect(redactionEnabled()).toBe(false);
  });

  it('is on for any other value', () => {
    process.env.MS365_MCP_REDACT_PII = 'yes';
    expect(redactionEnabled()).toBe(true);
  });
});

describe('describeShapeForLog', () => {
  const message = {
    subject: 'Quarterly results',
    body: { contentType: 'Text', content: 'Revenue fell 12%, do not share' },
    toRecipients: [{ emailAddress: { address: 'cfo@example.com' } }],
  };

  it('names the fields and the size, never the content', () => {
    const out = describeShapeForLog(message);
    expect(out).toMatch(/^object \{subject, body, toRecipients\}, \d+ bytes$/);
    expect(out).not.toContain('Quarterly');
    expect(out).not.toContain('Revenue');
    expect(out).not.toContain('cfo@');
  });

  it('describes strings, arrays and nothing', () => {
    expect(describeShapeForLog('héllo')).toBe('string, 6 bytes');
    expect(describeShapeForLog([1, 2, 3])).toBe('array(3), 7 bytes');
    expect(describeShapeForLog(undefined)).toBe('undefined');
    expect(describeShapeForLog(null)).toBe('null');
  });

  it('survives what cannot be serialized', () => {
    const loop: Record<string, unknown> = { a: 1 };
    loop.self = loop;
    expect(describeShapeForLog(loop)).toBe('object {a, self}');
  });
});

describe('describeRequestOptionsForLog', () => {
  it('keeps the method, names the headers and shapes the body', () => {
    const out = describeRequestOptionsForLog({
      method: 'POST',
      headers: { Prefer: 'outlook.timezone="UTC"' },
      body: JSON.stringify({ comment: 'Please call me at 555-0100' }),
    });
    expect(out).toContain('"method":"POST"');
    expect(out).toContain('"headers":["Prefer"]');
    expect(out).toMatch(/"body":"string, \d+ bytes"/);
    expect(out).not.toContain('555-0100');
    expect(out).not.toContain('outlook.timezone');
  });
});
