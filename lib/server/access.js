import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// One shared access code protects every change (and, if asked, every read). The product has one manager role and no
// accounts, so there is no user list: whoever knows the code can change records. The code is never stored in a
// cookie; the cookie holds an expiry and a signature over the code made with a key only this server has. So changing
// the code or restarting the server signs everyone out, and nobody can build a cookie to test a guessed code.

export const SESSION_COOKIE = 'fsf_access';
export const MIN_CODE_LENGTH = 12;
export const SESSION_DAYS = 7;
const MAX_FAILURES = 5;
// The client's address comes from a header the client can set, so wrong codes are also capped across all addresses.
export const MAX_TOTAL_FAILURES = 20;
const FAILURE_WINDOW_MS = 60_000;
// Shared by every route in this server process, even if each route loads its own copy of this module.
const state = (globalThis.__fsfAccess ??= { failures: new Map(), sessionKey: randomBytes(32) });
const { failures } = state;

const digest = (value) => createHash('sha256').update(String(value)).digest();
export const sameSecret = (given, expected) => timingSafeEqual(digest(given), digest(expected));
const sign = (code, expires) => createHmac('sha256', state.sessionKey).update(`fsf-manager-session:${expires}:${code}`).digest('hex');

// What the environment asks for. Everything is off unless FSF_ACCESS_CODE is set. A code shorter than
// MIN_CODE_LENGTH is refused, not used: changes stay blocked until it is fixed, so a weak code never protects anything.
export function accessSettings(env = process.env) {
  const code = env.FSF_ACCESS_CODE || '';
  return {
    enabled: code !== '',
    code,
    tooShort: code !== '' && code.length < MIN_CODE_LENGTH,
    protectReads: code !== '' && /^(1|true|yes)$/i.test(env.FSF_PROTECT_READS || ''),
  };
}

export function createSession(code, now = Date.now()) {
  const expires = now + SESSION_DAYS * 86_400_000;
  return { value: `${expires}.${sign(code, expires)}`, maxAge: SESSION_DAYS * 86_400 };
}

export function validSession(value, code, now = Date.now()) {
  const parts = String(value || '').split('.');
  if (parts.length !== 2 || !/^\d+$/.test(parts[0]) || Number(parts[0]) < now) return false;
  return sameSecret(parts[1], sign(code, parts[0]));
}

function cookieValue(request, name) {
  for (const part of String(request.headers.get('cookie') || '').split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=');
  }
  return '';
}

function suppliedCode(request) {
  const bearer = /^Bearer (.+)$/i.exec(request.headers.get('authorization') || '');
  return request.headers.get('x-access-code') || (bearer ? bearer[1] : '');
}

const clientKey = (request) => (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'local';

export function lockedOut(request, now = Date.now()) {
  for (const [key, times] of failures) {
    const recent = times.filter((time) => now - time < FAILURE_WINDOW_MS);
    if (recent.length) failures.set(key, recent); else failures.delete(key);
  }
  const total = [...failures.values()].reduce((sum, times) => sum + times.length, 0);
  return total >= MAX_TOTAL_FAILURES || (failures.get(clientKey(request)) || []).length >= MAX_FAILURES;
}

export function noteFailure(request, now = Date.now()) {
  const key = clientKey(request);
  failures.set(key, [...(failures.get(key) || []), now]);
}

export function clearFailures(request) {
  failures.delete(clientKey(request));
}

// 'ok', 'required' (no or wrong code), 'locked' (too many wrong codes), or 'misconfigured'. The lockout stops code
// attempts only: a browser already signed in keeps working while someone else is guessing.
// A script sends the code in the x-access-code header or as a bearer token; a browser sends the session cookie.
export function accessVerdict(request, now = Date.now()) {
  const settings = accessSettings();
  if (!settings.enabled) return 'ok';
  if (settings.tooShort) return 'misconfigured';
  const given = suppliedCode(request);
  if (given) {
    if (lockedOut(request, now)) return 'locked';
    if (sameSecret(given, settings.code)) return 'ok';
    noteFailure(request, now);
    return 'required';
  }
  return validSession(cookieValue(request, SESSION_COOKIE), settings.code, now) ? 'ok' : 'required';
}

// For the page: is this browser holding a valid session? (A header code does not count; pages use the cookie.)
export function hasSession(request, now = Date.now()) {
  const settings = accessSettings();
  return settings.enabled && !settings.tooShort && validSession(cookieValue(request, SESSION_COOKIE), settings.code, now);
}

export function sessionCookie(request, value, maxAge) {
  const secure = new URL(request.url).protocol === 'https:' || request.headers.get('x-forwarded-proto') === 'https';
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}
