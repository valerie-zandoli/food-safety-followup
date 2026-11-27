// Its own file, so its wrong-code count starts at zero: node runs each test file in a separate process.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { SESSION_COOKIE, accessVerdict, createSession, validSession } from '../lib/server/access.js';

const CODE = 'correct horse battery';
const ask = (headers) => accessVerdict(new Request('http://app.test/api/follow-ups', { method: 'POST', headers }));

test('a session cookie cannot be built from a guessed code, so cookies cannot be used to test guesses', () => {
  const expires = Date.now() + 86_400_000;
  const forged = `${expires}.${createHmac('sha256', CODE).update(`fsf-manager-session:${expires}`).digest('hex')}`;
  assert.equal(validSession(forged, CODE), false);
  assert.equal(validSession(createSession(CODE).value, CODE), true, 'a cookie the server made still works');
});

test('changing the claimed address does not get round the lockout, and a signed-in browser keeps working', () => {
  process.env.FSF_ACCESS_CODE = CODE;
  const signedIn = { cookie: `${SESSION_COOKIE}=${createSession(CODE).value}` };
  const answers = Array.from({ length: 200 }, (_, index) => ask({ 'x-access-code': `wrong ${index}`, 'x-forwarded-for': `10.2.0.${index}` }));
  assert.equal(answers.filter((answer) => answer === 'required').length, 20, 'only 20 wrong codes are checked in a minute');
  assert.equal(ask({ 'x-access-code': CODE, 'x-forwarded-for': '10.3.0.1' }), 'locked');
  assert.equal(ask(signedIn), 'ok');
  delete process.env.FSF_ACCESS_CODE;
});
