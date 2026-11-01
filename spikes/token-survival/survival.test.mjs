// 측정 도구 시험: 가짜 Chat Completions 서버로 요청 모양과 판정을 확인한다(실제 서비스·키 없이).
import assert from 'node:assert/strict';
import { createVerify, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { buildCases, classify, inventedTokens, makeToken, requestBody, responseText, rng, summarize } from './lib.mjs';
import { makeAuth, run } from './survival.mjs';

const token = '⟦PERSON_7Q2MK4XD9A⟧';

test('사례는 seed 로 정해지고 token 은 ADR 0008 모양이다', () => {
  const a = buildCases({ count: 10, seed: 1 });
  const b = buildCases({ count: 10, seed: 1 });
  assert.deepEqual(a, b);
  assert.equal(a.length, 10);
  for (const item of a) {
    assert.ok(item.tokens.length >= 2);
    for (const t of item.tokens) {
      assert.match(t, /^⟦[A-Z][A-Z0-9_]{0,23}_[0-9A-HJKMNP-TV-Z]{10}⟧$/);
      assert.ok(item.prompt.includes(t));
    }
  }
  assert.notEqual(makeToken('PERSON', rng(1)), makeToken('PERSON', rng(2)));
});

test('판정은 그대로·대소문자·괄호·공백·라벨·누락을 가른다', () => {
  assert.equal(classify(token, `안녕 ${token} 님`), 'exact');
  assert.equal(classify(token, '⟦person_7q2mk4xd9a⟧'), 'case');
  assert.equal(classify(token, '[PERSON_7Q2MK4XD9A]'), 'bracket');
  assert.equal(classify(token, '⟦PERSON_7Q2MK 4XD9A⟧'), 'spacing');
  assert.equal(classify(token, '⟦NAME_7Q2MK4XD9A⟧'), 'label');
  assert.equal(classify(token, '이름 없이 답함'), 'missing');
  assert.deepEqual(inventedTokens(`${token} ⟦EMAIL_0123456789⟧`, [token]), ['⟦EMAIL_0123456789⟧']);
});

test('본문에는 temperature·top_p 가 없고 안내 조건에서만 system 메시지가 붙는다', () => {
  const plain = requestBody({ model: 'm', maxTokens: 100, hint: false, prompt: 'p' });
  assert.deepEqual(plain, { model: 'm', messages: [{ role: 'user', content: 'p' }], max_completion_tokens: 100 });
  assert.equal(requestBody({ model: 'm', maxTokens: 100, hint: true, prompt: 'p' }).messages[0].role, 'system');
  assert.equal(responseText({ choices: [{ message: { content: [{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }] } }] }), 'ab');
  assert.equal(responseText({}), null);
});

test('인증 설정이 없거나 비면 실행하지 않는다', async () => {
  assert.throws(() => makeAuth({ type: 'bearer-env', env: 'PA_TS_MISSING' }, {}));
  assert.throws(() => makeAuth({ type: 'unknown' }, {}));
  assert.equal(await makeAuth({ type: 'bearer-env', env: 'K' }, { K: 'abc' })(), 'abc');
});

test('서비스 계정 키로 서명한 JWT 를 access token 으로 바꾸고 재사용한다', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const exchanges = [];
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', () => {
      const assertion = new URLSearchParams(raw).get('assertion');
      const [header, claims, signature] = assertion.split('.');
      const valid = createVerify('RSA-SHA256').update(`${header}.${claims}`).verify(publicKey, signature, 'base64url');
      exchanges.push({ valid, claims: JSON.parse(Buffer.from(claims, 'base64url').toString()) });
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ access_token: 'sa-token', expires_in: 3600 }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const tokenUri = `http://127.0.0.1:${server.address().port}/token`;
  const dir = mkdtempSync(path.join(tmpdir(), 'pa-ts-'));
  const keyFile = path.join(dir, 'key.json');
  writeFileSync(keyFile, JSON.stringify({ client_email: 'measure@example.invalid', token_uri: tokenUri,
    private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) }));
  try {
    const bearer = makeAuth({ type: 'service-account', path: keyFile }, {});
    assert.equal(await bearer(), 'sa-token');
    assert.equal(await bearer(), 'sa-token');
    assert.equal(exchanges.length, 1);  // 만료 전에는 다시 바꾸지 않는다
    assert.equal(exchanges[0].valid, true);
    assert.equal(exchanges[0].claims.aud, tokenUri);
    assert.equal(exchanges[0].claims.iss, 'measure@example.invalid');
  } finally {
    server.close();
  }
});

test('가짜 서버로 끝까지: 요청 모양, 재시도, 요약', async () => {
  const seen = [];
  let first = true;
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', () => {
      seen.push({ url: req.url, auth: req.headers.authorization, body: JSON.parse(raw) });
      if (first) {
        first = false;
        res.writeHead(503).end();
        return;
      }
      // 첫 token 은 그대로, 나머지는 소문자로 돌려준다.
      const prompt = seen.at(-1).body.messages.at(-1).content;
      const tokens = prompt.match(/⟦[^⟧]+⟧/g);
      const answer = tokens.map((t, i) => (i === 0 ? t : t.toLowerCase())).join(' ');
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ choices: [{ message: { role: 'model', content: answer } }] }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const endpoint = `http://127.0.0.1:${server.address().port}/v1/chat/completions`;
  try {
    const result = await run(
      { endpoint, model: 'test-model', auth: { type: 'bearer-env', env: 'PA_TS_KEY' }, cases: 3, conditions: ['plain'] },
      { env: { PA_TS_KEY: 'test-key' }, log: () => {} },
    );
    assert.equal(seen.length, 4);  // 503 한 번 뒤 재시도
    for (const call of seen) {
      assert.equal(call.url, '/v1/chat/completions');
      assert.equal(call.auth, 'Bearer test-key');
      assert.equal(call.body.model, 'test-model');
      assert.equal(call.body.temperature, undefined);
    }
    const s = result.summary.plain;
    assert.equal(s.calls, 3);
    assert.equal(s.failed, 0);
    assert.equal(s.counts.exact, 3);
    assert.equal(s.counts.case, s.tokens - 3);
    assert.equal(summarize([{ condition: 'x', error: 'HTTP 400' }]).x.failed, 1);
  } finally {
    server.close();
  }
});

test('게이트웨이 측정: 사업자등록번호 검증 숫자와 사례 원문', async () => {
  const { businessNumber, buildRawCases } = await import('./gateway.mjs');
  const seq = [0.05, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.05];  // 1,2,3,4,5,6,7,8,0
  let i = 0;
  assert.equal(businessNumber(() => seq[i++]), '123-45-67800');  // 검증 숫자 0(탐지기 시험의 유효 번호와 같음)
  const a = buildRawCases({ count: 16, seed: 7, internalTerms: ['한빛시청'] });
  const b = buildRawCases({ count: 16, seed: 7, internalTerms: ['한빛시청'] });
  assert.deepEqual(a, b);
  for (const c of a) {
    assert.ok(!c.prompt.includes('{'), c.id);
    assert.equal(new Set(c.values).size, c.values.length);
    for (const v of c.values.filter((x) => x.startsWith('010-'))) assert.match(v, /^010-[2-9]\d{3}-\d{4}$/);
  }
});

test('게이트웨이 측정: 감사 기록을 요청 순서대로 묶는다', async () => {
  const { groupAudit } = await import('./gateway.mjs');
  const groups = groupAudit([
    { kind: 'start' },
    { kind: 'egress', request_id: 'r1', sent: { m: 1 } },
    { kind: 'egress_answer', request_id: 'r1', answer: '{}' },
    { kind: 'request', request_id: 'r1', status: 200 },
    { kind: 'request', request_id: 'r2', status: 400, reason: 'blocked' },
  ]);
  assert.deepEqual(groups, [
    { sent: { m: 1 }, answer: '{}', status: 200, reason: null },
    { status: 400, reason: 'blocked' },
  ]);
});
