#!/usr/bin/env node
// token 보존율 측정 실행기. 설정 파일(기본 secrets/token-survival.json)을 읽어 Chat Completions 호환 주소로
// 합성 사례를 보내고, token 판정 결과를 out 폴더에 JSON 으로 남긴다. 자격 증명과 인증 헤더는 출력하지 않는다.
import { execFileSync } from 'node:child_process';
import { createSign } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { buildCases, classify, inventedTokens, requestBody, responseText, summarize } from './lib.mjs';

const base64url = (value) => Buffer.from(value).toString('base64url');

// 서비스 계정 키(JSON)로 JWT 를 서명해 access token 으로 바꾼다(OAuth 2.0 JWT bearer, gcloud 없이).
async function serviceAccountToken(key, fetchImpl) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64url(JSON.stringify({
    iss: key.client_email,
    scope: 'https://www.googleapis.com/auth/cloud-platform',
    aud: key.token_uri,
    iat: now,
    exp: now + 3600,
  }));
  const signature = createSign('RSA-SHA256').update(`${header}.${claims}`).sign(key.private_key, 'base64url');
  const response = await fetchImpl(key.token_uri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${header}.${claims}.${signature}` }),
  });
  if (!response.ok) throw new Error(`token 교환 실패 HTTP ${response.status}`);
  const json = await response.json();
  return { token: json.access_token, expiresAt: Date.now() + ((json.expires_in ?? 3600) - 300) * 1000 };
}

// 인증: bearer-env(환경 변수의 키), bearer-file(파일의 키), gcloud(application-default access token, 45분마다 갱신),
// service-account(서비스 계정 키 JSON, 만료 5분 전 갱신). 돌려주는 함수는 Bearer 값을 비동기로 준다.
export function makeAuth(auth, env = process.env, fetchImpl = fetch) {
  if (auth?.type === 'bearer-env') {
    const key = env[auth.env];
    if (!key) throw new Error(`환경 변수 ${auth.env} 가 비어 있다`);
    return async () => key;
  }
  if (auth?.type === 'bearer-file') {
    const key = readFileSync(auth.path, 'utf8').trim();
    if (!key) throw new Error(`${auth.path} 가 비어 있다`);
    return async () => key;
  }
  if (auth?.type === 'gcloud') {
    let token = null;
    let fetchedAt = 0;
    return async () => {
      if (!token || Date.now() - fetchedAt > 45 * 60 * 1000) {
        token = execFileSync('gcloud', ['auth', 'application-default', 'print-access-token'], {
          encoding: 'utf8',
          shell: process.platform === 'win32',
        }).trim();
        fetchedAt = Date.now();
      }
      return token;
    };
  }
  if (auth?.type === 'service-account') {
    const key = JSON.parse(readFileSync(auth.path, 'utf8'));
    if (!key.client_email || !key.private_key || !key.token_uri) throw new Error(`${auth.path} 는 서비스 계정 키가 아니다`);
    let cached = null;
    return async () => {
      if (!cached || Date.now() > cached.expiresAt) cached = await serviceAccountToken(key, fetchImpl);
      return cached.token;
    };
  }
  throw new Error('auth.type 은 bearer-env, bearer-file, gcloud, service-account 중 하나다');
}

async function post(url, body, bearer, { retries = 3, fetchImpl = fetch } = {}) {
  for (let attempt = 0; ; attempt += 1) {
    const response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${await bearer()}` },
      body: JSON.stringify(body),
    });
    if (response.ok) return response.json();
    // 429·5xx 는 잠시 뒤 다시 시도하고, 그 밖의 오류는 상태 코드만 남긴다.
    if (attempt < retries && (response.status === 429 || response.status >= 500)) {
      await new Promise((resolve) => setTimeout(resolve, 2000 * 2 ** attempt));
      continue;
    }
    throw new Error(`HTTP ${response.status}`);
  }
}

// 주소의 {project_id} 를 서비스 계정 키의 project_id 로 채운다. 키 파일만 바꿔 끼우면 주소도 따라간다.
export function resolveEndpoint(endpoint, auth) {
  if (!endpoint.includes('{project_id}')) return endpoint;
  if (auth?.type !== 'service-account') throw new Error('{project_id} 는 service-account 인증에서만 채울 수 있다');
  const { project_id: id } = JSON.parse(readFileSync(auth.path, 'utf8'));
  if (!id) throw new Error('서비스 계정 키에 project_id 가 없다');
  return endpoint.replaceAll('{project_id}', id);
}

export async function run(config, { env = process.env, log = console.log, fetchImpl = fetch } = {}) {
  const bearer = makeAuth(config.auth, env, fetchImpl);
  const endpoint = resolveEndpoint(config.endpoint, config.auth);
  const cases = buildCases({ count: config.cases ?? 40, seed: config.seed ?? 20261018 });
  const conditions = config.conditions ?? ['plain', 'hint'];
  const records = [];
  for (const condition of conditions) {
    for (const item of cases) {
      const body = requestBody({ model: config.model, maxTokens: config.max_tokens ?? 1024, hint: condition === 'hint', prompt: item.prompt });
      const record = { id: item.id, condition, tokens: item.tokens };
      try {
        const text = responseText(await post(endpoint, body, bearer, { fetchImpl }));
        if (text === null) throw new Error('응답에 글자가 없다');
        record.response = text;
        record.classes = Object.fromEntries(item.tokens.map((t) => [t, classify(t, text)]));
        record.invented = inventedTokens(text, item.tokens);
      } catch (error) {
        record.error = error instanceof Error ? error.message : String(error);
      }
      records.push(record);
      log(`${condition} ${item.id} ${record.error ?? Object.values(record.classes).join(',')}`);
    }
  }
  return { model: config.model, created: new Date().toISOString(), summary: summarize(records), records };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const configPath = process.argv[2] ?? 'secrets/token-survival.json';
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  const result = await run(config);
  const outDir = config.out_dir ?? 'secrets/token-survival-out';
  mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, `${result.created.replace(/[:.]/g, '-')}.json`);
  writeFileSync(file, JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result.summary, null, 2));
  console.log(`결과: ${file}`);
}
