#!/usr/bin/env node
// token 보존율 측정 실행기. 설정 파일(기본 secrets/token-survival.json)을 읽어 Chat Completions 호환 주소로
// 합성 사례를 보내고, token 판정 결과를 out 폴더에 JSON 으로 남긴다. 자격 증명과 인증 헤더는 출력하지 않는다.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { buildCases, classify, inventedTokens, requestBody, responseText, summarize } from './lib.mjs';

// 인증: bearer-env(환경 변수의 키), bearer-file(파일의 키), gcloud(application-default access token, 45분마다 갱신).
export function makeAuth(auth, env = process.env) {
  if (auth?.type === 'bearer-env') {
    const key = env[auth.env];
    if (!key) throw new Error(`환경 변수 ${auth.env} 가 비어 있다`);
    return () => key;
  }
  if (auth?.type === 'bearer-file') {
    const key = readFileSync(auth.path, 'utf8').trim();
    if (!key) throw new Error(`${auth.path} 가 비어 있다`);
    return () => key;
  }
  if (auth?.type === 'gcloud') {
    let token = null;
    let fetchedAt = 0;
    return () => {
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
  throw new Error('auth.type 은 bearer-env, bearer-file, gcloud 중 하나다');
}

async function post(url, body, bearer, { retries = 3, fetchImpl = fetch } = {}) {
  for (let attempt = 0; ; attempt += 1) {
    const response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${bearer()}` },
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

export async function run(config, { env = process.env, log = console.log, fetchImpl = fetch } = {}) {
  const bearer = makeAuth(config.auth, env);
  const cases = buildCases({ count: config.cases ?? 40, seed: config.seed ?? 20261018 });
  const conditions = config.conditions ?? ['plain', 'hint'];
  const records = [];
  for (const condition of conditions) {
    for (const item of cases) {
      const body = requestBody({ model: config.model, maxTokens: config.max_tokens ?? 1024, hint: condition === 'hint', prompt: item.prompt });
      const record = { id: item.id, condition, tokens: item.tokens };
      try {
        const text = responseText(await post(config.endpoint, body, bearer, { fetchImpl }));
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
