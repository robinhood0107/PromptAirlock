#!/usr/bin/env node
// 게이트웨이를 거친 실제 provider 왕복 측정(Phase 10-2). 합성 원문을 실행 중인 게이트웨이로 차례로 보내고,
// 게이트웨이 감사 기록의 외부 전송 본문(egress)과 복원 전 답(egress_answer)으로 token 보존율을 잰다(lib.mjs 의 같은 채점).
// 원문 값이 밖으로 나갔는지(egress 에 원문이 있는지)와 게이트웨이 결과(복원, 거절 사유)도 센다.
// 사용: node spikes/token-survival/gateway.mjs <설정.json>
//   설정: gateway(주소), ca(게이트웨이 인증서 PEM), token_file(출처 token), audit_dir, out_dir, model, max_tokens,
//         cases, seed, conditions(["plain","hint"]), internal_terms(게이트웨이 설정과 같게)
// 원문·답은 out_dir(저장소 밖 secrets/)에만 쓰고 화면에는 개수와 비율만 낸다.
import { readdirSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { CLOSE, HINT, OPEN, TASKS, TEMPLATES, classify, inventedTokens, responseText, rng, summarize } from './lib.mjs';

const PEOPLE = ['김서준', '박하린', '이도윤', '최지아', '정시우', '강예린', '조하준', '윤서아', '장민재', '임채원'];
const ORGS = ['가람물산', '누리정보통신', '한결산업', '온새미건설', '다솜제약', '새봄유통'];

// 사업자등록번호 검증 숫자(가중치 1,3,7,1,3,7,1,3,5).
export function businessNumber(next) {
  const d = Array.from({ length: 9 }, (_, i) => (i === 0 ? 1 + Math.floor(next() * 9) : Math.floor(next() * 10)));
  const w = [1, 3, 7, 1, 3, 7, 1, 3, 5];
  const sum = d.reduce((s, x, i) => s + x * w[i], 0) + Math.floor((d[8] * 5) / 10);
  const check = (10 - (sum % 10)) % 10;
  const s = [...d, check].join('');
  return `${s.slice(0, 3)}-${s.slice(3, 5)}-${s.slice(5)}`;
}

// lib.mjs 의 사례 틀에 token 대신 합성 원문을 넣는다. 같은 사례 안 같은 자리는 같은 값.
export function buildRawCases({ count, seed, internalTerms }) {
  const next = rng(seed);
  const pick = (list) => list[Math.floor(next() * list.length)];
  const digits = (n) => Array.from({ length: n }, () => Math.floor(next() * 10)).join('');
  const make = {
    PERSON: () => pick(PEOPLE),
    ORGANIZATION: () => pick(ORGS),
    EMAIL: () => `user${digits(4)}@example.com`,
    KOREAN_PHONE: () => `010-${digits(4)}-${digits(4)}`,
    INTERNAL_TERM: () => pick(internalTerms),
    KOREAN_BUSINESS_NO: () => businessNumber(next),
    IP_ADDRESS: () => `203.0.113.${1 + Math.floor(next() * 254)}`,
  };
  const cases = [];
  for (let i = 0; i < count; i += 1) {
    const template = TEMPLATES[i % TEMPLATES.length];
    const task = TASKS[Math.floor(i / TEMPLATES.length) % TASKS.length];
    const values = new Map();
    const body = template.replace(/\{([A-Z_]+?)(2?)\}/g, (_, label, suffix) => {
      const key = label + suffix;
      if (!values.has(key)) {
        let v;
        do v = make[label](); while ([...values.values()].includes(v));  // 두 사람·두 기관이 같은 값이 되지 않게
        values.set(key, v);
      }
      return values.get(key);
    });
    cases.push({ id: `g${String(i + 1).padStart(3, '0')}-${task.id}`, prompt: `${task.text}\n\n${body}`, values: [...values.values()] });
  }
  return cases;
}

// 감사 기록(시간 순)을 요청 단위로 묶는다. 요청을 하나씩 차례로 보냈으므로 k 번째 request 기록이 k 번째 사례다.
export function groupAudit(records) {
  const byId = new Map();
  const order = [];
  for (const r of records) {
    const id = r.request_id;
    if (!id) continue;
    if (!byId.has(id)) byId.set(id, {});
    const g = byId.get(id);
    if (r.kind === 'egress') g.sent = r.sent;
    if (r.kind === 'egress_answer') g.answer = r.answer;
    if (r.kind === 'request') {
      g.status = r.status;
      g.reason = r.reason ?? null;
      order.push(g);
    }
  }
  return order;
}

function readAudit(dir) {
  const records = [];
  for (const name of readdirSync(dir).filter((n) => /^audit-\d{4}-\d{2}-\d{2}\.jsonl$/.test(n)).sort()) {
    for (const line of readFileSync(path.join(dir, name), 'utf8').split('\n')) {
      if (!line.trim()) continue;
      const r = JSON.parse(line);
      if (r.kind) records.push(r);
    }
  }
  return records;
}

function post(url, body, { ca, token }) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = https.request(url, {
      method: 'POST', ca,
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, 'content-length': Buffer.byteLength(data) },
    }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { text += c; });
      res.on('end', () => resolve({ status: res.statusCode, text }));
    });
    req.on('error', reject);
    req.end(data);
  });
}

const tokenPattern = new RegExp(`${OPEN}[A-Z][A-Z0-9_]{0,23}_[0-9A-Z]{10}${CLOSE}`, 'g');

export async function run(config, { log = console.log } = {}) {
  const ca = readFileSync(config.ca);
  const token = readFileSync(config.token_file, 'utf8').trim();
  const before = readAudit(config.audit_dir).length;
  const cases = buildRawCases({ count: config.cases, seed: config.seed, internalTerms: config.internal_terms });
  const sent = [];
  for (const c of cases) {
    for (const condition of config.conditions) {
      const messages = condition === 'hint' ? [{ role: 'system', content: HINT }] : [];
      messages.push({ role: 'user', content: c.prompt });
      const started = Date.now();
      let reply;
      try {
        reply = await post(config.gateway, { model: config.model, messages, max_tokens: config.max_tokens }, { ca, token });
      } catch (e) {
        reply = { status: 0, text: String(e.code ?? e.message) };
      }
      sent.push({ id: c.id, condition, values: c.values, ms: Date.now() - started, ...reply });
      if (sent.length % 20 === 0) log(`${sent.length}/${cases.length * config.conditions.length}`);
    }
  }
  const groups = groupAudit(readAudit(config.audit_dir).slice(before));
  if (groups.length !== sent.length) throw new Error(`감사 기록 요청 ${groups.length} 개와 보낸 요청 ${sent.length} 개가 다르다`);
  const records = sent.map((s, k) => {
    const g = groups[k];
    const egress = g.sent ? JSON.stringify(g.sent) : '';
    const tokens = [...new Set(egress.match(tokenPattern) ?? [])];
    const leaked = s.values.filter((v) => egress.includes(v));
    const raw = g.answer ? responseText(JSON.parse(g.answer)) : null;
    let final = null;
    try { final = s.status === 200 ? responseText(JSON.parse(s.text)) : null; } catch { final = null; }
    const record = {
      id: s.id, condition: s.condition, ms: s.ms, status: s.status, reason: g.reason, sent: g.sent ?? null, answer: raw, final,
      tokens: tokens.length, leaked, error: raw == null ? `no answer (${g.reason ?? s.status})` : null,
      classes: {}, invented: [],
      final_has_token_mark: final != null && (final.includes(OPEN) || final.includes(CLOSE)),
      restored_values: final == null ? 0 : s.values.filter((v) => final.includes(v)).length,
    };
    if (raw != null) {
      for (const t of tokens) record.classes[t] = classify(t, raw);
      record.invented = inventedTokens(raw, tokens);
    }
    return record;
  });
  const summary = summarize(records);
  const outcomes = {};
  for (const r of records) {
    const key = `${r.condition} ${r.status}${r.reason ? ` ${r.reason}` : ''}`;
    outcomes[key] = (outcomes[key] ?? 0) + 1;
  }
  const leaks = records.reduce((n, r) => n + r.leaked.length, 0);
  const ms = records.map((r) => r.ms).sort((a, b) => a - b);
  const pct = (p) => ms[Math.min(ms.length - 1, Math.floor((p / 100) * ms.length))];
  const result = {
    summary, outcomes,
    leaked_values: leaks,
    values_sent: sent.reduce((n, s) => n + s.values.length, 0),
    final_with_token_mark: records.filter((r) => r.final_has_token_mark).length,
    round_trip_ms: { p50: pct(50), p95: pct(95), max: ms.at(-1) },
  };
  mkdirSync(config.out_dir, { recursive: true });
  const file = path.join(config.out_dir, `gateway-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  writeFileSync(file, JSON.stringify({ config: { ...config, token_file: undefined }, result, records }, null, 1));
  log(JSON.stringify(result, null, 1));
  log(`결과: ${file}`);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  run(config).catch((e) => { console.error(e.message); process.exit(1); });
}
