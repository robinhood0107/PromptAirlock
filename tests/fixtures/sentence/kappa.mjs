// 봉인 판정 셋의 정답 일치도(Cohen kappa) 계산(docs/sentence-eval/writing-guide.md 5절).
// 실행: node tests/fixtures/sentence/kappa.mjs 정답A.jsonl 정답B.jsonl
//       node tests/fixtures/sentence/kappa.mjs --self-check
// 12개 정답(범주 11 + None)의 kappa 와 "민감 여부" 두 갈래 kappa, 갈린 문장의 id 를 낸다. 문장 내용은 읽지 않는다.
import { readFileSync } from 'node:fs';

const LABELS = ['Health', 'Belief', 'LaborUnion', 'PoliticalParty', 'PoliticalView', 'SexLife', 'Genetic', 'Criminal', 'Biometric',
  'Ethnicity', 'Credential', 'None'];

export const kappa = (a, b) => {
  const n = a.length;
  const agree = a.filter((x, i) => x === b[i]).length / n;
  const kinds = [...new Set([...a, ...b])];
  const chance = kinds.reduce((s, k) => s + (a.filter((x) => x === k).length / n) * (b.filter((x) => x === k).length / n), 0);
  return chance === 1 ? 1 : (agree - chance) / (1 - chance);
};

const load = (path) => {
  const m = new Map();
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    const { id, label } = JSON.parse(line);
    if (!LABELS.includes(label)) throw new Error(`모르는 정답 "${label}" (${id})`);
    if (m.has(id)) throw new Error(`id 가 두 번: ${id}`);
    m.set(id, label);
  }
  return m;
};

if (process.argv[2] === '--self-check') {
  // 손으로 계산한 예: 10개 중 8개 일치, A 는 민감 5·정상 5, B 는 민감 5·정상 5 -> 우연 일치 0.5, kappa 0.6.
  const a = ['Health', 'Health', 'Health', 'Health', 'Health', 'None', 'None', 'None', 'None', 'None'];
  const b = ['Health', 'Health', 'Health', 'Health', 'None', 'Health', 'None', 'None', 'None', 'None'];
  const k = kappa(a, b);
  if (Math.abs(k - 0.6) > 1e-12) throw new Error(`self-check ${k}`);
  if (kappa(a, a) !== 1) throw new Error('self-check identical');
  console.log('ok');
} else {
  const [fa, fb] = process.argv.slice(2);
  const a = load(fa);
  const b = load(fb);
  const ids = [...a.keys()];
  if (ids.length !== b.size || ids.some((id) => !b.has(id))) throw new Error('두 파일의 id 가 다르다');
  const la = ids.map((id) => a.get(id));
  const lb = ids.map((id) => b.get(id));
  const bin = (l) => l.map((x) => (x === 'None' ? 'None' : 'Sensitive'));
  const diff = ids.filter((id) => a.get(id) !== b.get(id));
  console.log(`n ${ids.length}, agree ${ids.length - diff.length}`);
  console.log(`kappa 12-way ${kappa(la, lb).toFixed(4)}, kappa sensitive-or-not ${kappa(bin(la), bin(lb)).toFixed(4)} (need >= 0.8)`);
  console.log(`disagree ids: ${diff.join(' ')}`);
}
