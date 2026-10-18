// token 보존율 측정의 순수 함수: 합성 사례 만들기, 요청 본문, 응답 판정, 요약.
// token 형식은 ADR 0008(⟦LABEL_R⟧, R 은 Crockford base32 대문자 10자)과 같다.

export const OPEN = '⟦';
export const CLOSE = '⟧';
export const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// 모델에게 표시를 그대로 옮기라고 알려 주는 시스템 안내(조건 hint).
export const HINT = '⟦ 와 ⟧ 로 감싼 표시는 이름 대신 쓴 자리표시입니다. 글자 하나도 바꾸지 말고 그대로 옮겨 쓰세요.';

// 같은 seed 면 같은 사례가 나오도록 하는 결정적 난수(mulberry32).
export function rng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function makeToken(label, next) {
  let random = '';
  for (let i = 0; i < 10; i += 1) random += ALPHABET[Math.floor(next() * ALPHABET.length)];
  return `${OPEN}${label}_${random}${CLOSE}`;
}

const TASKS = [
  { id: 'summary', text: '다음 글을 두 문장으로 요약해 주세요.' },
  { id: 'reply', text: '다음 메일에 정중한 답장을 써 주세요.' },
  { id: 'list', text: '다음 내용에서 할 일을 목록으로 정리해 주세요.' },
  { id: 'translate', text: '다음 글을 영어로 번역해 주세요.' },
  { id: 'rewrite', text: '다음 글을 공문 문체로 다시 써 주세요.' },
];

// 자리표시 {LABEL} 를 token 으로 바꾼다. 같은 문장 안 같은 이름은 같은 token 을 쓴다.
const TEMPLATES = [
  '{PERSON} 과장이 {ORGANIZATION} 회의 결과를 {EMAIL} 로 보내 달라고 했습니다.',
  '{PERSON} 주무관은 다음 주 {INTERNAL_TERM} 점검 일정을 {KOREAN_PHONE} 으로 알려 주었습니다.',
  '{ORGANIZATION} 담당자 {PERSON} 님과 {PERSON2} 님이 예산 자료를 검토했습니다.',
  '{PERSON} 님, {INTERNAL_TERM} 관련 질의는 {EMAIL} 로 회신 바랍니다.',
  '{ORGANIZATION} 의 사업자등록번호는 {KOREAN_BUSINESS_NO} 이고, 접속 기록에는 {IP_ADDRESS} 가 남았습니다.',
  '어제 {PERSON} 팀장이 {PERSON2} 주무관에게 {ORGANIZATION} 보고서를 넘겼습니다. {PERSON} 팀장은 금요일까지 의견을 달라고 했습니다.',
  '{INTERNAL_TERM} 시스템 장애 문의는 {PERSON} 대리({KOREAN_PHONE})에게 하면 됩니다.',
  '{ORGANIZATION} 와 {ORGANIZATION2} 가 공동으로 {INTERNAL_TERM} 설명회를 엽니다. 신청은 {EMAIL}.',
];

export function buildCases({ count = 40, seed = 20261018 } = {}) {
  const next = rng(seed);
  const cases = [];
  for (let i = 0; i < count; i += 1) {
    const template = TEMPLATES[i % TEMPLATES.length];
    const task = TASKS[Math.floor(i / TEMPLATES.length) % TASKS.length];
    const tokens = new Map();
    const body = template.replace(/\{([A-Z_]+?)(2?)\}/g, (_, label, suffix) => {
      const key = label + suffix;
      if (!tokens.has(key)) tokens.set(key, makeToken(label, next));
      return tokens.get(key);
    });
    cases.push({ id: `c${String(i + 1).padStart(2, '0')}-${task.id}`, prompt: `${task.text}\n\n${body}`, tokens: [...tokens.values()] });
  }
  return cases;
}

// Chat Completions 호환 본문. temperature·top_p 는 보내지 않는다(일부 서비스가 최신 모델에서 거절).
export function requestBody({ model, maxTokens, hint, prompt }) {
  const messages = [];
  if (hint) messages.push({ role: 'system', content: HINT });
  messages.push({ role: 'user', content: prompt });
  return { model, messages, max_completion_tokens: maxTokens };
}

// 응답 본문에서 첫 choice 의 글자를 꺼낸다(content 가 문자열이거나 text part 배열).
export function responseText(json) {
  const content = json?.choices?.[0]?.message?.content;
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map((part) => (typeof part?.text === 'string' ? part.text : '')).join('');
  return null;
}

const squeeze = (text) => text.replace(/\s+/g, '');

// token 하나가 응답에 어떤 모양으로 남았는가. 앞쪽 판정이 이긴다.
export function classify(token, response) {
  const inner = token.slice(OPEN.length, -CLOSE.length);
  const random = inner.slice(inner.lastIndexOf('_') + 1);
  if (response.includes(token)) return 'exact';
  if (response.toLowerCase().includes(token.toLowerCase())) return 'case';
  if (response.includes(inner)) return 'bracket';
  if (squeeze(response).includes(token) || squeeze(response).includes(inner)) return 'spacing';
  if (response.toUpperCase().includes(random)) return 'label';
  return 'missing';
}

// 입력에 없던 token 모양(지어낸 token).
export function inventedTokens(response, expected) {
  const pattern = new RegExp(`${OPEN}[A-Z][A-Z0-9_]{0,23}_[${ALPHABET}]{10}${CLOSE}`, 'g');
  return [...new Set(response.match(pattern) ?? [])].filter((t) => !expected.includes(t));
}

export const CLASSES = ['exact', 'case', 'bracket', 'spacing', 'label', 'missing'];

// 조건별 요약. 보존률은 누락을 뺀 것(답에 어떤 모양으로든 남은 token) 기준과 전체 기준을 함께 낸다.
export function summarize(records) {
  const byCondition = {};
  for (const record of records) {
    const s = (byCondition[record.condition] ??= { calls: 0, failed: 0, tokens: 0, invented: 0, counts: Object.fromEntries(CLASSES.map((c) => [c, 0])) });
    s.calls += 1;
    if (record.error) {
      s.failed += 1;
      continue;
    }
    s.invented += record.invented.length;
    for (const cls of Object.values(record.classes)) {
      s.tokens += 1;
      s.counts[cls] += 1;
    }
  }
  for (const s of Object.values(byCondition)) {
    const present = s.tokens - s.counts.missing;
    s.exact_rate_present = present ? s.counts.exact / present : null;
    s.exact_rate_all = s.tokens ? s.counts.exact / s.tokens : null;
  }
  return byCondition;
}
