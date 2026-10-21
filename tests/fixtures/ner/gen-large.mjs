// 큰 합성 NER 셋 생성기(Phase 7-3). 개발 전용이며 런타임 경로에 들어가지 않는다.
// 모든 이름·기관은 음절을 조합한 가상의 것이다. 실제 인물·연락처·식별번호를 쓰지 않는다.
// 사람 300, 기관 300, 이름 없는 문장 300. 고정 seed 라 같은 Node 에서 언제 돌려도 같은 결과가 나온다.
// 실행: node tests/fixtures/ner/gen-large.mjs > tests/fixtures/ner/ner-large.jsonl          (개발용)
//       node tests/fixtures/ner/gen-large.mjs heldout > tests/fixtures/ner/ner-heldout.jsonl (판정용)
// 정답 이름에는 호칭·직함·조사·서술격 조사·법인 표기·부서명을 넣지 않는다(Phase 2 기준, 결정 #107).
// 판정용 셋은 경계 후처리 규칙을 고정한 뒤 만들었다. seed, 문장 틀, 이름·기관 목록, 직함이 개발용과 다르다.
// 개발용 셋으로 후처리를 다듬고 판정용 셋으로만 합격을 판정한다(측정 부풀림 방지).

const HELDOUT = process.argv[2] === 'heldout';
const SEED = HELDOUT ? 20261107 : 20261021;

// mulberry32: 작고 결정적인 PRNG.
let state = SEED >>> 0;
const rand = () => {
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (list) => list[Math.floor(rand() * list.length)];

const ZWSP = '​';
const NFD = (s) => s.normalize('NFD');
// 전각 ASCII(！ 부터 ～). 정규화(NFKC)가 반각으로 되돌린다.
const fullwidth = (s) => [...s].map((c) => (c >= '!' && c <= '~' ? String.fromCodePoint(c.codePointAt(0) + 0xfee0) : c)).join('');

// 마지막 한글 음절에 받침이 있는지. 한글이 아니면 받침 없음으로 본다.
const hasBatchim = (word) => {
  const last = [...word.normalize('NFC')].pop().codePointAt(0);
  return last >= 0xac00 && last <= 0xd7a3 && (last - 0xac00) % 28 !== 0;
};
// 조사 짝: [받침 있을 때, 없을 때]
const josa = (word, [withFinal, without]) => (hasBatchim(word) ? withFinal : without);
const I_GA = ['이', '가'], EUN_NEUN = ['은', '는'], EUL_REUL = ['을', '를'], GWA_WA = ['과', '와'], IRANG = ['이랑', '랑'];
const RO = ['으로', '로'], COPULA = ['이다', '다'], YEYO = ['이에요', '예요'];

const surnames = HELDOUT
  ? ['표', '변', '엄', '원', '천', '방', '공', '현', '함', '석', '선', '설', '마', '길', '연', '위', '김', '이', '박', '최',
    '정', '강', '조', '윤', '장', '임', '한', '오', '서', '신']
  : ['김', '이', '박', '최', '정', '강', '조', '윤', '장', '임', '한', '오', '서', '신', '권', '황', '안', '송',
  '류', '전', '홍', '고', '문', '양', '손', '배', '백', '허', '남', '심', '노', '하', '곽', '성', '차', '주', '우', '구', '민', '진'];
const givens = HELDOUT
  ? ['은서', '시윤', '하준', '서윤', '지안', '유준', '로아', '이준', '아린', '도하', '서아', '우진', '채윤', '민준', '지유',
    '태린', '예서', '하율', '지환', '소율', '다인', '시현', '윤서', '현서', '준우', '나윤', '라희', '은찬', '서하', '루아', '건희',
    '민채', '세린', '한결', '보람', '이안', '재윤', '선우', '아인', '해솔']
  : ['민수', '서연', '지호', '하은', '도윤', '서준', '지우', '수아', '예준', '하린', '시우', '지민', '은우', '유진',
  '현우', '다은', '준서', '채원', '건우', '소윤', '태호', '나래', '가은', '하늘', '현도', '서지', '윤아', '재민', '수빈', '동현',
  '예린', '승우', '민지', '지훈', '혜원', '성민', '유나', '정우', '다현', '준혁', '세아', '주원', '하람', '규리', '시은', '도현',
  '보민', '연우', '태윤', '수현'];
const romanSurnames = HELDOUT
  ? ['Cho', 'Bae', 'Moon', 'Shin', 'Hong', 'Song', 'Oh', 'Lim', 'Ahn', 'Ryu']
  : ['Kim', 'Lee', 'Park', 'Choi', 'Jung', 'Kang', 'Yoon', 'Han', 'Seo', 'Kwon'];
const romanGivens = HELDOUT
  ? ['Eunseo', 'Siyun', 'Hajun', 'Seoyun', 'Jian', 'Yujun', 'Roa', 'Ijun', 'Arin', 'Doha']
  : ['Minsu', 'Seoyeon', 'Jiho', 'Haeun', 'Doyun', 'Seojun', 'Jiwoo', 'Suah', 'Yejun', 'Harin'];
const titles = HELDOUT
  ? ['실장', '차장', '수석', '원장', '소장', '매니저', '이사', '상무', '위원장', '박사', '교수', '본부장']
  : ['팀장', '과장', '대리', '연구원', '교수', '사원', '부장', '주무관', '책임', '선임'];

const orgHeads = HELDOUT
  ? ['한누리', '별빛', '가람', '새솔', '늘해', '하나로', '빛가람', '미소', '다원', '늘품', '소담', '청솔', '해든', '다래',
    '꽃샘', '물빛', '산들', '윤슬', '너울', '아름', '세움', '함께', '바른길', '열매', '초록', '가비', '나래', '노을', '마중', '예담']
  : ['누리별', '가온', '솔빛', '다온', '새온', '하람', '미르', '푸른바다', '한빛', '늘봄', '은하수', '마루', '바름',
  '다솜', '아라', '이음', '해솔', '별하', '라온', '도담', '나린', '온누리', '새벽빛', '푸름', '고운결', '참빛', '한결', '단비',
  '여울', '비채'];
const orgTails = HELDOUT
  ? ['산업', '화학', '통신', '물류', '보험', '카드', '항공', '호텔', '신문', '방송', '출판', '학회', '공사', '공단', '의료원',
    '학원', '연구원', '조합', '은행', '전자']
  : ['테크', '해운', '연구소', '바이오', '전자', '물산', '대학교', '정보기술', '건설', '제약', '은행', '증권', '재단',
  '협회', '병원', '식품', '에너지', '소프트', '디자인', '컨설팅'];
const asciiHeads = HELDOUT
  ? ['QX', 'Hanaro', 'M&C', 'Zeta', 'ONE', 'Orbit', 'P2', 'Lumi']
  : ['ABC', 'K', 'NX', 'J&P', 'SKY', 'DMZ', 'Bluewave', 'Nova'];
const asciiTails = HELDOUT
  ? ['시스템', '물류', '컴퍼니', '그룹', '엔터']
  : ['솔루션즈', '랩스', '시스템즈', '파트너스', '네트웍스'];

// 사람 문장 틀. f 는 (이름) → [글, 이름 시작 위치를 찾을 표면]. 표면은 정답과 같다.
const heldoutPersonTemplates = [
  ['particle', (p) => `${p}${josa(p, I_GA)} 오늘 오전에 출장을 떠났다.`],
  ['particle', (p) => `고객 응대는 ${p}${josa(p, EUN_NEUN)} 맡고 있다.`],
  ['particle', (p) => `${p}에게서 회신이 왔다.`],
  ['particle', (p) => `${p}${josa(p, GWA_WA)} 함께 현장을 점검했다.`],
  ['particle', (p) => `${p}의 휴가 신청서를 승인했다.`],
  ['particle', (p) => `${p}${josa(p, EUL_REUL)} 위원으로 추천합니다.`],
  ['particle', (p) => `${p}부터 차례로 발표하세요.`],
  ['particle', (p) => `${p}처럼 꼼꼼한 사람은 드물다.`],
  ['particle', (p) => `${p}${josa(p, RO)} 담당자를 바꿨다.`],
  ['plain', (p) => `다음 주 당직자 ${p}, 연락은 메신저로.`],
  ['plain', (p) => `보고서 초안을 ${p} 쪽에서 보내왔다.`],
  ['honorific', (p) => `${p}씨는 어제 퇴근이 늦었다.`],
  ['honorific', (p) => `${p}님께서 승인하셨습니다.`],
  ['honorific_spaced', (p) => `${p} 님이 문의를 남겼습니다.`],
  ['title', (p) => { const t = pick(titles); return `${p} ${t}께서 결정하셨다.`; }],
  ['title_attached', (p) => { const t = pick(titles); return `${p}${t}에게 보고했다.`; }],
  ['copula', (p) => `이 문서의 작성자는 ${p}${josa(p, COPULA)}.`],
  ['copula', (p) => `책임자는 ${p}${josa(p, YEYO)}.`],
  ['punctuation', (p) => `[${p}] 출장 보고서를 올렸다.`],
  ['punctuation', (p) => `발신: ${p} / 수신: 전 직원`],
  ['list', (p) => `참석: ${p} 외 2명`],
];

const personTemplates = HELDOUT ? heldoutPersonTemplates : [
  ['particle', (p) => `${p}${josa(p, I_GA)} 내일 회의에 참석합니다.`],
  ['particle', (p) => `어제 ${p}${josa(p, EUL_REUL)} 만났다.`],
  ['particle', (p) => `${p}${josa(p, EUN_NEUN)} 보고서를 제출했다.`],
  ['particle', (p) => `${p}에게 자료를 보내 주세요.`],
  ['particle', (p) => `${p}${josa(p, GWA_WA)} 점심을 먹었다.`],
  ['particle', (p) => `${p}${josa(p, IRANG)} 영화를 봤다.`],
  ['particle', (p) => `${p}의 노트북이 고장 났다.`],
  ['particle', (p) => `${p}께서 말씀하셨다.`],
  ['particle', (p) => `${p}도 그 안에 동의했다.`],
  ['particle', (p) => `${p}한테 들었다.`],
  ['plain', (p) => `이번 건의 담당자는 ${p}입니다.`],
  ['plain', (p) => `참석자 명단 맨 앞에 ${p}의 이름이 있었다.`],
  ['plain', (p) => `회의록 작성은 ${p} 몫이다.`],
  ['honorific', (p) => `${p} 씨에게 연락해 주세요.`],
  ['honorific', (p) => `${p}님, 확인 부탁드립니다.`],
  ['honorific', (p) => `${p}님께 감사 인사를 전했다.`],
  ['title', (p) => { const t = pick(titles); return `${p} ${t}${josa(t, I_GA)} 결재를 요청했다.`; }],
  ['title', (p) => { const t = pick(titles); return `오늘 발표는 ${p} ${t}${josa(t, I_GA)} 맡았다.`; }],
  ['title_attached', (p) => { const t = pick(titles); return `${p}${t}${josa(t, GWA_WA)} 일정을 논의했다.`; }],
  ['title_digit', (p) => `${p}${1 + Math.floor(rand() * 9)}팀장과 배포 일정을 맞췄다.`],
  ['punctuation', (p) => `「${p}」라는 이름으로 예약했다.`],
  ['punctuation', (p) => `"${p}" 앞으로 소포가 왔습니다.`],
  ['punctuation', (p) => `문의: 담당 ${p}(내선 없음)`],
];

const heldoutOrgTemplates = [
  ['particle', (o) => `${o}${josa(o, EUN_NEUN)} 올해 신입 사원을 뽑는다.`],
  ['particle', (o) => `${o}${josa(o, GWA_WA)} 업무 협약을 체결했다.`],
  ['particle', (o) => `${o}에서 채용 공고를 냈다.`],
  ['particle', (o) => `${o}${josa(o, RO)}부터 공문이 왔다.`],
  ['particle', (o) => `${o}${josa(o, I_GA)} 감사 결과를 공개했다.`],
  ['plain', (o) => `${o} 소속 직원이 방문했다.`],
  ['department', (o) => `${o} 고객센터에 문의했다.`],
  ['department', (o) => `${o} 영업본부가 실적을 발표했다.`],
  ['prefix', (o) => `㈜${o}의 감사 보고서를 받았다.`],
  ['prefix', (o) => `재단법인 ${o}${josa(o, I_GA)} 장학금을 지급했다.`],
  ['punctuation', (o) => `[${o}] 보도자료를 배포했다.`],
];

const orgTemplates = HELDOUT ? heldoutOrgTemplates : [
  ['particle', (o) => `${o}${josa(o, I_GA)} 신제품을 출시했다.`],
  ['particle', (o) => `${o}${josa(o, GWA_WA)} 공급 계약을 맺었다.`],
  ['particle', (o) => `우리 팀은 ${o}에 다닌다.`],
  ['particle', (o) => `${o}의 분기 실적이 발표됐다.`],
  ['particle', (o) => `${o}${josa(o, EUN_NEUN)} 본사를 이전했다.`],
  ['particle', (o) => `다음 주에 ${o}${josa(o, EUL_REUL)} 방문한다.`],
  ['plain', (o) => `${o} 보안팀에서 점검을 나왔다.`],
  ['plain', (o) => `협력사 목록에 ${o} 이름을 추가했다.`],
  ['prefix', (o) => `(주)${o} 대표이사 명의로 공문을 보냈다.`],
  ['prefix', (o) => `주식회사 ${o}에서 견적서를 받았다.`],
  ['punctuation', (o) => `「${o}」 담당자 회의가 있다.`],
];

// 이름 없는 문장. 이름처럼 보이는 일반 낱말(하늘, 바다 등), 직함만 있는 문장, 기관 일반명사를 섞는다.
const negSubjects = HELDOUT
  ? ['산업 동향은', '보험 약관은', '카드 사용 내역은', '별빛이', '미소가', '소담한 마당은', '팀장 회의는', '고객센터 운영 시간은',
    '출판 일정은', '항공 운항 정보는', '호텔 예약은', '학회 발표 순서는', '본부 정기 회의는', '원장 직무 대행은', '물류 창고 점검은',
    '통신 장애 공지는', '노을이', '초록 숲길은', '열매가', '공사 구간 안내는']
  : ['오늘 회의는', '팀장님이', '담당자는', '연구소 이전은', '하늘이', '바다가', '보안 점검은', '새 정책은',
  '대학교 입학 설명회는', '본사 이전 일정은', '고객님 문의는', '분기 보고서는', '사내 메신저 공지는', '서버 장애는', '은행 점검 시간은',
  '병원 예약 시스템은', '협회 정기 총회는', '재단 이사회는', '기쁨과 보람은', '새벽 배송은'];
const negPredicates = HELDOUT
  ? ['지난달과 같다.', '홈페이지에 올라와 있다.', '유난히 아름다웠다.', '내일까지 확정된다.', '변동 없이 유지된다.',
    '다시 공지할 예정이다.', '모두 끝났다.', '조금 늦어질 수 있다.', '새로 정리했다.', '회의에서 다룬다.', '아직 검토 중이다.',
    '두 시간 걸렸다.', '예상보다 길어졌다.', '지난 분기보다 줄었다.', '문제없이 마쳤다.']
  : ['오후 3시에 시작합니다.', '다음 주까지 공유하겠습니다.', '맑고 푸르다.', '이번 달 말로 미뤄졌다.',
  '내일 다시 확인해 주세요.', '아직 결정되지 않았다.', '모두에게 안내되었다.', '예정대로 진행된다.', '두 번째 안으로 정했다.',
  '문서로 남겨 두었다.', '검토가 더 필요하다.', '지난주보다 빨라졌다.', '변경 사항이 없다.', '다시 점검하기로 했다.', '잘 마무리되었다.'];

const enc = new TextEncoder();
const cpLen = (s) => [...s].length;
const records = [];
const seen = new Set();

const add = (id, category, variant, text, entities) => {
  if (seen.has(text)) return false;
  seen.add(text);
  const out = entities.map(([type, surface]) => {
    const idx = text.indexOf(surface);
    if (idx < 0) throw new Error(`${id}: ${surface} 없음`);
    const pre = text.slice(0, idx);
    const sb = enc.encode(pre).length;
    return { type, text: surface, start_byte: sb, end_byte: sb + enc.encode(surface).length, start_cp: cpLen(pre), end_cp: cpLen(pre) + cpLen(surface) };
  });
  records.push({ id, category, variant, text, entities: out });
  return true;
};

// 사람: 10 % 영문 이름, 6 % NFD, 4 % 이름 안 zero-width, 나머지 한글 이름.
let n = 0;
while (n < 300) {
  const [variant, template] = pick(personTemplates);
  const r = rand();
  let name;
  let nameVariant = variant;
  if (r < 0.10) {
    name = `${pick(romanGivens)} ${pick(romanSurnames)}`;
    nameVariant = 'english';
  } else {
    name = pick(surnames) + pick(givens);
    if (r < 0.16) {
      name = NFD(name);
      nameVariant = 'nfd';
    } else if (r < 0.20) {
      const chars = [...name];
      name = chars[0] + ZWSP + chars.slice(1).join('');
      nameVariant = 'zero_width';
    }
  }
  if (add(`${HELDOUT ? 'h-' : ''}person-${String(n + 1).padStart(3, '0')}`, 'person', nameVariant, template(name), [['PERSON', name]])) n += 1;
}

// 기관: 15 % 영문 섞인 이름, 그중 절반은 전각.
n = 0;
while (n < 300) {
  const [variant, template] = pick(orgTemplates);
  let org;
  let orgVariant = variant;
  if (rand() < 0.15) {
    org = pick(asciiHeads) + pick(asciiTails);
    orgVariant = 'ascii';
    if (rand() < 0.5) {
      org = fullwidth(org);
      orgVariant = 'fullwidth';
    }
  } else {
    org = pick(orgHeads) + pick(orgTails);
  }
  if (add(`${HELDOUT ? 'h-' : ''}org-${String(n + 1).padStart(3, '0')}`, 'organization', orgVariant, template(org), [['ORG', org]])) n += 1;
}

n = 0;
while (n < 300) {
  const text = `${pick(negSubjects)} ${pick(negPredicates)}`;
  const longer = rand() < 0.3 ? `${text} ${pick(negSubjects)} ${pick(negPredicates)}` : text;
  if (add(`${HELDOUT ? 'h-' : ''}neg-${String(n + 1).padStart(3, '0')}`, 'negative', 'plain', longer, [])) n += 1;
}

for (const r of records) console.log(JSON.stringify(r));
