// 기관 정책 묶음 합성 셋 생성기(Phase 11-2). 개발 전용이며 런타임 경로에 들어가지 않는다.
// 번호와 문장은 모두 지어낸 것이다. 실제 기관·사람·문서를 쓰지 않는다.
// 실행: node tests/fixtures/institution/gen-institution.mjs dev   > tests/fixtures/institution/institution-dev.jsonl
//       node tests/fixtures/institution/gen-institution.mjs judge > tests/fixtures/institution/institution-judge.jsonl
// 개발용과 판정용은 seed 와 문장 틀이 모두 다르다(틀 단위 분리). 판정용 셋은 11-3 판정에 한 번만 쓴다.
//
// 무리(group)와 기대:
//   conf         기밀 표지어 + 업종 대상어, 같은 문장           confidential true
//   conf_split   표지어 문장 바로 다음 문장에 대상어            confidential true
//   conf_para    표지어 + 대상을 사전에 없는 말로 바꿔 말함      confidential true(규칙의 한계를 재려고 둔다)
//   far          표지어와 대상어 사이에 문장 하나               confidential false
//   marker_only  표지어만                                      confidential false
//   subject_only 대상어만                                      confidential false
//   business     둘 다 없는 업무 문장(번호 포함)                confidential false, ids []
//   id           업종 표지어 + 번호                            ids [번호]
//   id_neg       표지어만 또는 표지어 없는 번호                 ids []

const MODE = process.argv[2];
if (MODE !== 'dev' && MODE !== 'judge') throw new Error('사용: gen-institution.mjs dev|judge');
const DEV = MODE === 'dev';

let state = (DEV ? 20261102 : 20261215) >>> 0;
const rand = () => {
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (list) => list[Math.floor(rand() * list.length)];
const digits = (n) => Array.from({ length: n }, () => Math.floor(rand() * 10)).join('');
const batchim = (word) => {
  const c = [...word].pop().codePointAt(0);
  return c >= 0xac00 && c <= 0xd7a3 ? (c - 0xac00) % 28 !== 0 : /[0-9]$/.test(word) ? !/[2459]$/.test(word) : false;
};
const josa = (word, withB, without) => word + (batchim(word) ? withB : without);

const MARKERS = ['대외비', '비공개', '미공개', '내부 검토용', '내부용', '사내 한정', '외부 유출 금지', '유출 금지', '공개 금지',
  '배포 금지', '열람 제한', '취급 주의', '보안 문서', '비밀 문서', '기밀', '극비', '엠바고', 'Confidential', 'Internal only'];

// 대상어는 src/detect/data/confidential_terms.hpp 와 같은 말(띄어 쓴 꼴), 바꿔 말한 것(para)은 사전에 없는 말.
const INDUSTRIES = {
  'public-admin': {
    subjects: ['예산 편성안', '예산안 초안', '인사 발령안', '감사 결과', '감사 보고서', '입찰 예정가', '예정가격', '보도자료 초안', '도시계획안', '징계 의결'],
    para: ['내년도 살림 계획 초안', '다음 달 자리 이동 명단', '공사 낙찰 기준 금액'],
    labels: ['민원접수번호', '민원번호', '접수번호', '신청번호', '관리번호', '고지번호', '전자납부번호', '과세번호'],
  },
  'public-enterprise': {
    subjects: ['입찰 예정가', '예정가격', '계약 단가', '협상 전략', '요금 인상안', '사업 계획안', '감사 결과'],
    para: ['다음 분기 요금 조정 방향', '협력사 납품 가격표', '협상 때 물러설 선'],
    labels: ['고객번호', '계약번호', '발주번호', '사업번호', '검침번호', '관리번호'],
  },
  hospital: {
    subjects: ['의료사고', '임상시험 결과', '감염 발생', '수가 협상', '의료분쟁'],
    para: ['수술 중 생긴 사고 경위', '신약 시험 중간 성적', '병동 집단 감염 보고'],
    labels: ['차트번호', '환자번호', '환자등록번호', '진료번호', '병록번호', '의무기록번호', '처방번호', '검체번호', '진료카드번호'],
  },
  'human-resources': {
    subjects: ['구조조정', '희망퇴직', '해고 대상', '임금 협상안', '연봉 협상', '인사 평가 결과', '징계 대상', '노조 교섭'],
    para: ['감원 대상 부서 명단', '내년 급여 인상 폭 초안', '퇴직 권유 명단'],
    labels: ['사번', '사원번호', '직원번호', '직번', '인사번호', '임직원번호', '공무원증번호'],
  },
  bank: {
    subjects: ['인수합병', '잠정 실적', '실적 발표 전', '신용등급', '여신 심사', '대출 심사 결과', '부실 채권', '유상증자', '상장 계획'],
    para: ['경쟁 은행 합병 협상', '이번 분기 순이익 예상치', '거래처 부도 위험 등급'],
    labels: ['여신번호', '대출번호', '고객번호', '고객관리번호', '거래번호', '신청번호', '심사번호', '계약번호', 'CIF'],
  },
  card: {
    subjects: ['잠정 실적', '수수료 인상안', '가맹점 수수료율', '제휴 협상', '인수합병'],
    para: ['다음 달 가맹점 요율 조정', '항공사와 묶음 상품 협의'],
    labels: ['승인번호', '가맹점번호', '회원번호', '고객번호', '신청번호'],
  },
  insurance: {
    subjects: ['손해율', '보험금 지급 심사', '인수 심사', '잠정 실적', '인수합병', '요율 인상안'],
    para: ['자동차 보험료 조정 계획', '청구 건 지급 거절 기준'],
    labels: ['증권번호', '보험증권번호', '계약번호', '청구번호', '사고접수번호', '사고번호', '접수번호'],
  },
};

const VALUES = [
  () => digits(8),
  () => `${pick(['LN', 'HR', 'PL', 'CL', 'AC'])}-2026-${digits(5)}`,
  () => `${pick(['A', 'K', 'M', 'P'])}${digits(6)}`,
  () => `2026-${digits(6)}`,
  () => digits(10),
];

const FRAMES = DEV ? {
  conf: [
    (m, s) => `${m} ${s} 자료를 요약해 줘.`,
    (m, s) => `다음은 ${josa(m, '인', '인')} ${s} 내용입니다. 핵심만 뽑아 주세요.`,
    (m, s) => `${s} 관련 ${m} 문서를 표로 정리해 주세요.`,
    (m, s) => `이 ${s} 초안은 ${josa(m, '이니', '니')} 문장을 다듬어 줘.`,
  ],
  conf_split: [
    (m, s) => `이 문서는 ${josa(m, '입니다', '입니다')}. ${josa(s, '을', '를')} 세 줄로 정리해 주세요.`,
    (m, s) => `${m} 표시가 된 자료예요. ${s} 일정만 알려 줘.`,
  ],
  far: [
    (m, s) => `${m} 문서 관리 규정을 알려 줘. 오늘 회의는 3시입니다. ${s} 관련 기사 요약도 부탁해.`,
  ],
  marker_only: [
    (m) => `${m} 문서는 외부 서비스에 올리지 마세요.`,
    (m) => `${m} 표시는 문서 첫 장 위쪽에 붙입니다.`,
    (m) => `${m} 자료의 보관 기간을 알려 줘.`,
  ],
  subject_only: [
    (s) => `${s}의 일반적인 절차를 설명해 줘.`,
    (s) => `${s} 관련 법령을 찾아 줘.`,
    (s) => `${s} 기사들을 요약해 줘.`,
  ],
  id: [
    (l, v) => `${l}: ${v} 건을 처리해 줘.`,
    (l, v) => `${josa(l, '은', '는')} ${v} 입니다. 진행 상황을 알려 주세요.`,
    (l, v) => `${l} ${v} 의 담당자를 찾아 줘.`,
  ],
  id_neg: [
    (l) => `${josa(l, '을', '를')} 어디서 확인하나요?`,
    (l) => `${l} 발급 절차를 알려 줘.`,
    (_, v) => `주문 ${v} 건의 배송을 확인해 줘.`,
  ],
} : {
  conf: [
    (m, s) => `[${m}] ${s} 검토 메모를 간단히 줄여 주세요.`,
    (m, s) => `${s} 문서인데 ${josa(m, '이라', '라')} 조심해야 해요. 요점만 써 줘.`,
    (m, s) => `${m}로 분류된 ${s} 파일 내용을 영어로 옮겨 줘.`,
  ],
  conf_split: [
    (m, s) => `첨부는 ${m} 자료입니다. 그 안의 ${s} 숫자를 확인해 줘.`,
    (m, s) => `${m} 등급 보고서예요. ${s} 부분을 표로 바꿔 주세요.`,
  ],
  far: [
    (m, s) => `${m} 등급 분류 기준이 궁금해요. 점심은 뭐 먹을까요? ${s} 뉴스도 찾아 줘.`,
  ],
  marker_only: [
    (m) => `${m} 등급 분류 기준이 궁금해요.`,
    (m) => `${m} 자료를 출력할 때 주의할 점은?`,
    (m) => `직원 교육 자료에 ${m} 표시 예시를 넣어 줘.`,
  ],
  subject_only: [
    (s) => `${s}에 대해 신문 기사에 나온 내용을 정리해 줘.`,
    (s) => `${s} 용어 뜻을 쉽게 풀어 줘.`,
    (s) => `다른 나라의 ${s} 사례를 알려 줘.`,
  ],
  id: [
    (l, v) => `${l}(${v}) 고객 응대 기록을 정리해 줘.`,
    (l, v) => `확인 요청: ${l}=${v}`,
    (l, v) => `${josa(l, '이', '가')} ${v} 인 건 서류를 찾아 줘.`,
  ],
  id_neg: [
    (l) => `${l} 체계는 어떻게 바뀌었나요?`,
    (l) => `${josa(l, '이', '가')} 몇 자리인지 알려 줘.`,
    (_, v) => `회의실 예약 ${v} 건을 취소해 주세요.`,
  ],
};

const BUSINESS = DEV ? [
  '다음 주 부서 회의 안건을 정리해 주세요.',
  '보고서 문장을 공손하게 고쳐 줘.',
  '연차 신청 방법을 알려 줘.',
  '이번 달 교육 일정은 10일과 17일입니다.',
  '엑셀에서 중복 행을 지우는 방법은?',
  '민원 응대 매뉴얼을 쉬운 말로 바꿔 줘.',
  '출장비 정산 절차를 알려 주세요.',
  '회의록 초안을 세 문단으로 요약해 줘.',
] : [
  '홍보 문구 세 가지를 만들어 줘.',
  '사내 체육대회 공지문을 써 줘.',
  '이 표의 합계와 평균을 구해 줘.',
  '보안 교육 퀴즈 다섯 문제를 만들어 줘.',
  '문서 양식의 맞춤법을 확인해 줘.',
  '고객 설문 결과를 그래프로 그리는 방법은?',
  '업무 인수인계서 목차를 제안해 줘.',
  '휴가 일정 표를 달력 형식으로 바꿔 줘.',
];

const PER = { conf: 24, conf_split: 12, conf_para: 6, far: 6, marker_only: 18, subject_only: 18, business: 16, id: 24, id_neg: 12 };

const out = [];
let n = 0;
const push = (industry, group, text, confidential, ids) =>
  out.push({ id: `${MODE}-${String(++n).padStart(4, '0')}`, industry, group, text, confidential, ids });

for (const [industry, d] of Object.entries(INDUSTRIES)) {
  for (let i = 0; i < PER.conf; ++i) push(industry, 'conf', pick(FRAMES.conf)(pick(MARKERS), pick(d.subjects)), true, []);
  for (let i = 0; i < PER.conf_split; ++i) push(industry, 'conf_split', pick(FRAMES.conf_split)(pick(MARKERS), pick(d.subjects)), true, []);
  for (let i = 0; i < PER.conf_para; ++i) push(industry, 'conf_para', pick(FRAMES.conf)(pick(MARKERS), pick(d.para)), true, []);
  for (let i = 0; i < PER.far; ++i) push(industry, 'far', pick(FRAMES.far)(pick(MARKERS), pick(d.subjects)), false, []);
  for (let i = 0; i < PER.marker_only; ++i) push(industry, 'marker_only', pick(FRAMES.marker_only)(pick(MARKERS)), false, []);
  for (let i = 0; i < PER.subject_only; ++i) push(industry, 'subject_only', pick(FRAMES.subject_only)(pick(d.subjects)), false, []);
  for (let i = 0; i < PER.business; ++i) push(industry, 'business', pick(BUSINESS), false, []);
  for (let i = 0; i < PER.id; ++i) {
    const v = pick(VALUES)();
    push(industry, 'id', pick(FRAMES.id)(pick(d.labels), v), false, [v]);
  }
  for (let i = 0; i < PER.id_neg; ++i) push(industry, 'id_neg', pick(FRAMES.id_neg)(pick(d.labels), pick(VALUES)()), false, []);
}

for (const r of out) process.stdout.write(`${JSON.stringify(r)}\n`);
