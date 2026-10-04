// 개발 전용 fixture 생성기. 런타임 경로에 포함되지 않는다.
// 모든 이름·기관은 가상의 것이다. 실제 인물·전화번호·주민번호를 쓰지 않는다.
// 실행: node gen-fixtures.mjs > ner.jsonl
const NFD = (s) => s.normalize('NFD');
const ZWSP = '​', ZWNJ = '‌', BOM = '﻿', ACUTE = '́';

// [id, category, text, [[type, surface, occurrence(0부터)], ...]]
const cases = [
  ['name-01', 'name', '김민수가 내일 회의에 참석합니다.', [['PERSON', '김민수']]],
  ['name-02', 'name', '어제 박서준을 만났다.', [['PERSON', '박서준']]],
  ['name-03', 'name', '이영희는 보고서를 제출했다.', [['PERSON', '이영희']]],
  ['name-04', 'name', '정하늘은 오늘 휴가입니다.', [['PERSON', '정하늘']]],
  ['name-05', 'name', '이번 건의 담당자는 윤서연입니다.', [['PERSON', '윤서연']]],
  ['name-06', 'name', '강도윤 씨에게 연락해 주세요.', [['PERSON', '강도윤']]],
  ['name-07', 'name', '오태호님, 확인 부탁드립니다.', [['PERSON', '오태호']]],
  ['two-01', 'two_people', '김민수와 이영희가 함께 발표했다.', [['PERSON', '김민수'], ['PERSON', '이영희']]],
  ['two-02', 'two_people', '박서준과 정하늘은 같은 팀이다.', [['PERSON', '박서준'], ['PERSON', '정하늘']]],
  ['two-03', 'two_people', '임채원이 서지아에게 자료를 보냈다.', [['PERSON', '임채원'], ['PERSON', '서지아']]],
  ['two-04', 'two_people', '권나래, 문지호 두 사람이 참석했다.', [['PERSON', '권나래'], ['PERSON', '문지호']]],
  ['rep-01', 'repeat', '김민수는 회의에 늦었다. 김민수의 노트북이 고장 났기 때문이다.', [['PERSON', '김민수', 0], ['PERSON', '김민수', 1]]],
  ['rep-02', 'repeat', '이영희가 먼저 말했다. 그러자 이영희를 본 박서준이 웃었다.', [['PERSON', '이영희', 0], ['PERSON', '이영희', 1], ['PERSON', '박서준']]],
  ['org-01', 'person_org', '김민수는 누리별테크에 다닌다.', [['PERSON', '김민수'], ['ORG', '누리별테크']]],
  ['org-02', 'person_org', '가온해운의 윤서연 팀장이 방문했다.', [['ORG', '가온해운'], ['PERSON', '윤서연']]],
  ['org-03', 'person_org', '이영희 연구원은 솔빛연구소 소속이다.', [['PERSON', '이영희'], ['ORG', '솔빛연구소']]],
  ['org-04', 'person_org', '다온바이오와 새온전자가 공동 연구를 발표했다.', [['ORG', '다온바이오'], ['ORG', '새온전자']]],
  ['org-05', 'person_org', '푸른바다물산 대표 박서준은 하람대학교를 졸업했다.', [['ORG', '푸른바다물산'], ['PERSON', '박서준'], ['ORG', '하람대학교']]],
  ['org-06', 'person_org', '정하늘 과장은 미르정보기술 보안팀에서 일한다.', [['PERSON', '정하늘'], ['ORG', '미르정보기술']]],
  ['jo-01', 'particle', '정하늘을 회의실로 불러 주세요.', [['PERSON', '정하늘']]],
  ['jo-02', 'particle', '오태호를 찾습니다.', [['PERSON', '오태호']]],
  ['jo-03', 'particle', '강도윤에게 물어보세요.', [['PERSON', '강도윤']]],
  ['jo-04', 'particle', '서지아와 점심을 먹었다.', [['PERSON', '서지아']]],
  ['jo-05', 'particle', '임채원과 저녁을 먹었다.', [['PERSON', '임채원']]],
  ['jo-06', 'particle', '문지호한테 들었다.', [['PERSON', '문지호']]],
  ['jo-07', 'particle', '김하은은 오늘 출근했다.', [['PERSON', '김하은']]],
  ['jo-08', 'particle', '이가은이 발표를 맡았다.', [['PERSON', '이가은']]],
  ['jo-09', 'particle', '박서준께서 말씀하셨다.', [['PERSON', '박서준']]],
  ['jo-10', 'particle', '권나래도 그 안에 동의했다.', [['PERSON', '권나래']]],
  ['jo-11', 'particle', '김현도의 의견을 먼저 들었다.', [['PERSON', '김현도']]],
  ['jo-12', 'particle', '윤서연이랑 영화를 봤다.', [['PERSON', '윤서연']]],
  ['jo-13', 'particle', '누리별테크가 신제품을 출시했다.', [['ORG', '누리별테크']]],
  ['jo-14', 'particle', '서지아는 가온해운과 계약했다.', [['PERSON', '서지아'], ['ORG', '가온해운']]],
  ['mix-01', 'hangul_ascii', '김민수(Minsu Kim)는 Nuribyeol Tech에 근무한다.', [['PERSON', '김민수'], ['PERSON', 'Minsu Kim'], ['ORG', 'Nuribyeol Tech']]],
  ['mix-02', 'hangul_ascii', '이영희가 ABC솔루션즈와 MOU를 체결했다.', [['PERSON', '이영희'], ['ORG', 'ABC솔루션즈']]],
  ['mix-03', 'hangul_ascii', '박서준(PM)이 사내 메신저에 공지했다.', [['PERSON', '박서준']]],
  ['mix-04', 'hangul_ascii', '문의: minsu.kim@example.com 담당 김민수', [['PERSON', '김민수']]],
  ['mix-05', 'hangul_ascii', '정하늘2팀장과 v2.1 배포 일정을 논의했다.', [['PERSON', '정하늘']]],
  ['punct-01', 'punctuation', '「김민수」라는 이름으로 예약했다.', [['PERSON', '김민수']]],
  ['punct-02', 'punctuation', '"이영희"씨가 전화했습니다.', [['PERSON', '이영희']]],
  ['punct-03', 'punctuation', '참석자: 김민수, 이영희, 박서준.', [['PERSON', '김민수'], ['PERSON', '이영희'], ['PERSON', '박서준']]],
  ['punct-04', 'punctuation', '정하늘(32세)·윤서연(29세)이 합격했다.', [['PERSON', '정하늘'], ['PERSON', '윤서연']]],
  ['punct-05', 'punctuation', '누리별테크/가온해운 담당자 회의가 있다.', [['ORG', '누리별테크'], ['ORG', '가온해운']]],
  ['punct-06', 'punctuation', '...김민수?! 정말 왔어?', [['PERSON', '김민수']]],
  ['norm-01', 'normalization', NFD('김민수') + '는 회의에 참석했다.', [['PERSON', NFD('김민수')]]],
  ['norm-02', 'normalization', '어제 ' + NFD('이영희') + '를 만났다.', [['PERSON', NFD('이영희')]]],
  ['norm-03', 'normalization', '김민수，이영희　두 사람이 왔다.', [['PERSON', '김민수'], ['PERSON', '이영희']]],
  ['norm-04', 'normalization', 'ＡＢＣ솔루션즈의 김민수 대리', [['ORG', 'ＡＢＣ솔루션즈'], ['PERSON', '김민수']]],
  ['norm-05', 'normalization', 'Cafe' + ACUTE + ' 사장 박서준을 만났다.', [['PERSON', '박서준']]],
  ['norm-06', 'normalization', '김' + ZWSP + '민수가 왔다.', [['PERSON', '김' + ZWSP + '민수']]],
  ['norm-07', 'normalization', BOM + '이영희는 출장 중이다.', [['PERSON', '이영희']]],
  ['norm-08', 'normalization', '👍 김민수님 감사합니다 🙏', [['PERSON', '김민수']]],
  ['norm-09', 'normalization', '🎉이영희🎉 축하해요', [['PERSON', '이영희']]],
  ['norm-10', 'normalization', '박' + ZWNJ + '서준에게 전달했다.', [['PERSON', '박' + ZWNJ + '서준']]],
  ['norm-11', 'normalization', '정' + NFD('하늘') + '과 회의했다.', [['PERSON', '정' + NFD('하늘')]]],
  ['neg-01', 'negative', '오늘 회의는 오후 3시에 시작합니다.', []],
  ['neg-02', 'negative', '수정 사항을 반영해 주세요.', []],
  ['neg-03', 'negative', '하늘이 맑고 바다가 푸르다.', []],
  ['neg-04', 'negative', '보안 점검 결과를 다음 주까지 공유하겠습니다.', []],
  ['long-01', 'long',
    '지난주 금요일 누리별테크 본사에서 분기 보안 점검 회의가 열렸다. 회의는 김민수 팀장이 주재했고, 가온해운의 윤서연 과장과 솔빛연구소의 박서준 연구원이 외부 위원으로 참석했다. ' +
    '김민수 팀장은 먼저 지난 분기 사고 대응 현황을 설명했다. 이어 이영희 대리가 접근 통제 정책 변경안을 발표했는데, 윤서연 과장은 협력사 계정 관리 절차가 아직 문서화되지 않았다고 지적했다. ' +
    '박서준 연구원은 다온바이오와 새온전자가 함께 진행한 공동 연구 결과를 인용하며 로그 보존 기간을 늘려야 한다고 말했다. 정하늘 사원은 회의록을 작성해 하람대학교 산학협력단과 미르정보기술 담당자에게 공유하기로 했다. ' +
    '마지막으로 김민수 팀장은 다음 회의를 이번 달 말에 열겠다고 밝혔고, 이영희 대리와 정하늘 사원이 후속 조치를 맡았다.',
    [['ORG', '누리별테크'], ['PERSON', '김민수', 0], ['ORG', '가온해운'], ['PERSON', '윤서연', 0], ['ORG', '솔빛연구소'], ['PERSON', '박서준', 0],
     ['PERSON', '김민수', 1], ['PERSON', '이영희', 0], ['PERSON', '윤서연', 1], ['PERSON', '박서준', 1], ['ORG', '다온바이오'], ['ORG', '새온전자'],
     ['PERSON', '정하늘', 0], ['ORG', '하람대학교'], ['ORG', '미르정보기술'], ['PERSON', '김민수', 2], ['PERSON', '이영희', 1], ['PERSON', '정하늘', 1]]],
];

const enc = new TextEncoder();
const cpLen = (s) => [...s].length;
for (const [id, category, text, ents] of cases) {
  const out = [];
  for (const [type, surface, occ = 0] of ents) {
    let from = 0, idx = -1;
    for (let k = 0; k <= occ; k++) { idx = text.indexOf(surface, from); if (idx < 0) throw new Error(`${id}: ${surface}#${occ} 없음`); from = idx + surface.length; }
    const pre = text.slice(0, idx);
    const sb = enc.encode(pre).length, eb = sb + enc.encode(surface).length;
    const sc = cpLen(pre), ec = sc + cpLen(surface);
    out.push({ type, text: surface, start_byte: sb, end_byte: eb, start_cp: sc, end_cp: ec });
  }
  out.sort((a, b) => a.start_byte - b.start_byte);
  console.log(JSON.stringify({ id, category, text, entities: out }));
}
