// 문장 단위 민감정보 합성 셋 생성기(Phase 7.5-1). 개발 전용이며 런타임 경로에 들어가지 않는다.
// 모든 이름은 가상의 것이고, 인증 값도 지어낸 문자열이다. 실제 인물·병력·계정을 쓰지 않는다.
// 실행: node tests/fixtures/sentence/gen-sentence.mjs > tests/fixtures/sentence/sentence-dev.jsonl         (개발용)
//       node tests/fixtures/sentence/gen-sentence.mjs final > tests/fixtures/sentence/sentence-final.jsonl (판정용)
// 개발용 셋으로만 예시 문장·문턱값을 다듬고, 판정용 셋은 7.5-2 판정에만 쓴다(Phase 7 결정 #107 과 같은 이유).
// 판정용 셋은 seed, 이름, 직함, 문장이 개발용과 다르다.
//
// 무리(group)와 기대(sensitive):
//   direct   개인 표지 + 범주어                         true
//   variant  direct 의 범주어를 띄어 쓰기·ZWSP·자모 분리로 바꿈 true
//   split    개인 표지와 범주어 사이에 문장 하나를 끼움       true
//   evasive  개인 표지 + 범주어 없이 같은 뜻을 돌려 말함      true
//   general  범주어는 있지만 특정 개인이 없음(일반 지식)      false
//   personal 개인 표지는 있지만 민감한 내용이 없음(업무)      false
// 범주는 detect::SensitiveCategory 10개와 인증 정보(credential) 하나다.
// evasive·personal 문장과 split 사이 문장에 범주어(src/detect/data/sensitive_category_terms.hpp)가 섞이면 생성을 멈춘다.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const FINAL = process.argv[2] === 'final';
const SEED = FINAL ? 20261212 : 20261031;

let state = SEED >>> 0;
const rand = () => {
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (list) => list[Math.floor(rand() * list.length)];

const hasBatchim = (word) => {
  const last = [...word.normalize('NFC')].pop().codePointAt(0);
  return last >= 0xac00 && last <= 0xd7a3 && (last - 0xac00) % 28 !== 0;
};
const eun = (w) => w + (hasBatchim(w) ? '은' : '는');

// 범주어 목록을 제품 데이터에서 읽어 섞임을 검사한다(소문자 비교).
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const termFile = readFileSync(join(root, 'src/detect/data/sensitive_category_terms.hpp'), 'utf8');
const terms = [...termFile.matchAll(/U"([^"]+)"/g)].map((m) => m[1].toLowerCase());
const credFile = readFileSync(join(root, 'src/detect/data/credential_markers.hpp'), 'utf8');
const credMarkers = [...credFile.slice(0, credFile.indexOf('inline constexpr auto marker_particles')).matchAll(/U"([^"]+)"/g)]
  .map((m) => m[1].toLowerCase()).filter((t) => [...t].length > 3 || /[가-힣]/.test(t));
const findTerm = (text, list) => list.find((t) => text.toLowerCase().includes(t));

// 개인 표지. 이름+직함, 성+직함님, 자기 진술, 가족.
const people = FINAL
  ? ['서하린 주무관', '남궁도윤 사무관', '옥채원 대리', '전 실장님', '반 차장님', '갈 국장님', '모 선생님', '저', '제 남편', '저희 어머니']
  : ['김민수 과장', '이서연 대리', '박지호 주임', '최 팀장님', '정 부장님', '강 교수님', '윤 선생님', '저', '우리 엄마', '제 아내'];
const fillers = FINAL
  ? ['그건 그렇고 회의실은 바뀌었어요.', '아 참, 보고서는 내일 내요.', '점심은 같이 못 먹었어요.']
  : ['아무튼 오늘 회의는 길었어.', '그나저나 출장은 다음 주야.', '어쨌든 결재는 끝났어.'];

// 범주별 문장 조각. [ ] 안이 범주어(또는 인증 표지어)이고 variant 가 이 부분을 바꾼다.
// direct 와 split 은 같은 사실 조각을 쓰고, evasive 는 범주어 없이 같은 뜻을 쓴다.
// credential 의 {c} 는 지어낸 인증 값으로 채운다.
const dev = {
  Health: {
    direct: ['[당뇨] 때문에 매일 주사를 맞아요.', '지난달 [우울증] 진단을 받았대요.', '다음 주에 [수술] 일정이 잡혔대요.'],
    evasive: ['밥 먹기 전에 꼭 배에 주사를 놓더라고요.', '요즘 마음이 많이 힘들어서 매주 상담실에 다녀요.', '혈압약을 못 끊어서 아침마다 챙겨 먹어요.',
      '독한 약을 몇 달 맞고 나서 머리가 아직 덜 자랐어요.', '술 끊으려고 매주 모임에 나가요.'],
    general: ['[당뇨] 초기 증상을 정리해 주세요.', '[우울증] 예방법을 알려 주세요.', '[수술] 전 금식 기준이 뭐예요?'],
  },
  Belief: {
    direct: ['일요일마다 [교회]에 가요.', '독실한 [불교] 신자예요.', '[이슬람] 율법 때문에 돼지고기를 안 먹어요.'],
    evasive: ['주일마다 예배 드리느라 오전엔 연락이 안 돼요.', '매년 초파일에 연등 달러 절에 가요.', '라마단 기간이라 해 지기 전에는 아무것도 안 먹어요.',
      '식사 전에 늘 기도부터 하고 숟가락을 들어요.', '부활절 미사 때문에 그 주말은 빠진대요.'],
    general: ['[종교] 개혁의 역사를 요약해 주세요.', '[불교] 미술의 특징을 알려 주세요.', '[교회] 건축 양식을 비교해 주세요.'],
  },
  LaborUnion: {
    direct: ['[노조] 사무국장을 맡고 있어요.', '이번 [파업]에 앞장섰대요.', '작년에 [노동조합]에 가입했어요.'],
    evasive: ['단체교섭 때 사측 맞은편 자리에 앉았어요.', '조끼 입고 로비에서 피켓 들고 서 있었어요.', '분회 모임 회비를 매달 내고 있어요.',
      '임단협 교섭위원으로 뽑혔대요.', '지부 대의원 선거에 나간대요.'],
    general: ['[노동조합] 설립 절차를 알려 주세요.', '[파업] 관련 법 조항을 정리해 주세요.', '[노조] 전임자 제도를 설명해 주세요.'],
  },
  PoliticalParty: {
    direct: ['지난해 [입당]했어요.', '오래된 [당원]이에요.', '[정의당] 지역위원회에서 활동해요.'],
    evasive: ['당비를 매달 자동이체로 내고 있어요.', '지난 경선 때 선거인단으로 투표했어요.', '구의원 후보 캠프에서 자원봉사를 했어요.',
      '도당 청년위원회 모임에 나가요.', '당적을 바꾸고 싶다고 했어요.'],
    general: ['[정당] 등록 요건을 알려 주세요.', '[탈당] 절차를 설명해 주세요.', '[당원] 수 통계를 요약해 주세요.'],
  },
  PoliticalView: {
    direct: ['[정치 성향]이 꽤 강해요.', '[보수 성향]이라 그 정책을 반대해요.', '[지지하는 후보]를 자주 얘기해요.'],
    evasive: ['집회 때마다 광장에 나가서 촛불을 들어요.', '선거 때마다 같은 쪽만 찍는다고 했어요.', '그 대통령 얘기만 나오면 목소리가 커져요.',
      '시사 유튜브를 틀어 놓고 일해요.', '태극기 들고 주말 행진에 나가요.'],
    general: ['[정치 성향] 조사 방법론을 정리해 주세요.', '[진보 성향] 유권자 비율 통계를 찾아 주세요.', '[정치적 견해] 표현의 자유 판례를 알려 주세요.'],
  },
  SexLife: {
    direct: ['[동성애]자라고 털어놨어요.', '[트랜스젠더]라고 밝혔어요.', '[성병] 검사를 받았대요.'],
    evasive: ['남자친구랑 같이 산 지 3년 됐대요. 본인도 남자고요.', '퀴어 축제에 매년 같이 가요.', '커밍아웃한 뒤로 집에 안 간대요.',
      '같은 여자를 사귄다고 들었어요.', '호르몬 주사를 맞으면서 이름을 바꿨대요.'],
    general: ['[성소수자] 인권 정책을 요약해 주세요.', '[성적 지향] 차별 금지 조항을 알려 주세요.', '[성병] 예방 지침을 정리해 주세요.'],
  },
  Genetic: {
    direct: ['[유전자 검사]에서 이상이 나왔대요.', '집안 내력인 [유전질환]이 있어요.', '[유전정보]를 회사에 냈대요.'],
    evasive: ['피 검사로 집안 내력을 알아봤는데 결과가 안 좋았대요.', '어머니 쪽 내력 때문에 아이 갖기를 미루고 있어요.', '침 뽑아서 보내는 검사로 조상 분석을 받았어요.',
      '브라카 변이가 있어서 예방 절제를 고민해요.', '염색체 검사 결과를 기다리고 있어요.'],
    general: ['[유전자 검사] 비용을 비교해 주세요.', '[유전질환] 종류를 정리해 주세요.', '[dna] 구조를 설명해 주세요.'],
  },
  Criminal: {
    direct: ['[전과 기록]이 있어요.', '예전에 [교도소]에 있었대요.', '음주운전으로 [집행유예]를 받았어요.'],
    evasive: ['몇 년 전에 빵에 다녀왔대요.', '면허가 취소돼서 법원에 몇 번 불려 갔어요.', '보호관찰 기간이라 밤에 못 나가요.',
      '출소하고 나서 이 일을 시작했대요.', '전자발찌 때문에 출장을 못 간대요.'],
    general: ['[집행유예] 요건을 알려 주세요.', '[범죄경력] 조회 절차를 정리해 주세요.', '[교도소] 교정 프로그램을 요약해 주세요.'],
  },
  Biometric: {
    direct: ['[지문정보]가 출입 시스템에 등록돼 있어요.', '[홍채] 정보를 은행에 등록했어요.', '[안면인식] 데이터를 제출했어요.'],
    evasive: ['손가락 찍어야 문이 열리게 해 뒀어요.', '눈동자 스캔으로 금고를 열어요.', '얼굴 사진을 출입 단말에 등록해 뒀어요.',
      '손바닥 정맥 패턴으로 결제해요.', '목소리 샘플을 은행 인증용으로 녹음했어요.'],
    general: ['[생체인식] 기술 동향을 요약해 주세요.', '[지문인식] 센서 원리를 설명해 주세요.', '[홍채] 인식 정확도 자료를 찾아 주세요.'],
  },
  Ethnicity: {
    direct: ['[혈통]이 절반은 몽골이에요.', '소수 [민족] 출신이에요.', '[인종] 때문에 차별을 받았대요.'],
    evasive: ['어머니가 베트남 분이라 집에서는 베트남어를 써요.', '할아버지가 조선족이셨대요.', '피부색 때문에 학교에서 많이 놀림받았대요.',
      '아버지 고향이 우즈베키스탄이고 고려인이에요.', '귀화하기 전 국적이 필리핀이었어요.'],
    general: ['[민족] 개념의 역사를 정리해 주세요.', '[인종] 차별 철폐 협약을 요약해 주세요.', '[혈통] 주의와 출생지주의를 비교해 주세요.'],
  },
  Credential: {
    direct: ['[비밀번호]는 {c}예요.', '사내망 [패스워드]는 {c}입니다.', '[인증번호]는 {c}이에요.'],
    evasive: ['그 사이트 첫 화면에서 치는 건 {c} 이거예요.', '그 사이트 들어갈 때 쓰는 글자는 {c}이에요.', '메일 열 때 넣는 문자열이 {c}래요.',
      '공유기 연결할 때 {c} 넣으면 돼요.', '그 계좌 앱 잠금 푸는 숫자는 {c}예요.'],
    general: ['[비밀번호] 변경 주기를 알려 주세요.', '[패스워드] 정책 문서를 요약해 주세요.', '[인증번호] 발송 절차를 정리해 주세요.'],
  },
};

const fin = {
  Health: {
    direct: ['[고혈압] 약을 먹고 있어요.', '[공황장애]로 휴직했대요.', '[입원] 치료를 받는 중이에요.'],
    evasive: ['손이 떨려서 신경과 약을 아침저녁으로 먹어요.', '투석 때문에 일주일에 세 번 일찍 퇴근해요.', '갑자기 숨이 막히는 일이 잦아서 약을 늘렸대요.',
      '잠을 못 자서 수면제 없으면 못 버틴대요.', '배 속 아이가 다음 달이면 나온대요.', '인공관절 넣고 나서 계단을 못 오른대요.'],
    general: ['[고혈압] 식단 지침을 정리해 주세요.', '[공황장애] 대처법을 알려 주세요.', '[입원] 절차 안내문을 써 주세요.'],
  },
  Belief: {
    direct: ['[천주교] 세례를 받았어요.', '[성당] 성가대에서 활동해요.', '[신앙] 때문에 수혈을 거부한대요.'],
    evasive: ['새벽마다 108배를 한대요.', '하루 다섯 번 메카 쪽을 보고 절해요.', '토요일은 안식일이라 일을 안 한대요.',
      '고해성사 보러 가야 한다고 일찍 나갔어요.', '할랄 음식만 먹어서 회식 장소를 바꿨어요.', '주일학교 교사라 일요일엔 못 나와요.'],
    general: ['[천주교] 전례력을 설명해 주세요.', '[성당] 건축 사례를 찾아 주세요.', '[신앙]과 과학의 관계를 정리해 주세요.'],
  },
  LaborUnion: {
    direct: ['[조합원]으로 등록돼 있어요.', '[노조] 위원장 선거에 나왔어요.', '[파업] 투표에서 찬성했대요.'],
    evasive: ['노사협의회 근로자 위원 몫으로 들어갔어요.', '쟁의 기간에 출근 대신 천막에 있었어요.', '본조 교육에 다녀와서 현장 간부를 맡았대요.',
      '지회 회계감사를 맡고 있어요.', '교섭 결렬되면 피켓 라인에 서겠대요.', '연대 집회 버스를 대절했대요.'],
    general: ['[조합원] 자격 요건을 알려 주세요.', '[노조] 조직률 통계를 찾아 주세요.', '[파업] 손해배상 판례를 정리해 주세요.'],
  },
  PoliticalParty: {
    direct: ['[국민의힘] 당원 명부에 있어요.', '[더불어민주당] 청년위원이에요.', '최근에 [탈당]했대요.'],
    evasive: ['당 대표 선거에서 투표권이 있는 사람이에요.', '당비를 내는 정식 회원이라 매달 돈이 빠져나가요.', '지역구 사무실에서 당직을 맡았대요.',
      '공천 신청서를 냈다고 들었어요.', '당 행사 때마다 버스 타고 올라가요.', '비례 후보 명단에 이름이 올랐대요.'],
    general: ['[국민의힘] 강령을 요약해 주세요.', '[더불어민주당] 역사를 정리해 주세요.', '[탈당] 후 복당 규정을 알려 주세요.'],
  },
  PoliticalView: {
    direct: ['[진보 성향]이 뚜렷해요.', '[정치적 견해]를 회의 때 자주 밝혀요.', '[보수 성향] 모임에 나가요.'],
    evasive: ['탄핵 찬성 서명을 받으러 다녔대요.', '저쪽 진영 사람들은 상대도 안 한대요.', '선거 끝나고 며칠을 앓아누웠대요.',
      '특정 신문만 구독하고 나머지는 안 본대요.', '정권 바뀌면 이민 간다고 했어요.', '토론회 때마다 한쪽 편만 들어요.'],
    general: ['[진보 성향] 정당의 정책을 비교해 주세요.', '[정치적 견해] 표현 관련 판례를 정리해 주세요.', '[보수 성향] 개념의 기원을 설명해 주세요.'],
  },
  SexLife: {
    direct: ['[양성애]자라고 했어요.', '[성적 지향]을 회사에 밝히지 않았어요.', '[레즈비언] 커플이에요.'],
    evasive: ['동성 배우자와 해외에서 결혼식을 올렸대요.', '같은 성별 애인 사진을 휴대폰 배경으로 해 놨어요.', '성별 정정 신청을 법원에 냈대요.',
      '남편이 아니라 아내가 있는 여자예요.', '데이트 앱에서 같은 남자를 만났대요.', '무지개 깃발을 책상에 꽂아 두고 정체성을 밝혔어요.'],
    general: ['[양성애] 관련 연구를 요약해 주세요.', '[성적 지향] 통계를 찾아 주세요.', '[레즈비언] 문학 작품을 소개해 주세요.'],
  },
  Genetic: {
    direct: ['[유전자 검사] 결과를 보험사에 냈대요.', '[유전질환] 보인자라고 들었어요.', '[dna] 분석 결과가 회사로 왔대요.'],
    evasive: ['헌팅턴 가족력 때문에 검사를 받을지 고민해요.', '아이도 같은 변이를 물려받았는지 확인했대요.', '조상 분석 키트 결과를 단체방에 올렸어요.',
      '피검사로 혈우병 인자를 확인했대요.', '친자 확인 결과가 나왔다고 했어요.', '산전 검사에서 염색체 문제가 보였대요.'],
    general: ['[유전자 검사] 윤리 지침을 정리해 주세요.', '[유전질환] 지원 제도를 알려 주세요.', '[dna] 증거의 법적 효력을 설명해 주세요.'],
  },
  Criminal: {
    direct: ['[실형]을 살고 나왔어요.', '사기 혐의로 [기소]됐대요.', '예전에 [구속]된 적이 있어요.'],
    evasive: ['수의 입고 지냈던 시절 얘기를 가끔 해요.', '가석방 상태라 주거지를 못 옮긴대요.', '벌금 못 내서 노역장에 다녀왔대요.',
      '재판 끝나고 1년 동안 사회봉사를 했어요.', '빨간 줄 때문에 공무원 시험을 못 본대요.', '형기 마치고 직업훈련을 받았대요.'],
    general: ['[실형]과 [집행유예]의 차이를 알려 주세요.', '[기소] 유예 제도를 설명해 주세요.', '[구속] 영장 심사 절차를 정리해 주세요.'],
  },
  Biometric: {
    direct: ['[정맥인식]으로 출입해요.', '[얼굴인식] 정보를 사원증에 넣었어요.', '[생체정보] 수집에 동의했대요.'],
    evasive: ['엄지 대야 노트북이 풀려요.', '눈을 기계에 갖다 대야 서버실에 들어가요.', '카메라가 얼굴 보고 출근 처리를 해요.',
      '음성으로 본인 확인하게 목소리를 등록했어요.', '걸음걸이 분석용 영상을 찍어 갔대요.', '손등 혈관 사진을 단말에 등록했어요.'],
    general: ['[정맥인식] 장비 원리를 설명해 주세요.', '[얼굴인식] 규제 동향을 정리해 주세요.', '[생체정보] 보관 기준을 알려 주세요.'],
  },
  Ethnicity: {
    direct: ['[혈통]이 러시아계예요.', '[민족] 차별을 겪었다고 했어요.', '[인종] 문제로 입사 면접에서 떨어졌대요.'],
    evasive: ['외할머니가 일본 분이라 이름이 두 개예요.', '부모님이 탈북하셔서 말투가 조금 달라요.', '피부가 까무잡잡하다고 별명이 생겼대요.',
      '아버지가 나이지리아 사람이에요.', '다문화 가정 지원을 받았어요.', '이주노동자로 와서 귀화했대요.'],
    general: ['[민족] 자결권의 역사를 정리해 주세요.', '[인종] 통계 수집 기준을 알려 주세요.', '[혈통] 기반 국적법을 비교해 주세요.'],
  },
  Credential: {
    direct: ['[비번]은 {c}로 바꿨어요.', '와이파이 [암호]는 {c}입니다.', '[OTP] 번호는 {c}예요.'],
    evasive: ['회사 메일 잠금 풀 때 {c} 쳐요.', '그 서버 붙을 때 {c} 넣으면 돼요.', '현관 도어락은 {c}이에요.',
      '공용 컴퓨터 켤 때 {c}만 넣으면 돼요.', '결재 시스템 열쇠 문자열이 {c}예요.', '금고 다이얼은 {c}로 맞춰 놨어요.'],
    general: ['[비번] 재설정 방법을 알려 주세요.', '[암호] 복잡도 기준을 정리해 주세요.', '[OTP] 도입 효과를 요약해 주세요.'],
  },
};

const personal = FINAL
  ? ['다음 주 월요일 오전에 출장 일정이 있어요.', '어제 보낸 견적서를 다시 확인해 달래요.', '회의록 초안을 오후까지 보내 준대요.',
    '새 프로젝트 담당으로 옮겼어요.', '휴가 결재를 올렸어요.', '고객사 미팅이 3시로 바뀌었대요.', '분기 보고서 표를 고쳐 달래요.',
    '사무실 자리를 창가로 옮겼어요.', '교육 신청서를 냈어요.', '택배를 대신 받아 달래요.', '점심 메뉴를 정해 달래요.', '보고 일정을 하루 미뤘어요.']
  : ['내일 오전에 거래처 미팅이 있어요.', '어제 보고서를 다시 써야 한대요.', '오늘 저녁 회식에 늦는대요.',
    '새 노트북 신청을 했어요.', '이번 달 실적표를 정리하고 있어요.', '팀 워크숍 장소를 알아보고 있어요.', '출근길에 차가 막혀서 늦었대요.',
    '발표 자료 디자인을 바꿨어요.', '외부 교육을 다녀왔어요.', '계약서 검토를 부탁했어요.'];

const credValues = FINAL ? ['Rk9#vT2q!m', 'wolf-Sky-482!', 'Zq8x@Lp0Nn', '7391-ab-QQ', 'Hp4$eM2w9z'] : ['Qx7!sunflower', 'Tb3@mK9pL2', 'blue#Ocean77', 'Vv81&hJk0q', 'Np2!Lr7#Ws'];

const sets = FINAL ? fin : dev;
const out = [];
let n = 0;
const add = (category, group, variant, text, sensitive) => {
  n += 1;
  out.push({ id: `${FINAL ? 'f' : 'd'}-${String(n).padStart(4, '0')}`, category, group, variant, text, sensitive });
};
const strip = (s) => s.replace(/\[|\]/g, '');
const fillCred = (s) => s.replace('{c}', () => pick(credValues));
// 범주어를 글자 사이에 공백, ZWSP, 자모 분리(NFD)로 바꾼다.
const obfuscate = (fact, how) => fact.replace(/\[([^\]]+)\]/g, (_, term) => {
  const chars = [...term];
  if (how === 'spacing') return chars.join(' ');
  if (how === 'zwsp') return chars.join('​');
  return term.normalize('NFD');
});
const subject = (person) => (person === '저' ? '저는' : eun(person));

for (const [category, t] of Object.entries(sets)) {
  const cred = category === 'Credential';
  for (const fact of t.direct) {
    for (let k = 0; k < 2; k += 1) {
      const p = pick(people);
      add(category, 'direct', '', fillCred(cred ? strip(fact) : `${subject(p)} ${strip(fact)}`), true);
    }
    for (const how of ['spacing', pick(['zwsp', 'nfd'])]) {
      const p = pick(people);
      add(category, 'variant', how, fillCred(cred ? obfuscate(fact, how) : `${subject(p)} ${obfuscate(fact, how)}`), true);
    }
    const p = pick(people);
    const filler = pick(fillers);
    if (findTerm(filler, terms)) throw new Error(`filler 에 범주어: ${filler}`);
    add(category, 'split', '', fillCred(cred ? `${p === '저' ? '제' : p} 계정 얘기예요. ${filler} ${strip(fact)}` : `${p === '저' ? '제' : p} 얘기예요. ${filler} ${strip(fact)}`), true);
  }
  for (const fact of t.evasive) {
    for (let k = 0; k < 2; k += 1) {
      const p = pick(people);
      const text = fillCred(cred ? fact : `${subject(p)} ${fact}`);
      const hit = findTerm(text, terms) ?? (cred ? findTerm(text.replace(/\S*[0-9@#$!&%]\S*/g, ''), credMarkers) : undefined);
      if (hit) throw new Error(`evasive 에 범주어 "${hit}": ${text}`);
      add(category, 'evasive', '', text, true);
    }
  }
  for (const s of t.general) add(category, 'general', '', strip(s), false);
}
for (const s of personal) {
  for (let k = 0; k < 2; k += 1) {
    const p = pick(people);
    const text = `${subject(p)} ${s}`;
    const hit = findTerm(text, terms);
    if (hit) throw new Error(`personal 에 범주어 "${hit}": ${text}`);
    add('None', 'personal', '', text, false);
  }
}
for (const r of out) console.log(JSON.stringify(r));
