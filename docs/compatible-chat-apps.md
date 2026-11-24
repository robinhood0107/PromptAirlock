# 호환 채팅 앱 연결

Open WebUI와 Chatbox는 이 저장소에서 설치하거나 실행하지 않습니다. 기존 앱의 Chat Completions 호환 endpoint를 Gateway의 기관 승인 HTTPS 주소로 바꾸고, 각 앱의 API key 칸에는 해당 출처에 등록한 Gateway token만 사용합니다. 외부 provider 자격 증명을 앱에 입력하지 않습니다.

운영자는 Gateway에서 출처별 `o-only` 또는 승인된 등급 정책을 적용하고 HTTPS 인증서와 신뢰 경로를 설치해야 합니다. 로컬 시험에서만 `127.0.0.1`과 임시 CA를 사용합니다. 임의 endpoint, 인증서 검증 해제, C·S 등급 전송은 지원하지 않습니다. 앱의 재시도는 0 또는 확인 가능한 단일 요청으로 제한하고, 보호 실패·차단·미승인 입력을 다시 전송하지 않습니다.

Open WebUI 또는 Chatbox에 파일을 첨부할 때는 사용 중인 버전이 원본 파일을 Gateway의 Chat Completions 요청에 인라인으로 보내는지 먼저 확인합니다. Gateway가 받은 요청은 일반 대화와 같은 파일 전체 추출·검사 경로를 거칩니다. 파일 URL, 앱 저장소 URL 또는 검색/RAG 경로를 Gateway로 우회해 보내지 않습니다.

이 안내는 연결 설정만 다룹니다. 앱별 사용자 관리, 별도 저장소, 보존, 백업과 암호화는 해당 운영자가 정합니다.