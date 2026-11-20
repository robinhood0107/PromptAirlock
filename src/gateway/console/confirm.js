'use strict';
const form = document.getElementById('approval-form');
const credential = document.getElementById('origin-token');
const button = document.getElementById('approve');
const status = document.getElementById('status');
const tokens = new URLSearchParams(window.location.search).getAll('token');
const token = tokens.length === 1 ? tokens[0] : '';
if (!/^[0-9a-f]{32}$/.test(token)) {
  button.disabled = true;
  status.textContent = '유효한 확인 요청이 없습니다. 원래 앱에서 요청을 다시 보내 새 확인 링크를 받으세요.';
}
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (button.disabled) return;
  button.disabled = true;
  const secret = credential.value;
  credential.value = '';
  status.textContent = '승인 요청을 확인하고 있습니다.';
  try {
    const reply = await fetch('/v1/confirmations/approve', {
      method: 'POST', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + secret, 'X-Prompt-Airlock-Grade': 'O' },
      body: JSON.stringify({ token })
    });
    const data = await reply.json();
    if (reply.ok && data.approved === true) {
      form.hidden = true;
      status.textContent = '승인했습니다. 원래 채팅 앱에서 같은 요청을 다시 생성하면 보호 검사를 다시 거쳐 한 번 전송합니다.';
    } else {
      const messages = {
        unauthorized: '출처 token을 확인하세요. 외부 제공자의 키와는 다른 값입니다.',
        too_many_auth_failures: '인증 시도가 잠시 잠겼습니다. 잠시 뒤 다시 시도하세요.',
        confirmation_invalid: '이미 처리됐거나 만료된 요청입니다. 원래 앱에서 요청을 다시 생성해 확인하세요.',
        local_only: '게이트웨이를 실행한 PC의 로컬 주소에서 열어 주세요.'
      };
      status.textContent = messages[data.error?.code] || '승인을 완료하지 못했습니다. 원래 앱에서 요청 상태를 다시 확인하세요.';
      button.disabled = false;
      credential.focus();
    }
  } catch {
    status.textContent = '승인 결과를 확인하지 못했습니다. 원래 앱에서 요청을 다시 생성하면 보호 검사를 다시 진행합니다.';
    button.disabled = false;
  } finally {
    credential.value = '';
  }
});
