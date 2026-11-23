'use strict';
const form = document.getElementById('preview-form');
const textMode = document.querySelector('input[name="input-mode"][value="text"]');
const fileMode = document.querySelector('input[name="input-mode"][value="file"]');
const textPanel = document.getElementById('text-panel');
const filePanel = document.getElementById('file-panel');
const prompt = document.getElementById('prompt');
const documentInput = document.getElementById('document');
const credential = document.getElementById('origin-token');
const gradeConfirm = document.getElementById('grade-confirm');
const button = document.getElementById('preview');
const status = document.getElementById('status');
const results = document.getElementById('results');
const decision = document.getElementById('decision');
const entityTotal = document.getElementById('entity-total');
const entityCounts = document.getElementById('entity-counts');
const documentTotal = document.getElementById('document-total');
const documentDetails = document.getElementById('document-details');
const documentList = document.getElementById('document-list');
const outbound = document.getElementById('outbound');
const maxTextBytes = 64 * 1024;
const maxFileBytes = 32 * 1024 * 1024;
const blockedCodes = new Set([
  'grade_classified', 'grade_sensitive', 'grade_unresolved', 'entity_blocked',
  'encoded_target', 'opaque_encoded_blob', 'residual_found'
]);

function setMode() {
  const useText = textMode.checked;
  textPanel.hidden = !useText;
  filePanel.hidden = useText;
  prompt.required = useText;
  documentInput.required = !useText;
}

function clearGradeConfirmation() {
  gradeConfirm.checked = false;
}

function readDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener('load', () => resolve(typeof reader.result === 'string' ? reader.result : ''));
    reader.addEventListener('error', () => reject(new Error('file_read_failed')));
    reader.readAsDataURL(file);
  });
}

function validDocument(document) {
  return document && Number.isSafeInteger(document.index) && document.index >= 0 &&
    Number.isSafeInteger(document.bytes) && document.bytes >= 0 &&
    (document.format === null || (typeof document.format === 'string' && /^[a-z0-9_-]{1,24}$/i.test(document.format))) &&
    (document.pages === null || (Number.isSafeInteger(document.pages) && document.pages >= 0)) &&
    Number.isSafeInteger(document.characters) && document.characters >= 0 &&
    document.omitted && ['comments', 'revisions', 'hidden', 'other_parts'].every(key =>
      Number.isSafeInteger(document.omitted[key]) && document.omitted[key] >= 0);
}

function validPreview(data) {
  return data && (data.decision === 'pass' || data.decision === 'pseudonymized') &&
    (typeof data.outbound === 'string' || (data.outbound && typeof data.outbound === 'object' && !Array.isArray(data.outbound))) &&
    data.entities && typeof data.entities === 'object' && !Array.isArray(data.entities) &&
    Object.entries(data.entities).every(([name, count]) => /^[A-Z][A-Z0-9_]{0,47}$/.test(name) &&
      Number.isSafeInteger(count) && count >= 0) &&
    Array.isArray(data.documents) && data.documents.every(validDocument);
}

function appendHighlighted(target, text) {
  const pattern = /⟦[A-Z][A-Z0-9_]{0,23}_[0-9A-HJKMNP-TV-Z]{10}⟧/g;
  let position = 0;
  for (const match of text.matchAll(pattern)) {
    target.append(document.createTextNode(text.slice(position, match.index)));
    const mark = document.createElement('mark');
    mark.textContent = match[0];
    target.append(mark);
    position = match.index + match[0].length;
  }
  target.append(document.createTextNode(text.slice(position)));
}

function renderPreview(data) {
  decision.textContent = data.decision === 'pseudonymized' ? '가명으로 바꾼 뒤 검사 통과' : '검사 통과';
  const entities = Object.entries(data.entities).filter(([, count]) => count > 0);
  entityTotal.textContent = String(entities.reduce((sum, [, count]) => sum + count, 0));
  entityCounts.replaceChildren();
  entityCounts.hidden = entities.length === 0;
  for (const [name, count] of entities) {
    const item = document.createElement('li');
    item.textContent = `${name}: ${count}건`;
    entityCounts.append(item);
  }
  documentTotal.textContent = String(data.documents.length);
  documentList.replaceChildren();
  documentDetails.hidden = data.documents.length === 0;
  for (const doc of data.documents) {
    const item = document.createElement('li');
    const format = doc.format || '형식 미분류';
    const pages = doc.pages === null ? '페이지 정보 없음' : `${doc.pages}쪽`;
    const omitted = ['comments', 'revisions', 'hidden', 'other_parts']
      .reduce((sum, key) => sum + doc.omitted[key], 0);
    item.textContent = `${doc.index + 1}번 파일 · ${format} · ${doc.bytes}바이트 · ${pages} · ${doc.characters}자 · 제외 항목 ${omitted}건`;
    documentList.append(item);
  }
  outbound.replaceChildren();
  const preview = typeof data.outbound === 'string' ? data.outbound : JSON.stringify(data.outbound, null, 2);
  appendHighlighted(outbound, preview);
  results.hidden = false;
  status.textContent = '보호 검사를 통과했습니다. 제공자 호출은 0회이며, 이 화면에서는 보내지 않았습니다.';
}

function showError(reply, data) {
  results.hidden = true;
  const code = data && data.error && typeof data.error.code === 'string' ? data.error.code : '';
  if (reply.status === 409 && code === 'confirmation_required' && /^[0-9a-f]{32}$/.test(data.error.confirm_token || '')) {
    status.replaceChildren(document.createTextNode('확인이 필요해 요청을 멈췄습니다. 제공자 호출은 0회입니다. '));
    const link = document.createElement('a');
    link.href = `/console/confirm?token=${data.error.confirm_token}`;
    link.textContent = '기존 확인 화면 열기';
    status.append(link);
  } else if (blockedCodes.has(code)) {
    status.textContent = '보호 정책에 따라 차단했습니다. 제공자 호출은 0회입니다.';
  } else if (code.startsWith('provider_')) {
    status.textContent = '제공자 오류 응답을 받았습니다. 이 화면은 미리보기만 요청했으므로 내용을 표시하지 않습니다.';
  } else {
    status.textContent = '검사를 완료하지 못했습니다. 결과를 확인할 수 없어 전송 미리보기를 표시하지 않습니다.';
  }
}

textMode.addEventListener('change', () => { setMode(); clearGradeConfirmation(); });
fileMode.addEventListener('change', () => { setMode(); clearGradeConfirmation(); });
prompt.addEventListener('input', clearGradeConfirmation);
documentInput.addEventListener('change', clearGradeConfirmation);
setMode();

form.addEventListener('submit', async event => {
  event.preventDefault();
  results.hidden = true;
  if (!gradeConfirm.checked) {
    status.textContent = '기관 분류에서 공개(O) 등급을 확인한 뒤 검사하세요. 요청은 보내지 않았습니다.';
    gradeConfirm.focus();
    return;
  }
  const secret = credential.value;
  if (!secret) {
    status.textContent = '게이트웨이 출처 token을 입력하세요.';
    credential.focus();
    return;
  }
  button.disabled = true;
  const controls = [textMode, fileMode, prompt, documentInput, credential, gradeConfirm];
  controls.forEach(control => { control.disabled = true; });
  credential.value = '';
  try {
    let body;
    try {
      if (textMode.checked) {
        if (prompt.value.length === 0) {
          status.textContent = '검사할 텍스트를 입력하세요.';
          return;
        }
        if (new TextEncoder().encode(prompt.value).length > maxTextBytes) {
          status.textContent = '텍스트가 64 KiB를 넘습니다. 내용을 줄인 뒤 다시 검사하세요.';
          return;
        }
        body = { messages: [{ role: 'user', content: prompt.value }] };
      } else {
        const file = documentInput.files[0];
        if (!file || file.size === 0 || file.size > maxFileBytes || /[\u0000-\u001f\u007f/\\:]/.test(file.name)) {
          status.textContent = '파일을 선택하고 크기와 파일 이름을 확인하세요.';
          return;
        }
        const dataUrl = await readDataUrl(file);
        const comma = dataUrl.indexOf(',');
        if (comma < 0) throw new Error('file_read_failed');
        const mime = /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(file.type) ? file.type : 'application/octet-stream';
        body = { messages: [{ role: 'user', content: [{ type: 'file', file: {
          filename: file.name, file_data: `data:${mime};base64,${dataUrl.slice(comma + 1)}`
        } }] }] };
      }
    } catch {
      status.textContent = '입력을 읽지 못했습니다. 원문은 전송되지 않았습니다.';
      return;
    }
    status.textContent = '로컬 보호 검사를 진행하고 있습니다. 제공자 호출은 0회입니다.';
    try {
      const reply = await fetch('/v1/preview', {
        method: 'POST', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
        referrerPolicy: 'no-referrer',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + secret, 'X-Prompt-Airlock-Grade': 'O' },
        body: JSON.stringify(body)
      });
      const data = await reply.json();
      if (reply.ok && validPreview(data)) renderPreview(data);
      else showError(reply, data);
    } catch {
      results.hidden = true;
      status.textContent = '검사 결과를 확인하지 못했습니다. 성공 여부가 확인될 때까지 전송 미리보기를 숨깁니다.';
    }
  } finally {
    credential.value = '';
    clearGradeConfirmation();
    controls.forEach(control => { control.disabled = false; });
    button.disabled = false;
  }
});
