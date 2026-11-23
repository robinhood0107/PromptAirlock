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
const rotationToken = document.getElementById('rotation-token');
const providerCredential = document.getElementById('provider-credential');
const credentialSave = document.getElementById('credential-save');
const credentialStatus = document.getElementById('credential-status');
const gatewayCheck = document.getElementById('gateway-check');
const gatewayStatus = document.getElementById('gateway-status');
const approvalListPanel = document.getElementById('approval-list-panel');
const approvalOriginToken = document.getElementById('approval-origin-token');
const approvalOpenConfirm = document.getElementById('approval-open-confirm');
const approvalListLoad = document.getElementById('approval-list-load');
const approvalListStatus = document.getElementById('approval-list-status');
const approvalListItems = document.getElementById('approval-list-items');
const adminToken = document.getElementById('admin-token');
const adminPanel = document.getElementById('admin-history');
const adminOpen = document.getElementById('admin-open');
const adminClose = document.getElementById('admin-close');
const adminStatus = document.getElementById('admin-status');
const adminCountsLoad = document.getElementById('admin-counts-load');
const adminEventsLoad = document.getElementById('admin-events-load');
const adminCountsSection = document.getElementById('admin-counts-section');
const adminCountsScope = document.getElementById('admin-counts-scope');
const adminEventsSection = document.getElementById('admin-events-section');
const adminEventsScope = document.getElementById('admin-events-scope');
const adminEvents = document.getElementById('admin-events');
const adminEventsPrevious = document.getElementById('admin-events-previous');
const adminEventsNext = document.getElementById('admin-events-next');
const adminEventsPageLabel = document.getElementById('admin-events-page');
const adminCountFields = [
  ['requests', 'admin-count-requests'], ['request_rejections', 'admin-count-rejections'],
  ['previews', 'admin-count-previews'], ['confirmations', 'admin-count-confirmations'],
  ['credential_rotations', 'admin-count-rotations'], ['egress_prepared', 'admin-count-egress'],
  ['provider_response_records', 'admin-count-provider-responses'],
  ['authentication_events', 'admin-count-auth'], ['admin_reads', 'admin-count-admin-reads'], ['other', 'admin-count-other']
];
const adminEventFields = [
  ['origin', '출처'], ['severity', '심각도'], ['status', 'HTTP 상태'], ['result', '판정'],
  ['grade', '등급'], ['entity_count', '가명 표지 건수'], ['blocked_type_count', '차단 종류 수'],
  ['duration_ms', '처리 시간(ms)'], ['operation', '조회 종류']
];
let approvalListBusy = false;
let approvalListController = null;
let approvalListGeneration = 0;
let adminBusy = false;
let adminController = null;
let adminGeneration = 0;
let adminEventsPage = 0;
let adminEventsHasMore = false;
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

let credentialBusy = false;
credentialSave.addEventListener('click', async () => {
  if (credentialBusy) return;
  credentialBusy = true;
  credentialSave.disabled = true;
  rotationToken.disabled = true;
  providerCredential.disabled = true;
  let authToken = rotationToken.value;
  let newCredential = providerCredential.value;
  rotationToken.value = '';
  providerCredential.value = '';
  try {
    if (!authToken || authToken.length > 256 || !/^[\x21-\x7e]{1,4000}$/.test(newCredential) ||
        new TextEncoder().encode(JSON.stringify({ credential: newCredential })).length > 4096) {
      credentialStatus.textContent = '입력값을 확인하세요. 값은 화면에서 지웠으며 요청하지 않았습니다.';
      return;
    }
    const body = JSON.stringify({ credential: newCredential });
    newCredential = '';
    const headers = {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + authToken,
      'X-Prompt-Airlock-Grade': 'O'
    };
    authToken = '';
    credentialStatus.textContent = '보호 저장 요청을 처리하고 있습니다.';
    try {
      const reply = await fetch('/v1/provider/credential', {
        method: 'POST', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
        referrerPolicy: 'no-referrer', headers, body
      });
      const data = await reply.json();
      const code = data && data.error && typeof data.error.code === 'string' ? data.error.code : '';
      if (reply.ok && data && data.ok === true) {
        credentialStatus.textContent = '보호 저장이 완료됐습니다. 다음 제공자 요청부터 새 값이 쓰입니다.';
      } else if (reply.status === 404 && code === 'not_found') {
        credentialStatus.textContent = '지정 출처인지, 자격 증명 교체 기능이 켜져 있는지 확인하세요.';
      } else if (code === 'unauthorized' || code === 'too_many_auth_failures') {
        credentialStatus.textContent = '출처 인증에 실패했거나 잠겼습니다. 입력값은 화면에서 지웠습니다.';
      } else if (code === 'grade_classified' || code === 'grade_sensitive' || code === 'grade_unresolved') {
        credentialStatus.textContent = '이 출처는 공개(O) 등급의 자격 증명 교체를 허용하지 않습니다.';
      } else if (code === 'local_only') {
        credentialStatus.textContent = '로컬 접속 경계를 통과하지 못했습니다.';
      } else if (code === 'bad_request' || code === 'body_too_large' || code === 'unsupported_media_type') {
        credentialStatus.textContent = '입력 형식이나 길이를 확인하세요. 입력값은 화면에서 지웠습니다.';
      } else if (code === 'unavailable') {
        credentialStatus.textContent = '보호 저장 또는 감사 처리에 실패해 교체를 완료하지 못했습니다.';
      } else if (code === 'overloaded') {
        credentialStatus.textContent = '로컬 게이트웨이가 바쁩니다. 저장 결과를 확인하지 못했습니다.';
      } else {
        credentialStatus.textContent = '교체 결과를 확인하지 못했습니다. 오류 원문은 표시하지 않습니다.';
      }
    } catch {
      credentialStatus.textContent = '서버 응답을 확인하지 못했습니다. 저장 여부를 판정하지 않았습니다.';
    }
  } finally {
    authToken = '';
    newCredential = '';
    rotationToken.value = '';
    providerCredential.value = '';
    rotationToken.disabled = false;
    providerCredential.disabled = false;
    credentialSave.disabled = false;
    credentialBusy = false;
  }
});

let gatewayCheckBusy = false;
gatewayCheck.addEventListener('click', async () => {
  if (gatewayCheckBusy) return;
  gatewayCheckBusy = true;
  gatewayCheck.disabled = true;
  gatewayStatus.textContent = '로컬 게이트웨이 응답을 확인하고 있습니다.';
  try {
    const reply = await fetch('/console/start.css', {
      method: 'GET', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
      referrerPolicy: 'no-referrer'
    });
    const contentType = reply.headers.get('content-type') || '';
    gatewayStatus.textContent = reply.status === 200 && contentType.toLowerCase().startsWith('text/css')
      ? '로컬 게이트웨이 응답을 확인했습니다. 제공자 연결과 전체 구성은 확인하지 않았습니다.'
      : '로컬 게이트웨이 응답을 확인하지 못했습니다.';
  } catch {
    gatewayStatus.textContent = '로컬 게이트웨이 응답을 확인하지 못했습니다.';
  } finally {
    gatewayCheck.disabled = false;
    gatewayCheckBusy = false;
  }
});

function setApprovalListStatus(message, state = 'neutral') {
  approvalListStatus.textContent = message;
  approvalListStatus.dataset.state = state;
}

function clearApprovalList() {
  approvalListGeneration += 1;
  if (approvalListController) approvalListController.abort();
  approvalListController = null;
  approvalOriginToken.value = '';
  approvalOpenConfirm.checked = false;
  approvalListItems.replaceChildren();
  const empty = document.createElement('li');
  empty.textContent = '확인 요청을 아직 조회하지 않았습니다.';
  approvalListItems.append(empty);
  setApprovalListStatus('조회 전에 출처 token을 입력하고 공개(O) 등급을 확인하세요.');
}

function validApprovalList(data) {
  if (!data || Object.keys(data).sort().join(',') !== 'items,status,truncated' ||
      data.status !== 'available' || typeof data.truncated !== 'boolean' ||
      !Array.isArray(data.items) || data.items.length > 25) return false;
  const marks = new Set();
  return data.items.every(item => {
    if (!item || !Number.isSafeInteger(item.expires_in_seconds) ||
        item.expires_in_seconds < 1 || item.expires_in_seconds > 300) return false;
    if (item.state === 'pending') {
      if (Object.keys(item).sort().join(',') !== 'approval_mark,expires_in_seconds,state' ||
          typeof item.approval_mark !== 'string' || !/^[0-9a-f]{32}$/.test(item.approval_mark) ||
          marks.has(item.approval_mark)) return false;
      marks.add(item.approval_mark);
      return true;
    }
    return item.state === 'approved' && Object.keys(item).sort().join(',') === 'expires_in_seconds,state';
  });
}

function renderApprovalItem(item) {
  const row = document.createElement('li');
  const text = document.createElement('span');
  text.textContent = item.state === 'approved'
    ? `이미 승인됨 · ${item.expires_in_seconds}초 후 만료`
    : `승인 대기 · ${item.expires_in_seconds}초 후 만료 `;
  row.append(text);
  if (item.state === 'pending') {
    const link = document.createElement('a');
    link.href = '/console/confirm?token=' + encodeURIComponent(item.approval_mark);
    link.rel = 'noreferrer';
    link.textContent = '기존 확인 화면 열기';
    row.append(link);
  }
  return row;
}

async function loadApprovalList() {
  if (approvalListBusy) return;
  approvalListItems.replaceChildren();
  if (!approvalOpenConfirm.checked) {
    approvalOriginToken.value = '';
    setApprovalListStatus('공개(O) 등급을 확인하지 않아 요청을 보내지 않았습니다.', 'denied');
    approvalOpenConfirm.focus();
    return;
  }
  let sourceToken = approvalOriginToken.value;
  approvalOriginToken.value = '';
  approvalOpenConfirm.checked = false;
  if (!sourceToken || sourceToken.length > 256 || !/^[\x21-\x7e]+$/.test(sourceToken)) {
    setApprovalListStatus('등록된 출처 token을 확인하세요. 요청은 보내지 않았습니다.', 'denied');
    approvalOriginToken.focus();
    return;
  }
  const generation = approvalListGeneration;
  let temporaryToken = sourceToken;
  const headers = { Authorization: 'Bearer ' + temporaryToken, 'X-Prompt-Airlock-Grade': 'O' };
  temporaryToken = '';
  sourceToken = '';
  const controller = new AbortController();
  approvalListController = controller;
  approvalListBusy = true;
  approvalListLoad.disabled = true;
  setApprovalListStatus('현재 출처의 확인 요청을 조회하고 있습니다.');
  try {
    const reply = await fetch('/v1/confirmations/pending', {
      method: 'GET', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
      referrerPolicy: 'no-referrer', headers, signal: controller.signal
    });
    let data;
    try { data = await reply.json(); } catch { data = null; }
    if (generation !== approvalListGeneration) return;
    if (!reply.ok) {
      const code = data && data.error && typeof data.error.code === 'string' ? data.error.code : '';
      if (reply.status === 401 || reply.status === 429 || code === 'unauthorized' ||
          code === 'too_many_failures' || code === 'too_many_auth_failures') {
        setApprovalListStatus('출처 인증이 거절됐습니다. token을 확인하세요.', 'denied');
      } else if (reply.status === 403 || code.startsWith('grade_') || code === 'local_only') {
        setApprovalListStatus('로컬 접속 또는 공개(O) 등급 조건에서 거절됐습니다.', 'denied');
      } else if (reply.status === 404 || code === 'not_found') {
        setApprovalListStatus('이 출처에서는 확인 요청 목록을 사용할 수 없습니다.', 'denied');
      } else if (reply.status === 503 && code === 'unavailable') {
        setApprovalListStatus('감사 기록에 실패해 확인 요청을 반환하지 않았습니다.', 'audit-failure');
      } else if (code === 'overloaded') {
        setApprovalListStatus('게이트웨이가 바쁩니다. 조회 결과를 반환하지 않았습니다.', 'busy');
      } else {
        setApprovalListStatus('목록 조회를 완료하지 못했습니다. 오류 원문은 표시하지 않습니다.', 'error');
      }
      return;
    }
    if (!validApprovalList(data)) {
      setApprovalListStatus('목록 응답 형식을 확인하지 못했습니다. 표지를 표시하지 않습니다.', 'error');
      return;
    }
    approvalListItems.replaceChildren();
    if (data.items.length === 0) {
      const empty = document.createElement('li');
      empty.textContent = '현재 이 출처의 유효한 확인 요청이 없습니다.';
      approvalListItems.append(empty);
    } else {
      for (const item of data.items) approvalListItems.append(renderApprovalItem(item));
    }
    setApprovalListStatus(data.truncated
      ? '먼저 만료될 요청 최대 25개를 표시했습니다. 목록 조회는 승인 상태나 만료를 바꾸지 않습니다.'
      : '현재 출처의 유효한 확인 요청을 표시했습니다. 목록 조회는 승인 상태나 만료를 바꾸지 않습니다.',
    data.truncated ? 'partial' : 'available');
  } catch {
    if (generation === approvalListGeneration) {
      setApprovalListStatus('로컬 승인 목록 조회에 연결하지 못했습니다.', 'error');
    }
  } finally {
    temporaryToken = '';
    if (approvalListController === controller) approvalListController = null;
    approvalListBusy = false;
    approvalListLoad.disabled = false;
  }
}

approvalListLoad.addEventListener('click', loadApprovalList);
approvalListPanel.addEventListener('toggle', () => {
  if (!approvalListPanel.open) clearApprovalList();
});
window.addEventListener('pagehide', () => {
  clearApprovalList();
  approvalListPanel.open = false;
});

function setAdminStatus(message, state = 'neutral') {
  adminStatus.textContent = message;
  adminStatus.dataset.state = state;
}

function updateAdminButtons() {
  adminCountsLoad.disabled = adminBusy;
  adminEventsLoad.disabled = adminBusy;
  adminEventsPrevious.disabled = adminBusy || adminEventsPage === 0;
  adminEventsNext.disabled = adminBusy || !adminEventsHasMore || adminEventsPage >= 39;
  document.querySelectorAll('.admin-detail-load').forEach(control => { control.disabled = adminBusy; });
}

function showAdminError(reply, data) {
  const code = data && data.error && typeof data.error.code === 'string' ? data.error.code : '';
  if (reply.status === 401 || reply.status === 403 || reply.status === 404 || reply.status === 429 ||
      code === 'unauthorized' || code === 'too_many_auth_failures' || code === 'too_many_failures' ||
      code === 'local_only' || code === 'not_found') {
    setAdminStatus('관리자 인증 또는 로컬 접속 조건에서 거절됐습니다. 지정된 관리자 출처와 접속 위치를 확인하세요.', 'denied');
  } else if (code === 'overloaded') {
    setAdminStatus('다른 관리자 조회가 진행 중입니다. 잠시 뒤 다시 조회하세요.', 'busy');
  } else if (reply.status === 503 && code === 'unavailable') {
    setAdminStatus('감사 기록 검증 또는 열람 기록에 실패해 조회 데이터를 반환하지 않았습니다.', 'audit-failure');
  } else {
    setAdminStatus('관리자 조회 응답을 확인하지 못했습니다. 원문 오류는 표시하지 않습니다.', 'error');
  }
}

async function requestAdmin(path) {
  if (adminBusy) return null;
  if (!adminToken.value || adminToken.value.length > 256 || !/^[\x21-\x7e]+$/.test(adminToken.value)) {
    setAdminStatus('관리자 token을 입력하세요. token을 URL에 넣지 마세요.', 'denied');
    adminToken.focus();
    return null;
  }
  const generation = adminGeneration;
  let token = adminToken.value;
  const headers = { Authorization: 'Bearer ' + token };
  token = '';
  adminToken.value = '';
  const controller = new AbortController();
  adminController = controller;
  adminBusy = true;
  updateAdminButtons();
  setAdminStatus('로컬 관리자 조회를 진행하고 있습니다.');
  try {
    const reply = await fetch(path, {
      method: 'GET', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
      referrerPolicy: 'no-referrer', headers, signal: controller.signal
    });
    let data;
    try { data = await reply.json(); } catch { data = null; }
    if (generation !== adminGeneration) return null;
    if (!reply.ok) {
      showAdminError(reply, data);
      return null;
    }
    return { data, reply };
  } catch {
    if (generation === adminGeneration) {
      setAdminStatus('로컬 관리자 조회에 연결하지 못했습니다. 결과를 확인할 수 없습니다.', 'error');
    }
    return null;
  } finally {
    if (adminController === controller) adminController = null;
    adminBusy = false;
    updateAdminButtons();
  }
}

function partialAdminScope(data, kind) {
  if (data.complete === false || data.status === 'partial' || data.status === 'range_limited') {
    if (kind === 'counts' && Number.isSafeInteger(data.verified_records)) {
      return `일부 최신 연속 구간만 검증했습니다. 아래 숫자는 검증된 ${data.verified_records}개 기록의 집계이며 전체 건수가 아닙니다.`;
    }
    return '일부 최신 연속 구간만 검증했습니다. 아래 목록은 전체 이력이 아닙니다.';
  }
  return '최근 24시간 조회 범위의 기록을 검증했습니다.';
}

function validAdminScope(data) {
  return data && data.window_hours === 24 &&
    ((data.complete === true && data.verification_scope === 'recent_segments') ||
     (data.complete === false && data.verification_scope === 'verified_latest_suffix'));
}

function clearAdminCounts() {
  adminCountsSection.hidden = true;
  for (const [, id] of adminCountFields) document.getElementById(id).textContent = '—';
}

async function loadAdminCounts() {
  clearAdminCounts();
  const result = await requestAdmin('/v1/admin/audit/counts');
  if (!result) return;
  const { data } = result;
  if (data && data.status === 'range_limited' && data.complete === false) {
    setAdminStatus('검증 범위가 제한돼 집계 숫자를 반환하지 않았습니다. token 입력은 지웠습니다.', 'partial');
    return;
  }
  const valid = data && (data.status === 'available' || data.status === 'partial') &&
    data.complete === (data.status === 'available') && validAdminScope(data) &&
    Number.isSafeInteger(data.verified_records) && data.verified_records >= 0 &&
    data.counts && typeof data.counts === 'object' && !Array.isArray(data.counts) &&
    adminCountFields.every(([key]) => Number.isSafeInteger(data.counts[key]) && data.counts[key] >= 0);
  if (!valid) {
    setAdminStatus('집계 응답 형식을 확인하지 못했습니다. 숫자를 표시하지 않습니다.', 'error');
    return;
  }
  for (const [key, id] of adminCountFields) document.getElementById(id).textContent = String(data.counts[key]);
  adminCountsScope.textContent = partialAdminScope(data, 'counts');
  adminCountsSection.hidden = false;
  setAdminStatus(data.complete ? '최근 집계 조회를 마쳤습니다. token 입력은 지웠습니다.' :
    '부분 범위의 집계를 표시합니다. token 입력은 지웠습니다.', data.complete ? 'available' : 'partial');
}

const adminKindLabels = {
  request: '요청 판정', preview: '미리보기', confirmation: '확인', credential_rotation: '자격 증명 교체',
  egress: '전송 준비', egress_answer: '제공자 응답 기록', auth: '인증', admin_history_access: '관리자 열람',
  expire: '만료 삭제', boot: '기동', shutdown: '종료', other: '기타'
};

function validAdminEvent(item) {
  return item && typeof item.timestamp === 'string' &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(item.timestamp) &&
    typeof item.kind === 'string' && typeof item.severity === 'string';
}

function appendAdminEventField(target, label, value) {
  const row = document.createElement('div');
  const term = document.createElement('dt');
  const detail = document.createElement('dd');
  term.textContent = label;
  detail.textContent = String(value);
  row.append(term, detail);
  target.append(row);
}

function renderAdminEvent(item) {
  const entry = document.createElement('li');
  entry.className = 'admin-event';
  const heading = document.createElement('h4');
  heading.className = 'admin-event-heading';
  heading.textContent = `${adminKindLabels[item.kind] || '기타'} · ${item.timestamp}`;
  entry.append(heading);
  const metadata = document.createElement('dl');
  metadata.className = 'admin-event-meta';
  if (['info', 'warn', 'error'].includes(item.severity)) appendAdminEventField(metadata, '심각도', item.severity);
  for (const [key, label] of adminEventFields) {
    const value = item[key];
    if ((typeof value === 'string' && value.length <= 128) || Number.isSafeInteger(value) ||
        (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 600000)) {
      if ((key !== 'grade' || value === 'O') && (key !== 'result' ||
          ['pass', 'reject', 'attempt', 'checked', 'read', 'range_limited', 'out_of_range'].includes(value))) {
        appendAdminEventField(metadata, label, value);
      }
    }
  }
  if (typeof item.request_id === 'string' && /^chatcmpl-pa-[0-9a-f]{24}$/.test(item.request_id)) {
    appendAdminEventField(metadata, '요청 식별자', item.request_id);
  }
  entry.append(metadata);
  if (item.kind === 'egress' && typeof item.request_id === 'string' && /^chatcmpl-pa-[0-9a-f]{24}$/.test(item.request_id)) {
    const disclosure = document.createElement('details');
    const summary = document.createElement('summary');
    const load = document.createElement('button');
    const detailStatus = document.createElement('p');
    const text = document.createElement('pre');
    summary.textContent = '검증된 요청 상세';
    load.className = 'admin-detail-load';
    load.type = 'button';
    load.textContent = '요청 내용 조회';
    detailStatus.className = 'status';
    detailStatus.setAttribute('role', 'status');
    detailStatus.setAttribute('aria-live', 'polite');
    detailStatus.textContent = '선택한 뒤 조회할 수 있습니다. 전송 준비 상태이며 전달 완료는 확인되지 않았습니다.';
    text.className = 'admin-detail-text';
    text.tabIndex = 0;
    text.hidden = true;
    load.addEventListener('click', async () => {
      text.hidden = true;
      text.replaceChildren();
      detailStatus.textContent = '검증된 전송 요청을 조회하고 있습니다.';
      const result = await requestAdmin('/v1/admin/audit/egress/' + encodeURIComponent(item.request_id));
      if (!result) {
        detailStatus.textContent = '접근이 거절되었거나 감사 검증에 실패해 요청 내용을 표시하지 않았습니다.';
        return;
      }
      const data = result.data;
      if (data && data.status === 'prepared' && data.request_id === item.request_id &&
          data.delivery_confirmed === false && typeof data.request_text === 'string' &&
          new TextEncoder().encode(data.request_text).length <= 128 * 1024 &&
          validAdminScope(data)) {
        appendHighlighted(text, data.request_text);
        text.hidden = false;
        detailStatus.textContent = data.complete === false
          ? '검증된 최신 일부 구간의 전송 준비 요청입니다. 실제 전달 완료는 확인되지 않았습니다. token 입력은 지웠습니다.'
          : '검증된 전송 준비 요청입니다. 실제 전달 완료는 확인되지 않았습니다. token 입력은 지웠습니다.';
        setAdminStatus(data.complete ? '요청 상세를 검증했습니다. token 입력은 지웠습니다.' :
          '부분 최신 구간의 요청 상세를 검증했습니다. token 입력은 지웠습니다.', data.complete ? 'available' : 'partial');
      } else if (data && data.status === 'range_limited') {
        detailStatus.textContent = '일부 최신 구간에서 요청을 확인하지 못해 상세를 반환하지 않았습니다. token 입력은 지웠습니다.';
        setAdminStatus('부분 조회 범위에서 요청을 확인하지 못했습니다. token 입력은 지웠습니다.', 'partial');
      } else if (data && data.status === 'out_of_range') {
        detailStatus.textContent = '최근 조회 범위 밖이거나 상세 상한을 넘은 기록입니다. token 입력은 지웠습니다.';
        setAdminStatus('요청 상세가 최근 범위 밖이거나 상세 상한을 넘습니다. token 입력은 지웠습니다.', 'partial');
      } else {
        detailStatus.textContent = '상세 응답을 검증하지 못해 요청 내용을 표시하지 않았습니다.';
        setAdminStatus('상세 응답을 검증하지 못해 요청 내용을 표시하지 않았습니다.', 'error');
      }
    });
    disclosure.append(summary, load, detailStatus, text);
    entry.append(disclosure);
  }
  return entry;
}

async function loadAdminEvents(page) {
  adminEventsSection.hidden = true;
  adminEvents.replaceChildren();
  const result = await requestAdmin(`/v1/admin/audit/events?page=${page}`);
  if (!result) return;
  const { data } = result;
  if (data && data.status === 'range_limited' && data.complete === false) {
    adminEventsSection.hidden = false;
    const empty = document.createElement('li');
    empty.textContent = '검증 범위가 제한돼 기록 목록을 표시하지 않았습니다.';
    adminEvents.append(empty);
    adminEventsPage = page;
    adminEventsHasMore = false;
    adminEventsScope.textContent = partialAdminScope(data, 'events');
    adminEventsPageLabel.textContent = `${page + 1}페이지`;
    updateAdminButtons();
    setAdminStatus('검증 범위가 제한돼 기록 목록을 반환하지 않았습니다. token 입력은 지웠습니다.', 'partial');
    return;
  }
  const valid = data && (data.status === 'available' || data.status === 'partial') &&
    data.complete === (data.status === 'available') && validAdminScope(data) && data.page === page &&
    Array.isArray(data.events) && data.events.length <= 25 && typeof data.has_more === 'boolean' &&
    typeof data.truncated === 'boolean' && data.events.every(validAdminEvent);
  if (!valid) {
    setAdminStatus('기록 목록 응답 형식을 확인하지 못했습니다. 항목을 표시하지 않습니다.', 'error');
    return;
  }
  adminEventsPage = page;
  adminEventsHasMore = data.has_more;
  adminEventsScope.textContent = partialAdminScope(data, 'events') +
    (data.truncated === true ? ' 목록 표시 상한에 도달했습니다.' : '');
  if (data.events.length === 0) {
    const empty = document.createElement('li');
    empty.textContent = '이 페이지에 표시할 검증 기록이 없습니다.';
    adminEvents.append(empty);
  } else {
    for (const item of data.events) adminEvents.append(renderAdminEvent(item));
  }
  adminEventsSection.hidden = false;
  adminEventsPageLabel.textContent = `${page + 1}페이지`;
  updateAdminButtons();
  setAdminStatus(data.complete ? '최근 기록 목록 조회를 마쳤습니다. token 입력은 지웠습니다.' :
    '부분 범위의 최신 기록을 표시합니다. token 입력은 지웠습니다.',
    data.complete ? 'available' : 'partial');
}

adminCountsLoad.addEventListener('click', loadAdminCounts);
adminEventsLoad.addEventListener('click', () => { adminEventsHasMore = false; loadAdminEvents(0); });
adminEventsPrevious.addEventListener('click', () => {
  if (adminEventsPage > 0) loadAdminEvents(adminEventsPage - 1);
});
adminEventsNext.addEventListener('click', () => {
  if (adminEventsHasMore && adminEventsPage < 39) loadAdminEvents(adminEventsPage + 1);
});
function closeAdminView(focusOpener) {
  adminGeneration += 1;
  if (adminController) adminController.abort();
  adminController = null;
  adminToken.value = '';
  clearAdminCounts();
  adminCountsScope.textContent = '';
  adminEventsSection.hidden = true;
  adminEventsScope.textContent = '';
  adminEvents.replaceChildren();
  const empty = document.createElement('li');
  empty.textContent = '기록 목록을 아직 조회하지 않았습니다.';
  adminEvents.append(empty);
  adminEventsPage = 0;
  adminEventsHasMore = false;
  adminEventsPageLabel.textContent = '1페이지';
  setAdminStatus('관리자 조회가 닫혔습니다. 집계·목록·상세 내용을 지웠습니다.');
  adminPanel.hidden = true;
  adminOpen.hidden = false;
  adminOpen.setAttribute('aria-expanded', 'false');
  updateAdminButtons();
  if (focusOpener) adminOpen.focus();
}

adminOpen.addEventListener('click', () => {
  adminOpen.hidden = true;
  adminPanel.hidden = false;
  adminOpen.setAttribute('aria-expanded', 'true');
  adminToken.focus();
});
adminClose.addEventListener('click', () => closeAdminView(true));
window.addEventListener('pagehide', () => closeAdminView(false));
updateAdminButtons();

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
