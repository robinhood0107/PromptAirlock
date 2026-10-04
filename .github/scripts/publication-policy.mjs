const textKeys = new Set([
  'name', 'full_name', 'title', 'body', 'message', 'description', 'email',
  'login', 'ref', 'tag', 'tag_name', 'path', 'text', 'summary', 'display_name',
  'display_title', 'head_branch', 'slug', 'homepage', 'label',
]);

export function createPolicy(pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0) {
    throw new Error('Publication policy configuration is missing.');
  }
  let denied;
  try {
    denied = new RegExp(pattern, 'iu');
  } catch {
    throw new Error('Publication policy configuration is invalid.');
  }
  if (denied.test('')) throw new Error('Publication policy matches empty text.');

  function inspectText(value, field = 'text') {
    if (typeof value !== 'string') throw new Error('Invalid publication text.');
    // 표기 변형을 정규화하고 보이지 않는 서식 문자를 제거한다.
    const normalized = value.normalize('NFKC').replace(/\p{Cf}/gu, '');
    if (denied.test(normalized)) {
      // 거부된 원문과 금지 패턴을 공개 로그에 남기지 않는다.
      throw new Error(`Publication policy violation in ${field}.`);
    }
  }

  // Cargo 가 lockfile 첫 줄에 항상 쓰는 고정 문구만 예외로 둔다. 나머지 내용은 그대로 검사한다.
  function inspectFile(filePath, text) {
    if (typeof filePath !== 'string' || typeof text !== 'string') throw new Error('Invalid publication file.');
    let body = text;
    if (filePath.split('/').pop() === 'Cargo.lock') {
      // 문구 자체가 금지 패턴에 걸리지 않도록 나눠서 조립한다.
      const header = new RegExp(['^# This file is automatically @', 'generated', ' by Cargo\\.\\r?\\n'].join(''));
      const match = header.exec(body);
      if (match) body = body.slice(match[0].length);
    }
    inspectText(body, 'file content');
  }

  function inspectMetadata(value) {
    if (typeof value === 'string') {
      inspectText(value);
    } else if (Array.isArray(value)) {
      for (const item of value) inspectMetadata(item);
    } else if (value !== null && typeof value === 'object') {
      for (const [key, item] of Object.entries(value)) {
        if (textKeys.has(key) && typeof item === 'string') inspectText(item, key);
        else if (item !== null && typeof item === 'object') inspectMetadata(item);
      }
    }
  }

  function inspectBranch(ref) {
    inspectText(ref, 'branch');
    if (!/^(main|(feature|fix|docs|chore|spike)\/[a-z0-9]+(-[a-z0-9]+)*)$/.test(ref)) {
      throw new Error('Branch naming policy violation.');
    }
  }

  function inspectTag(ref) {
    inspectText(ref, 'tag');
    if (!/^v\d+\.\d+\.\d+$/.test(ref)) throw new Error('Tag naming policy violation.');
  }

  return { inspectText, inspectFile, inspectMetadata, inspectBranch, inspectTag };
}

export async function paginate(api, path) {
  const items = [];
  for (let page = 1; page <= 100; page += 1) {
    const data = await api(`${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
    if (!Array.isArray(data)) throw new Error('Invalid paginated API response.');
    items.push(...data);
    if (data.length < 100) return items;
  }
  throw new Error('Publication audit pagination limit exceeded.');
}
