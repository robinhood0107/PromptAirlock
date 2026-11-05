// 어느 작업 디렉터리에서 실행해도 같은 저장소의 비공개 정책으로 검사한다.
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPolicy } from './publication-policy.mjs';

export function checkFiles(files, root = fileURLToPath(new URL('../../', import.meta.url)), env = process.env) {
  if (!files.length) throw new Error('검사할 파일이 없습니다.');
  const config = path.join(root, '.publication-policy.local.json');
  const pattern = existsSync(config) ? JSON.parse(readFileSync(config, 'utf8')).pattern : env.PUBLICATION_DENY_PATTERN;
  const policy = createPolicy(pattern);
  for (const file of files) policy.inspectText(readFileSync(file, 'utf8'), 'text');
}

export function runCheck(files = process.argv.slice(2)) {
  try {
    checkFiles(files);
    console.log('policy ok');
  } catch {
    console.error('공개 텍스트 검사를 통과하지 못했습니다. 정책 설정과 입력 파일을 확인하세요.');
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) runCheck();
