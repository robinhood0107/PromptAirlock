// 게시 전 로컬 검사: CI와 같은 정책 모듈과 금지 패턴을 재사용한다.
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import path from 'node:path';

function fail(message) {
  // 금지된 원문은 출력하지 않는다.
  console.error(`[publication-policy] ${message}`);
  process.exit(1);
}

const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
const { createPolicy } = await import(pathToFileURL(path.join(root, '.github/scripts/publication-policy.mjs')).href);

// 패턴은 저장소에 두지 않는다. 로컬 파일 또는 환경 변수가 없으면 검사 없이 통과시키지 않는다.
const localConfig = path.join(root, '.publication-policy.local.json');
const pattern = existsSync(localConfig)
  ? JSON.parse(readFileSync(localConfig, 'utf8')).pattern
  : process.env.PUBLICATION_DENY_PATTERN;
if (!pattern) fail('Pattern missing. Create .publication-policy.local.json or set PUBLICATION_DENY_PATTERN.');

let policy;
try {
  policy = createPolicy(pattern);
} catch (error) {
  fail(error instanceof Error ? error.message : 'Publication policy configuration is invalid.');
}
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' });
const splitNul = (text) => text.split(/[\0\n]/).filter(Boolean);

const [mode, ...rest] = process.argv.slice(2);
try {
  if (mode === 'commit-msg') {
    policy.inspectText(readFileSync(rest[0], 'utf8'), 'commit message');
    policy.inspectText(git('var', 'GIT_AUTHOR_IDENT'), 'author');
    policy.inspectText(git('var', 'GIT_COMMITTER_IDENT'), 'committer');
    for (const file of splitNul(git('diff', '--cached', '--name-only', '-z'))) policy.inspectText(file, 'path');
  } else if (mode === 'pre-push') {
    const zero = /^0+$/;
    const input = readFileSync(0, 'utf8').trim();
    for (const line of input ? input.split('\n') : []) {
      const [, localSha, remoteRef, remoteSha] = line.trim().split(' ');
      if (remoteRef.startsWith('refs/heads/')) policy.inspectBranch(remoteRef.slice('refs/heads/'.length));
      else if (remoteRef.startsWith('refs/tags/')) policy.inspectTag(remoteRef.slice('refs/tags/'.length));
      if (zero.test(localSha)) continue;
      // 새 브랜치는 원격에 없는 커밋만, 기존 브랜치는 증분만 검사한다.
      const range = zero.test(remoteSha) ? [localSha, '--not', '--remotes'] : [`${remoteSha}..${localSha}`];
      const log = git('log', '--format=%an <%ae>%n%cn <%ce>%n%B%x00', ...range);
      for (const entry of log.split('\0')) if (entry.trim()) policy.inspectText(entry, 'commit');
      for (const file of splitNul(git('log', '--name-only', '--format=', '-z', ...range))) policy.inspectText(file, 'path');
    }
  } else {
    fail('Unknown hook mode.');
  }
} catch (error) {
  fail(error instanceof Error ? error.message : 'Publication policy check failed.');
}
