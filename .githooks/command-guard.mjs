// 셸 실행 전에 훅 우회를 차단한다. 명령이나 입력 원문은 오류에 싣지 않는다.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function inspectCommandEvent(input) {
  const command = input?.tool_input?.command;
  if (typeof command !== 'string' || !command.trim()) throw new Error('셸 명령 입력을 확인할 수 없습니다.');
  const lowered = command.toLowerCase();
  if (/--no-verify\b/.test(lowered) || /\bgit(?:\.exe)?\b[^\n;&|]*\bcommit\b[^\n;&|]*\s-[a-z]*n[a-z]*(\s|$)/.test(lowered)) {
    throw new Error('Git 훅 우회는 허용되지 않습니다. 거절된 메시지나 이름을 고치세요.');
  }
  for (const part of lowered.split(/[\n;&|]/)) {
    if (!/core\.hookspath/.test(part)) continue;
    // 조회 허용이 뒤에 이어지는 별도 변경 명령까지 허용하지 않게 한다.
    if (/\bgit(?:\.exe)?\s+config\b/.test(part) && /\s(?:--get|--get-all|--get-regexp|--list|-l)(?:\s|$)/.test(part) &&
        !/\s(?:-c|--unset(?:-all)?|--add|--replace-all|--rename-section|--remove-section)(?:\s|$)/.test(part)) continue;
    throw new Error('Git 훅 경로 변경은 허용되지 않습니다.');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    inspectCommandEvent(JSON.parse(readFileSync(0, 'utf8')));
  } catch {
    console.error('명령 검사를 통과하지 못했습니다. 입력과 Git 훅 우회 여부를 확인하세요.');
    process.exitCode = 2;
  }
}
