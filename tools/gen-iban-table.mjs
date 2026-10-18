// SWIFT IBAN Registry 텍스트(탭 구분, 국가가 열)에서 src/detect/data/iban_registry.hpp 를 만든다.
// 사용: node tools/gen-iban-table.mjs "official/formats/IBAN Registry.txt" > src/detect/data/iban_registry.hpp
// 원천 파일은 추적하지 않는다(official/). 바뀌면 새 파일로 다시 만들고 SHA-256 을 머리 주석과 manifest 에 적는다.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const path = process.argv[2];
if (!path) {
  console.error('사용: node tools/gen-iban-table.mjs <IBAN Registry.txt>');
  process.exit(2);
}
const bytes = readFileSync(path);
const text = bytes.toString('latin1');

// 따옴표 안의 줄바꿈과 탭을 허용하는 TSV 파서.
const rows = [];
let row = [];
let field = '';
let quoted = false;
for (let i = 0; i < text.length; i++) {
  const c = text[i];
  if (quoted) {
    if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
    else if (c === '"') quoted = false;
    else field += c;
  } else if (c === '"') quoted = true;
  else if (c === '\t') { row.push(field); field = ''; }
  else if (c === '\n' || c === '\r') {
    if (c === '\r' && text[i + 1] === '\n') i++;
    row.push(field); rows.push(row); row = []; field = '';
  } else field += c;
}
if (field || row.length) { row.push(field); rows.push(row); }

const get = (name) => {
  const found = rows.find((r) => r[0].trim() === name);
  if (!found) throw new Error(`행 없음: ${name}`);
  return found.slice(1).map((v) => v.trim());
};
const codes = get('IBAN prefix country code (ISO 3166)');
const bbans = get('BBAN structure');
const lengths = get('IBAN length');

const entries = codes.map((code, i) => {
  const bban = bbans[i];
  const length = Number(lengths[i]);
  if (!/^[A-Z]{2}$/.test(code) || !/^(\d+!?[nac])+$/.test(bban) || !Number.isInteger(length)) {
    throw new Error(`형식 오류: ${code} ${bban} ${lengths[i]}`);
  }
  const sum = [...bban.matchAll(/(\d+)!?[nac]/g)].reduce((s, m) => s + Number(m[1]), 0);
  if (sum !== length - 4) throw new Error(`길이 불일치: ${code}`);
  return { code, length, bban };
}).sort((a, b) => a.code.localeCompare(b.code));

const sha = createHash('sha256').update(bytes).digest('hex');
const lines = entries.map((e) => `    IbanCountry{"${e.code}", ${e.length}, "${e.bban}"},`);
process.stdout.write(`// 이 파일은 tools/gen-iban-table.mjs 가 만든다. 직접 고치지 않는다.
// 원천: SWIFT IBAN Registry 텍스트판(국가 ${entries.length}개, SHA-256 앞 8자리 ${sha.slice(0, 8)}, 확인일 2026-10-18).
// 구조 기호(SWIFT): n 숫자, a 영문 대문자, c 영숫자, 숫자는 자리 수, '!' 는 고정 길이.
// 바꾸는 절차: 새 Registry 를 official/formats/ 에 넣고 위 도구로 다시 만든 뒤 detect_accounts_test 를 돌린다.
#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace prompt_airlock::detect::data {

struct IbanCountry {
    std::string_view country;  // ISO 3166 두 글자
    std::uint8_t length;       // IBAN 전체 길이(국가 2 + 검증 2 + BBAN)
    std::string_view bban;     // BBAN 구조 기호
};

inline constexpr std::array<IbanCountry, ${entries.length}> iban_countries = {{
${lines.join('\n')}
}};

}  // namespace prompt_airlock::detect::data
`);
