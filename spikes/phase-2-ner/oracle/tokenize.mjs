// 개발 전용 tokenizer oracle. 런타임 경로에 포함되지 않는다.
// tok_dump 출력(norm_text, native ids)을 읽어 transformers.js 로 같은 문자열을 토큰화하고 비교한다.
// 사용: node tokenize.mjs <model_root> <tokenizer_dir> <fixtures.jsonl> <tok_dump.jsonl> <out_oracle.jsonl>
import fs from 'node:fs';
import { AutoTokenizer, env } from '@huggingface/transformers';

const [modelRoot, tokDir, fixturesPath, dumpPath, outPath] = process.argv.slice(2);
env.localModelPath = modelRoot.endsWith('/') ? modelRoot : modelRoot + '/';
env.allowRemoteModels = false;
env.allowLocalModels = true;

const tokenizer = await AutoTokenizer.from_pretrained(tokDir);
const fixtures = new Map(fs.readFileSync(fixturesPath, 'utf8').trim().split('\n').map((l) => {
  const j = JSON.parse(l);
  return [j.id, j.text];
}));
const ZW = /[​‌‍⁠﻿]/g;

let total = 0, exact = 0, nfcAgree = 0;
const out = [];
for (const line of fs.readFileSync(dumpPath, 'utf8').trim().split('\n')) {
  const d = JSON.parse(line);
  const ids = Array.from(tokenizer.encode(d.norm_text), Number);
  total++;
  const same = ids.length === d.ids.length && ids.every((v, i) => v === d.ids[i]);
  if (same) exact++;
  else {
    let k = 0;
    while (k < ids.length && ids[k] === d.ids[k]) k++;
    console.log(`MISMATCH ${d.id} at ${k}: oracle=${JSON.stringify(ids.slice(k, k + 5))} native=${JSON.stringify(d.ids.slice(k, k + 5))}`);
  }
  // native 정규화(utf8proc NFC + zero-width 제거)와 JS(ICU) 정규화가 같은지도 본다.
  const expected = d.mode === 'raw' ? fixtures.get(d.id) : fixtures.get(d.id).replace(ZW, '').normalize('NFC');
  if (expected === d.norm_text) nfcAgree++;
  else console.log(`NORM-DIFF ${d.id}`);
  out.push(JSON.stringify({ id: d.id, mode: d.mode, norm_text: d.norm_text, ids }));
}
fs.writeFileSync(outPath, out.join('\n') + '\n');
console.log(`SUMMARY tokenizer=${tokDir} mode=${JSON.parse(fs.readFileSync(dumpPath, 'utf8').split('\n')[0]).mode} exact=${exact}/${total} normalization_agree=${nfcAgree}/${total}`);
