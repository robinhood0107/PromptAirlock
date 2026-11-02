#!/usr/bin/env node
// 측정용 자격 증명 갱신 작업(ADR 0026 의 gcloud 자리). 설정의 auth 로 access token 을 받아 표준 출력에 한 줄로 낸다.
// 게이트웨이 설정을 함께 주면 그 provider.url 을 측정 설정의 endpoint(키의 project_id 로 채운 값)로 맞춘다.
// 게이트웨이는 기동 때만 설정을 읽으므로 url 이 바뀌면 다시 띄운다.
// 사용: node spikes/token-survival/print-token.mjs <설정.json> [게이트웨이 설정.json] | prompt-airlock protect-credential - <자격 증명 파일>
import { readFileSync, writeFileSync } from 'node:fs';

import { makeAuth, resolveEndpoint } from './survival.mjs';

const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const gatewayPath = process.argv[3];
if (gatewayPath) {
  const gateway = JSON.parse(readFileSync(gatewayPath, 'utf8'));
  const url = resolveEndpoint(config.endpoint, config.auth);
  if (gateway.provider.url !== url) {
    gateway.provider.url = url;
    writeFileSync(gatewayPath, `${JSON.stringify(gateway, null, 2)}
`);
    console.error(`게이트웨이 설정의 provider.url 을 바꿨다(게이트웨이를 다시 띄울 것): ${gatewayPath}`);
  }
}
process.stdout.write(`${await makeAuth(config.auth)()}
`);
