#!/usr/bin/env node
// 측정용 자격 증명 갱신 작업(ADR 0026 의 gcloud 자리). 설정의 auth 로 access token 을 받아 표준 출력에 한 줄로 낸다.
// 사용: node spikes/token-survival/print-token.mjs <설정.json> | prompt-airlock protect-credential - <자격 증명 파일>
import { readFileSync } from 'node:fs';

import { makeAuth } from './survival.mjs';

const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
process.stdout.write(`${await makeAuth(config.auth)()}\n`);
