import test from 'node:test';
import assert from 'node:assert/strict';
import { createPolicy, paginate } from './publication-policy.mjs';
import { auditEvent, auditPull, auditPush, makeApi, runAudit } from './run-publication-policy.mjs';

const pattern = 'sampletool|co[- ]?authored[- ]?by\\s*:|generated\\s+by';
const policy = createPolicy(pattern);
const sha = 'a'.repeat(40);
const treeSha = 'b'.repeat(40);
const blobSha = 'c'.repeat(40);

test('neutral changes and approved branches pass', () => {
  policy.inspectText('fix: repair request validation');
  for (const branch of ['main', 'feature/domain-core', 'fix/parser', 'docs/license', 'chore/checks', 'spike/runtime']) {
    policy.inspectBranch(branch);
  }
  policy.inspectTag('v1.2.3');
});

test('all text-bearing metadata fields reject attribution', () => {
  for (const key of ['message', 'name', 'email', 'title', 'body', 'description', 'login', 'ref', 'tag_name', 'path']) {
    assert.throws(() => policy.inspectMetadata({ outer: [{ [key]: 'SampleTool' }] }), /violation/);
  }
  assert.throws(() => policy.inspectText(`${['Co', 'Authored', 'By'].join('-')}: Example`), /violation/);
  assert.throws(() => policy.inspectText(['Generated', 'by', 'Example'].join(' ')), /violation/);
  assert.throws(() => policy.inspectMetadata({ topics: ['SampleTool'] }), /violation/);
});

test('case, fullwidth characters and invisible formatting cannot bypass the policy', () => {
  for (const value of ['SAMPLETOOL', 'ＳａｍｐｌｅＴｏｏｌ', 'Sample\u200bTool']) {
    assert.throws(() => policy.inspectText(value), /violation/);
  }
});

test('configuration errors fail closed without echoing the pattern', () => {
  for (const value of ['', undefined, '[', '.*']) assert.throws(() => createPolicy(value));
  try { policy.inspectText('SampleTool private text'); }
  catch (error) { assert.doesNotMatch(error.message, /SampleTool|private text/); }
});

test('unapproved ref names fail', () => {
  for (const ref of ['develop', 'feature/SampleTool', 'feature/UPPER', 'feature/a/b', 'feat/test']) {
    assert.throws(() => policy.inspectBranch(ref));
  }
  assert.throws(() => policy.inspectTag('v1.2.3-sampletool'));
});

test('only the standard Cargo lockfile header is exempt', () => {
  const header = ['# This file is automatically @', 'generated', ' by Cargo.'].join('');
  const lock = `${header}\n# It is not intended for manual editing.\nversion = 4\n`;
  policy.inspectFile('vault/Cargo.lock', lock);
  policy.inspectFile('Cargo.lock', lock.replace(/\n/g, '\r\n'));
  assert.throws(() => policy.inspectFile('vault/notes.md', lock), /violation/);
  assert.throws(() => policy.inspectFile('vault/Cargo.lock', `${lock}# SampleTool\n`), /violation/);
  assert.throws(() => policy.inspectFile('vault/Cargo.lock', `version = 4\n${header}\n`), /violation/);
});

test('metadata is data and shell-like text never executes', () => {
  policy.inspectMetadata({ body: '$(touch /tmp/unwanted) `exit 1`\n::error::test' });
});

test('pagination includes later pages and fails on incomplete responses', async () => {
  let calls = 0;
  const values = await paginate(async () => ++calls === 1 ? Array(100).fill({}) : [{ name: 'SampleTool' }], 'repos/o/r/tags');
  assert.equal(values.length, 101);
  assert.throws(() => policy.inspectMetadata(values), /violation/);
  await assert.rejects(paginate(async () => ({}), 'repos/o/r/tags'));
  await assert.rejects(paginate(async () => Array(100).fill({}), 'repos/o/r/tags'), /limit/);
});

test('API errors do not expose server response or credentials', async () => {
  const api = makeApi('private-token', async () => ({ ok: false, status: 403 }));
  await assert.rejects(api('repos/o/r'), { message: 'Repository API failed (403).' });
  await assert.rejects(api('https://example.com'));
});

function fixtureApi({ text = 'Neutral source', truncated = false, changed = false, failCommits = false, failPullList = false,
  tooManyFiles = false } = {}) {
  const writes = [];
  let pullReads = 0;
  const pull = { number: 1, title: 'chore: add checks', body: '', state: 'open', user: { login: 'owner' },
    head: { sha, ref: 'chore/checks' }, base: { ref: 'main' } };
  const files = tooManyFiles
    ? Array.from({ length: 300 }, (_, i) => ({ filename: `f${i}.txt`, status: 'added', sha: blobSha }))
    : [{ filename: 'src/core.cpp', status: 'modified', sha: blobSha }];
  const api = async (path, method, body) => {
    if (method === 'POST') { writes.push({ path, ...body }); return {}; }
    const tail = path.replace('repos/owner/repository', '');
    if (tail === '') return { name: 'Repository', description: 'Security project' };
    if (tail.startsWith('/pulls?')) {
      if (failPullList) throw new Error('Unavailable');
      return [pull];
    }
    if (tail.startsWith('/pulls/1/commits')) {
      if (failCommits) throw new Error('Unavailable');
      return [{ sha }];
    }
    if (tail === '/pulls/1') {
      pullReads += 1;
      return changed && pullReads > 1 ? { ...pull, body: 'Changed during audit' } : pull;
    }
    if (tail.startsWith('/compare/')) return { commits: [{ sha }] };
    if (tail === `/commits/${sha}`) {
      if (failCommits) throw new Error('Unavailable');
      return { commit: { message: 'chore: initial work', author: { name: 'Owner' } }, files };
    }
    if (tail.startsWith('/branches?')) return [{ name: 'main', commit: { sha } }];
    if (tail.startsWith('/commits?')) {
      if (failCommits) throw new Error('Unavailable');
      return [{ sha, commit: { message: 'chore: initial work', author: { name: 'Owner' }, tree: { sha: treeSha } } }];
    }
    if (tail.startsWith('/git/trees/')) return { truncated, tree: [{ type: 'blob', path: 'src/core.cpp', sha: blobSha, size: Buffer.byteLength(text) }] };
    if (tail.startsWith('/git/blobs/')) {
      return { encoding: 'base64', content: Buffer.from(text).toString('base64'), size: Buffer.byteLength(text) };
    }
    if (tail === '/actions/workflows?per_page=100') return { total_count: 0, workflows: [] };
    return [];
  };
  return { api, writes };
}

const repository = 'owner/repository';

test('PR audit binds the required status to the exact PR head', async () => {
  const fixture = fixtureApi();
  const result = await auditPull({ ...fixture, repository, pattern, number: 1, writeStatuses: true });
  assert.deepEqual(result, { commits: 1, files: 1 });
  assert.equal(fixture.writes[0].state, 'pending');
  assert.equal(fixture.writes.at(-1).state, 'success');
  assert.ok(fixture.writes.every((entry) => entry.path.endsWith(`/statuses/${sha}`)));
  assert.ok(fixture.writes.every((entry) => entry.context === 'publication-policy'));
});

for (const [name, options] of Object.entries({
  'forbidden file content': { text: 'SampleTool' },
  'binary content': { text: '\u0000binary' },
  'API failure': { failCommits: true },
  'too many changed files': { tooManyFiles: true },
  'concurrent PR edit': { changed: true },
})) {
  test(`PR audit fails closed for ${name}`, async () => {
    const fixture = fixtureApi(options);
    await assert.rejects(auditPull({ ...fixture, repository, pattern, number: 1, writeStatuses: true }));
    assert.equal(fixture.writes.at(-1).state, 'failure');
    assert.ok(fixture.writes.every((entry) => entry.state !== 'success'));
  });
}

test('missing configuration or failed checker never publishes a passing PR status', async () => {
  for (const options of [{ pattern: '' }, { pattern, validationPassed: false }]) {
    const fixture = fixtureApi();
    await assert.rejects(auditPull({ ...fixture, repository, number: 1, writeStatuses: true, ...options }));
    assert.equal(fixture.writes[0].state, 'pending');
    assert.equal(fixture.writes.at(-1).state, 'failure');
  }
});

test('issue and comment events check only the current text and never touch PR statuses', () => {
  const clean = { issue: { title: 'Measure', body: 'Neutral', labels: [{ name: 'phase:4', description: '' }] },
    comment: { body: 'Neutral reply' },
    // 수정 전 문구는 이미 지워졌으므로 위반이어도 실패시키지 않는다.
    changes: { body: { from: 'SampleTool' } } };
  assert.deepEqual(auditEvent({ pattern, event: clean }), { items: 2 });
  assert.throws(() => auditEvent({ pattern, event: { comment: { body: 'SampleTool' } } }), /violation/);
  assert.throws(() => auditEvent({ pattern, event: { issue: { title: 'x', body: '', labels: [{ name: 'SampleTool' }] } } }), /violation/);
});

test('push audit checks only commits that are not on main', async () => {
  const fixture = fixtureApi();
  assert.deepEqual(await auditPush({ ...fixture, repository, pattern, head: sha, branch: 'chore/checks' }), { commits: 1, files: 1 });
  await assert.rejects(auditPush({ ...fixtureApi({ text: 'SampleTool' }), repository, pattern, head: sha, branch: 'chore/checks' }));
  await assert.rejects(auditPush({ ...fixture, repository, pattern, head: sha, branch: 'unapproved' }));
  assert.deepEqual(fixture.writes, []);
});

test('repository audit sweeps everything and never posts statuses', async () => {
  const fixture = fixtureApi();
  assert.deepEqual(await runAudit({ ...fixture, repository, pattern }), { commits: 1, files: 1 });
  assert.deepEqual(fixture.writes, []);
  for (const options of [{ text: 'SampleTool' }, { truncated: true }, { failCommits: true }, { failPullList: true }]) {
    await assert.rejects(runAudit({ ...fixtureApi(options), repository, pattern }));
  }
  await assert.rejects(runAudit({ ...fixture, repository, pattern, validationPassed: false }));
});
