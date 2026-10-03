import test from 'node:test';
import assert from 'node:assert/strict';
import { createPolicy, paginate } from './publication-policy.mjs';
import { makeApi, runAudit } from './run-publication-policy.mjs';

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

function fixtureApi({ text = 'Neutral source', truncated = false, changed = false, failCommits = false, failPullList = false } = {}) {
  const writes = [];
  const pull = { number: 1, title: 'chore: add checks', body: '', state: 'open',
    head: { sha, ref: 'chore/checks' }, base: { ref: 'main' } };
  const api = async (path, method, body) => {
    if (method === 'POST') { writes.push({ path, ...body }); return {}; }
    const tail = path.replace('repos/owner/repository', '');
    if (tail === '') return { name: 'Repository', description: 'Security project' };
    if (tail.startsWith('/pulls?')) {
      if (failPullList) throw new Error('Unavailable');
      return [pull];
    }
    if (tail.startsWith('/branches?')) return [{ name: 'main', commit: { sha } }];
    if (tail.startsWith('/commits?')) {
      if (failCommits) throw new Error('Unavailable');
      return [{ sha, commit: { message: 'chore: initial work', author: { name: 'Owner' }, tree: { sha: treeSha } } }];
    }
    if (tail.startsWith('/git/trees/')) return { truncated, tree: [{ type: 'blob', path: 'src/core.cpp', sha: blobSha, size: Buffer.byteLength(text) }] };
    if (tail.startsWith('/git/blobs/')) return { encoding: 'base64', content: Buffer.from(text).toString('base64') };
    if (tail === '/actions/workflows?per_page=100') return { total_count: 0, workflows: [] };
    if (tail === '/pulls/1') return changed ? { ...pull, body: 'Changed during audit' } : pull;
    return [];
  };
  return { api, writes, event: { pull_request: pull } };
}

test('audit binds required status to the exact PR head', async () => {
  const fixture = fixtureApi();
  const result = await runAudit({ ...fixture, repository: 'owner/repository', pattern, writeStatuses: true });
  assert.deepEqual(result, { commits: 1, files: 1 });
  assert.equal(fixture.writes.at(-1).state, 'success');
  assert.ok(fixture.writes.every((entry) => entry.path.endsWith(`/statuses/${sha}`)));
  assert.ok(fixture.writes.every((entry) => entry.context === 'publication-policy'));
});

for (const [name, options] of Object.entries({
  'forbidden file content': { text: 'SampleTool' },
  'binary content': { text: '\u0000binary' },
  'truncated tree': { truncated: true },
  'API failure': { failCommits: true },
  'early PR listing failure': { failPullList: true },
  'concurrent PR edit': { changed: true },
})) {
  test(`audit fails closed for ${name}`, async () => {
    const fixture = fixtureApi(options);
    await assert.rejects(runAudit({ ...fixture, repository: 'owner/repository', pattern, writeStatuses: true }));
    assert.equal(fixture.writes.at(-1).state, 'failure');
    assert.ok(fixture.writes.every((entry) => entry.state !== 'success'));
  });
}

test('missing configuration invalidates the previous PR status', async () => {
  const fixture = fixtureApi();
  await assert.rejects(runAudit({ ...fixture, repository: 'owner/repository', pattern: '', writeStatuses: true }));
  assert.equal(fixture.writes[0].state, 'pending');
  assert.equal(fixture.writes.at(-1).state, 'failure');
});

test('failed checker validation cannot publish a passing status', async () => {
  const fixture = fixtureApi();
  await assert.rejects(runAudit({ ...fixture, repository: 'owner/repository', pattern, writeStatuses: true, validationPassed: false }));
  assert.equal(fixture.writes.at(-1).state, 'failure');
});

test('trusted downstream events invalidate the head before listing failure', async () => {
  const fixture = fixtureApi({ failPullList: true });
  const event = { workflow_run: { head_sha: sha, pull_requests: [{ head: { sha } }] } };
  await assert.rejects(runAudit({ ...fixture, event, repository: 'owner/repository', pattern, writeStatuses: true }));
  assert.equal(fixture.writes[0].state, 'pending');
  assert.equal(fixture.writes.at(-1).state, 'failure');
});

test('read-only audits never post repository statuses', async () => {
  const fixture = fixtureApi();
  await runAudit({ ...fixture, repository: 'owner/repository', pattern });
  assert.deepEqual(fixture.writes, []);
});
