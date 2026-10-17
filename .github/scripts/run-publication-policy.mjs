import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createPolicy, paginate } from './publication-policy.mjs';

const shaPattern = /^[0-9a-f]{40}$/;
const repositoryPattern = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function makeApi(token, fetcher = fetch) {
  if (!token) throw new Error('Repository authentication is missing.');
  let requests = 0;
  return async function api(path, method = 'GET', body) {
    if (++requests > 4000) throw new Error('Publication audit request limit exceeded.');
    if (!path.startsWith('repos/') || path.includes('..')) {
      throw new Error('Invalid repository API path.');
    }
    const response = await fetcher(`https://api.github.com/${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
        'x-github-api-version': '2022-11-28',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });
    if (!response.ok) throw new Error(`Repository API failed (${response.status}).`);
    return response.json();
  };
}

function repositoryRoot(repository) {
  if (!repositoryPattern.test(repository)) throw new Error('Invalid repository identifier.');
  return `repos/${repository}`;
}

// 파일 내용과 커밋을 검사하는 도구. 같은 blob·tree·commit 은 한 번만 내려받는다.
function makeInspector(api, root, policy) {
  const seenCommits = new Set();
  const seenTrees = new Set();
  const seenBlobs = new Set();
  const decoder = new TextDecoder('utf-8', { fatal: true });

  async function inspectBlob(path, blobSha) {
    policy.inspectText(path, 'file path');
    if (!shaPattern.test(blobSha)) throw new Error('Invalid blob identifier.');
    if (seenBlobs.has(blobSha)) return;
    const blob = await api(`${root}/git/blobs/${blobSha}`);
    if (blob.encoding !== 'base64' || typeof blob.content !== 'string' || !Number.isInteger(blob.size)) {
      throw new Error('Invalid publication file response.');
    }
    if (blob.size > 2 * 1024 * 1024) throw new Error('Publication file exceeds the audit limit.');
    const content = Buffer.from(blob.content, 'base64');
    if (content.length !== blob.size || content.includes(0)) {
      throw new Error('Publication file requires manual review.');
    }
    let text;
    try { text = decoder.decode(content); }
    catch { throw new Error('Publication file requires manual review.'); }
    policy.inspectFile(path, text);
    seenBlobs.add(blobSha);
  }

  async function inspectTree(treeSha) {
    if (!shaPattern.test(treeSha)) throw new Error('Invalid tree identifier.');
    if (seenTrees.has(treeSha)) return;
    seenTrees.add(treeSha);
    const tree = await api(`${root}/git/trees/${treeSha}?recursive=1`);
    if (tree.truncated !== false || !Array.isArray(tree.tree)) {
      throw new Error('Publication tree is incomplete.');
    }
    for (const entry of tree.tree) {
      policy.inspectText(entry.path, 'file path');
      if (entry.type === 'tree') continue;
      if (entry.type !== 'blob') throw new Error('External repository content requires review.');
      await inspectBlob(entry.path, entry.sha);
    }
  }

  // 커밋 하나의 메타데이터와 그 커밋이 바꾼 파일만 검사한다. 모든 커밋의 변경을 보면 모든 tree 를 본 것과 같다.
  async function inspectCommitChanges(commitSha) {
    if (!shaPattern.test(commitSha)) throw new Error('Invalid commit identifier.');
    if (seenCommits.has(commitSha)) return;
    const detail = await api(`${root}/commits/${commitSha}`);
    policy.inspectMetadata(detail.commit);
    policy.inspectMetadata(detail.author ?? {});
    policy.inspectMetadata(detail.committer ?? {});
    if (!Array.isArray(detail.files) || detail.files.length >= 300) {
      throw new Error('Commit changes require manual review.');
    }
    for (const file of detail.files) {
      if (typeof file.previous_filename === 'string') policy.inspectText(file.previous_filename, 'file path');
      if (file.status === 'removed') {
        policy.inspectText(file.filename, 'file path');
        continue;
      }
      await inspectBlob(file.filename, file.sha);
    }
    seenCommits.add(commitSha);
  }

  async function inspectHistory(head) {
    if (!shaPattern.test(head)) throw new Error('Invalid history identifier.');
    const commits = await paginate(api, `${root}/commits?sha=${head}`);
    if (commits.length === 0) throw new Error('Publication history is empty.');
    for (const commit of commits) {
      if (!shaPattern.test(commit.sha)) throw new Error('Invalid commit identifier.');
      if (seenCommits.has(commit.sha)) continue;
      policy.inspectMetadata(commit);
      await inspectTree(commit.commit.tree.sha);
      seenCommits.add(commit.sha);
    }
  }

  return { inspectCommitChanges, inspectHistory, counts: () => ({ commits: seenCommits.size, files: seenBlobs.size }) };
}

// PR 하나의 필수 status 를 정한다. 그 PR 의 제목·본문·브랜치와 PR 커밋들이 바꾼 파일만 본다.
// 저장소의 다른 이슈·댓글은 이 status 에 영향을 주지 않는다.
export async function auditPull({ api, repository, pattern, number, writeStatuses = false, validationPassed = true }) {
  const root = repositoryRoot(repository);
  if (!Number.isInteger(number) || number <= 0) throw new Error('Invalid pull request number.');
  let head = null;
  const status = async (state) => {
    if (!writeStatuses || head === null) return;
    await api(`${root}/statuses/${head}`, 'POST', {
      context: 'publication-policy', state,
      description: state === 'success' ? 'Publication audit passed.' : 'Publication audit required.',
    });
  };
  try {
    const original = await api(`${root}/pulls/${number}`);
    if (!shaPattern.test(original?.head?.sha ?? '')) throw new Error('Invalid pull request head.');
    head = original.head.sha;
    await status('pending');
    if (!validationPassed) throw new Error('Policy checker validation failed.');
    const policy = createPolicy(pattern);
    policy.inspectMetadata({ title: original.title, body: original.body ?? '', user: original.user ?? {} });
    policy.inspectBranch(original.head.ref);
    if (original.base.ref !== 'main') throw new Error('Pull request must target main.');

    const commits = await paginate(api, `${root}/pulls/${number}/commits`);
    if (commits.length === 0 || commits.length >= 250) throw new Error('Pull request commits require manual review.');
    const inspector = makeInspector(api, root, policy);
    for (const commit of commits) await inspector.inspectCommitChanges(commit.sha);

    // 검사 도중 head 나 PR 내용이 바뀌었다면 성공 결과를 기록하지 않는다.
    const current = await api(`${root}/pulls/${number}`);
    if (current.head.sha !== original.head.sha || current.title !== original.title || current.body !== original.body ||
        current.head.ref !== original.head.ref || current.base.ref !== original.base.ref) {
      throw new Error('Pull request changed during the publication audit.');
    }
    await status('success');
    return inspector.counts();
  } catch (error) {
    try { await status('failure'); }
    catch { /* status 를 쓰지 못하면 이전 pending 이 남아 병합 차단 상태를 유지한다. */ }
    throw error;
  }
}

// 이슈·댓글 이벤트: 지금 게시된 글만 본다. 수정 전 문구(changes)는 이미 지워졌으므로 보지 않는다.
// 어떤 PR status 도 바꾸지 않는다. 위반이면 이 실행만 실패해 알린다.
export function auditEvent({ pattern, event }) {
  const policy = createPolicy(pattern);
  if (event.issue) {
    policy.inspectMetadata({ title: event.issue.title, body: event.issue.body ?? '' });
    for (const label of event.issue.labels ?? []) policy.inspectMetadata({ name: label.name, description: label.description ?? '' });
  }
  if (event.comment) policy.inspectMetadata({ body: event.comment.body ?? '' });
  return { items: Number(Boolean(event.issue)) + Number(Boolean(event.comment)) };
}

// 브랜치 push: main 에 없는 커밋(main 에 push 되면 그 커밋 자체)과 브랜치 이름만 본다. PR status 는 PR 이벤트가 정한다.
export async function auditPush({ api, repository, pattern, head, branch }) {
  const root = repositoryRoot(repository);
  if (!shaPattern.test(head)) throw new Error('Invalid history identifier.');
  const policy = createPolicy(pattern);
  if (typeof branch === 'string') policy.inspectBranch(branch);
  const inspector = makeInspector(api, root, policy);
  const compare = await api(`${root}/compare/main...${head}`);
  const commits = Array.isArray(compare.commits) ? compare.commits : [];
  if (commits.length >= 250) throw new Error('Push commits require manual review.');
  for (const commit of commits.length > 0 ? commits : [{ sha: head }]) await inspector.inspectCommitChanges(commit.sha);
  return inspector.counts();
}

// 저장소 전체 점검(하루 한 번, 수동 실행). PR status 는 바꾸지 않는다.
export async function runAudit({ api, repository, pattern, validationPassed = true }) {
  const root = repositoryRoot(repository);
  if (!validationPassed) throw new Error('Policy checker validation failed.');
  const policy = createPolicy(pattern);
  policy.inspectMetadata(await api(root));
  const inspector = makeInspector(api, root, policy);

  for (const branch of await paginate(api, `${root}/branches`)) {
    policy.inspectBranch(branch.name);
    await inspector.inspectHistory(branch.commit.sha);
  }
  for (const tag of await paginate(api, `${root}/tags`)) {
    policy.inspectTag(tag.name);
    let object = (await api(`${root}/git/ref/tags/${encodeURIComponent(tag.name)}`)).object;
    for (let depth = 0; object.type === 'tag'; depth += 1) {
      if (depth >= 16 || !shaPattern.test(object.sha)) throw new Error('Invalid annotated tag.');
      const annotated = await api(`${root}/git/tags/${object.sha}`);
      policy.inspectMetadata(annotated);
      object = annotated.object;
    }
    if (object.type !== 'commit') throw new Error('Unsupported tag target.');
    await inspector.inspectHistory(object.sha);
  }

  const pulls = await paginate(api, `${root}/pulls?state=all`);
  for (const pull of pulls) {
    policy.inspectMetadata(pull);
    policy.inspectBranch(pull.head.ref);
    if (pull.base.ref !== 'main') throw new Error('Pull request must target main.');
    await inspector.inspectHistory(pull.head.sha);
    policy.inspectMetadata(await paginate(api, `${root}/pulls/${pull.number}/reviews`));
  }
  for (const path of ['issues?state=all', 'issues/comments', 'pulls/comments', 'releases', 'labels', 'milestones?state=all']) {
    policy.inspectMetadata(await paginate(api, `${root}/${path}`));
  }
  const workflows = await api(`${root}/actions/workflows?per_page=100`);
  if (!Array.isArray(workflows.workflows) || workflows.total_count !== workflows.workflows.length) {
    throw new Error('Workflow inventory is incomplete.');
  }
  policy.inspectMetadata(workflows.workflows);
  return inspector.counts();
}

async function main() {
  const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const name = process.env.GITHUB_EVENT_NAME;
  const inActions = process.env.GITHUB_ACTIONS === 'true';
  const common = {
    repository: process.env.GH_REPO,
    pattern: process.env.PUBLICATION_DENY_PATTERN,
  };
  const validationPassed = !inActions || process.env.POLICY_TESTS_PASSED === 'true';
  if (!validationPassed) throw new Error('Policy checker validation failed.');

  if (name === 'pull_request_target') {
    if (event.action === 'closed') return console.log('Closed pull request: nothing to audit.');
    const result = await auditPull({ ...common, api: makeApi(process.env.GH_TOKEN), number: event.pull_request?.number,
      writeStatuses: inActions, validationPassed });
    return console.log(`Pull request audit passed: ${result.commits} commits, ${result.files} text files.`);
  }
  if (name === 'issues' || name === 'issue_comment') {
    auditEvent({ ...common, event });
    return console.log('Issue audit passed.');
  }
  if (name === 'workflow_run') {
    const result = await auditPush({ ...common, api: makeApi(process.env.GH_TOKEN),
      head: event.workflow_run?.head_sha, branch: event.workflow_run?.head_branch });
    return console.log(`Push audit passed: ${result.commits} commits, ${result.files} text files.`);
  }
  // schedule, workflow_dispatch: 저장소 전체 점검 뒤 열린 PR 마다 status 를 다시 정한다(막힌 status 복구).
  const api = makeApi(process.env.GH_TOKEN);
  const root = repositoryRoot(common.repository);
  let failed = false;
  for (const pull of await paginate(api, `${root}/pulls?state=open`)) {
    try { await auditPull({ ...common, api, number: pull.number, writeStatuses: inActions, validationPassed }); }
    catch { failed = true; }
  }
  const result = await runAudit({ ...common, api, validationPassed });
  if (failed) throw new Error('An open pull request failed the publication audit.');
  console.log(`Repository audit passed: ${result.commits} commits, ${result.files} text files.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    // 네트워크·JSON·신뢰할 수 없는 메타데이터에서 나온 예외 원문을 출력하지 않는다.
    console.error('Publication audit failed. Check policy configuration and published material.');
    process.exitCode = 1;
  });
}
