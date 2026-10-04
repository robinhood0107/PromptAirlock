import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createPolicy, paginate } from './publication-policy.mjs';

const shaPattern = /^[0-9a-f]{40}$/;

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

export async function runAudit({ api, repository, pattern, event = {}, writeStatuses = false, validationPassed = true }) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error('Invalid repository identifier.');
  }
  const root = `repos/${repository}`;
  const pending = new Set();
  const statuses = async (sha, state) => {
    if (!shaPattern.test(sha)) throw new Error('Invalid status commit identifier.');
    if (!writeStatuses) return;
    await api(`${root}/statuses/${sha}`, 'POST', {
      context: 'publication-policy', state,
      description: state === 'success' ? 'Publication audit passed.' : 'Publication audit required.',
    });
  };

  try {
    // 설정이나 다른 API를 조회하기 전에 해당 이벤트의 이전 검사 결과를 무효화한다.
    const eventHeads = [event.pull_request?.head?.sha, event.workflow_run?.head_sha,
      ...(event.workflow_run?.pull_requests ?? []).map((pull) => pull.head?.sha)];
    for (const head of eventHeads.filter((value) => typeof value === 'string')) {
      pending.add(head);
      await statuses(head, 'pending');
    }
    const openPulls = await paginate(api, `${root}/pulls?state=open`);
    for (const pull of openPulls) {
      pending.add(pull.head.sha);
      await statuses(pull.head.sha, 'pending');
    }

    if (!validationPassed) throw new Error('Policy checker validation failed.');
    const policy = createPolicy(pattern);
    policy.inspectMetadata(event);
    policy.inspectMetadata(await api(root));

    const seenCommits = new Set();
    const seenTrees = new Set();
    const seenBlobs = new Set();
    const decoder = new TextDecoder('utf-8', { fatal: true });

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
        if (!shaPattern.test(entry.sha)) throw new Error('Invalid blob identifier.');
        if (seenBlobs.has(entry.sha)) continue;
        if (!Number.isInteger(entry.size) || entry.size > 2 * 1024 * 1024) {
          throw new Error('Publication file exceeds the audit limit.');
        }
        const blob = await api(`${root}/git/blobs/${entry.sha}`);
        if (blob.encoding !== 'base64' || typeof blob.content !== 'string') {
          throw new Error('Invalid publication file response.');
        }
        const content = Buffer.from(blob.content, 'base64');
        if (content.length !== entry.size || content.includes(0)) {
          throw new Error('Publication file requires manual review.');
        }
        let text;
        try { text = decoder.decode(content); }
        catch { throw new Error('Publication file requires manual review.'); }
        policy.inspectFile(entry.path, text);
        seenBlobs.add(entry.sha);
      }
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

    for (const head of pending) await inspectHistory(head);

    for (const branch of await paginate(api, `${root}/branches`)) {
      policy.inspectBranch(branch.name);
      await inspectHistory(branch.commit.sha);
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
      await inspectHistory(object.sha);
    }

    const pulls = await paginate(api, `${root}/pulls?state=all`);
    for (const pull of pulls) {
      policy.inspectMetadata(pull);
      policy.inspectBranch(pull.head.ref);
      if (pull.base.ref !== 'main') throw new Error('Pull request must target main.');
      await inspectHistory(pull.head.sha);
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

    // 검사 도중 head나 PR 내용이 바뀌었다면 성공 결과를 기록하지 않는다.
    for (const original of openPulls) {
      const current = await api(`${root}/pulls/${original.number}`);
      if (current.head.sha !== original.head.sha || current.title !== original.title || current.body !== original.body ||
          current.head.ref !== original.head.ref || current.base.ref !== original.base.ref) {
        throw new Error('Pull request changed during the publication audit.');
      }
      policy.inspectMetadata(current);
    }
    for (const sha of pending) await statuses(sha, 'success');
    return { commits: seenCommits.size, files: seenBlobs.size };
  } catch (error) {
    for (const sha of pending) {
      try { await statuses(sha, 'failure'); }
      catch { /* status가 없거나 pending이면 병합 차단 상태를 유지한다. */ }
    }
    throw error;
  }
}

async function main() {
  const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const result = await runAudit({
    api: makeApi(process.env.GH_TOKEN), repository: process.env.GH_REPO,
    pattern: process.env.PUBLICATION_DENY_PATTERN, event,
    writeStatuses: process.env.GITHUB_ACTIONS === 'true',
    validationPassed: process.env.GITHUB_ACTIONS !== 'true' || process.env.POLICY_TESTS_PASSED === 'true',
  });
  console.log(`Publication audit passed: ${result.commits} commits, ${result.files} text files.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    // 네트워크·JSON·신뢰할 수 없는 메타데이터에서 나온 예외 원문을 출력하지 않는다.
    console.error('Publication audit failed. Check policy configuration and published material.');
    process.exitCode = 1;
  });
}
