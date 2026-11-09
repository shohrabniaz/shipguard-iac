'use strict';

/**
 * Rovo Agent action handlers.
 * Payload inputs come from the action manifest; issue context may include issueKey.
 */

const { repair, scan } = require('../core');

function getFetch() {
  try {
    return require('@forge/api').fetch;
  } catch {
    return globalThis.fetch;
  }
}

async function maybeCreateJiraIssue(summary, description, projectKey) {
  if (!projectKey) {
    return { created: false, reason: 'No projectKey provided' };
  }
  try {
    const { route, requestJira } = require('@forge/api');
    const body = {
      fields: {
        project: { key: projectKey },
        summary: summary.slice(0, 255),
        description,
        issuetype: { name: 'Task' },
      },
    };
    // ADF description for modern Jira; fall back to plain string if needed by site
    const adf = {
      fields: {
        project: { key: projectKey },
        summary: summary.slice(0, 255),
        issuetype: { name: 'Task' },
        description: {
          type: 'doc',
          version: 1,
          content: [
            {
              type: 'paragraph',
              content: [{ type: 'text', text: description.slice(0, 4000) }],
            },
          ],
        },
      },
    };
    const res = await requestJira(route`/rest/api/3/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(adf),
    });
    if (res.status >= 200 && res.status < 300) {
      const data = await res.json();
      return { created: true, key: data.key, id: data.id };
    }
    const text = await res.text();
    // Retry with classic string description for older configs
    const res2 = await requestJira(route`/rest/api/2/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res2.status >= 200 && res2.status < 300) {
      const data = await res2.json();
      return { created: true, key: data.key, id: data.id };
    }
    return { created: false, reason: `Jira ${res.status}: ${text.slice(0, 300)}` };
  } catch (err) {
    return { created: false, reason: String(err && err.message ? err.message : err) };
  }
}

/** Action: scan-iac */
async function scanIac(payload = {}) {
  const content = payload.content || payload.iacContent || '';
  const filename = payload.filename || 'pasted.tf';
  const result = scan(content, { path: filename });
  return {
    kind: result.kind,
    error: result.error,
    findingCount: result.findings.length,
    findings: result.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      resource: f.resource,
      needsHuman: f.needsHuman,
    })),
  };
}

/** Action: suggest-verified-fix */
async function suggestVerifiedFix(payload = {}) {
  const content = payload.content || payload.iacContent || '';
  const filename = payload.filename || 'pasted.tf';
  const mode = process.env.GROQ_API_KEY ? 'groq' : 'mock';
  const result = await repair(content, {
    path: filename,
    mode,
    apiKey: process.env.GROQ_API_KEY,
    fetchImpl: getFetch(),
  });

  // Never return secrets
  return {
    verdict: result.verdict,
    kind: result.kind,
    notes: result.notes || '',
    originalFindingCount: (result.originalFindings || []).length,
    remainingFindingCount: (result.remainingFindings || []).length,
    remainingFindings: (result.remainingFindings || []).map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      resource: f.resource,
      needsHuman: f.needsHuman,
    })),
    fixedContent: result.fixed,
    rounds: (result.rounds || []).map((r) => ({ round: r.round, status: r.status })),
    error: result.error,
  };
}

/** Action: create-finding-issue */
async function createFindingIssue(payload = {}, context = {}) {
  const ruleId = payload.ruleId || 'IaC';
  const title = payload.title || 'IaC security finding';
  const resource = payload.resource || '';
  const detail = payload.detail || '';
  const projectKey = payload.projectKey || payload.project || '';
  const issueKey = payload.issueKey || context.issueKey || '';

  const summary = `[ShipGuard] ${ruleId}: ${title}`;
  const description = [
    `ShipGuard IaC finding`,
    `Rule: ${ruleId}`,
    `Resource: ${resource}`,
    detail ? `Detail: ${detail}` : '',
    issueKey ? `Related issue: ${issueKey}` : '',
    '',
    'This finding was flagged as needing a human decision (or tracked from a verified repair).',
  ]
    .filter(Boolean)
    .join('\n');

  const created = await maybeCreateJiraIssue(summary, description, projectKey);
  return { summary, ...created };
}

module.exports = {
  scanIac,
  suggestVerifiedFix,
  createFindingIssue,
};
