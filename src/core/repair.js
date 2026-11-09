'use strict';

const { scan } = require('./rules');
const { verifyIntent } = require('./intent');
const { proposeFix } = require('./llm');
const { findingKey, indexByKey } = require('./findings');

/**
 * EASE-style repair loop for Forge:
 *   scan → (optional) LLM fix → intent check → re-scan → accept or retry.
 * Checkov/Trivy/terraform CLI are NOT available in Forge; the JS rule engine
 * is both the scanner and the re-scan verifier.
 */
async function repair(content, opts = {}) {
  const maxRounds = opts.maxRounds ?? 3;
  const path = opts.path || 'pasted.tf';
  const initial = scan(content, { path, kind: opts.kind });
  if (initial.error) {
    return {
      ok: false,
      kind: null,
      verdict: 'error',
      error: initial.error,
      originalFindings: [],
      remainingFindings: [],
      fixed: content,
      rounds: [],
    };
  }

  const fixable = initial.findings.filter((f) => !f.needsHuman);
  const deferred = initial.findings.filter((f) => f.needsHuman);

  if (fixable.length === 0) {
    return {
      ok: true,
      kind: initial.kind,
      verdict: deferred.length ? 'human-only' : 'clean',
      error: null,
      originalFindings: initial.findings,
      remainingFindings: initial.findings,
      fixed: content,
      rounds: [],
      notes: deferred.length
        ? 'Only human-decision findings present; nothing auto-fixed.'
        : 'No findings.',
    };
  }

  let current = content;
  let priorReason = '';
  const rounds = [];

  for (let i = 0; i < maxRounds; i++) {
    const proposal = await proposeFix(initial.kind, current, initial.findings, {
      mode: opts.mode,
      apiKey: opts.apiKey,
      fetchImpl: opts.fetchImpl,
      model: opts.model,
      priorReason,
    });

    if (proposal.error || !proposal.fixed) {
      rounds.push({ round: i + 1, status: 'llm-error', error: proposal.error || 'empty fix' });
      priorReason = proposal.error || 'empty fix';
      continue;
    }

    const intent = verifyIntent(initial.kind, content, proposal.fixed);
    if (!intent.ok) {
      rounds.push({ round: i + 1, status: 'intent-fail', reasons: intent.reasons, notes: proposal.notes });
      priorReason = intent.reasons.join('; ');
      continue;
    }

    const rescanned = scan(proposal.fixed, { path, kind: initial.kind });
    const beforeKeys = new Set(fixable.map(findingKey));
    const afterFixable = rescanned.findings.filter((f) => !f.needsHuman);
    const afterKeys = new Set(afterFixable.map(findingKey));

    const removed = [...beforeKeys].filter((k) => !afterKeys.has(k));
    const added = [...afterKeys].filter((k) => !beforeKeys.has(k));

    if (added.length > 0) {
      rounds.push({
        round: i + 1,
        status: 'new-findings',
        added,
        notes: proposal.notes,
      });
      priorReason = `Re-scan introduced new findings: ${added.join(', ')}`;
      continue;
    }

    if (removed.length === 0) {
      rounds.push({ round: i + 1, status: 'no-progress', notes: proposal.notes });
      priorReason = 'Re-scan showed no findings removed';
      continue;
    }

    // Accept
    const remaining = [
      ...afterFixable,
      ...rescanned.findings.filter((f) => f.needsHuman),
    ];
    const allFixed = afterFixable.length === 0;
    rounds.push({
      round: i + 1,
      status: 'accepted',
      removed,
      notes: proposal.notes,
    });

    return {
      ok: true,
      kind: initial.kind,
      verdict: allFixed ? 'verified' : 'partial',
      error: null,
      originalFindings: initial.findings,
      remainingFindings: remaining,
      fixed: proposal.fixed,
      rounds,
      notes: proposal.notes,
    };
  }

  return {
    ok: false,
    kind: initial.kind,
    verdict: 'rejected',
    error: priorReason || 'All repair rounds failed',
    originalFindings: initial.findings,
    remainingFindings: initial.findings,
    fixed: content,
    rounds,
  };
}

module.exports = { repair };
