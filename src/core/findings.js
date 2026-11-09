'use strict';

/**
 * @typedef {Object} Finding
 * @property {string} ruleId
 * @property {string} title
 * @property {string} severity  CRITICAL|HIGH|MEDIUM|LOW
 * @property {string} resource
 * @property {string} [detail]
 * @property {boolean} [needsHuman]  if true, never auto-fix
 */

function finding(partial) {
  return {
    ruleId: partial.ruleId,
    title: partial.title,
    severity: partial.severity || 'MEDIUM',
    resource: partial.resource || '(unknown)',
    detail: partial.detail || '',
    needsHuman: Boolean(partial.needsHuman),
  };
}

/** Stable compare key (line numbers move when files edit). */
function findingKey(f) {
  return `${f.ruleId}::${f.resource}`;
}

function indexByKey(list) {
  const m = new Map();
  for (const f of list) m.set(findingKey(f), f);
  return m;
}

module.exports = { finding, findingKey, indexByKey };
