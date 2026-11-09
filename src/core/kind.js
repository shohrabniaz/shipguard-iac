'use strict';

/**
 * Detect IaC kind from filename + content.
 * @returns {'terraform'|'kubernetes'|null}
 */
function detectKind(path, content = '') {
  const n = String(path || '').toLowerCase();
  if (n.endsWith('.tf') || n.endsWith('.tf.json')) return 'terraform';
  if (n.endsWith('.yaml') || n.endsWith('.yml') || n.endsWith('.json')) {
    if (/apiVersion\s*:/.test(content) && /\bkind\s*:/.test(content)) return 'kubernetes';
    return null;
  }
  // untitled paste: sniff content
  if (/^\s*resource\s+"/.test(content) || /^\s*provider\s+"/.test(content)) return 'terraform';
  if (/apiVersion\s*:/.test(content) && /\bkind\s*:/.test(content)) return 'kubernetes';
  return null;
}

module.exports = { detectKind };
