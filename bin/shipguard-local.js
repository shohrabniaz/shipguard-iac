#!/usr/bin/env node
'use strict';
/**
 * Local CLI (no Forge). Usage:
 *   node bin/shipguard-local.js scan examples/open-ssh.tf
 *   node bin/shipguard-local.js repair examples/open-ssh.tf
 */
const fs = require('fs');
const path = require('path');
const { scan, repair } = require('../src/core');

async function main() {
  const [cmd, file] = process.argv.slice(2);
  if (!cmd || !file) {
    console.error('Usage: node bin/shipguard-local.js <scan|repair> <file>');
    process.exit(2);
  }
  const content = fs.readFileSync(file, 'utf8');
  const filename = path.basename(file);
  if (cmd === 'scan') {
    console.log(JSON.stringify(scan(content, { path: filename }), null, 2));
    return;
  }
  if (cmd === 'repair') {
    const mode = process.env.GROQ_API_KEY ? 'groq' : 'mock';
    const result = await repair(content, { path: filename, mode });
    console.log(JSON.stringify({
      verdict: result.verdict,
      kind: result.kind,
      notes: result.notes,
      originalFindingCount: (result.originalFindings || []).length,
      remainingFindings: result.remainingFindings,
      rounds: result.rounds,
      fixed: result.fixed,
      error: result.error,
    }, null, 2));
    return;
  }
  console.error('Unknown command', cmd);
  process.exit(2);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
