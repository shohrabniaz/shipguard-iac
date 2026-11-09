'use strict';

/**
 * Custom UI resolver for the Jira issue panel.
 * Pure logic lives in src/core so unit tests never need Forge.
 * When Forge APIs are unavailable (local node), handlers still work in mock mode.
 */

const Resolver = require('@forge/resolver').default;
const { repair, scan, detectKind } = require('../core');

const resolver = new Resolver();

resolver.define('scanContent', async ({ payload }) => {
  const content = payload?.content || '';
  const path = payload?.filename || 'pasted.tf';
  return scan(content, { path });
});

resolver.define('repairContent', async ({ payload }) => {
  const content = payload?.content || '';
  const path = payload?.filename || 'pasted.tf';
  const mode = payload?.mode || (process.env.GROQ_API_KEY ? 'groq' : 'mock');

  // Lazy-load Forge fetch only when needed so core tests stay pure.
  let fetchImpl;
  try {
    // eslint-disable-next-line global-require
    fetchImpl = require('@forge/api').fetch;
  } catch {
    fetchImpl = globalThis.fetch;
  }

  return repair(content, {
    path,
    mode,
    apiKey: process.env.GROQ_API_KEY,
    fetchImpl,
    maxRounds: payload?.maxRounds || 3,
  });
});

resolver.define('detect', async ({ payload }) => {
  return { kind: detectKind(payload?.filename || '', payload?.content || '') };
});

module.exports = { handler: resolver.getDefinitions() };
