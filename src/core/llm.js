'use strict';

/**
 * LLM client. Modes:
 *  - mock: deterministic local repairs for demos/tests (no network)
 *  - groq: OpenAI-compatible chat to api.groq.com (Forge fetch or node fetch)
 *
 * Never logs the API key.
 */

const DEFAULT_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-120b';

function buildPrompt(kind, content, findings, priorReason) {
  const findingLines = findings
    .filter((f) => !f.needsHuman)
    .map((f) => `- [${f.severity}] ${f.ruleId} @ ${f.resource}: ${f.title}`)
    .join('\n');
  const deferred = findings
    .filter((f) => f.needsHuman)
    .map((f) => `- ${f.ruleId} @ ${f.resource}: ${f.title}`)
    .join('\n');

  return [
    `You repair ${kind} Infrastructure-as-Code security misconfigurations.`,
    'Return exactly this format:',
    'NOTES: <one short paragraph>',
    'FIXED_FILE:',
    '<the complete fixed file>',
    '',
    'Rules:',
    '- Do not delete resources, objects, containers, or ports to silence a finding.',
    '- Do not invent AMIs, account IDs, KMS keys, image digests, or regions.',
    '- Prefer the smallest safe change (restrict CIDR, set encrypted=true, add limits, set runAsNonRoot).',
    '- Leave findings marked for a human untouched.',
    priorReason ? `\nPrevious attempt was rejected because: ${priorReason}\n` : '',
    'Findings to fix:',
    findingLines || '(none)',
    '',
    'Findings to leave for a human:',
    deferred || '(none)',
    '',
    'FILE:',
    content,
  ].join('\n');
}

function parseModelResponse(text) {
  const raw = String(text || '');
  const marker = raw.indexOf('FIXED_FILE:');
  if (marker < 0) {
    return { notes: '', fixed: raw.trim(), error: 'Missing FIXED_FILE marker' };
  }
  const notesPart = raw.slice(0, marker);
  const notes = (notesPart.match(/NOTES:\s*([\s\S]*)/i) || [, ''])[1].trim();
  let fixed = raw.slice(marker + 'FIXED_FILE:'.length).trim();
  // Strip accidental markdown fences
  fixed = fixed.replace(/^```[a-zA-Z]*\n/, '').replace(/\n```$/, '').trim();
  return { notes, fixed, error: null };
}

/**
 * @param {object} opts
 * @param {'mock'|'groq'} opts.mode
 * @param {function} [opts.fetchImpl]  inject Forge fetch or node fetch
 * @param {string} [opts.apiKey]
 * @param {string} [opts.model]
 */
async function proposeFix(kind, content, findings, opts = {}) {
  const mode = opts.mode || (opts.apiKey ? 'groq' : 'mock');
  const priorReason = opts.priorReason || '';
  const prompt = buildPrompt(kind, content, findings, priorReason);

  if (mode === 'mock') {
    return parseModelResponse(mockRepair(kind, content, findings));
  }

  const apiKey = opts.apiKey || process.env.GROQ_API_KEY;
  if (!apiKey) {
    return { notes: '', fixed: '', error: 'GROQ_API_KEY not set' };
  }
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) {
    return { notes: '', fixed: '', error: 'No fetch implementation available' };
  }

  const res = await fetchImpl('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: opts.model || DEFAULT_MODEL,
      temperature: 0.2,
      messages: [
        { role: 'system', content: 'You are a careful IaC security repair assistant.' },
        { role: 'user', content: prompt },
      ],
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    return { notes: '', fixed: '', error: `Groq HTTP ${res.status}: ${body.slice(0, 200)}` };
  }
  const data = await res.json();
  const text = data?.choices?.[0]?.message?.content || '';
  return parseModelResponse(text);
}

/** Deterministic mock repairs for tests and offline demos. */
function mockRepair(kind, content, findings) {
  let fixed = content;
  const notes = [];

  if (kind === 'terraform') {
    if (findings.some((f) => f.ruleId === 'CKV_AWS_24')) {
      fixed = fixed.replace(/0\.0\.0\.0\/0/g, '10.0.0.0/16');
      notes.push('Restricted open CIDR to 10.0.0.0/16');
    }
    if (findings.some((f) => f.ruleId === 'CKV_AWS_17')) {
      fixed = fixed.replace(/publicly_accessible\s*=\s*true/g, 'publicly_accessible = false');
      notes.push('Disabled public accessibility on RDS');
    }
    if (findings.some((f) => f.ruleId === 'CKV_AWS_16')) {
      if (!/storage_encrypted\s*=/.test(fixed)) {
        fixed = fixed.replace(
          /(resource\s+"aws_db_instance"\s+"[^"]+"\s*\{)/,
          '$1\n  storage_encrypted = true'
        );
      } else {
        fixed = fixed.replace(/storage_encrypted\s*=\s*false/g, 'storage_encrypted = true');
      }
      notes.push('Enabled RDS storage encryption');
    }
    if (findings.some((f) => f.ruleId === 'CKV_AWS_3')) {
      fixed = fixed.replace(
        /(resource\s+"aws_ebs_volume"\s+"[^"]+"\s*\{)/,
        '$1\n  encrypted = true'
      );
      if (/encrypted\s*=\s*false/.test(fixed)) {
        fixed = fixed.replace(/encrypted\s*=\s*false/g, 'encrypted = true');
      }
      notes.push('Enabled EBS encryption');
    }
    if (findings.some((f) => f.ruleId === 'CKV_AWS_8')) {
      if (/root_block_device\s*\{/.test(fixed) && !/root_block_device\s*\{[^}]*encrypted\s*=\s*true/s.test(fixed)) {
        fixed = fixed.replace(/(root_block_device\s*\{)/, '$1\n    encrypted = true');
      }
      notes.push('Encrypted EC2 root volume');
    }
    if (findings.some((f) => f.ruleId === 'CKV_AWS_70')) {
      // Add a public access block resource if missing
      const bucket = fixed.match(/resource\s+"aws_s3_bucket"\s+"([^"]+)"/);
      if (bucket && !/aws_s3_bucket_public_access_block/.test(fixed)) {
        fixed += `

resource "aws_s3_bucket_public_access_block" "${bucket[1]}_public_access" {
  bucket = aws_s3_bucket.${bucket[1]}.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`;
        notes.push('Added S3 public access block');
      } else {
        fixed = fixed
          .replace(/block_public_acls\s*=\s*false/g, 'block_public_acls = true')
          .replace(/block_public_policy\s*=\s*false/g, 'block_public_policy = true')
          .replace(/ignore_public_acls\s*=\s*false/g, 'ignore_public_acls = true')
          .replace(/restrict_public_buckets\s*=\s*false/g, 'restrict_public_buckets = true');
        notes.push('Hardened S3 public access block flags');
      }
    }
  }

  if (kind === 'kubernetes') {
    if (findings.some((f) => f.ruleId === 'CKV_K8S_16')) {
      fixed = fixed.replace(/privileged:\s*true/g, 'privileged: false');
      notes.push('Disabled privileged');
    }
    if (findings.some((f) => f.ruleId === 'CKV_K8S_19')) {
      fixed = fixed.replace(/hostNetwork:\s*true/g, 'hostNetwork: false');
      notes.push('Disabled hostNetwork');
    }
    if (findings.some((f) => f.ruleId === 'CKV_K8S_37')) {
      fixed = fixed.replace(/- SYS_ADMIN\n?/g, '');
      notes.push('Removed CAP_SYS_ADMIN');
    }
    if (findings.some((f) => f.ruleId === 'CKV_K8S_23_ROOT')) {
      if (!/runAsNonRoot:\s*true/.test(fixed)) {
        if (/securityContext:/.test(fixed)) {
          fixed = fixed.replace(/(securityContext:\s*\n)/, '$1          runAsNonRoot: true\n');
        } else {
          fixed = fixed.replace(
            /(containers:\s*\n)/,
            '      securityContext:\n        runAsNonRoot: true\n$1'
          );
        }
      }
      fixed = fixed.replace(/runAsUser:\s*0\b/g, 'runAsUser: 1000');
      notes.push('Set runAsNonRoot');
    }
    if (findings.some((f) => f.ruleId === 'CKV_K8S_11')) {
      if (!/limits:/.test(fixed)) {
        fixed = fixed.replace(
          /(image:\s*\S+\s*\n)/,
          '$1        resources:\n          limits:\n            cpu: "500m"\n            memory: "256Mi"\n          requests:\n            cpu: "100m"\n            memory: "128Mi"\n'
        );
        notes.push('Added CPU/memory limits');
      }
    }
    if (findings.some((f) => f.ruleId === 'CKV_K8S_LB')) {
      if (!/loadBalancerSourceRanges:/.test(fixed)) {
        fixed = fixed.replace(
          /(type:\s*LoadBalancer\s*\n)/,
          '$1  loadBalancerSourceRanges:\n    - 10.0.0.0/8\n'
        );
        notes.push('Scoped LoadBalancer source ranges');
      }
    }
  }

  return `NOTES: ${notes.join('; ') || 'No automatic mock changes'}\nFIXED_FILE:\n${fixed}`;
}

module.exports = { buildPrompt, parseModelResponse, proposeFix, mockRepair, DEFAULT_MODEL };
