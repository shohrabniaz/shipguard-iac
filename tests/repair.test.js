'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { repair } = require('../src/core/repair');
const { parseModelResponse } = require('../src/core/llm');
const { scan } = require('../src/core/rules');

describe('parseModelResponse', () => {
  it('splits NOTES and FIXED_FILE', () => {
    const r = parseModelResponse('NOTES: hello\nFIXED_FILE:\nresource "x" "y" {}\n');
    assert.equal(r.notes, 'hello');
    assert.match(r.fixed, /resource "x" "y"/);
    assert.equal(r.error, null);
  });
});

describe('repair (mock mode)', () => {
  it('verifies a terraform SSH fix end-to-end', async () => {
    const tf = `
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
    const result = await repair(tf, { path: 'sg.tf', mode: 'mock' });
    assert.equal(result.ok, true);
    assert.equal(result.verdict, 'verified');
    assert.ok(!result.fixed.includes('0.0.0.0/0'));
    const after = scan(result.fixed, { path: 'sg.tf' });
    assert.ok(!after.findings.some((f) => f.ruleId === 'CKV_AWS_24'));
  });

  it('verifies a kubernetes privileged fix end-to-end', async () => {
    const y = `
apiVersion: v1
kind: Pod
metadata:
  name: risky
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: true
`;
    const result = await repair(y, { path: 'pod.yaml', mode: 'mock' });
    assert.equal(result.ok, true);
    assert.ok(['verified', 'partial'].includes(result.verdict));
    assert.ok(!/privileged:\s*true/.test(result.fixed));
  });

  it('leaves human-only findings alone', async () => {
    const y = `
apiVersion: v1
kind: Pod
metadata:
  name: agent
spec:
  containers:
    - name: app
      image: nginx:latest
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
      securityContext:
        runAsNonRoot: true
        privileged: false
`;
    // :latest is needsHuman; with limits + runAsNonRoot + not privileged, may be human-only or clean-ish
    const result = await repair(y, { path: 'pod.yaml', mode: 'mock' });
    assert.ok(['human-only', 'clean', 'verified', 'partial'].includes(result.verdict));
    // Image must not be rewritten by mock for needsHuman latest-tag
    assert.match(result.fixed, /nginx:latest/);
  });

  it('never echoes a fake api key in notes/fixed when using mock', async () => {
    const tf = `
resource "aws_ebs_volume" "data" {
  availability_zone = "ap-southeast-2a"
  size              = 10
}
`;
    const result = await repair(tf, {
      path: 'ebs.tf',
      mode: 'mock',
      apiKey: 'gsk_THIS_SHOULD_NEVER_APPEAR',
    });
    const blob = JSON.stringify(result);
    assert.ok(!blob.includes('gsk_THIS_SHOULD_NEVER_APPEAR'));
  });
});
