'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { scan } = require('../src/core/rules');
const { detectKind } = require('../src/core/kind');

describe('detectKind', () => {
  it('detects terraform by extension and content', () => {
    assert.equal(detectKind('main.tf', ''), 'terraform');
    assert.equal(detectKind('x.txt', 'resource "aws_s3_bucket" "b" {\n}\n'), 'terraform');
  });
  it('detects kubernetes by apiVersion+kind', () => {
    const y = 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n';
    assert.equal(detectKind('pod.yaml', y), 'kubernetes');
  });
});

describe('terraform rules', () => {
  it('flags open SSH from the internet', () => {
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
    const { findings } = scan(tf, { path: 'sg.tf' });
    assert.ok(findings.some((f) => f.ruleId === 'CKV_AWS_24'));
  });

  it('flags missing S3 public access block', () => {
    const tf = `
resource "aws_s3_bucket" "logs" {
  bucket = "my-logs-bucket-example"
}
`;
    const { findings } = scan(tf, { path: 's3.tf' });
    assert.ok(findings.some((f) => f.ruleId === 'CKV_AWS_70'));
  });

  it('flags public RDS', () => {
    const tf = `
resource "aws_db_instance" "db" {
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  publicly_accessible  = true
  storage_encrypted    = false
}
`;
    const { findings } = scan(tf, { path: 'rds.tf' });
    assert.ok(findings.some((f) => f.ruleId === 'CKV_AWS_17'));
    assert.ok(findings.some((f) => f.ruleId === 'CKV_AWS_16'));
  });
});

describe('kubernetes rules', () => {
  it('flags privileged + missing limits', () => {
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
    const { findings } = scan(y, { path: 'pod.yaml' });
    assert.ok(findings.some((f) => f.ruleId === 'CKV_K8S_16'));
    assert.ok(findings.some((f) => f.ruleId === 'CKV_K8S_11'));
  });
});
