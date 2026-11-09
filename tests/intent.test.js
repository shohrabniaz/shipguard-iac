'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { verifyIntent } = require('../src/core/intent');

describe('verifyIntent', () => {
  it('rejects deleted terraform resources', () => {
    const before = 'resource "aws_s3_bucket" "a" {}\nresource "aws_s3_bucket" "b" {}\n';
    const after = 'resource "aws_s3_bucket" "a" {}\n';
    const r = verifyIntent('terraform', before, after);
    assert.equal(r.ok, false);
    assert.ok(r.reasons.some((x) => x.includes('aws_s3_bucket.b')));
  });

  it('rejects invented AMI ids', () => {
    const before = 'resource "aws_instance" "web" {\n  instance_type = "t3.micro"\n}\n';
    const after = 'resource "aws_instance" "web" {\n  instance_type = "t3.micro"\n  ami = "ami-0deadbeefcafe"\n}\n';
    const r = verifyIntent('terraform', before, after);
    assert.equal(r.ok, false);
  });

  it('accepts a safe CIDR tighten', () => {
    const before = `
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
    const after = before.replace('0.0.0.0/0', '10.0.0.0/16');
    const r = verifyIntent('terraform', before, after);
    assert.equal(r.ok, true);
  });
});
