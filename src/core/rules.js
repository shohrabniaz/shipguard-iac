'use strict';

const { finding } = require('./findings');
const { detectKind } = require('./kind');

/**
 * Lightweight Checkov-inspired rule engine that runs inside Forge (pure JS).
 * Covers high-signal Terraform + Kubernetes misconfigs. Not a full Checkov
 * replacement — by design, so the Forge runtime never shells out.
 */

function scan(content, opts = {}) {
  const kind = opts.kind || detectKind(opts.path || '', content);
  if (!kind) return { kind: null, findings: [], error: 'Could not detect Terraform or Kubernetes content' };
  const findings = kind === 'terraform' ? scanTerraform(content) : scanKubernetes(content);
  return { kind, findings, error: null };
}

function scanTerraform(src) {
  const findings = [];
  const resources = extractTfResources(src);

  for (const r of resources) {
    if (r.type === 'aws_security_group' || r.type === 'aws_security_group_rule') {
      checkOpenIngress(r, findings);
    }
    if (r.type === 'aws_s3_bucket_public_access_block' || r.type === 'aws_s3_bucket') {
      checkS3Public(r, findings, src);
    }
    if (r.type === 'aws_db_instance') {
      checkRdsPublic(r, findings);
      checkRdsStorageEncrypted(r, findings);
    }
    if (r.type === 'aws_ebs_volume' || r.type === 'aws_instance') {
      checkEbsEncrypted(r, findings);
    }
    if (r.type === 'aws_iam_policy' || r.type === 'aws_iam_role_policy') {
      checkIamStar(r, findings);
    }
    if (r.type === 'aws_kms_key') {
      findings.push(finding({
        ruleId: 'TF-KMS-HUMAN',
        title: 'KMS key policy / rotation needs human review',
        severity: 'MEDIUM',
        resource: r.address,
        detail: 'Key policy and rotation decisions are deferred to a human.',
        needsHuman: true,
      }));
    }
  }

  // Bare aws_s3_bucket without a public access block sibling
  const buckets = resources.filter((r) => r.type === 'aws_s3_bucket');
  const blocks = new Set(
    resources
      .filter((r) => r.type === 'aws_s3_bucket_public_access_block')
      .map((r) => extractBucketRef(r.body))
  );
  for (const b of buckets) {
    const ref = `${b.type}.${b.name}`;
    const hasInline = /block_public_acls\s*=\s*true/.test(b.body);
    if (!hasInline && ![...blocks].some((x) => x && x.includes(b.name))) {
      findings.push(finding({
        ruleId: 'CKV_AWS_70',
        title: 'S3 bucket missing public access block',
        severity: 'HIGH',
        resource: b.address,
        detail: 'Ensure a aws_s3_bucket_public_access_block (all four flags true) exists for this bucket.',
      }));
    }
  }

  return dedupe(findings);
}

function scanKubernetes(src) {
  const findings = [];
  const docs = splitYamlDocs(src);

  for (const doc of docs) {
    const kind = matchField(doc, 'kind');
    const name = matchField(doc, 'name') || '(unnamed)';
    const metaName = nestedName(doc) || name;
    const address = `${kind || 'Object'}/${metaName}`;

    if (!kind) continue;
    if (['Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet'].includes(kind)) {
      checkPrivileged(doc, address, findings);
      checkHostNetwork(doc, address, findings);
      checkHostPath(doc, address, findings);
      checkRunAsRoot(doc, address, findings);
      checkResourceLimits(doc, address, findings);
      checkLatestTag(doc, address, findings);
      checkCapSysAdmin(doc, address, findings);
    }
    if (kind === 'Service') {
      checkNodePort(doc, address, findings);
      checkLoadBalancer(doc, address, findings);
    }
  }
  return dedupe(findings);
}

/* ---------------- Terraform helpers ---------------- */

function extractTfResources(src) {
  const out = [];
  // resource "type" "name" { ... } — brace-matched body
  const re = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g;
  let m;
  while ((m = re.exec(src))) {
    const start = m.index + m[0].length - 1;
    const body = braceSlice(src, start);
    out.push({ type: m[1], name: m[2], address: `${m[1]}.${m[2]}`, body });
  }
  return out;
}

function braceSlice(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return src.slice(openIdx + 1, i);
    }
  }
  return src.slice(openIdx + 1);
}

function checkOpenIngress(r, findings) {
  const body = r.body;
  // Look for ingress blocks with 0.0.0.0/0 or ::/0 on sensitive ports
  const ingressBlocks = [...body.matchAll(/ingress\s*\{/g)];
  if (ingressBlocks.length === 0 && /type\s*=\s*"ingress"/.test(body)) {
    // aws_security_group_rule style
    if (isOpenCidr(body) && touchesSensitivePort(body)) {
      findings.push(finding({
        ruleId: 'CKV_AWS_24',
        title: 'Security group allows ingress from 0.0.0.0/0 on a sensitive port',
        severity: 'CRITICAL',
        resource: r.address,
        detail: 'Restrict cidr_blocks / ipv6_cidr_blocks away from the public internet for SSH/RDP/DB ports.',
      }));
    }
    return;
  }
  // Walk each ingress { } inside the SG
  let searchFrom = 0;
  while (true) {
    const idx = body.indexOf('ingress', searchFrom);
    if (idx < 0) break;
    const brace = body.indexOf('{', idx);
    if (brace < 0) break;
    const block = braceSlice(body, brace);
    if (isOpenCidr(block) && touchesSensitivePort(block)) {
      findings.push(finding({
        ruleId: 'CKV_AWS_24',
        title: 'Security group allows ingress from 0.0.0.0/0 on a sensitive port',
        severity: 'CRITICAL',
        resource: r.address,
        detail: 'Open ingress on SSH (22), RDP (3389), or common DB ports from the internet.',
      }));
      break;
    }
    searchFrom = brace + 1;
  }
}

function isOpenCidr(block) {
  return /0\.0\.0\.0\/0/.test(block) || /::\/0/.test(block);
}

function touchesSensitivePort(block) {
  const sensitive = new Set([22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 445, 21]);
  const from = Number((block.match(/from_port\s*=\s*(-?\d+)/) || [])[1]);
  const to = Number((block.match(/to_port\s*=\s*(-?\d+)/) || [])[1]);
  if (Number.isNaN(from) || Number.isNaN(to)) return false;
  if (from === 0 && to === 0) return false; // ICMP sometimes
  if (from === -1 || to === -1) return true; // all protocols
  for (const p of sensitive) {
    if (p >= Math.min(from, to) && p <= Math.max(from, to)) return true;
  }
  // Wide open port range
  if (Math.abs(to - from) >= 1000) return true;
  return false;
}

function checkS3Public(r, findings, fullSrc) {
  if (r.type !== 'aws_s3_bucket_public_access_block') return;
  const flags = ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets'];
  for (const f of flags) {
    const m = r.body.match(new RegExp(`${f}\\s*=\\s*(true|false)`));
    if (!m || m[1] !== 'true') {
      findings.push(finding({
        ruleId: 'CKV_AWS_70',
        title: `S3 public access block has ${f} not true`,
        severity: 'HIGH',
        resource: r.address,
      }));
    }
  }
}

function extractBucketRef(body) {
  const m = body.match(/bucket\s*=\s*(.+)/);
  return m ? m[1].trim() : '';
}

function checkRdsPublic(r, findings) {
  if (/publicly_accessible\s*=\s*true/.test(r.body)) {
    findings.push(finding({
      ruleId: 'CKV_AWS_17',
      title: 'RDS instance is publicly accessible',
      severity: 'CRITICAL',
      resource: r.address,
    }));
  }
}

function checkRdsStorageEncrypted(r, findings) {
  if (!/storage_encrypted\s*=\s*true/.test(r.body)) {
    findings.push(finding({
      ruleId: 'CKV_AWS_16',
      title: 'RDS storage is not encrypted',
      severity: 'HIGH',
      resource: r.address,
      needsHuman: /kms_key_id/.test(r.body) ? false : true,
      detail: 'Enable storage_encrypted = true. Choosing a KMS key may need a human.',
    }));
  }
}

function checkEbsEncrypted(r, findings) {
  if (r.type === 'aws_ebs_volume' && !/encrypted\s*=\s*true/.test(r.body)) {
    findings.push(finding({
      ruleId: 'CKV_AWS_3',
      title: 'EBS volume is not encrypted',
      severity: 'HIGH',
      resource: r.address,
    }));
  }
  if (r.type === 'aws_instance') {
    // root_block_device without encrypted
    const root = r.body.match(/root_block_device\s*\{/);
    if (root) {
      const brace = r.body.indexOf('{', root.index);
      const block = braceSlice(r.body, brace);
      if (!/encrypted\s*=\s*true/.test(block)) {
        findings.push(finding({
          ruleId: 'CKV_AWS_8',
          title: 'EC2 root block device is not encrypted',
          severity: 'HIGH',
          resource: r.address,
        }));
      }
    }
  }
}

function checkIamStar(r, findings) {
  if (/"Action"\s*:\s*"\*"/i.test(r.body) || /Action\s*=\s*"\*"/i.test(r.body) || /actions\s*=\s*\[[^\]]*"\*"/i.test(r.body)) {
    if (/"Resource"\s*:\s*"\*"/i.test(r.body) || /Resource\s*=\s*"\*"/i.test(r.body) || /resources\s*=\s*\[[^\]]*"\*"/i.test(r.body)) {
      findings.push(finding({
        ruleId: 'CKV_AWS_62',
        title: 'IAM policy allows Action:* on Resource:*',
        severity: 'CRITICAL',
        resource: r.address,
        needsHuman: true,
        detail: 'Broadening or narrowing IAM is a human decision; flagged only.',
      }));
    }
  }
}

/* ---------------- Kubernetes helpers ---------------- */

function splitYamlDocs(src) {
  return src.split(/^---$/m).map((d) => d.trim()).filter(Boolean);
}

function matchField(doc, field) {
  const m = doc.match(new RegExp(`^${field}:\\s*["']?([^"'\\n#]+)`, 'm'));
  return m ? m[1].trim() : null;
}

function nestedName(doc) {
  const m = doc.match(/metadata:\s*\n(?:[ \t]+.*\n)*?[ \t]+name:\s*["']?([^"'\n#]+)/);
  return m ? m[1].trim() : null;
}

function checkPrivileged(doc, address, findings) {
  if (/privileged:\s*true/.test(doc)) {
    findings.push(finding({
      ruleId: 'CKV_K8S_16',
      title: 'Container runs privileged',
      severity: 'CRITICAL',
      resource: address,
    }));
  }
}

function checkHostNetwork(doc, address, findings) {
  if (/hostNetwork:\s*true/.test(doc)) {
    findings.push(finding({
      ruleId: 'CKV_K8S_19',
      title: 'Pod uses hostNetwork',
      severity: 'HIGH',
      resource: address,
    }));
  }
}

function checkHostPath(doc, address, findings) {
  if (/hostPath\s*:/.test(doc)) {
    findings.push(finding({
      ruleId: 'CKV_K8S_23',
      title: 'Volume uses hostPath',
      severity: 'HIGH',
      resource: address,
      needsHuman: true,
      detail: 'hostPath may be required for node agents; human must confirm.',
    }));
  }
}

function checkRunAsRoot(doc, address, findings) {
  const hasRunAsNonRoot = /runAsNonRoot:\s*true/.test(doc);
  const runAsUser0 = /runAsUser:\s*0\b/.test(doc);
  if (runAsUser0 || !hasRunAsNonRoot) {
    // Only flag if securityContext is present or clearly a workload
    if (/securityContext:/.test(doc) || /containers:/.test(doc)) {
      if (runAsUser0 || !/runAsNonRoot:\s*true/.test(doc)) {
        findings.push(finding({
          ruleId: 'CKV_K8S_23_ROOT',
          title: 'Workload may run as root (missing runAsNonRoot: true)',
          severity: 'MEDIUM',
          resource: address,
        }));
      }
    }
  }
}

function checkResourceLimits(doc, address, findings) {
  if (!/containers:/.test(doc)) return;
  // Heuristic: at least one limits: block with cpu and memory
  const hasLimits = /limits:\s*\n(?:[ \t]+.*\n)*?[ \t]+(cpu|memory):/.test(doc);
  if (!hasLimits) {
    findings.push(finding({
      ruleId: 'CKV_K8S_11',
      title: 'Container missing CPU/memory limits',
      severity: 'MEDIUM',
      resource: address,
    }));
  }
}

function checkLatestTag(doc, address, findings) {
  if (/image:\s*\S+:latest\b/.test(doc) || /image:\s*[^:\s\n]+\s*$/m.test(doc)) {
    // Flag :latest explicitly; bare images without tag also count as latest
    if (/image:\s*\S+:latest\b/.test(doc)) {
      findings.push(finding({
        ruleId: 'CKV_K8S_14',
        title: 'Container image uses :latest tag',
        severity: 'MEDIUM',
        resource: address,
        needsHuman: true,
        detail: 'Pinning a digest/tag needs a known good version from a human.',
      }));
    }
  }
}

function checkCapSysAdmin(doc, address, findings) {
  if (/SYS_ADMIN/.test(doc) && /add:/.test(doc)) {
    findings.push(finding({
      ruleId: 'CKV_K8S_37',
      title: 'Container adds CAP_SYS_ADMIN',
      severity: 'CRITICAL',
      resource: address,
    }));
  }
}

function checkNodePort(doc, address, findings) {
  if (/type:\s*NodePort/.test(doc)) {
    findings.push(finding({
      ruleId: 'CKV_K8S_28',
      title: 'Service type is NodePort',
      severity: 'MEDIUM',
      resource: address,
      needsHuman: true,
    }));
  }
}

function checkLoadBalancer(doc, address, findings) {
  if (/type:\s*LoadBalancer/.test(doc) && !/loadBalancerSourceRanges:/.test(doc)) {
    findings.push(finding({
      ruleId: 'CKV_K8S_LB',
      title: 'LoadBalancer Service has no loadBalancerSourceRanges',
      severity: 'HIGH',
      resource: address,
    }));
  }
}

function dedupe(list) {
  const seen = new Set();
  const out = [];
  for (const f of list) {
    const k = `${f.ruleId}::${f.resource}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}

module.exports = { scan, scanTerraform, scanKubernetes };
