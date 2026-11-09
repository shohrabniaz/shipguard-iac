'use strict';

/**
 * Structural intent checks — ported in spirit from EASE-Bot.
 * A "verified" fix must not delete resources/objects or invent AMI/image digests.
 */

function verifyIntent(kind, before, after) {
  const reasons = [];
  if (!after || !String(after).trim()) {
    return { ok: false, reasons: ['Fixed content is empty'] };
  }
  if (kind === 'terraform') {
    const b = tfAddresses(before);
    const a = tfAddresses(after);
    for (const addr of b) {
      if (!a.has(addr)) reasons.push(`Deleted Terraform resource ${addr}`);
    }
    // Invented EC2 with a made-up AMI is a known failure mode
    if (/ami-[0-9a-f]{8,}/i.test(after) && !/ami-[0-9a-f]{8,}/i.test(before)) {
      reasons.push('Introduced a new AMI id that was not in the original file');
    }
  } else if (kind === 'kubernetes') {
    const b = k8sObjects(before);
    const a = k8sObjects(after);
    for (const key of b) {
      if (!a.has(key)) reasons.push(`Deleted Kubernetes object ${key}`);
    }
    // Container images must not silently change to something else
    const bi = images(before);
    const ai = images(after);
    for (const img of bi) {
      // Allow adding a tag/digest to :latest, but not swapping the repository
      const repo = img.split(':')[0].split('@')[0];
      const still = [...ai].some((x) => x.startsWith(repo));
      if (!still) reasons.push(`Changed or removed container image repository ${repo}`);
    }
  }
  return { ok: reasons.length === 0, reasons };
}

function tfAddresses(src) {
  const set = new Set();
  const re = /resource\s+"([^"]+)"\s+"([^"]+)"/g;
  let m;
  while ((m = re.exec(src))) set.add(`${m[1]}.${m[2]}`);
  return set;
}

function k8sObjects(src) {
  const set = new Set();
  for (const doc of String(src).split(/^---$/m)) {
    const kind = (doc.match(/^kind:\s*["']?([^"'\n#]+)/m) || [])[1];
    const name = (doc.match(/metadata:\s*\n(?:[ \t]+.*\n)*?[ \t]+name:\s*["']?([^"'\n#]+)/) || [])[1];
    if (kind && name) set.add(`${kind.trim()}/${name.trim()}`);
  }
  return set;
}

function images(src) {
  const set = new Set();
  const re = /image:\s*["']?([^\s"'#]+)/g;
  let m;
  while ((m = re.exec(src))) set.add(m[1]);
  return set;
}

module.exports = { verifyIntent, tfAddresses, k8sObjects };
