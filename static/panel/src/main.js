import { invoke } from '@forge/bridge';

const $ = (id) => document.getElementById(id);

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function renderFindings(list, title) {
  if (!list || !list.length) {
    $('findings').innerHTML = `<p class="muted">${title}: none</p>`;
    return;
  }
  const rows = list
    .map(
      (f) => `
    <tr>
      <td class="sev-${f.severity}">${f.severity}</td>
      <td><code>${f.ruleId}</code></td>
      <td>${escapeHtml(f.resource)}</td>
      <td>${escapeHtml(f.title)}${f.needsHuman ? ' <em>(human)</em>' : ''}</td>
    </tr>`
    )
    .join('');
  $('findings').innerHTML = `
    <h2 style="font-size:14px">${title} (${list.length})</h2>
    <table>
      <thead><tr><th>Sev</th><th>Rule</th><th>Resource</th><th>Title</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

$('scanBtn').onclick = async () => {
  $('status').textContent = 'Scanning…';
  $('verdict').innerHTML = '';
  $('fixed').innerHTML = '';
  try {
    const res = await invoke('scanContent', {
      content: $('content').value,
      filename: $('filename').value,
    });
    if (res.error) {
      $('status').textContent = res.error;
      return;
    }
    $('status').textContent = `Detected ${res.kind}`;
    renderFindings(res.findings, 'Findings');
  } catch (e) {
    $('status').textContent = String(e);
  }
};

$('fixBtn').onclick = async () => {
  $('status').textContent = 'Repairing (scan → LLM → verify → re-scan)…';
  $('fixed').innerHTML = '';
  try {
    const res = await invoke('repairContent', {
      content: $('content').value,
      filename: $('filename').value,
    });
    $('verdict').innerHTML = `<span class="badge ${res.verdict}">${res.verdict}</span>`;
    $('status').textContent = res.notes || res.error || '';
    renderFindings(res.remainingFindings || res.originalFindings, 'Remaining findings');
    if (res.fixed && res.verdict !== 'rejected' && res.verdict !== 'error') {
      $('fixed').innerHTML = `<h2 style="font-size:14px">Fixed file</h2><pre>${escapeHtml(res.fixed)}</pre>`;
    }
  } catch (e) {
    $('status').textContent = String(e);
  }
};
