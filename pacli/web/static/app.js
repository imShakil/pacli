/* ========================================================================
   pacli Web UI — app.js
   ======================================================================== */

const S = {          // app state
  secrets: [],
  filter: 'all',
  query: '',
  currentId: null,   // ID open in view modal
  currentSecret: null, // full secret object (revealed)
  editingId: null,   // null = new, string = update
  sshConnectionId: null,
  socket: null,
  backupFile: null,
  revealTimer: null,
};

// ------------------------------------------------------------------
// Boot
// ------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  S.socket = io();
  bindSocketEvents();
  const res = await api('GET', '/api/auth/check');
  if (!res) return showLogin();
  if (!res.configured) return showSetup();
  if (res.authenticated) { showApp(); await loadSecrets(); }
  else showLogin();
});

// ------------------------------------------------------------------
// Setup (first run)
// ------------------------------------------------------------------
function showSetup() {
  hide('login-overlay'); hide('app');
  show('setup-overlay');
  document.getElementById('setup-pw').focus();
}

async function doSetup() {
  const pw = val('setup-pw'), pw2 = val('setup-pw2');
  if (pw.length < 6) return showMsg('setup-error', 'error', 'Password must be at least 6 characters.');
  if (pw !== pw2) return showMsg('setup-error', 'error', 'Passwords do not match.');
  hide('setup-error');
  const res = await api('POST', '/api/setup/init', { password: pw, confirm: pw2 });
  if (res?.success) { hide('setup-overlay'); showApp(); await loadSecrets(); }
  else showMsg('setup-error', 'error', res?.error || 'Setup failed.');
}

// ------------------------------------------------------------------
// Login / Logout
// ------------------------------------------------------------------
function showLogin() {
  hide('setup-overlay'); hide('app');
  show('login-overlay');
  document.getElementById('login-pw').focus();
}

async function doLogin() {
  const pw = val('login-pw');
  if (!pw) return showMsg('login-error', 'error', 'Password required.');
  hide('login-error');
  const res = await api('POST', '/api/auth/login', { password: pw });
  if (res?.success) { hide('login-overlay'); showApp(); await loadSecrets(); }
  else showMsg('login-error', 'error', res?.error || 'Invalid password.');
}

async function doLogout() {
  await api('POST', '/api/auth/logout');
  hide('app'); showLogin();
  document.getElementById('login-pw').value = '';
}

function showApp() { show('app'); }

// ------------------------------------------------------------------
// Secrets
// ------------------------------------------------------------------
async function loadSecrets() {
  const res = await api('GET', '/api/secrets');
  S.secrets = res?.secrets || [];
  renderGrid();
  populateSSHDropdowns();
}

function renderGrid() {
  const grid = document.getElementById('secrets-grid');

  // Counts
  const counts = { all: S.secrets.length, password: 0, token: 0, ssh: 0 };
  S.secrets.forEach(s => { if (counts[s.type] !== undefined) counts[s.type]++; });
  Object.entries(counts).forEach(([k, v]) => {
    const el = document.getElementById('cnt-' + k);
    if (el) el.textContent = v;
  });
  document.getElementById('total-count').textContent = `${counts.all} secret${counts.all !== 1 ? 's' : ''}`;

  // Filter + search
  const visible = S.secrets.filter(s => {
    const matchFilter = S.filter === 'all' || s.type === S.filter;
    const matchQuery = !S.query || s.label.toLowerCase().includes(S.query);
    return matchFilter && matchQuery;
  });

  if (!visible.length) {
    grid.innerHTML = `<div class="empty-state"><div class="es-icon">🔍</div><h3>${S.query ? 'No results found' : 'No secrets yet'}</h3><p>${S.query ? 'Try a different search.' : 'Click "+ Add Secret" to get started.'}</p></div>`;
    return;
  }

  grid.innerHTML = visible.map(s => `
    <div class="secret-card" onclick="openViewModal('${s.id}')">
      <div class="secret-card-top">
        <div class="secret-card-label">${esc(s.label)}</div>
        <span class="badge badge-${s.type}">${s.type}</span>
      </div>
      <div class="secret-card-meta">Updated ${s.update_date}</div>
    </div>
  `).join('');
}

function setFilter(f, btn) {
  S.filter = f;
  document.querySelectorAll('.filter-item').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderGrid();
}

function doSearch(q) { S.query = q.toLowerCase(); renderGrid(); }

// ------------------------------------------------------------------
// Add / Edit modal
// ------------------------------------------------------------------
function openAddModal() {
  S.editingId = null;
  document.getElementById('edit-title').textContent = 'Add Secret';
  document.getElementById('edit-label').value = '';
  document.getElementById('edit-label').disabled = false;
  document.getElementById('edit-type').value = 'password';
  document.getElementById('edit-type').disabled = false;
  document.getElementById('edit-value').value = '';
  hide('edit-error');
  show('edit-backdrop');
  document.getElementById('edit-label').focus();
}

function openEditFromView() {
  const s = S.secrets.find(x => x.id === S.currentId);
  if (!s) return;
  closeViewModal();
  S.editingId = s.id;
  document.getElementById('edit-title').textContent = 'Edit Secret';
  document.getElementById('edit-label').value = s.label;
  document.getElementById('edit-label').disabled = true;
  document.getElementById('edit-type').value = s.type;
  document.getElementById('edit-type').disabled = true;
  // Pre-fill with current revealed value if available, else blank
  document.getElementById('edit-value').value = S.currentSecret?.secret || '';
  hide('edit-error');
  show('edit-backdrop');
  document.getElementById('edit-value').focus();
}

function closeEditModal() { hide('edit-backdrop'); }

async function saveSecret() {
  const label = document.getElementById('edit-label').value.trim();
  const type  = document.getElementById('edit-type').value;
  const secret = document.getElementById('edit-value').value.trim();
  if (!label || !secret) return showMsg('edit-error', 'error', 'Label and secret value are required.');
  hide('edit-error');

  let res;
  if (S.editingId) {
    res = await api('PUT', `/api/secrets/${S.editingId}`, { secret });
  } else {
    res = await api('POST', '/api/secrets', { label, type, secret });
  }

  if (res?.success) { closeEditModal(); await loadSecrets(); }
  else showMsg('edit-error', 'error', res?.error || 'Save failed.');
}

// ------------------------------------------------------------------
// View modal
// ------------------------------------------------------------------
async function openViewModal(id) {
  const s = S.secrets.find(x => x.id === id);
  if (!s) return;
  S.currentId = id;
  S.currentSecret = null;

  document.getElementById('view-title-text').textContent = s.label;
  document.getElementById('view-label-val').textContent  = s.label;
  document.getElementById('view-type-val').textContent   = s.type;
  document.getElementById('view-created-val').textContent = new Date(s.creation_time * 1000).toLocaleString();
  document.getElementById('view-updated-val').textContent = new Date(s.update_time * 1000).toLocaleString();

  // Reset reveal state
  setRevealMasked();
  hide('view-msg');
  show('view-backdrop');
}

function setRevealMasked() {
  const el = document.getElementById('reveal-text');
  el.textContent = '••••••••••••••••';
  el.classList.add('masked');
  document.getElementById('reveal-toggle-btn').textContent = '👁 Show';
  clearTimeout(S.revealTimer);
}

function setRevealVisible(text) {
  const el = document.getElementById('reveal-text');
  el.textContent = text;
  el.classList.remove('masked');
  document.getElementById('reveal-toggle-btn').textContent = '🙈 Hide';
  // Auto-hide after 30s
  clearTimeout(S.revealTimer);
  S.revealTimer = setTimeout(setRevealMasked, 30000);
}

async function fetchSecret() {
  if (S.currentSecret) return S.currentSecret.secret;
  const res = await api('GET', `/api/secrets/${S.currentId}/reveal`);
  if (res?.secret !== undefined) {
    S.currentSecret = res;
    return res.secret;
  }
  return null;
}

async function toggleReveal() {
  const el = document.getElementById('reveal-text');
  if (!el.classList.contains('masked')) {
    // Currently visible — hide
    setRevealMasked();
    return;
  }
  const text = await fetchSecret();
  if (text === null) return showMsg('view-msg', 'error', 'Failed to reveal secret.');
  setRevealVisible(text);
}

async function copySecret() {
  // Copy works regardless of reveal state
  const text = await fetchSecret();
  if (text === null) return showMsg('view-msg', 'error', 'Failed to retrieve secret.');
  try {
    await navigator.clipboard.writeText(text);
    showMsg('view-msg', 'success', '📋 Copied to clipboard!');
    setTimeout(() => hide('view-msg'), 2500);
  } catch {
    showMsg('view-msg', 'error', 'Clipboard access denied. Please allow clipboard permissions.');
  }
}

function closeViewModal() {
  hide('view-backdrop');
  setRevealMasked();
  S.currentSecret = null;
}

async function deleteSecret() {
  if (!S.currentId) return;
  const s = S.secrets.find(x => x.id === S.currentId);
  if (!confirm(`Delete "${s?.label}"? This cannot be undone.`)) return;
  const res = await api('DELETE', `/api/secrets/${S.currentId}`);
  if (res?.success) { closeViewModal(); await loadSecrets(); }
  else alert(res?.error || 'Delete failed.');
}

// ------------------------------------------------------------------
// SSH Terminal
// ------------------------------------------------------------------
function openSSHModal() { show('ssh-backdrop'); }
function closeSSHModal() {
  if (S.sshConnectionId) {
    if (!confirm('You have an active SSH connection. Disconnect and close?')) return;
    sshDisconnect();
  }
  hide('ssh-backdrop');
}

function toggleSSHAuth() {
  const v = document.getElementById('ssh-auth').value;
  document.getElementById('ssh-pw-field').style.display    = v === 'password' ? '' : 'none';
  document.getElementById('ssh-key-fields').style.display  = v === 'key' ? '' : 'none';
}

function populateSSHDropdowns() {
  const sshSecrets = S.secrets.filter(s => s.type === 'ssh');

  // Key select (for manual connection)
  const ks = document.getElementById('ssh-key-select');
  ks.innerHTML = '<option value="">— Choose stored key —</option>';
  sshSecrets.forEach(s => {
    const o = document.createElement('option');
    o.value = s.id; o.textContent = s.label;
    ks.appendChild(o);
  });

  // Stored server select
  const ss = document.getElementById('ssh-stored-select');
  ss.innerHTML = '<option value="">— Choose —</option>';
  sshSecrets.forEach(s => {
    const o = document.createElement('option');
    o.value = s.id; o.textContent = s.label;
    ss.appendChild(o);
  });
}

async function sshConnect(mode) {
  const errId = mode === 'manual' ? 'ssh-manual-error' : 'ssh-stored-error';
  hide(errId);

  let payload = {};

  if (mode === 'manual') {
    const host = val('ssh-host'), user = val('ssh-user');
    const port = parseInt(document.getElementById('ssh-port').value) || 22;
    const auth = document.getElementById('ssh-auth').value;
    if (!host || !user) return showMsg(errId, 'error', 'Hostname and username are required.');
    payload = { hostname: host, username: user, port };
    if (auth === 'password') {
      const pw = val('ssh-password');
      if (!pw) return showMsg(errId, 'error', 'Password is required.');
      payload.password = pw;
    } else {
      const keyId = document.getElementById('ssh-key-select').value;
      if (keyId) {
        const r = await api('GET', `/api/secrets/${keyId}/reveal`);
        if (!r?.secret) return showMsg(errId, 'error', 'Could not retrieve SSH key.');
        payload.ssh_key = r.secret;
      } else {
        const pasted = val('ssh-key-paste');
        if (!pasted) return showMsg(errId, 'error', 'Provide an SSH key.');
        payload.ssh_key = pasted;
      }
    }
  } else {
    const keyId = document.getElementById('ssh-stored-select').value;
    if (!keyId) return showMsg(errId, 'error', 'Select a stored SSH server.');
    payload = { key_id: keyId };
  }

  // Connect via WebSocket
  if (S.socket?.connected) {
    S.socket.emit('ssh_connect', payload);
  } else {
    // REST fallback
    const r = await api('POST', '/api/ssh/connect', payload);
    if (r?.success) {
      S.sshConnectionId = r.connection_id;
      showSSHTerminal();
      appendSSH(`Connected: ${r.message}\n`);
    } else {
      showMsg(errId, 'error', r?.error || 'Connection failed.');
    }
  }
}

function showSSHTerminal() {
  hide('ssh-connect-area');
  show('ssh-terminal-wrap');
  const cmd = document.getElementById('ssh-cmd');
  cmd.disabled = false;
  cmd.focus();
}

function hideSSHTerminal() {
  show('ssh-connect-area');
  hide('ssh-terminal-wrap');
  document.getElementById('ssh-output').textContent = '';
  document.getElementById('ssh-cmd').disabled = true;
  document.getElementById('ssh-cmd').value = '';
}

function appendSSH(text) {
  const out = document.getElementById('ssh-output');
  out.textContent += text;
  out.scrollTop = out.scrollHeight;
}

function sshKey(e) {
  if (e.key !== 'Enter') return;
  const cmd = document.getElementById('ssh-cmd');
  const command = cmd.value;
  if (!command.trim() || !S.sshConnectionId) return;
  appendSSH(`$ ${command}\n`);
  cmd.value = '';

  if (S.socket?.connected) {
    S.socket.emit('ssh_command', { connection_id: S.sshConnectionId, command });
  } else {
    api('POST', '/api/ssh/execute', { connection_id: S.sshConnectionId, command })
      .then(r => { if (r?.output) appendSSH(r.output); });
  }
}

function sshDisconnect() {
  if (!S.sshConnectionId) return;
  if (S.socket?.connected) {
    S.socket.emit('ssh_disconnect', { connection_id: S.sshConnectionId });
  } else {
    api('POST', `/api/ssh/disconnect/${S.sshConnectionId}`);
    appendSSH('\nDisconnected.\n');
    S.sshConnectionId = null;
    hideSSHTerminal();
  }
}

function bindSocketEvents() {
  S.socket.on('ssh_connected', d => {
    S.sshConnectionId = d.connection_id;
    showSSHTerminal();
    appendSSH(`Connected: ${d.message}\n`);
  });
  S.socket.on('ssh_output', d => { if (d.output) appendSSH(d.output); });
  S.socket.on('ssh_disconnected', d => {
    appendSSH(`\n${d.message}\n`);
    S.sshConnectionId = null;
    setTimeout(hideSSHTerminal, 1200);
  });
  S.socket.on('error', d => {
    // Show error in whichever SSH form is active
    const errId = document.getElementById('ssh-panel-manual').classList.contains('active')
      ? 'ssh-manual-error' : 'ssh-stored-error';
    showMsg(errId, 'error', d.message || 'SSH error');
  });
}

// ------------------------------------------------------------------
// Backup
// ------------------------------------------------------------------
function openBackupModal() { show('backup-backdrop'); }
function closeBackupModal() { hide('backup-backdrop'); }

async function doBackupExport() {
  const pw = val('backup-export-pw'), pw2 = val('backup-export-pw2');
  if (pw.length < 6) return showMsg('backup-export-msg', 'error', 'Password must be at least 6 characters.');
  if (pw !== pw2) return showMsg('backup-export-msg', 'error', 'Passwords do not match.');
  hide('backup-export-msg');

  try {
    const resp = await fetch('/api/backup/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ password: pw }),
    });
    if (!resp.ok) {
      const err = await resp.json();
      return showMsg('backup-export-msg', 'error', err.error || 'Export failed.');
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pacli_backup_${new Date().toISOString().slice(0,10)}.pacli`;
    a.click();
    URL.revokeObjectURL(url);
    showMsg('backup-export-msg', 'success', '✅ Backup downloaded! Store it somewhere safe.');
  } catch (e) {
    showMsg('backup-export-msg', 'error', 'Export failed: ' + e.message);
  }
}

function onFileSelected(input) {
  S.backupFile = input.files[0];
  document.getElementById('upload-zone-label').textContent = `📄 ${S.backupFile.name}`;
}

function handleFileDrop(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.remove('drag-over');
  S.backupFile = e.dataTransfer.files[0];
  if (S.backupFile) document.getElementById('upload-zone-label').textContent = `📄 ${S.backupFile.name}`;
}

async function doBackupImport() {
  if (!S.backupFile) return showMsg('backup-import-msg', 'error', 'Please select a backup file.');
  const pw = val('backup-import-pw');
  if (!pw) return showMsg('backup-import-msg', 'error', 'Backup password is required.');
  const overwrite = document.getElementById('import-overwrite').checked;
  hide('backup-import-msg');

  const fd = new FormData();
  fd.append('file', S.backupFile);
  fd.append('password', pw);
  fd.append('overwrite', overwrite ? 'true' : 'false');

  try {
    const resp = await fetch('/api/backup/import', { method: 'POST', credentials: 'include', body: fd });
    const data = await resp.json();
    if (!resp.ok) return showMsg('backup-import-msg', 'error', data.error || 'Import failed.');
    showMsg('backup-import-msg', 'success',
      `✅ Import done: ${data.imported} imported, ${data.skipped} skipped, ${data.errors} errors.`);
    await loadSecrets();
  } catch (e) {
    showMsg('backup-import-msg', 'error', 'Import failed: ' + e.message);
  }
}

// ------------------------------------------------------------------
// Tab switcher (generic)
// ------------------------------------------------------------------
function switchTab(group, panel, btn) {
  // Buttons
  btn.closest('.tabs').querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  // Panels — find sibling panels by id prefix
  document.querySelectorAll(`[id^="${group}-panel-"]`).forEach(p => p.classList.remove('active'));
  document.getElementById(`${group}-panel-${panel}`).classList.add('active');
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
async function api(method, url, body) {
  try {
    const opts = { method, credentials: 'include', headers: {} };
    if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const r = await fetch(url, opts);
    if (r.status === 401) { showLogin(); return null; }
    return await r.json();
  } catch (e) {
    console.error('API error', url, e);
    return null;
  }
}

function val(id) { return document.getElementById(id).value.trim(); }
function show(id) { document.getElementById(id).classList.remove('hidden'); }
function hide(id) { document.getElementById(id).classList.add('hidden'); }
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function showMsg(id, type, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `alert alert-${type}`;
  el.textContent = text;
  el.classList.remove('hidden');
}
