'use strict';

const API_BASE = '';
const STORAGE_KEY = 'admin_backend_token';
const USER_KEY = 'admin_backend_user';

function $(sel, ctx = document) { return ctx.querySelector(sel); }
function $all(sel, ctx = document) { return Array.from(ctx.querySelectorAll(sel)); }

function toast(msg, isErr=false) {
  const t = $('#toast');
  t.textContent = msg || '';
  t.className = `toast${isErr ? ' error' : ''}`;
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => t.classList.remove('show'), 3000);
}

function setAuth(token, user) {
  if (token) localStorage.setItem(STORAGE_KEY, token); else localStorage.removeItem(STORAGE_KEY);
  const status = $('#authUser');
  const logout = $('#btnLogout');
  const stored = getStoredUser();
  const u = user || stored;
  if (token && u) {
    status.textContent = `${u.name} <${u.email}> (${u.role})`;
    logout.hidden = false;
  } else {
    status.textContent = '';
    logout.hidden = true;
  }
  if (user) setStoredUser(user);
}

function getToken() { return localStorage.getItem(STORAGE_KEY); }

function authHeaders() {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function getStoredUser() { try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); } catch { return null; } }
function setStoredUser(u) { if (u) localStorage.setItem(USER_KEY, JSON.stringify(u)); else localStorage.removeItem(USER_KEY); }
function decodeJwt(token) { try { const p = token.split('.')[1]; return JSON.parse(atob(p)); } catch { return null; } }
async function ensureUserLoaded() {
  const token = getToken();
  if (!token) return null;
  let u = getStoredUser();
  if (u) return u;
  const payload = decodeJwt(token);
  if (payload?.id) {
    try {
      const res = await api(`/api/admin/users/${payload.id}`);
      setStoredUser({ id: res._id || res.id, name: res.name, email: res.email, role: res.role, active: res.active });
      return getStoredUser();
    } catch (e) {
      return null;
    }
  }
  return null;
}

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...authHeaders(), ...(opts.headers || {}) };
  const res = await fetch(API_BASE + path, { ...opts, headers });
  if (!res.ok) {
    let detail = '';
    try { detail = JSON.stringify(await res.json()); } catch (_) {}
    throw new Error(`${res.status} ${res.statusText} ${detail}`.trim());
  }
  const type = res.headers.get('content-type') || '';
  return type.includes('application/json') ? res.json() : res.text();
}

function show(el) { el.hidden = false; }
function hide(el) { el.hidden = true; }
function setMsg(el, msg, isErr = false) {
  el.textContent = msg || '';
  el.style.color = isErr ? '#f87171' : '#a3e635';
}

// Tabs for auth
$all('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    $all('.tab').forEach(b => b.classList.remove('active'));
    $all('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    $('#' + btn.dataset.tab).classList.add('active');
  });
});

// Debounce helper
function debounce(fn, ms=300) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// Logout
$('#btnLogout').addEventListener('click', () => {
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(USER_KEY);
  setAuth(null);
  toast('Logged out');
  window.location.href = '/admin/login';
});

// Auth forms
$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  setMsg($('#authMsg'), '');
  try {
    const email = $('#loginEmail').value.trim();
    const password = $('#loginPassword').value;
    const { token, user } = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
    setAuth(token, user);
    hide($('#authSection'));
    $('#dashboardNav').hidden = false;
    activateSection('usersSection');
    await refreshUsers();
    toast('Logged in');
  } catch (err) {
    setMsg($('#authMsg'), err.message, true);
    toast(err.message, true);
  }
});

$('#registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  setMsg($('#authMsg'), '');
  try {
    const name = $('#registerName').value.trim();
    const email = $('#registerEmail').value.trim();
    const password = $('#registerPassword').value;
    const { token, user } = await api('/api/auth/register-admin', { method: 'POST', body: JSON.stringify({ name, email, password }) });
    setAuth(token, user);
    hide($('#authSection'));
    $('#dashboardNav').hidden = false;
    activateSection('usersSection');
    await refreshUsers();
    toast('Admin registered and logged in');
  } catch (err) {
    setMsg($('#authMsg'), err.message, true);
    toast(err.message, true);
  }
});

// Users list
let state = { page: 1 };

function activateSection(id) {
  ['usersSection','feedbackSection','shakesSection','rewardsSection'].forEach(sec => hide(document.getElementById(sec)));
  show(document.getElementById(id));
  $all('.navbtn').forEach(b => b.classList.toggle('active', b.dataset.target === id));
}

// Dashboard nav handlers
$all('.navbtn').forEach(btn => {
  btn.addEventListener('click', async () => {
    activateSection(btn.dataset.target);
    if (btn.dataset.target === 'usersSection') await refreshUsers();
    if (btn.dataset.target === 'feedbackSection') await refreshFeedback();
    if (btn.dataset.target === 'shakesSection') await refreshShakes();
    if (btn.dataset.target === 'rewardsSection') await refreshRewards();
  });
});

async function refreshUsers() {
  $('#usersLoader').hidden = false;
  const q = new URLSearchParams({
    page: String(state.page || 1),
    limit: $('#limit').value,
    search: $('#searchInput').value.trim(),
    sort: $('#sortField').value,
    order: $('#sortOrder').value,
  });
  try {
    const data = await api(`/api/admin/users?${q.toString()}`);
    $('#pageInfo').textContent = `Page ${data.page} / ${data.totalPages} — ${data.total} total`;
    $('#prevPage').disabled = data.page <= 1;
    $('#nextPage').disabled = data.page >= data.totalPages;
    const tbody = $('#usersTbody');
    tbody.innerHTML = '';
    if (!data.data.length) tbody.innerHTML = '<tr class="muted"><td colspan="6">No users found</td></tr>';
    data.data.forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${u.name}</td>
        <td>${u.email}</td>
        <td><span class="badge">${u.role}</span></td>
        <td>${u.active ? 'true' : 'false'}</td>
        <td>${new Date(u.createdAt).toLocaleString()}</td>
        <td>
          <button class="btn btn-secondary" data-action="edit" data-id="${u.id}">Edit</button>
          <button class="btn" data-action="delete" data-id="${u.id}">Delete</button>
        </td>`;
      tbody.appendChild(tr);
    });
  } catch (err) {
    setMsg($('#usersMsg'), err.message, true);
    toast(err.message, true);
  } finally {
    $('#usersLoader').hidden = true;
  }
}

$('#btnRefresh').addEventListener('click', () => { state.page = 1; refreshUsers(); });
$('#searchInput').addEventListener('input', debounce(() => { state.page = 1; refreshUsers(); }, 350));
$('#sortField').addEventListener('change', () => { state.page = 1; refreshUsers(); });
$('#sortOrder').addEventListener('change', () => { state.page = 1; refreshUsers(); });
$('#limit').addEventListener('change', () => { state.page = 1; refreshUsers(); });
$('#prevPage').addEventListener('click', () => { state.page = Math.max(1, (state.page || 1) - 1); refreshUsers(); });
$('#nextPage').addEventListener('click', () => { state.page = (state.page || 1) + 1; refreshUsers(); });

// Create
$('#btnShowCreate').addEventListener('click', () => {
  $('#createMsg').textContent = '';
  $('#cName').value = '';
  $('#cEmail').value = '';
  $('#cPassword').value = '';
  $('#cRole').value = 'user';
  $('#createDialog').showModal();
});

$('#createForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  setMsg($('#createMsg'), '');
  try {
    const body = {
      name: $('#cName').value.trim(),
      email: $('#cEmail').value.trim(),
      password: $('#cPassword').value,
      role: $('#cRole').value,
    };
    await api('/api/admin/users', { method: 'POST', body: JSON.stringify(body) });
    $('#createDialog').close();
    await refreshUsers();
    toast('User created');
  } catch (err) {
    setMsg($('#createMsg'), err.message, true);
    toast(err.message, true);
  }
});

// Edit/Delete via delegation
$('#usersTbody').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const id = btn.dataset.id;
  const action = btn.dataset.action;
  if (action === 'delete') {
    const confirmed = await confirmDialog('Delete this user?');
    if (!confirmed) return;
    try {
      await api(`/api/admin/users/${id}`, { method: 'DELETE' });
      await refreshUsers();
      toast('User deleted');
    } catch (err) {
      setMsg($('#usersMsg'), err.message, true);
      toast(err.message, true);
    }
  }
  if (action === 'edit') {
    try {
      const u = await api(`/api/admin/users/${id}`);
      $('#eId').value = u._id || u.id;
      $('#eName').value = u.name;
      $('#eEmail').value = u.email;
      $('#eRole').value = u.role;
      $('#eActive').value = String(Boolean(u.active));
      $('#ePassword').value = '';
      $('#editMsg').textContent = '';
      $('#editDialog').showModal();
    } catch (err) {
      setMsg($('#usersMsg'), err.message, true);
      toast(err.message, true);
    }
  }
});

$('#editForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  setMsg($('#editMsg'), '');
  try {
    const id = $('#eId').value;
    const body = {
      name: $('#eName').value.trim(),
      email: $('#eEmail').value.trim(),
      role: $('#eRole').value,
      active: $('#eActive').value === 'true',
    };
    const pwd = $('#ePassword').value;
    if (pwd) body.password = pwd;

    await api(`/api/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
    $('#editDialog').close();
    await refreshUsers();
    toast('User updated');
  } catch (err) {
    setMsg($('#editMsg'), err.message, true);
    toast(err.message, true);
  }
});

// Feedback section
let fbState = { page: 1 };
async function refreshFeedback() {
  $('#fbLoader').hidden = false;
  const q = new URLSearchParams({ page: String(fbState.page||1), limit: $('#fbLimit').value, search: $('#fbSearch').value.trim() });
  try {
    const data = await api(`/api/admin/feedback?${q.toString()}`);
    $('#fbPageInfo').textContent = `Page ${data.page} / ${data.totalPages} — ${data.total} total`;
    $('#fbPrev').disabled = data.page <= 1;
    $('#fbNext').disabled = data.page >= data.totalPages;
    const tbody = $('#feedbackTbody');
    tbody.innerHTML = '';
    if (!(data.data||[]).length) tbody.innerHTML = '<tr class="muted"><td colspan="4">No feedback to display</td></tr>';
    (data.data||[]).forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${f.user?.email||f.user||''}</td><td>${f.message||''}</td><td>${f.rating??''}</td><td>${new Date(f.createdAt).toLocaleString()}</td>`;
      tbody.appendChild(tr);
    });
  } catch (err) {
    setMsg($('#feedbackMsg'), err.message, true);
    toast(err.message, true);
  } finally { $('#fbLoader').hidden = true; }
}
$('#fbRefresh').addEventListener('click', () => { fbState.page=1; refreshFeedback(); });
$('#fbSearch').addEventListener('input', debounce(() => { fbState.page=1; refreshFeedback(); }, 350));
$('#fbLimit').addEventListener('change', () => { fbState.page=1; refreshFeedback(); });
$('#fbPrev').addEventListener('click', () => { fbState.page=Math.max(1,(fbState.page||1)-1); refreshFeedback(); });
$('#fbNext').addEventListener('click', () => { fbState.page=(fbState.page||1)+1; refreshFeedback(); });

// Shakes section
let shState = { page: 1 };
async function refreshShakes() {
  $('#shLoader').hidden = false;
  const q = new URLSearchParams({ page: String(shState.page||1), limit: $('#shLimit').value, search: $('#shSearch').value.trim() });
  try {
    const data = await api(`/api/admin/shakes?${q.toString()}`);
    $('#shPageInfo').textContent = `Page ${data.page} / ${data.totalPages} — ${data.total} total`;
    $('#shPrev').disabled = data.page <= 1;
    $('#shNext').disabled = data.page >= data.totalPages;
    const tbody = $('#shakesTbody');
    tbody.innerHTML = '';
    if (!(data.data||[]).length) tbody.innerHTML = '<tr class="muted"><td colspan="4">No activity to display</td></tr>';
    (data.data||[]).forEach(s => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${s.user?.email||s.user||''}</td><td>${s.type||''}</td><td>${s.details||''}</td><td>${new Date(s.createdAt).toLocaleString()}</td>`;
      tbody.appendChild(tr);
    });
  } catch (err) {
    setMsg($('#shakesMsg'), err.message, true);
    toast(err.message, true);
  } finally { $('#shLoader').hidden = true; }
}
$('#shRefresh').addEventListener('click', () => { shState.page=1; refreshShakes(); });
$('#shSearch').addEventListener('input', debounce(() => { shState.page=1; refreshShakes(); }, 350));
$('#shLimit').addEventListener('change', () => { shState.page=1; refreshShakes(); });
$('#shPrev').addEventListener('click', () => { shState.page=Math.max(1,(shState.page||1)-1); refreshShakes(); });
$('#shNext').addEventListener('click', () => { shState.page=(shState.page||1)+1; refreshShakes(); });

// Rewards section
async function refreshRewards() {
  $('#rwLoader').hidden = false;
  try {
    const data = await api('/api/admin/rewards');
    const tbody = $('#rewardsTbody');
    tbody.innerHTML = '';
    const arr = (data.data||data||[]);
    if (!arr.length) tbody.innerHTML = '<tr class="muted"><td colspan="5">No rewards yet</td></tr>';
    arr.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${r.title||''}</td><td>${r.points??''}</td><td>${r.active?'true':'false'}</td><td>${new Date(r.createdAt).toLocaleString()}</td>
        <td><button class="btn btn-secondary" data-action="edit-reward" data-id="${r.id||r._id}">Edit</button>
        <button class="btn" data-action="delete-reward" data-id="${r.id||r._id}">Delete</button></td>`;
      tbody.appendChild(tr);
    });
  } catch (err) {
    setMsg($('#rewardsMsg'), err.message, true);
    toast(err.message, true);
  } finally { $('#rwLoader').hidden = true; }
}

$('#btnShowCreateReward').addEventListener('click', () => {
  $('#createRewardMsg').textContent = '';
  $('#rTitle').value = '';
  $('#rDesc').value = '';
  $('#rPoints').value = '0';
  $('#rActive').checked = true;
  $('#createRewardDialog').showModal();
});

$('#createRewardForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  setMsg($('#createRewardMsg'), '');
  try {
    const body = { title: $('#rTitle').value.trim(), description: $('#rDesc').value.trim(), points: Number($('#rPoints').value||0), active: $('#rActive').checked };
    await api('/api/admin/rewards', { method: 'POST', body: JSON.stringify(body) });
    $('#createRewardDialog').close();
    await refreshRewards();
    toast('Reward created');
  } catch (err) {
    setMsg($('#createRewardMsg'), err.message, true);
    toast(err.message, true);
  }
});

$('#rewardsTbody').addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const id = btn.dataset.id;
  const action = btn.dataset.action;
  if (action === 'delete-reward') {
    const confirmed = await confirmDialog('Delete this reward?');
    if (!confirmed) return;
    try { await api(`/api/admin/rewards/${id}`, { method: 'DELETE' }); await refreshRewards(); toast('Reward deleted'); } catch (err) { setMsg($('#rewardsMsg'), err.message, true); toast(err.message, true); }
  }
  if (action === 'edit-reward') {
    try {
      const r = await api(`/api/admin/rewards/${id}`);
      $('#erId').value = r._id||r.id; $('#erTitle').value = r.title||''; $('#erDesc').value = r.description||''; $('#erPoints').value = r.points??0; $('#erActive').checked = !!r.active;
      $('#editRewardMsg').textContent='';
      $('#editRewardDialog').showModal();
    } catch (err) { setMsg($('#rewardsMsg'), err.message, true); toast(err.message, true); }
  }
});

$('#editRewardForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  setMsg($('#editRewardMsg'), '');
  try {
    const id = $('#erId').value;
    const body = { title: $('#erTitle').value.trim(), description: $('#erDesc').value.trim(), points: Number($('#erPoints').value||0), active: $('#erActive').checked };
    await api(`/api/admin/rewards/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
    $('#editRewardDialog').close();
    await refreshRewards();
    toast('Reward updated');
  } catch (err) { setMsg($('#editRewardMsg'), err.message, true); toast(err.message, true); }
});

async function confirmDialog(text) {
  $('#confirmText').textContent = text || 'Are you sure?';
  $('#confirmDialog').showModal();
  return new Promise((resolve) => {
    const ok = $('#confirmOk');
    const handler = (e) => { $('#confirmDialog').close(); ok.removeEventListener('click', handler); resolve(e.target === ok); };
    ok.addEventListener('click', handler, { once: true });
    $('#confirmDialog').addEventListener('close', () => resolve(false), { once: true });
  });
}

(async function init() {
  const token = getToken();
  if (token) {
    const user = await ensureUserLoaded();
    setAuth(token, user);
    hide($('#authSection'));
    $('#dashboardNav').hidden = false;
    activateSection('usersSection');
    try { await refreshUsers(); } catch (err) { setMsg($('#usersMsg'), err.message, true); toast(err.message, true); }
  } else {
    // Not logged in; redirect to login page
    window.location.href = '/admin/login';
  }
})();
