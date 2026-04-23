const state = {
  items: [],
  activeId: null,
  counts: { total: 0, New: 0, InProgress: 0, Closed: 0 }
};

const tableBody = document.querySelector('[data-query-rows]');
const emptyState = document.querySelector('[data-empty-state]');
const drawer = document.querySelector('[data-drawer]');
const searchInput = document.querySelector('[data-search]');
const statusFilter = document.querySelector('[data-status-filter]');
const serviceFilter = document.querySelector('[data-service-filter]');
const reloadButton = document.querySelector('[data-reload]');
const saveButton = document.querySelector('[data-save]');
const drawerStatus = document.querySelector('[data-drawer-status]');
const drawerNotes = document.querySelector('[data-drawer-notes]');
const currentUser = document.querySelector('[data-current-user]');
const totalCard = document.querySelector('[data-total]');
const newCard = document.querySelector('[data-new]');
const progressCard = document.querySelector('[data-progress]');
const closedCard = document.querySelector('[data-closed]');
const drawerTitle = document.querySelector('[data-drawer-title]');
const drawerMeta = document.querySelector('[data-drawer-meta]');
const drawerMessage = document.querySelector('[data-drawer-message]');
const drawerContact = document.querySelector('[data-drawer-contact]');
const drawerService = document.querySelector('[data-drawer-service]');
const drawerCompany = document.querySelector('[data-drawer-company]');
const drawerId = document.querySelector('[data-drawer-id]');
const dashboardNotice = document.querySelector('[data-dashboard-notice]');

function statusClass(status) {
  return status.replace(/\s+/g, '');
}

function setNotice(message, type = 'error') {
  if (!dashboardNotice) return;
  dashboardNotice.textContent = message;
  dashboardNotice.className = `notice show ${type}`;
}

function clearNotice() {
  if (!dashboardNotice) return;
  dashboardNotice.textContent = '';
  dashboardNotice.className = 'notice';
}

function renderCounts() {
  totalCard.textContent = String(state.counts.total || 0);
  newCard.textContent = String(state.counts.New || 0);
  progressCard.textContent = String(state.counts.InProgress || 0);
  closedCard.textContent = String(state.counts.Closed || 0);
}

function renderTable() {
  tableBody.innerHTML = '';
  if (!state.items.length) {
    emptyState.hidden = false;
    return;
  }

  emptyState.hidden = true;
  state.items.forEach((item) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${escapeHtml(item.name)}</td>
      <td>${escapeHtml(item.company || '-')}</td>
      <td>${escapeHtml(item.serviceInterestedIn)}</td>
      <td><span class="status-badge status-${statusClass(item.status)}">${escapeHtml(item.status)}</span></td>
      <td>${formatDate(item.createdAt)}</td>
      <td><button data-open="${item.id}">View</button></td>
    `;
    tableBody.appendChild(row);
  });

  tableBody.querySelectorAll('[data-open]').forEach((button) => {
    button.addEventListener('click', () => {
      state.activeId = button.getAttribute('data-open');
      renderDrawer();
    });
  });
}

function renderDrawer() {
  const item = state.items.find((entry) => entry.id === state.activeId);
  if (!item) {
    drawerTitle.textContent = 'Select a query';
    drawerMeta.textContent = 'Choose a row from the table to review details.';
    drawerMessage.textContent = '-';
    drawerContact.textContent = '-';
    drawerService.textContent = '-';
    drawerCompany.textContent = '-';
    drawerId.textContent = '-';
    drawerStatus.value = 'New';
    drawerNotes.value = '';
    saveButton.disabled = true;
    return;
  }

  drawerTitle.textContent = item.name;
  drawerMeta.textContent = `${formatDate(item.createdAt)} | ${item.email}`;
  drawerMessage.textContent = item.message;
  drawerContact.textContent = `${item.email} | ${item.phone || '-'}`;
  drawerService.textContent = item.serviceInterestedIn;
  drawerCompany.textContent = item.company || '-';
  drawerId.textContent = item.id;
  drawerStatus.value = item.status;
  drawerNotes.value = item.ownerNotes || '';
  saveButton.disabled = false;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDate(value) {
  const date = new Date(value);
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date);
}

async function fetchCurrentUser() {
  try {
    const response = await fetch('/api/user');
    if (!response.ok) return;
    const result = await response.json();
    if (result.clientPrincipal && currentUser) {
      currentUser.textContent = `${result.clientPrincipal.userDetails || 'Owner'} | ${result.clientPrincipal.identityProvider || 'Auth'}`;
    }
  } catch (error) {
    console.error(error);
  }
}

function currentFilters() {
  const params = new URLSearchParams();
  if (searchInput.value.trim()) params.set('search', searchInput.value.trim());
  if (statusFilter.value) params.set('status', statusFilter.value);
  if (serviceFilter.value) params.set('service', serviceFilter.value);
  return params.toString();
}

async function fetchCounts() {
  const response = await fetch('/api/query-counts');
  if (!response.ok) throw new Error('Unable to load dashboard counts.');
  state.counts = await response.json();
  renderCounts();
}

async function fetchQueries() {
  const query = currentFilters();
  const response = await fetch(`/api/get-queries${query ? `?${query}` : ''}`);
  if (!response.ok) throw new Error('Unable to load submitted queries.');
  state.items = await response.json();
  if (state.items.length && !state.items.some((item) => item.id === state.activeId)) {
    state.activeId = state.items[0].id;
  }
  if (!state.items.length) {
    state.activeId = null;
  }
  renderTable();
  renderDrawer();
}

async function refreshDashboard() {
  clearNotice();
  try {
    await Promise.all([fetchCounts(), fetchQueries(), fetchCurrentUser()]);
  } catch (error) {
    setNotice(error.message || 'Unable to refresh dashboard.');
  }
}

async function saveActiveQuery() {
  const item = state.items.find((entry) => entry.id === state.activeId);
  if (!item) return;

  saveButton.disabled = true;
  saveButton.textContent = 'Saving...';
  clearNotice();

  try {
    const response = await fetch('/api/update-query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        id: item.id,
        status: drawerStatus.value,
        ownerNotes: drawerNotes.value
      })
    });

    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || 'Unable to update query.');
    }

    setNotice('Query updated successfully.', 'success');
    await refreshDashboard();
  } catch (error) {
    setNotice(error.message || 'Unable to update query.');
  } finally {
    saveButton.disabled = false;
    saveButton.textContent = 'Save Changes';
  }
}

if (reloadButton) reloadButton.addEventListener('click', refreshDashboard);
if (saveButton) saveButton.addEventListener('click', saveActiveQuery);
if (searchInput) searchInput.addEventListener('input', () => window.clearTimeout(searchInput._timer));
if (searchInput) {
  searchInput.addEventListener('input', () => {
    window.clearTimeout(searchInput._timer);
    searchInput._timer = window.setTimeout(refreshDashboard, 250);
  });
}
if (statusFilter) statusFilter.addEventListener('change', refreshDashboard);
if (serviceFilter) serviceFilter.addEventListener('change', refreshDashboard);

refreshDashboard();
