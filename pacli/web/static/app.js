// App State
const app = {
    authenticated: false,
    secrets: [],
    filteredSecrets: [],
    currentFilter: 'all',
    currentSecret: null,
    isEditing: false,
};

// DOM Elements
const loginScreen = document.getElementById('login-screen');
const mainScreen = document.getElementById('main-screen');
const loginForm = document.getElementById('login-form');
const passwordInput = document.getElementById('password');
const loginError = document.getElementById('login-error');
const logoutBtn = document.getElementById('logout-btn');
const addSecretBtn = document.getElementById('add-secret-btn');
const secretsList = document.getElementById('secrets-list');
const secretModal = document.getElementById('secret-modal');
const viewModal = document.getElementById('view-modal');
const secretForm = document.getElementById('secret-form');
const secretLabel = document.getElementById('secret-label');
const secretType = document.getElementById('secret-type');
const secretValue = document.getElementById('secret-value');
const modalTitle = document.getElementById('modal-title');
const modalError = document.getElementById('modal-error');
const searchInput = document.getElementById('search-input');
const filterButtons = document.querySelectorAll('.filter-btn');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupEventListeners();
});

function setupEventListeners() {
    loginForm.addEventListener('submit', handleLogin);
    logoutBtn.addEventListener('click', handleLogout);
    addSecretBtn.addEventListener('click', openAddSecretModal);
    secretForm.addEventListener('submit', handleSaveSecret);
    searchInput.addEventListener('input', handleSearch);
    filterButtons.forEach(btn => {
        btn.addEventListener('click', handleFilter);
    });

    // Modal close buttons
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', closeModals);
    });
    document.querySelectorAll('.modal-close-btn').forEach(btn => {
        btn.addEventListener('click', closeModals);
    });

    // View modal buttons
    document.getElementById('edit-secret-btn').addEventListener('click', editSecret);
    document.getElementById('delete-secret-btn').addEventListener('click', deleteSecret);
    document.getElementById('copy-secret-btn').addEventListener('click', copySecret);
    document.getElementById('toggle-secret-btn').addEventListener('click', toggleSecretVisibility);

    // Close modals when clicking outside
    secretModal.addEventListener('click', (e) => {
        if (e.target === secretModal) closeModals();
    });
    viewModal.addEventListener('click', (e) => {
        if (e.target === viewModal) closeModals();
    });
}

async function checkAuth() {
    try {
        const response = await fetch('/api/auth/check', {
            credentials: 'include'
        });
        const data = await response.json();

        if (data.authenticated) {
            app.authenticated = true;
            showMainScreen();
            loadSecrets();
        } else {
            showLoginScreen();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        showLoginScreen();
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const password = passwordInput.value;

    if (!password) {
        showError(loginError, 'Password is required');
        return;
    }

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ password }),
        });

        if (response.ok) {
            app.authenticated = true;
            passwordInput.value = '';
            loginError.textContent = '';
            showMainScreen();
            loadSecrets();
        } else {
            const data = await response.json();
            showError(loginError, data.error || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        showError(loginError, 'Login failed. Please try again.');
    }
}

async function handleLogout() {
    try {
        await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include'
        });
        app.authenticated = false;
        app.secrets = [];
        showLoginScreen();
        passwordInput.value = '';
    } catch (error) {
        console.error('Logout error:', error);
    }
}

function showLoginScreen() {
    loginScreen.classList.add('active');
    mainScreen.classList.remove('active');
}

function showMainScreen() {
    loginScreen.classList.remove('active');
    mainScreen.classList.add('active');
}

async function loadSecrets() {
    try {
        secretsList.innerHTML = '<div class="loading">Loading secrets...</div>';
        const response = await fetch('/api/secrets', {
            credentials: 'include'
        });

        if (response.status === 401) {
            showLoginScreen();
            return;
        }

        const data = await response.json();
        app.secrets = data.secrets || [];
        app.filteredSecrets = [...app.secrets];
        renderSecrets();
    } catch (error) {
        console.error('Load secrets error:', error);
        secretsList.innerHTML = '<div class="error-message show">Failed to load secrets</div>';
    }
}

function renderSecrets() {
    if (app.filteredSecrets.length === 0) {
        secretsList.innerHTML = `
            <div class="empty-state">
                <h3>No secrets found</h3>
                <p>Click "Add Secret" to create your first secret</p>
            </div>
        `;
        return;
    }

    secretsList.innerHTML = app.filteredSecrets.map(secret => `
        <div class="secret-card" onclick="viewSecret('${secret.id}')">
            <div class="secret-card-header">
                <div class="secret-card-label">${escapeHtml(secret.label)}</div>
                <span class="secret-card-type ${secret.type}">${secret.type}</span>
            </div>
            <div class="secret-card-meta">
                <div>Created: ${secret.creation_date}</div>
                <div>Updated: ${secret.update_date}</div>
            </div>
        </div>
    `).join('');
}

function openAddSecretModal() {
    app.isEditing = false;
    app.currentSecret = null;
    modalTitle.textContent = 'Add Secret';
    secretLabel.value = '';
    secretType.value = 'password';
    secretValue.value = '';
    modalError.textContent = '';
    secretModal.classList.add('active');
    secretLabel.focus();
}

async function handleSaveSecret(e) {
    e.preventDefault();
    const label = secretLabel.value.trim();
    const type = secretType.value;
    const secret = secretValue.value;

    if (!label || !secret) {
        showError(modalError, 'Label and secret are required');
        return;
    }

    try {
        const method = app.isEditing ? 'PUT' : 'POST';
        const url = app.isEditing ? `/api/secrets/${app.currentSecret.id}` : '/api/secrets';
        const body = app.isEditing
            ? { secret }
            : { label, type, secret };

        const response = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(body),
        });

        if (response.ok) {
            closeModals();
            loadSecrets();
        } else {
            const data = await response.json();
            showError(modalError, data.error || 'Failed to save secret');
        }
    } catch (error) {
        console.error('Save secret error:', error);
        showError(modalError, 'Failed to save secret');
    }
}

async function viewSecret(secretId) {
    try {
        const response = await fetch(`/api/secrets/${secretId}`, {
            credentials: 'include'
        });

        if (response.ok) {
            const secret = await response.json();
            app.currentSecret = secret;

            document.getElementById('view-label').textContent = escapeHtml(secret.label);
            document.getElementById('view-type').textContent = secret.type;
            document.getElementById('view-secret').textContent = secret.secret;
            document.getElementById('view-secret').classList.remove('hidden');
            document.getElementById('toggle-secret-btn').textContent = 'Hide';
            document.getElementById('view-created').textContent = new Date(secret.creation_time * 1000).toLocaleString();
            document.getElementById('view-updated').textContent = new Date(secret.update_time * 1000).toLocaleString();

            viewModal.classList.add('active');
        }
    } catch (error) {
        console.error('View secret error:', error);
    }
}

function editSecret() {
    if (!app.currentSecret) return;

    app.isEditing = true;
    closeModals();

    modalTitle.textContent = 'Edit Secret';
    secretLabel.value = app.currentSecret.label;
    secretLabel.disabled = true;
    secretType.value = app.currentSecret.type;
    secretType.disabled = true;
    secretValue.value = app.currentSecret.secret;
    modalError.textContent = '';
    secretModal.classList.add('active');
    secretValue.focus();
}

async function deleteSecret() {
    if (!app.currentSecret) return;

    if (!confirm(`Are you sure you want to delete "${app.currentSecret.label}"?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/secrets/${app.currentSecret.id}`, {
            method: 'DELETE',
            credentials: 'include',
        });

        if (response.ok) {
            closeModals();
            loadSecrets();
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to delete secret');
        }
    } catch (error) {
        console.error('Delete secret error:', error);
        alert('Failed to delete secret');
    }
}

function copySecret() {
    const secretElement = document.getElementById('view-secret');
    const text = secretElement.textContent;

    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copy-secret-btn');
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => {
            btn.textContent = originalText;
        }, 2000);
    }).catch(err => {
        console.error('Copy failed:', err);
        alert('Failed to copy to clipboard');
    });
}

function toggleSecretVisibility() {
    const secretElement = document.getElementById('view-secret');
    const btn = document.getElementById('toggle-secret-btn');

    secretElement.classList.toggle('hidden');
    btn.textContent = secretElement.classList.contains('hidden') ? 'Show' : 'Hide';
}

function handleSearch(e) {
    const query = e.target.value.toLowerCase();

    if (query === '') {
        app.filteredSecrets = app.secrets.filter(s => {
            if (app.currentFilter === 'all') return true;
            return s.type === app.currentFilter;
        });
    } else {
        app.filteredSecrets = app.secrets.filter(s => {
            const matchesQuery = s.label.toLowerCase().includes(query);
            const matchesFilter = app.currentFilter === 'all' || s.type === app.currentFilter;
            return matchesQuery && matchesFilter;
        });
    }

    renderSecrets();
}

function handleFilter(e) {
    filterButtons.forEach(btn => btn.classList.remove('active'));
    e.target.classList.add('active');

    app.currentFilter = e.target.dataset.filter;
    const query = searchInput.value.toLowerCase();

    if (query === '') {
        app.filteredSecrets = app.secrets.filter(s => {
            if (app.currentFilter === 'all') return true;
            return s.type === app.currentFilter;
        });
    } else {
        app.filteredSecrets = app.secrets.filter(s => {
            const matchesQuery = s.label.toLowerCase().includes(query);
            const matchesFilter = app.currentFilter === 'all' || s.type === app.currentFilter;
            return matchesQuery && matchesFilter;
        });
    }

    renderSecrets();
}

function closeModals() {
    secretModal.classList.remove('active');
    viewModal.classList.remove('active');
    secretLabel.disabled = false;
    secretType.disabled = false;
    app.isEditing = false;
}

function showError(element, message) {
    element.textContent = message;
    element.classList.add('show');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
