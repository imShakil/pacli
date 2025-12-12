// App State
const app = {
    authenticated: false,
    secrets: [],
    filteredSecrets: [],
    currentFilter: 'all',
    currentSecret: null,
    isEditing: false,
    sshConnection: null,
    socket: null,
    secretVisibilityTimeout: null,
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
const sshModal = document.getElementById('ssh-modal');
const secretForm = document.getElementById('secret-form');
const secretLabel = document.getElementById('secret-label');
const secretType = document.getElementById('secret-type');
const secretValue = document.getElementById('secret-value');
const modalTitle = document.getElementById('modal-title');
const modalError = document.getElementById('modal-error');
const searchInput = document.getElementById('search-input');
const filterButtons = document.querySelectorAll('.filter-btn');

// SSH Elements
const sshTerminalBtn = document.getElementById('ssh-terminal-btn');
const sshAuthType = document.getElementById('ssh-auth-type');
const sshPasswordGroup = document.getElementById('ssh-password-group');
const sshKeyGroup = document.getElementById('ssh-key-group');
const sshConnectBtn = document.getElementById('ssh-connect-btn');
const sshDisconnectBtn = document.getElementById('ssh-disconnect-btn');
const sshCommandInput = document.getElementById('ssh-command-input');
const sshOutput = document.getElementById('ssh-output');
const sshConnectionForm = document.getElementById('ssh-connection-form');
const sshTerminal = document.getElementById('ssh-terminal');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupEventListeners();
    initializeSocket();
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

    // SSH Terminal listeners
    sshTerminalBtn.addEventListener('click', openSSHModal);
    sshAuthType.addEventListener('change', handleAuthTypeChange);
    sshConnectBtn.addEventListener('click', handleSSHConnect);
    sshDisconnectBtn.addEventListener('click', handleSSHDisconnect);
    sshCommandInput.addEventListener('keypress', handleSSHCommandKeypress);

    // SSH Tab switching
    document.querySelectorAll('.ssh-tab-btn').forEach(btn => {
        btn.addEventListener('click', handleSSHTabSwitch);
    });

    // Stored SSH server connection
    const storedConnectBtn = document.getElementById('ssh-stored-connect-btn');
    if (storedConnectBtn) {
        storedConnectBtn.addEventListener('click', handleStoredSSHConnect);
    }

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
    document.getElementById('toggle-secret-btn').addEventListener('click', toggleSecretVisibility);
    document.getElementById('copy-secret-btn').addEventListener('click', copySecretToClipboard);

    // Close modals when clicking outside
    secretModal.addEventListener('click', (e) => {
        if (e.target === secretModal) closeModals();
    });
    viewModal.addEventListener('click', (e) => {
        if (e.target === viewModal) closeModals();
    });
    sshModal.addEventListener('click', (e) => {
        if (e.target === sshModal) closeModals();
    });
}

function initializeSocket() {
    app.socket = io();

    app.socket.on('connect', () => {
        console.log('Connected to WebSocket server');
    });

    app.socket.on('ssh_connected', (data) => {
        app.sshConnection = data.connection_id;
        showSSHTerminal();
        appendSSHOutput(`Connected to ${data.message}\n`);
        sshCommandInput.disabled = false;
        sshCommandInput.focus();
    });

    app.socket.on('ssh_output', (data) => {
        if (data.output) {
            appendSSHOutput(data.output);
        }
    });

    app.socket.on('ssh_disconnected', (data) => {
        appendSSHOutput(`\nDisconnected: ${data.message}\n`);
        hideSSHTerminal();
        app.sshConnection = null;
    });

    app.socket.on('error', (data) => {
        console.error('WebSocket error:', data);
        showSSHError(data.message || 'An error occurred');
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
        populateSSHKeySelect();
        populateStoredSSHServers();
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
            // Store the placeholder, actual secret will be fetched on demand
            document.getElementById('view-secret').textContent = secret.secret;
            document.getElementById('view-secret').classList.add('hidden');
            document.getElementById('toggle-secret-btn').textContent = 'Show';
            document.getElementById('copy-secret-btn').style.display = 'none';
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

async function toggleSecretVisibility() {
    const secretElement = document.getElementById('view-secret');
    const btn = document.getElementById('toggle-secret-btn');
    const copyBtn = document.getElementById('copy-secret-btn');

    // If hidden, fetch and show the actual secret
    if (secretElement.classList.contains('hidden')) {
        try {
            // Fetch the actual secret from the backend
            const response = await fetch(`/api/secrets/${app.currentSecret.id}/reveal`, {
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                // Replace placeholder with actual secret
                secretElement.textContent = data.secret;
                secretElement.classList.remove('hidden');
                btn.textContent = 'Hide';
                copyBtn.style.display = 'inline-block';

                // Set auto-hide timeout (30 seconds)
                clearTimeout(app.secretVisibilityTimeout);
                app.secretVisibilityTimeout = setTimeout(() => {
                    // Replace actual secret back with placeholder
                    secretElement.textContent = '•••••••';
                    secretElement.classList.add('hidden');
                    btn.textContent = 'Show';
                    copyBtn.style.display = 'none';
                }, 30000);
            } else {
                console.error('Failed to reveal secret');
                alert('Failed to reveal secret');
            }
        } catch (error) {
            console.error('Reveal secret error:', error);
            alert('Failed to reveal secret');
        }
    } else {
        // If visible, hide immediately and replace with placeholder
        secretElement.textContent = '•••••••';
        secretElement.classList.add('hidden');
        btn.textContent = 'Show';
        copyBtn.style.display = 'none';
        clearTimeout(app.secretVisibilityTimeout);
    }
}

function copySecretToClipboard() {
    const secretElement = document.getElementById('view-secret');
    const text = secretElement.textContent;

    navigator.clipboard.writeText(text).then(() => {
        // Show feedback
        const copyBtn = document.getElementById('copy-secret-btn');
        const originalText = copyBtn.textContent;
        copyBtn.textContent = '✓ Copied!';
        setTimeout(() => {
            copyBtn.textContent = originalText;
        }, 2000);
    }).catch(err => {
        console.error('Copy failed:', err);
        alert('Failed to copy secret');
    });
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

// SSH Terminal Functions
function openSSHModal() {
    sshModal.classList.add('active');
    document.getElementById('ssh-hostname').focus();
}

function handleSSHTabSwitch(e) {
    const tabName = e.target.dataset.tab;

    // Don't allow tab switching if there's an active connection
    if (app.sshConnection) {
        alert('Please disconnect before switching tabs');
        return;
    }

    // Update active tab button
    document.querySelectorAll('.ssh-tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    e.target.classList.add('active');

    // Update active tab content
    document.querySelectorAll('.ssh-tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.querySelector(`.ssh-tab-content[data-tab="${tabName}"]`).classList.add('active');
}

function handleAuthTypeChange(e) {
    if (e.target.value === 'password') {
        sshPasswordGroup.style.display = 'flex';
        sshKeyGroup.style.display = 'none';
    } else {
        sshPasswordGroup.style.display = 'none';
        sshKeyGroup.style.display = 'flex';
    }
}

function populateSSHKeySelect() {
    const sshKeySelect = document.getElementById('ssh-key-select');
    if (!sshKeySelect) return; // Element doesn't exist, skip

    const sshKeys = app.secrets.filter(s => s.type === 'ssh');

    sshKeySelect.innerHTML = '<option value="">Select SSH key from secrets...</option>';
    sshKeys.forEach(key => {
        const option = document.createElement('option');
        option.value = key.id;
        option.textContent = key.label;
        sshKeySelect.appendChild(option);
    });
}

function populateStoredSSHServers() {
    const storedSelect = document.getElementById('ssh-stored-select');
    if (!storedSelect) return;

    // Only show SSH secrets that have the stored server format (user:host|...)
    // Plain SSH keys should be used in the manual connection tab
    const sshServers = app.secrets.filter(s => s.type === 'ssh');

    storedSelect.innerHTML = '<option value="">Select a stored SSH server...</option>';
    sshServers.forEach(server => {
        const option = document.createElement('option');
        option.value = server.id;
        option.textContent = server.label;
        storedSelect.appendChild(option);
    });
}

async function handleSSHConnect() {
    const hostname = document.getElementById('ssh-hostname').value.trim();
    const username = document.getElementById('ssh-username').value.trim();
    const port = parseInt(document.getElementById('ssh-port').value) || 22;
    const authType = sshAuthType.value;
    const errorDiv = document.getElementById('ssh-form-error');

    if (!hostname || !username) {
        showError(errorDiv, 'Hostname and username are required');
        return;
    }

    const connectionData = {
        hostname,
        username,
        port,
    };

    if (authType === 'password') {
        const password = document.getElementById('ssh-password').value;
        if (!password) {
            showError(errorDiv, 'Password is required');
            return;
        }
        connectionData.password = password;
    } else {
        // Check if a key is selected from secrets first
        const sshKeySelect = document.getElementById('ssh-key-select');
        const selectedKeyId = sshKeySelect ? sshKeySelect.value : '';

        if (selectedKeyId) {
            // Use the selected key from secrets - fetch its content
            try {
                const response = await fetch(`/api/secrets/${selectedKeyId}/reveal`, {
                    credentials: 'include'
                });
                if (response.ok) {
                    const data = await response.json();
                    connectionData.ssh_key = data.secret;
                } else {
                    showError(errorDiv, 'Failed to retrieve SSH key from secrets');
                    return;
                }
            } catch (error) {
                console.error('Error fetching SSH key:', error);
                showError(errorDiv, 'Failed to retrieve SSH key');
                return;
            }
        } else {
            // Fall back to pasted key
            const keyInput = document.getElementById('ssh-key-input').value.trim();
            if (!keyInput) {
                showError(errorDiv, 'SSH private key is required');
                return;
            }
            connectionData.ssh_key = keyInput;
        }
    }

    // Clear any previous errors
    errorDiv.textContent = '';
    errorDiv.classList.remove('show');

    // Use WebSocket for real-time terminal
    if (app.socket && app.socket.connected) {
        app.socket.emit('ssh_connect', connectionData);
    } else {
        // Fallback to REST API
        try {
            const response = await fetch('/api/ssh/connect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(connectionData),
            });

            if (response.ok) {
                const data = await response.json();
                app.sshConnection = data.connection_id;
                showSSHTerminal();
                appendSSHOutput(`Connected to ${hostname}\n`);
                sshCommandInput.disabled = false;
                sshCommandInput.focus();
            } else {
                const data = await response.json();
                showError(errorDiv, data.error || 'Failed to connect');
            }
        } catch (error) {
            console.error('SSH connect error:', error);
            showError(errorDiv, 'Failed to connect to SSH server');
        }
    }
}

async function handleStoredSSHConnect() {
    const serverId = document.getElementById('ssh-stored-select').value;
    const errorDiv = document.getElementById('ssh-stored-form-error');

    if (!serverId) {
        showError(errorDiv, 'Please select an SSH server');
        return;
    }

    // Find the selected server in secrets
    const server = app.secrets.find(s => s.id === serverId);
    if (!server) {
        showError(errorDiv, 'Server not found');
        return;
    }

    // Clear any previous errors
    errorDiv.textContent = '';
    errorDiv.classList.remove('show');

    // For stored SSH servers, we need to parse the SSH key content
    // The secret contains the SSH key, and we need to extract connection details
    // For now, we'll use the key_id and let the backend handle it
    const connectionData = {
        key_id: serverId
    };

    // Use WebSocket for real-time terminal
    if (app.socket && app.socket.connected) {
        app.socket.emit('ssh_connect', connectionData);
    } else {
        // Fallback to REST API
        try {
            const response = await fetch('/api/ssh/connect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(connectionData),
            });

            if (response.ok) {
                const data = await response.json();
                app.sshConnection = data.connection_id;
                showSSHTerminal();
                appendSSHOutput(`Connected to ${server.label}\n`);
                sshCommandInput.disabled = false;
                sshCommandInput.focus();
            } else {
                const data = await response.json();
                showError(errorDiv, data.error || 'Failed to connect');
            }
        } catch (error) {
            console.error('SSH connect error:', error);
            showError(errorDiv, 'Failed to connect to SSH server');
        }
    }
}

function handleSSHDisconnect() {
    if (app.sshConnection) {
        const connectionId = app.sshConnection;
        if (app.socket && app.socket.connected) {
            app.socket.emit('ssh_disconnect', { connection_id: connectionId });
        } else {
            // Fallback to REST API
            fetch(`/api/ssh/disconnect/${connectionId}`, {
                method: 'POST',
                credentials: 'include',
            }).catch(err => console.error('Disconnect error:', err));
        }
        app.sshConnection = null;
        hideSSHTerminal();
    }
}

function handleSSHCommandKeypress(e) {
    if (e.key === 'Enter') {
        const command = sshCommandInput.value;
        if (command.trim()) {
            appendSSHOutput(`$ ${command}\n`);

            if (app.socket && app.socket.connected) {
                app.socket.emit('ssh_command', {
                    connection_id: app.sshConnection,
                    command: command
                });
            } else {
                // Fallback to REST API
                fetch('/api/ssh/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({
                        connection_id: app.sshConnection,
                        command: command
                    }),
                }).then(res => res.json())
                  .then(data => {
                      if (data.output) {
                          appendSSHOutput(data.output);
                      }
                  })
                  .catch(err => console.error('Command error:', err));
            }

            sshCommandInput.value = '';
        }
    }
}

function showSSHTerminal() {
    // Hide all tab contents and buttons
    document.querySelectorAll('.ssh-tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.querySelectorAll('.ssh-tab-btn').forEach(btn => {
        btn.disabled = true;
        btn.style.opacity = '0.5';
        btn.style.cursor = 'not-allowed';
    });
    // Hide tabs container
    document.querySelector('.ssh-tabs').style.display = 'none';
    // Show terminal
    sshTerminal.style.display = 'flex';
}

function hideSSHTerminal() {
    // Hide terminal
    sshTerminal.style.display = 'none';
    sshOutput.innerHTML = '';
    sshCommandInput.disabled = true;
    sshCommandInput.value = '';

    // Re-enable tabs and show them
    document.querySelector('.ssh-tabs').style.display = 'flex';
    document.querySelectorAll('.ssh-tab-btn').forEach(btn => {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
    });

    // Show the currently active tab's form by ensuring it has the active class
    const activeTab = document.querySelector('.ssh-tab-btn.active');
    if (activeTab) {
        const tabName = activeTab.dataset.tab;
        const activeContent = document.querySelector(`.ssh-tab-content[data-tab="${tabName}"]`);
        if (activeContent) {
            // Remove active class from all tab contents
            document.querySelectorAll('.ssh-tab-content').forEach(content => {
                content.classList.remove('active');
            });
            // Add active class to the current tab
            activeContent.classList.add('active');
        }
    }
}

function appendSSHOutput(text) {
    sshOutput.textContent += text;
    sshOutput.scrollTop = sshOutput.scrollHeight;
}

function showSSHError(message) {
    // Try to show error in the currently visible form
    const manualErrorDiv = document.getElementById('ssh-form-error');
    const storedErrorDiv = document.getElementById('ssh-stored-form-error');

    // Check which tab is currently active
    const activeTab = document.querySelector('.ssh-tab-btn.active');
    if (activeTab && activeTab.dataset.tab === 'stored') {
        showError(storedErrorDiv, message);
    } else {
        showError(manualErrorDiv, message);
    }
}

function closeModals() {
    secretModal.classList.remove('active');
    viewModal.classList.remove('active');
    sshModal.classList.remove('active');
    secretLabel.disabled = false;
    secretType.disabled = false;
    app.isEditing = false;
    clearTimeout(app.secretVisibilityTimeout);
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
