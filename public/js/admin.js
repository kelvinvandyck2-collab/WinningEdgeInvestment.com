
// Admin Dashboard JavaScript

// DOM Elements
const sidebarLinks = document.querySelectorAll('.sidebar-menu a');
const pageTitle = document.getElementById('page-title');
const pageContent = document.getElementById('page-content');
const userDropdownBtn = document.getElementById('user-dropdown-btn');
const userDropdownMenu = document.getElementById('user-dropdown-menu');
const userAvatar = document.getElementById('user-avatar');

// State
let currentUser = null;

// Initialize the dashboard
document.addEventListener('DOMContentLoaded', async () => {
    // Check authentication
    await checkAuth();
    
    // Load dashboard content by default
    loadSection('dashboard');
    
    // Set up event listeners
    setupEventListeners();
});

// Check if user is authenticated
async function checkAuth() {
    try {        
        const response = await fetchAdminAPI('/api/admin/check-auth');
        const data = await response.json();
        currentUser = data.user;
        updateUserInfo();
    } catch (error) {
        // The fetchAdminAPI helper will handle redirection for auth errors.
        // We only need to log other types of errors.
        if (error.message !== 'Session expired') {
            console.error('Auth check failed:', error);
            window.location.href = '/admin-login.html';
        }
    }
}

// Helper function for authenticated API calls
async function fetchAdminAPI(url, options = {}) {
    const defaultOptions = {
        credentials: 'same-origin',
        ...options,
    };

    const response = await fetch(url, defaultOptions);

    if (response.status === 401) {
        showAlert('Your session has expired. Please log in again.', 'warning');
        setTimeout(() => { window.location.href = '/admin-login.html'; }, 2000);
        throw new Error('Session expired');
    }

    return response;
}

// Update user information in the UI
function updateUserInfo() {
    if (!currentUser) return;
    
    // Update avatar with user initials
    const nameParts = currentUser.name.split(' ');
    const initials = nameParts.length > 1 
        ? `${nameParts[0][0]}${nameParts[1][0]}`
        : nameParts[0][0];
    
    userAvatar.textContent = initials.toUpperCase();
}

// Set up event listeners
function setupEventListeners() {
    // Sidebar navigation
    sidebarLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = link.getAttribute('data-section');
            
            // Update active state
            sidebarLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            
            // Load section content
            loadSection(section);
        });
    });
    
    // User dropdown toggle
    userDropdownBtn.addEventListener('click', () => {
        userDropdownMenu.classList.toggle('show');
    });
    
    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (!userDropdownBtn.contains(e.target) && !userDropdownMenu.contains(e.target)) {
            userDropdownMenu.classList.remove('show');
        }
    });
}

// Load section content
async function loadSection(section, ...args) {
    try {
        // Show loading state
        pageContent.innerHTML = `
            <div class="d-flex justify-content-center align-items-center" style="min-height: 300px;">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        `;
        
        // Update page title
        const sectionTitle = section.charAt(0).toUpperCase() + section.slice(1);
        pageTitle.textContent = sectionTitle;
        
        // Load section content
        let content = '';
        
        switch (section) {
            case 'dashboard':
                content = await loadDashboard();
                break;
            case 'users':
                content = await loadUsers(...(args.length > 0 ? args : [1, '', '']));
                break;
            case 'investments':
                content = await loadInvestments(1, '', '');
                break;
            case 'transactions':
                content = await loadTransactions();
                break;
            case 'withdrawals':
                content = await loadWithdrawals();
                break;
            case 'deposits':
                content = await loadDeposits();
                break;
            case 'support':
                content = await loadSupport();
                break;
            case 'settings':
                content = await loadSettings();
                break;
            case 'signup-tokens':
                content = await loadSignupTokens();
                break;
            default:
                content = '<p>Section not found</p>';
        }
        
        pageContent.innerHTML = content;
        
        // Initialize any section-specific scripts
        initializeSection(section);
        
    } catch (error) {
        console.error(`Error loading ${section}:`, error);
        pageContent.innerHTML = `
            <div class="alert alert-danger">
                Failed to load ${section}. Please try again later.
            </div>
        `;
    }
}

// Load dashboard content
async function loadDashboard() {
    try {
        const [statsRes, recentUsersRes, recentTransactionsRes] = await Promise.all([
            fetchAdminAPI('/api/admin/stats'),
            fetchAdminAPI('/api/admin/users?limit=5'),
            fetchAdminAPI('/api/admin/transactions?limit=5')
        ]);
        
        if (!statsRes.ok || !recentUsersRes.ok || !recentTransactionsRes.ok) {
            throw new Error('Failed to fetch dashboard data');
        }
        
        const stats = await statsRes.json();
        const recentUsers = await recentUsersRes.json();
        const recentTransactions = await recentTransactionsRes.json();
        
        return `
            <div class="container-fluid">
                <!-- Stats Cards -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title mb-4">Overview</h5>
                                <div class="row g-4">
                                    <!-- Total Users -->
                                    <div class="col-md-6 col-lg-3">
                                        <div class="stat-card p-3 bg-light rounded">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <div>
                                                    <h6 class="text-muted mb-1">Total Users</h6>
                                                    <h3 class="mb-0">${stats.users.total || 0}</h3>
                                                </div>
                                                <div class="stat-icon bg-primary">
                                                    <i class='bx bx-user'></i>
                                                </div>
                                            </div>
                                            <div class="mt-2">
                                                <span class="text-success">
                                                    <i class='bx bx-up-arrow-alt'></i> 
                                                    ${stats.users.active_users || 0} active
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <!-- Total Investments -->
                                    <div class="col-md-6 col-lg-3">
                                        <div class="stat-card p-3 bg-light rounded">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <div>
                                                    <h6 class="text-muted mb-1">Total Investments</h6>
                                                    <h3 class="mb-0">${stats.investments.total || 0}</h3>
                                                </div>
                                                <div class="stat-icon bg-success">
                                                    <i class='bx bx-line-chart'></i>
                                                </div>
                                            </div>
                                            <div class="mt-2">
                                                <span class="text-success">
                                                    <i class='bx bx-up-arrow-alt'></i> 
                                                    $${(stats.investments.total_invested || 0).toLocaleString()}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <!-- Total Transactions -->
                                    <div class="col-md-6 col-lg-3">
                                        <div class="stat-card p-3 bg-light rounded">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <div>
                                                    <h6 class="text-muted mb-1">Total Transactions</h6>
                                                    <h3 class="mb-0">${stats.transactions.total || 0}</h3>
                                                </div>
                                                <div class="stat-icon bg-warning">
                                                    <i class='bx bx-transfer'></i>
                                                </div>
                                            </div>
                                            <div class="mt-2">
                                                <span class="text-success">
                                                    <i class='bx bx-up-arrow-alt'></i> 
                                                    $${(stats.transactions.total_volume || 0).toLocaleString()}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <!-- Pending Withdrawals -->
                                    <div class="col-md-6 col-lg-3">
                                        <div class="stat-card p-3 bg-light rounded">
                                            <div class="d-flex justify-content-between align-items-center">
                                                <div>
                                                    <h6 class="text-muted mb-1">Pending Withdrawals</h6>
                                                    <h3 class="mb-0">${stats.withdrawals.pending || 0}</h3>
                                                </div>
                                                <div class="stat-icon bg-danger">
                                                    <i class='bx bx-wallet'></i>
                                                </div>
                                            </div>
                                            <div class="mt-2">
                                                <a href="#" class="text-primary" data-section="withdrawals">View all</a>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <!-- Recent Users -->
                    <div class="col-lg-6 mb-4">
                        <div class="card h-100">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0">Recent Users</h5>
                                <a href="#" class="btn btn-sm btn-outline-primary" data-section="users">View All</a>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-hover mb-0">
                                        <thead class="bg-light">
                                            <tr>
                                                <th>Name</th>
                                                <th>Email</th>
                                                <th>Joined</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${recentUsers.users.map(user => `
                                                <tr>
                                                    <td>${escapeHtml(user.name)}</td>
                                                    <td>${escapeHtml(user.email)}</td>
                                                    <td>${new Date(user.created_at).toLocaleDateString()}</td>
                                                    <td><span class="badge bg-success">Active</span>
                                                    </td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Recent Transactions -->
                    <div class="col-lg-6 mb-4">
                        <div class="card h-100">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0">Recent Transactions</h5>
                                <a href="#" class="btn btn-sm btn-outline-primary" data-section="transactions">View All</a>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-hover mb-0">
                                        <thead class="bg-light">
                                            <tr>
                                                <th>ID</th>
                                                <th>Type</th>
                                                <th>Amount</th>
                                                <th>Status</th>
                                                <th>Date</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${recentTransactions.transactions.map(tx => `
                                                <tr>
                                                    <td>#${tx.id}</td>
                                                    <td>${tx.type}</td>
                                                    <td>$${parseFloat(tx.amount).toFixed(2)}</td>
                                                    <td>
                                                        <span class="badge bg-${getStatusBadgeClass(tx.status)}">
                                                            ${tx.status}
                                                        </span>
                                                    </td>
                                                    <td>${new Date(tx.created_at).toLocaleDateString()}</td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading dashboard:', error);
        return `
            <div class="alert alert-danger">
                Failed to load dashboard data. Please try again later.
            </div>
        `;
    }
}

// Load users content
async function loadUsers(page = 1, search = '', status = '') {
    try {
        const url = new URL('/api/admin/users', window.location.origin);
        url.searchParams.set('page', page);
        if (search) url.searchParams.set('search', search);
        if (status) url.searchParams.set('status', status);

        const response = await fetchAdminAPI(url);
        if (!response.ok) throw new Error('Failed to fetch users');
        
        const data = await response.json();
        
        return `
            <div class="container-fluid">
                <div class="card">
                    <div class="card-header">
                        <div class="d-flex flex-wrap justify-content-between align-items-center">
                            <h5 class="card-title mb-2 mb-md-0">Manage Users</h5>
                            <div class="d-flex flex-wrap gap-2">
                                <input type="search" id="user-search-input" class="form-control form-control-sm" style="width: 200px;" placeholder="Search name, email..." value="${escapeHtml(search)}">
                                <select id="user-status-filter" class="form-select form-select-sm" style="width: 150px;">
                                    <option value="">All Statuses</option>
                                    <option value="active" ${status === 'active' ? 'selected' : ''}>Active</option>
                                    <option value="inactive" ${status === 'inactive' ? 'selected' : ''}>Inactive</option>
                                    <option value="suspended" ${status === 'suspended' ? 'selected' : ''}>Suspended</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="users-table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Name</th>
                                        <th>Email</th>
                                        <th>Status</th>
                                        <th>Joined</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.users.map(user => `
                                        <tr>
                                            <td>${user.id}</td>
                                            <td>
                                                <div class="d-flex align-items-center">
                                                    <div class="avatar me-2">
                                                        ${getUserInitials(user.name)}
                                                    </div>
                                                    <div>
                                                        <h6 class="mb-0">${escapeHtml(user.name)}</h6>
                                                        <small class="text-muted">${user.username || 'N/A'}</small>
                                                    </div>
                                                </div>
                                            </td>
                                            <td>${escapeHtml(user.email)}</td>
                                            <td>
                                                <span class="badge bg-${getStatusBadgeClass(user.status)}">${user.status || 'active'}</span>
                                            </td>
                                            <td>${new Date(user.created_at).toLocaleDateString()}</td>
                                            <td>
                                                <div class="btn-group">
                                                    <button class="btn btn-sm btn-outline-primary view-user" data-id="${user.id}">
                                                        <i class='bx bx-show'></i>
                                                    </button>
                                                    <button class="btn btn-sm btn-outline-secondary edit-user" data-id="${user.id}">
                                                        <i class='bx bx-edit'></i>
                                                    </button>
                                                    <button class="btn btn-sm btn-outline-danger delete-user" data-id="${user.id}">
                                                        <i class='bx bx-trash'></i>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                        
                        <!-- Pagination -->
                        ${generatePagination(data.pagination)}
                    </div>
                </div>
            </div>
            
            <!-- User Details Modal -->
            <div class="modal fade" id="userModal" tabindex="-1" aria-hidden="true">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="userModalLabel">User Details</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body" id="userModalBody">
                            Loading user details...
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="button" class="btn btn-primary" id="save-user-details-btn">Save changes</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading users:', error);
        return `
            <div class="alert alert-danger">
                Failed to load users. Please try again later.
            </div>
        `;
    }
}

// Load investments content
async function loadInvestments(page = 1, search = '', status = '') {
    try {
        const url = new URL('/api/admin/investments', window.location.origin);
        url.searchParams.set('page', page);
        if (search) url.searchParams.set('search', search);
        if (status) url.searchParams.set('status', status);

        const response = await fetchAdminAPI(url);
        if (!response.ok) throw new Error('Failed to fetch investments');
        const data = await response.json();

        return `
            <div class="card">
                <div class="card-header">
                    <div class="d-flex flex-wrap justify-content-between align-items-center">
                        <h5 class="card-title mb-2 mb-md-0">All Investments</h5>
                        <div class="d-flex flex-wrap gap-2">
                            <input type="search" id="investment-search-input" class="form-control form-control-sm" style="width: 200px;" placeholder="Search user or plan..." value="${escapeHtml(search)}">
                            <select id="investment-status-filter" class="form-select form-select-sm" style="width: 150px;">
                                <option value="">All Statuses</option>
                                <option value="active" ${status === 'active' ? 'selected' : ''}>Active</option>
                                <option value="completed" ${status === 'completed' ? 'selected' : ''}>Completed</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead><tr><th>ID</th><th>User</th><th>Plan</th><th>Amount</th><th>Status</th><th>Start Date</th><th>End Date</th></tr></thead>
                            <tbody>
                                ${data.investments.map(inv => `
                                    <tr>
                                        <td>${inv.id}</td>
                                        <td>${escapeHtml(inv.user_name)} (ID: ${inv.user_id})</td>
                                        <td>${escapeHtml(inv.package_name)}</td>
                                        <td>$${parseFloat(inv.amount).toFixed(2)}</td>
                                        <td><span class="badge bg-${getStatusBadgeClass(inv.status)}">${inv.status}</span></td>
                                        <td>${new Date(inv.start_date).toLocaleDateString()}</td>
                                        <td>${new Date(inv.end_date).toLocaleDateString()}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                        ${generatePagination(data.pagination)}
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading investments:', error);
        return `<div class="alert alert-danger">Failed to load investments.</div>`;
    }
}

// Load transactions content
async function loadTransactions() {
    try {
        // This API endpoint needs to be created in server.js
        const response = await fetchAdminAPI('/api/admin/all-transactions');
        if (!response.ok) throw new Error('Failed to fetch transactions');
        const data = await response.json();

        return `
            <div class="card">
                <div class="card-header"><h5 class="card-title mb-0">All Transactions</h5></div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead><tr><th>ID</th><th>User</th><th>Type</th><th>Amount</th><th>Method</th><th>Status</th><th>Date</th></tr></thead>
                            <tbody>
                                ${data.transactions.map(tx => `
                                    <tr>
                                        <td>#${tx.id}</td>
                                        <td>${escapeHtml(tx.full_name)} (ID: ${tx.user_id})</td>
                                        <td>${tx.type}</td>
                                        <td>$${parseFloat(tx.amount).toFixed(2)}</td>
                                        <td>${escapeHtml(tx.method.toUpperCase())}</td>
                                        <td><span class="badge bg-${getStatusBadgeClass(tx.status)}">${tx.status}</span></td>
                                        <td>${new Date(tx.request_date).toLocaleString()}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading transactions:', error);
        return `<div class="alert alert-danger">Failed to load transactions.</div>`;
    }
}

// Load withdrawals content
async function loadWithdrawals(page = 1, search = '', status = '') {
    try {
        const url = new URL('/api/admin/withdrawals', window.location.origin);
        url.searchParams.set('page', page);
        if (search) url.searchParams.set('search', search);
        if (status) url.searchParams.set('status', status);

        const response = await fetchAdminAPI(url);
        if (!response.ok) throw new Error('Failed to fetch withdrawals');
        const data = await response.json();

        return `
            <div class="card">
                <div class="card-header">
                    <div class="d-flex flex-wrap justify-content-between align-items-center">
                        <h5 class="card-title mb-2 mb-md-0">Withdrawal Requests</h5>
                        <div class="d-flex flex-wrap gap-2">
                            <input type="search" id="withdrawal-search-input" class="form-control form-control-sm" style="width: 200px;" placeholder="Search user, wallet..." value="${escapeHtml(search)}">
                            <select id="withdrawal-status-filter" class="form-select form-select-sm" style="width: 150px;">
                                <option value="">All Statuses</option>
                                <option value="Pending" ${status === 'Pending' ? 'selected' : ''}>Pending</option>
                                <option value="Completed" ${status === 'Completed' ? 'selected' : ''}>Completed</option>
                                <option value="Rejected" ${status === 'Rejected' ? 'selected' : ''}>Rejected</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead><tr><th>ID</th><th>User</th><th>Amount</th><th>Method</th><th>Wallet Address</th><th>Status</th><th>Date</th><th>Actions</th></tr></thead>
                            <tbody>
                                ${data.withdrawals.map(wd => `
                                    <tr>
                                        <td>${wd.id}</td>
                                        <td>${escapeHtml(wd.full_name)} (ID: ${wd.user_id})</td>
                                        <td>$${parseFloat(wd.amount).toFixed(2)}</td>
                                        <td>${escapeHtml(wd.method.toUpperCase())}</td>
                                        <td><code>${escapeHtml(wd.wallet_address)}</code></td>
                                        <td><span class="badge bg-${getStatusBadgeClass(wd.status)}">${wd.status}</span></td>
                                        <td>${new Date(wd.request_date).toLocaleString()}</td>
                                        <td><button class="btn btn-sm btn-success approve-withdrawal" data-id="${wd.id}" title="Approve" ${wd.status !== 'Pending' ? 'disabled' : ''}><i class='bx bx-check'></i></button> <button class="btn btn-sm btn-danger reject-withdrawal" data-id="${wd.id}" title="Reject" ${wd.status !== 'Pending' ? 'disabled' : ''}><i class='bx bx-x'></i></button></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                        ${generatePagination(data.pagination)}
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading withdrawals:', error);
        return `<div class="alert alert-danger">Failed to load withdrawals.</div>`;
    }
}

// Load deposits content
async function loadDeposits(page = 1, search = '', status = '') {
    try {
        const url = new URL('/api/admin/deposits', window.location.origin);
        url.searchParams.set('page', page);
        if (search) url.searchParams.set('search', search);
        if (status) url.searchParams.set('status', status);

        const response = await fetchAdminAPI(url);
        if (!response.ok) throw new Error('Failed to fetch deposits');
        const data = await response.json();

        return `
            <div class="card">
                <div class="card-header">
                    <div class="d-flex flex-wrap justify-content-between align-items-center">
                        <h5 class="card-title mb-2 mb-md-0">Deposit Requests</h5>
                        <div class="d-flex flex-wrap gap-2">
                            <input type="search" id="deposit-search-input" class="form-control form-control-sm" style="width: 200px;" placeholder="Search user, txn id..." value="${escapeHtml(search)}">
                            <select id="deposit-status-filter" class="form-select form-select-sm" style="width: 150px;">
                                <option value="">All Statuses</option>
                                <option value="Pending" ${status === 'Pending' ? 'selected' : ''}>Pending</option>
                                <option value="Completed" ${status === 'Completed' ? 'selected' : ''}>Completed</option>
                                <option value="Rejected" ${status === 'Rejected' ? 'selected' : ''}>Rejected</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead><tr><th>ID</th><th>User</th><th>Deposit Amount</th><th>Current Balance</th><th>Method</th><th>TXN ID</th><th>Status</th><th>Date</th><th>Actions</th></tr></thead>
                            <tbody>
                                ${data.deposits.map(dep => `
                                    <tr>
                                        <td>${dep.id}</td>
                                        <td>${escapeHtml(dep.full_name)} (ID: ${dep.user_id})</td>
                                        <td class="text-success fw-bold">$${parseFloat(dep.amount).toFixed(2)}</td>
                                        <td>$${parseFloat(dep.current_balance).toFixed(2)}</td>
                                        <td>${escapeHtml(dep.method.toUpperCase())}</td>
                                        <td title="${escapeHtml(dep.txn_id)}"><code>${escapeHtml(dep.txn_id).substring(0, 20)}...</code></td>
                                        <td><span class="badge bg-${getStatusBadgeClass(dep.status)}">${dep.status}</span></td>
                                        <td>${new Date(dep.request_date).toLocaleString()}</td>
                                        <td>
                                            <button class="btn btn-sm btn-success approve-deposit" data-id="${dep.id}" title="Approve" ${dep.status !== 'Pending' ? 'disabled' : ''}><i class='bx bx-check'></i></button> 
                                            <button class="btn btn-sm btn-danger reject-deposit" data-id="${dep.id}" title="Reject" ${dep.status !== 'Pending' ? 'disabled' : ''}><i class='bx bx-x'></i></button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                        ${generatePagination(data.pagination)}
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading deposits:', error);
        return `<div class="alert alert-danger">Failed to load deposits.</div>`;
    }
}

// Handle deposit approval or rejection
async function handleDepositAction(depositId, status) {
    try {
        const response = await fetch(`/api/admin/deposits/${depositId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status }),
            credentials: 'same-origin'
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || 'An unknown error occurred.');
        }

        showAlert(`Deposit successfully marked as ${status}.`, 'success');
        loadSection('deposits'); // Refresh the list

    } catch (error) {
        console.error(`Error updating deposit ${depositId}:`, error);
        showAlert(error.message, 'danger');
    }
}

// Load support tickets content
async function loadSupport() {
    try {
        const response = await fetchAdminAPI('/api/admin/support/tickets');
        if (!response.ok) throw new Error('Failed to fetch support tickets');
        const data = await response.json();

        return `
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="card-title mb-0">Support Tickets</h5>
                    <button id="back-to-tickets-btn" class="btn btn-sm btn-outline-secondary" style="display: none;"><i class='bx bx-arrow-back'></i> Back to List</button>
                </div>
                <div class="card-body" id="support-content-area">
                    ${generateTicketListHtml(data.tickets)}
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading support tickets:', error);
        return `<div class="alert alert-danger">Failed to load support tickets.</div>`;
    }
}

function generateTicketListHtml(tickets) {
    return `
        <div class="table-responsive">
            <table class="table table-hover">
                <thead><tr><th>ID</th><th>User</th><th>Subject</th><th>Status</th><th>Last Updated</th><th>Actions</th></tr></thead>
                <tbody>
                    ${tickets.map(t => `
                        <tr>
                            <td>#${t.id}</td>
                            <td>${escapeHtml(t.user_name)}</td>
                            <td>${escapeHtml(t.subject)}</td>
                            <td><span class="badge bg-${getStatusBadgeClass(t.status)}">${t.status}</span></td>
                            <td>${new Date(t.updated_at).toLocaleString()}</td>
                            <td><button class="btn btn-sm btn-primary view-ticket" data-id="${t.id}">View</button></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

async function viewAdminTicket(ticketId) {
    try {
        const response = await fetchAdminAPI(`/api/admin/support/tickets/${ticketId}`);
        if (!response.ok) throw new Error('Failed to fetch ticket details');
        const data = await response.json();

        const supportArea = document.getElementById('support-content-area');
        document.getElementById('back-to-tickets-btn').style.display = 'block';

        supportArea.innerHTML = `
            <h5>${escapeHtml(data.ticket.subject)}</h5>
            <p class="text-muted">Ticket from: ${escapeHtml(data.ticket.user_name)}</p>
            <hr>
            <div class="message-thread mb-4" style="max-height: 400px; overflow-y: auto; padding: 1rem; background: #f8f9fa; border-radius: 8px;">
                ${data.messages.map(m => `
                    <div class="message-bubble ${m.is_admin_reply ? 'admin' : 'user'} mb-3">
                        <p class="mb-1">${escapeHtml(m.message).replace(/\n/g, '<br>')}</p>
                        <small class="text-muted">${m.is_admin_reply ? 'You' : escapeHtml(data.ticket.user_name)} &bull; ${new Date(m.created_at).toLocaleString()}</small>
                    </div>
                `).join('')}
            </div>
            <form id="reply-ticket-form" data-ticket-id="${ticketId}" data-user-id="${data.ticket.user_id}">
                <div class="mb-3">
                    <label for="reply-message" class="form-label">Your Reply</label>
                    <textarea id="reply-message" class="form-control" rows="4" required></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Send Reply</button>
            </form>
        `;

        // Add event listener for the reply form
        document.getElementById('reply-ticket-form').addEventListener('submit', handleAdminReply);

    } catch (error) {
        console.error('Error viewing ticket:', error);
        showAlert('Could not load ticket details.', 'danger');
    }
}

async function handleAdminReply(e) {
    e.preventDefault();
    const form = e.target;
    const ticketId = form.dataset.ticketId;
    const userId = form.dataset.userId;
    const message = form.querySelector('#reply-message').value;

    const response = await fetch(`/api/admin/support/tickets/${ticketId}/reply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'credentials': 'same-origin' },
        body: JSON.stringify({ message, user_id: userId })
    });
    const result = await response.json();
    showAlert(result.message, result.success ? 'success' : 'danger');
    if (result.success) {
        viewAdminTicket(ticketId); // Refresh the view
    }
}

// Load settings content
async function loadSettings() {
    try {
        const response = await fetchAdminAPI('/api/admin/settings');
        if (!response.ok) throw new Error('Failed to fetch settings');
        const settings = await response.json();

        const html = `
            <div class="container-fluid">
                <div class="row">
                    <div class="col-lg-8">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="card-title mb-0">General Settings</h5>
                            </div>
                            <div class="card-body">
                                <form id="settings-form">
                                    <div class="mb-3">
                                        <label class="form-label">Site Title</label>
                                        <input type="text" class="form-control" name="site_title" value="${escapeHtml(settings.site_title || '')}">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Admin Email</label>
                                        <input type="email" class="form-control" name="admin_email" value="${escapeHtml(settings.admin_email || '')}">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Currency</label>
                                        <select class="form-select" name="currency">
                                            <option value="USD" ${settings.currency === 'USD' ? 'selected' : ''}>US Dollar ($)</option>
                                            <option value="EUR" ${settings.currency === 'EUR' ? 'selected' : ''}>Euro (€)</option>
                                            <option value="GBP" ${settings.currency === 'GBP' ? 'selected' : ''}>British Pound (£)</option>
                                        </select>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Maintenance Mode</label>
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" id="maintenance-mode" name="maintenance_mode" ${settings.maintenance_mode === 'true' ? 'checked' : ''}>
                                            <label class="form-check-label" for="maintenance-mode">Enable maintenance mode</label>
                                        </div>
                                    </div>
                                    <hr>
                                    <h6 class="card-subtitle mb-2 text-muted">Wallet Addresses</h6>
                                    <div class="mb-3">
                                        <label class="form-label">Bitcoin (BTC) Address</label>
                                        <input type="text" class="form-control" name="btc_address" value="${escapeHtml(settings.btc_address || '')}">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Litecoin (LTC) Address</label>
                                        <input type="text" class="form-control" name="ltc_address" value="${escapeHtml(settings.ltc_address || '')}">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">USDT (ERC20) Address</label>
                                        <input type="text" class="form-control" name="usdt_address" value="${escapeHtml(settings.usdt_address || '')}">
                                    </div>
                                    <button type="submit" class="btn btn-primary">Save Settings</button>
                                </form>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="card">
                            <div class="card-header"><h5 class="card-title mb-0">System Information</h5></div>
                            <div class="card-body">
                                <ul class="list-group list-group-flush">
                                    <li class="list-group-item d-flex justify-content-between align-items-center">Platform Version<span class="badge bg-primary">v1.0.0</span></li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">Server Status<span class="badge bg-success">Online</span></li>
                                </ul>
                            </div>
                        </div>
                        <div class="card mt-4">
                            <div class="card-header"><h5 class="card-title mb-0">Security</h5></div>
                            <div class="card-body" id="tfa-settings-area"></div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        return html;
    } catch (error) {
        console.error('Error loading settings:', error);
        return `<div class="alert alert-danger">Failed to load settings.</div>`;
    }
}

// Load signup tokens content
async function loadSignupTokens() {
    try {
        const response = await fetchAdminAPI('/api/admin/signup-tokens');
        if (!response.ok) throw new Error('Failed to fetch tokens');
        const data = await response.json();

        return `
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="card-title mb-0">Signup Access Tokens</h5>
                    <button class="btn btn-primary" id="generate-token-btn"><i class='bx bx-plus'></i> Generate New Token</button>
                </div>
                <div class="card-body">
                    <p class="text-muted">Share these tokens with users to allow them to sign up. Each token can only be used once.</p>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead><tr><th>Token</th><th>Status</th><th>Created On</th></tr></thead>
                            <tbody>
                                ${data.tokens.map(t => `
                                    <tr>
                                        <td><code>${t.token}</code></td>
                                        <td><span class="badge bg-${t.status === 'unused' ? 'success' : 'secondary'}">${t.status}</span></td>
                                        <td>${new Date(t.created_at).toLocaleString()}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading signup tokens:', error);
        return `<div class="alert alert-danger">Failed to load signup tokens.</div>`;
    }
}

async function generateNewToken() {
    try {
        const response = await fetchAdminAPI('/api/admin/signup-tokens', { method: 'POST' });
        const result = await response.json();
        showAlert(result.message, result.success ? 'success' : 'danger');
        if (result.success) {
            loadSection('signup-tokens'); // Refresh the list
        }
    } catch (error) {
        showAlert('An error occurred while generating the token.', 'danger');
    }
}

// Generate pagination controls
function generatePagination({ total, page, totalPages }) {
    if (totalPages <= 1) return '';

    let paginationHtml = `
        <div class="d-flex justify-content-between align-items-center mt-3">
            <div class="text-muted">
                Total <b>${total}</b> entries
            </div>
            <nav>
                <ul class="pagination mb-0">
    `;

    // Previous button
    paginationHtml += `
        <li class="page-item ${page === 1 ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${page - 1}">Previous</a>
        </li>
    `;

    // Page numbers (simplified for brevity)
    for (let i = 1; i <= totalPages; i++) {
        if (i === page) {
            paginationHtml += `<li class="page-item active"><a class="page-link" href="#">${i}</a></li>`;
        } else {
            paginationHtml += `<li class="page-item"><a class="page-link" href="#" data-page="${i}">${i}</a></li>`;
        }
    }

    // Next button
    paginationHtml += `
        <li class="page-item ${page === totalPages ? 'disabled' : ''}">
            <a class="page-link" href="#" data-page="${page + 1}">Next</a>
        </li>
    `;

    paginationHtml += `
                </ul>
            </nav>
        </div>`;
    return paginationHtml;
}

// Initialize section-specific functionality
function initializeSection(section) {
    // Initialize any section-specific JavaScript here
    switch (section) {
        case 'users':
            initializeUsersSection();
            break;
        case 'investments':
            initializeInvestmentsSection();
            break;
        case 'dashboard':
            initializeDashboardCharts();
            break;
        case 'withdrawals':
            initializeWithdrawalsSection();
            break;
        case 'deposits':
            initializeDepositsSection();
            break;
        case 'support':
            initializeSupportSection();
            break;
        case 'settings':
            initializeSettingsSection();
            initializeTFASettings();
            break;
        case 'signup-tokens':
            initializeSignupTokensSection();
            break;
        // Add more sections as needed
    }
}

// Initialize users section functionality
function initializeUsersSection() {
    // View user details
    document.querySelectorAll('.view-user').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const userId = e.currentTarget.getAttribute('data-id');
            await showUserDetails(userId);
        });
    });
    
    // Add user button
    const addUserBtn = document.getElementById('add-user-btn');
    if (addUserBtn) {
        addUserBtn.addEventListener('click', () => {
            showAddUserForm();
        });
    }

    // Search and filter listeners
    const searchInput = document.getElementById('user-search-input');
    const statusFilter = document.getElementById('user-status-filter');

    const applyFilters = () => {
        const searchTerm = searchInput.value;
        const statusValue = statusFilter.value;
        loadSection('users', 1, searchTerm, statusValue);
    };

    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') applyFilters();
    });
    statusFilter.addEventListener('change', applyFilters);

    // Pagination listener
    document.querySelectorAll('.pagination .page-link[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            loadSection('users', e.target.dataset.page, searchInput.value, statusFilter.value);
        });
    });
}

// Initialize investments section functionality
function initializeInvestmentsSection() {
    const searchInput = document.getElementById('investment-search-input');
    const statusFilter = document.getElementById('investment-status-filter');

    const applyFilters = () => {
        loadSection('investments', 1, searchInput.value, statusFilter.value);
    };

    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') applyFilters();
    });
    statusFilter.addEventListener('change', applyFilters);

    // Pagination listener
    document.querySelectorAll('.pagination .page-link[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = e.target.dataset.page;
            loadSection('investments', page, searchInput.value, statusFilter.value);
        });
    });
}

// Initialize withdrawals section functionality
function initializeWithdrawalsSection() {
    document.querySelectorAll('.approve-withdrawal, .reject-withdrawal').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const button = e.currentTarget;
            const withdrawalId = button.dataset.id;
            const action = button.classList.contains('approve-withdrawal') ? 'Completed' : 'Rejected';

            if (confirm(`Are you sure you want to ${action.toLowerCase()} this withdrawal?`)) {
                await handleWithdrawalAction(withdrawalId, action);
            }
        });
    });

    const searchInput = document.getElementById('withdrawal-search-input');
    const statusFilter = document.getElementById('withdrawal-status-filter');

    const applyFilters = () => {
        loadSection('withdrawals', 1, searchInput.value, statusFilter.value);
    };

    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') applyFilters();
    });
    statusFilter.addEventListener('change', applyFilters);

    // Pagination listener
    document.querySelectorAll('.pagination .page-link[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = e.target.dataset.page;
            loadSection('withdrawals', page, searchInput.value, statusFilter.value);
        });
    });
}

// Handle withdrawal approval or rejection
async function handleWithdrawalAction(withdrawalId, status) {
    try {
        const response = await fetch(`/api/admin/withdrawals/${withdrawalId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status }),
            credentials: 'same-origin'
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || 'An unknown error occurred.');
        }

        // Show success message
        showAlert(`Withdrawal successfully marked as ${status}.`, 'success');

        // Refresh the withdrawals list to show the updated status
        loadSection('withdrawals');

    } catch (error) {
        console.error(`Error updating withdrawal ${withdrawalId}:`, error);
        showAlert(error.message, 'danger');
    }
}

// Initialize deposits section functionality
function initializeDepositsSection() {
    document.querySelectorAll('.approve-deposit, .reject-deposit').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const button = e.currentTarget;
            const depositId = button.dataset.id;
            const action = button.classList.contains('approve-deposit') ? 'Completed' : 'Rejected';

            if (confirm(`Are you sure you want to ${action.toLowerCase()} this deposit?`)) {
                await handleDepositAction(depositId, action);
            }
        });
    });

    const searchInput = document.getElementById('deposit-search-input');
    const statusFilter = document.getElementById('deposit-status-filter');

    const applyFilters = () => {
        loadSection('deposits', 1, searchInput.value, statusFilter.value);
    };

    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') applyFilters();
    });
    statusFilter.addEventListener('change', applyFilters);

    // Pagination listener
    document.querySelectorAll('.pagination .page-link[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = e.target.dataset.page;
            loadSection('deposits', page, searchInput.value, statusFilter.value);
        });
    });
}

// Initialize support section functionality
function initializeSupportSection() {
    document.querySelectorAll('.view-ticket').forEach(btn => {
        btn.addEventListener('click', (e) => {
            viewAdminTicket(e.currentTarget.dataset.id);
        });
    });

    const backBtn = document.getElementById('back-to-tickets-btn');
    if (backBtn) {
        backBtn.addEventListener('click', () => loadSection('support'));
    }
}

// Initialize settings section functionality
function initializeSettingsSection() {
    const settingsForm = document.getElementById('settings-form');
    if (settingsForm) {
        settingsForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(settingsForm);
            const settingsData = Object.fromEntries(formData.entries());

            // Handle checkbox value
            settingsData.maintenance_mode = !!settingsData.maintenance_mode;

            try {
                const response = await fetch('/api/admin/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(settingsData),
                    credentials: 'same-origin'
                });

                const result = await response.json();
                if (!response.ok) throw new Error(result.message || 'Failed to save settings.');

                showAlert(result.message, 'success');

            } catch (error) {
                showAlert(error.message, 'danger');
            }
        });
    }
}

// Initialize signup tokens section functionality
function initializeSignupTokensSection() {
    const generateBtn = document.getElementById('generate-token-btn');
    if (generateBtn) {
        generateBtn.addEventListener('click', generateNewToken);
    }
}

// Initialize 2FA settings section
function initializeTFASettings() {
    const tfaArea = document.getElementById('tfa-settings-area');
    if (!tfaArea) return;

    // currentUser is populated from checkAuth()
    if (currentUser && currentUser.tfa_enabled) {
        tfaArea.innerHTML = `
            <p>Two-Factor Authentication is currently <strong>enabled</strong>.</p>
            <button id="disable-tfa-btn" class="btn btn-danger">Disable 2FA</button>
        `;
        document.getElementById('disable-tfa-btn').addEventListener('click', handleDisableTFA);
    } else {
        tfaArea.innerHTML = `
            <p>Two-Factor Authentication is currently <strong>disabled</strong>.</p>
            <p class="text-muted small">Add an extra layer of security to your account.</p>
            <button id="enable-tfa-btn" class="btn btn-success">Enable 2FA</button>
            <div id="tfa-setup-area" class="mt-4" style="display: none;"></div>
        `;
        document.getElementById('enable-tfa-btn').addEventListener('click', handleEnableTFA);
    }
}

async function handleDisableTFA() {
    if (!confirm('Are you sure you want to disable Two-Factor Authentication? This will reduce your account security.')) {
        return;
    }
    try {
        const response = await fetch('/api/admin/tfa/disable', {
            method: 'POST',
            credentials: 'same-origin'
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);

        showAlert(result.message, 'success');
        // Reload the user's auth status and then the section
        await checkAuth();
        loadSection('settings');
    } catch (error) {
        showAlert(error.message, 'danger');
    }
}

async function handleEnableTFA() {
    const enableBtn = document.getElementById('enable-tfa-btn');
    enableBtn.disabled = true;
    enableBtn.innerHTML = `<span class="spinner-border spinner-border-sm"></span> Generating...`;

    try {
        const response = await fetch('/api/admin/tfa/setup', {
            method: 'POST',
            credentials: 'same-origin'
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);

        const setupArea = document.getElementById('tfa-setup-area');
        setupArea.style.display = 'block';
        setupArea.innerHTML = `
            <h6>Step 1: Scan QR Code</h6>
            <p>Scan the image below with your authenticator app (like Google Authenticator, Authy, or 1Password).</p>
            <div class="text-center my-3">
                <img src="${result.qrCode}" alt="2FA QR Code">
            </div>
            <p>If you can't scan the code, you can manually enter this secret key:</p>
            <p><code class="p-2 bg-light rounded d-block text-center">${result.secret}</code></p>
            <hr>
            <h6>Step 2: Verify Token</h6>
            <p>Enter the 6-digit code from your authenticator app to complete the setup.</p>
            <form id="tfa-verify-form">
                <div class="input-group mb-3">
                    <input type="text" id="tfa-token-input" class="form-control" placeholder="123456" required pattern="\\d{6}" maxlength="6">
                    <button type="submit" class="btn btn-primary">Verify & Enable</button>
                </div>
            </form>
        `;
        enableBtn.style.display = 'none'; // Hide the original enable button

        document.getElementById('tfa-verify-form').addEventListener('submit', handleVerifyTFA);

    } catch (error) {
        showAlert(error.message, 'danger');
        enableBtn.disabled = false;
        enableBtn.textContent = 'Enable 2FA';
    }
}

async function handleVerifyTFA(e) {
    e.preventDefault();
    const token = document.getElementById('tfa-token-input').value;
    try {
        const response = await fetch('/api/admin/tfa/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token }),
            credentials: 'same-origin'
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);

        showAlert(result.message, 'success');
        // Reload the user's auth status and then the section
        await checkAuth();
        loadSection('settings');

    } catch (error) {
        showAlert(error.message, 'danger');
    }
}

// Show user details in modal
async function showUserDetails(userId) {
    try {
        const response = await fetch(`/api/admin/users/${userId}`, { credentials: 'same-origin' });
        if (!response.ok) throw new Error('Failed to fetch user details');
        
        const user = await response.json();
        
        // Format the user details
        const userDetailsHtml = `
            <div class="row">
                <div class="col-md-4 text-center">
                    <div class="avatar avatar-xxl mb-3">
                        ${getUserInitials(user.name)}
                    </div>
                    <h5>${escapeHtml(user.name)}</h5>
                    <p class="text-muted">${user.username || 'N/A'}</p>
                    <span class="badge bg-${user.status === 'active' ? 'success' : 'secondary'}">
                        ${user.status}
                    </span>
                </div>
                <div class="col-md-8">
                    <div class="mb-3">
                        <h6>Contact Information</h6>
                        <p class="mb-1"><strong>Email:</strong> ${escapeHtml(user.email)}</p>
                        <p class="mb-1"><strong>Phone:</strong> ${user.phone_number || 'N/A'}</p>
                        <p class="mb-1"><strong>Joined:</strong> ${new Date(user.created_at).toLocaleString()}</p>
                        <p class="mb-1"><strong>Last Login:</strong> ${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</p>
                    </div>
                    
                    <div class="mb-3">
                        <h6>Account Balance</h6>
                        <div class="input-group">
                            <span class="input-group-text">$</span>
                            <input type="number" class="form-control" id="user-balance-input" value="${parseFloat(user.balance || 0).toFixed(2)}" step="0.01" required>
                        </div>
                    </div>

                    <div class="mb-3">
                        <h6>Account Status</h6>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="user-active-toggle" ${user.status === 'active' ? 'checked' : ''}>
                            <label class="form-check-label" for="user-active">
                                Account Active
                            </label>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <h6>User Statistics</h6>
                        <div class="row">
                            <div class="col-6">
                                <div class="p-2 bg-light rounded text-center">
                                    <h5 class="mb-0">${user.investments.length || 0}</h5>
                                    <small class="text-muted">Investments</small>
                                </div>
                            </div>
                            <div class="col-6">
                                <div class="p-2 bg-light rounded text-center">
                                    <h5 class="mb-0">${user.transactions.length || 0}</h5>
                                    <small class="text-muted">Transactions</small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Update modal content
        document.getElementById('userModalLabel').textContent = 'User Details';
        document.getElementById('userModalBody').innerHTML = userDetailsHtml;
        
        // Show the modal
        const modal = new bootstrap.Modal(document.getElementById('userModal'));
        modal.show();

        // Add event listener for the main "Save changes" button
        const saveBtn = document.getElementById('save-user-details-btn');
        saveBtn.onclick = () => saveUserDetails(userId); // Use onclick to re-assign easily
        
    } catch (error) {
        console.error('Error loading user details:', error);
        alert('Failed to load user details. Please try again.');
    }
}

// Save user details from the modal
async function saveUserDetails(userId) {
    const isActive = document.getElementById('user-active-toggle').checked;
    const newBalance = document.getElementById('user-balance-input').value;
    const status = isActive ? 'active' : 'inactive';

    try {
        // We can save both in parallel for efficiency
        const statusPromise = fetch(`/api/admin/users/${userId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'credentials': 'same-origin' },
            body: JSON.stringify({ status })
        });

        const balancePromise = fetch(`/api/admin/users/${userId}/balance`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'credentials': 'same-origin' },
            body: JSON.stringify({ newBalance })
        });

        const [statusResponse, balanceResponse] = await Promise.all([statusPromise, balancePromise]);

        if (!statusResponse.ok || !balanceResponse.ok) {
            const statusError = !statusResponse.ok ? await statusResponse.json() : null;
            const balanceError = !balanceResponse.ok ? await balanceResponse.json() : null;
            const errorMessage = (statusError?.message || '') + ' ' + (balanceError?.message || '');
            throw new Error(errorMessage.trim() || 'An unknown error occurred.');
        }

        // Show success message
        showAlert('User details updated successfully!', 'success');

        // Close the modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('userModal'));
        modal.hide();

        // Refresh the user list to show the updated status
        loadSection('users');

    } catch (error) {
        console.error('Error updating user status:', error);
        // Show error inside the modal for better UX
        const modalBody = document.getElementById('userModalBody');
        const errorAlert = `<div class="alert alert-danger mt-3">${error.message || 'Failed to update user.'}</div>`;
        modalBody.insertAdjacentHTML('beforeend', errorAlert);
    }
}

// Show add user form
function showAddUserForm() {
    const formHtml = `
        <form id="add-user-form">
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label class="form-label">Full Name</label>
                    <input type="text" class="form-control" name="name" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label class="form-label">Username</label>
                    <input type="text" class="form-control" name="username" required>
                </div>
            </div>
            <div class="mb-3">
                <label class="form-label">Email</label>
                <input type="email" class="form-control" name="email" required>
            </div>
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-control" name="password" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label class="form-label">Confirm Password</label>
                    <input type="password" class="form-control" name="confirm_password" required>
                </div>
            </div>
            <div class="mb-3">
                <label class="form-label">Phone Number</label>
                <input type="tel" class="form-control" name="phone_number">
            </div>
            <div class="mb-3">
                <label class="form-label">Status</label>
                <select class="form-select" name="status">
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                    <option value="suspended">Suspended</option>
                </select>
            </div>
            <div class="form-check mb-3">
                <input class="form-check-input" type="checkbox" name="is_admin" id="is-admin">
                <label class="form-check-label" for="is-admin">
                    Administrator Account
                </label>
            </div>
        </form>
    `;
    
    // Update modal content
    document.getElementById('userModalLabel').textContent = 'Add New User';
    document.getElementById('userModalBody').innerHTML = formHtml;
    
    // Update modal footer
    const modalFooter = document.querySelector('#userModal .modal-footer');
    modalFooter.innerHTML = `
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-primary" id="save-user-btn">Save User</button>
    `;
    
    // Add event listener for save button
    document.getElementById('save-user-btn').addEventListener('click', saveNewUser);
    
    // Show the modal
    const modal = new bootstrap.Modal(document.getElementById('userModal'));
    modal.show();
}

// Save new user
async function saveNewUser() {
    const form = document.getElementById('add-user-form');
    if (!form.checkValidity()) {
        form.classList.add('was-validated');
        return;
    }
    
    const formData = new FormData(form);
    const userData = Object.fromEntries(formData.entries());
    
    try {
        const response = await fetch('/api/admin/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData),
            credentials: 'same-origin'
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to create user');
        }
        
        // Close modal and refresh users list
        const modal = bootstrap.Modal.getInstance(document.getElementById('userModal'));
        modal.hide();
        
        // Show success message
        showAlert('User created successfully', 'success');
        
        // Reload users section
        loadSection('users');
        
    } catch (error) {
        console.error('Error creating user:', error);
        showAlert(error.message || 'Failed to create user', 'danger');
    }
}

// Initialize dashboard charts
async function initializeDashboardCharts() {
    // Example chart initialization using Chart.js
    const containerCard = document.querySelector('#page-content .card');
    if (!containerCard) return; // Exit if the main card isn't there

    try {
        const response = await fetch('/api/admin/financial-overview', { credentials: 'same-origin' });
        if (!response.ok) throw new Error('Failed to fetch financial data. Status: ' + response.status);
        const chartData = await response.json();

        const chartContainer = document.createElement('div');
        chartContainer.className = 'card mt-4';
        chartContainer.innerHTML = `
                <div class="card-header">
                    <h5 class="card-title mb-0">Financial Overview (Last 30 Days)</h5>
                </div>
                <div class="card-body">
                    <canvas id="financialChart"></canvas>
                </div>
        `;
        containerCard.insertAdjacentElement('afterend', chartContainer);

        const data = {
            labels: chartData.labels,
            datasets: [
                {
                    label: 'Investments',
                    data: chartData.investmentData,
                    backgroundColor: 'rgba(217, 119, 6, 0.1)',
                    borderColor: '#D97706', // Primary color (Gold)
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    yAxisID: 'y'
                },
                {
                    label: 'Deposits',
                    data: chartData.transactionData,
                    backgroundColor: 'rgba(25, 135, 84, 0.1)',
                    borderColor: '#198754', // Success color
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    yAxisID: 'y'
                },
                {
                    label: 'Withdrawals',
                    data: chartData.withdrawalData,
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    borderColor: '#DC3545', // Danger color
                    borderWidth: 2,
                    tension: 0.4,
                    fill: false, // Keep outflow line unfilled for visual distinction
                    yAxisID: 'y'
                }
            ]
        };

        const config = {
            type: 'line',
            data: data,
            options: {
                responsive: true,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: { display: true, position: 'top' },
                    tooltip: { mode: 'index', intersect: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        type: 'linear',
                        display: true,
                        position: 'left',
                        ticks: {
                            callback: function(value) {
                                return '$' + value.toLocaleString();
                            }
                        }
                    }
                }
            },
        };

        new Chart(document.getElementById('financialChart'), config);

    } catch (error) {
        console.error('Error initializing dashboard charts:', error);
    }
}

// Show alert message
function showAlert(message, type = 'info') {
    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    
    // Insert at the top of the page content
    pageContent.insertAdjacentHTML('afterbegin', alertHtml);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        const alert = document.querySelector('.alert');
        if (alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }
    }, 5000);
}

// Get user initials for avatar
function getUserInitials(name) {
    if (!name) return '';
    const nameParts = name.trim().split(' ');
    if (nameParts.length > 1) {
        return nameParts[0][0].toUpperCase() + nameParts[1][0].toUpperCase();
    }
    return name[0].toUpperCase();
}

// Get status badge class
function getStatusBadgeClass(status) {
    // Add a fallback for undefined or null status
    switch ((status || '').toLowerCase()) {
        case 'completed':
        case 'active':
        case 'success':
            return 'success';
        case 'pending':
        case 'processing':
            return 'warning';
        case 'failed':
        case 'rejected':
        case 'cancelled':
            return 'danger';
        default:
            return 'secondary';
    }
}

// Simple XSS protection
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return unsafe
        .toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Handle clicks on dynamically added elements
document.addEventListener('click', (e) => {
    // Handle section links in content (if they are not part of the main sidebar nav)
    const sectionLink = e.target.closest('a[data-section]');
    if (sectionLink && !sectionLink.closest('.sidebar-menu')) {
        e.preventDefault();
        const section = sectionLink.getAttribute('data-section');
        
        // Find the corresponding sidebar link and click it to navigate
        const sidebarLink = document.querySelector(`.sidebar-menu a[data-section="${section}"]`);
        if (sidebarLink) {
            sidebarLink.click();
        }
    }
});