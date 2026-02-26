/*
    User Dashboard Script
    Handles all client-side logic for the user dashboard.
*/

document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const sidebar = document.querySelector('.sidebar');
    const menuBtn = document.getElementById('btn');
    const navLinks = document.querySelectorAll('.nav-link');
    const pageTitle = document.getElementById('page-title');
    const mainContent = document.getElementById('main-content');
    const userNameDisplay = document.getElementById('user-name-display');
    const notificationBell = document.getElementById('notification-bell');
    const notificationDropdown = document.getElementById('notification-dropdown');

    // --- State ---
    let currentUser = null;
    let activeCharts = [];

    // --- Initial Load ---
    const initializeDashboard = async () => {
        try {
            // Fetch user data first to personalize the UI
            const userRes = await fetch('/api/user/me');
            if (!userRes.ok) {
                // If this fails, the requireLogin middleware likely redirected,
                // but as a fallback, we redirect manually.
                window.location.href = '/login.html';
                return;
            }
            currentUser = await userRes.json();
            userNameDisplay.textContent = currentUser.name;

            // Load the default section
            loadSection('dashboard');

            // Fetch notification count
            updateNotificationCount();

        } catch (error) {
            console.error('Initialization failed:', error);
            mainContent.innerHTML = createAlert('Could not load dashboard. Please try logging in again.', 'danger');
        }
    };

    // --- Event Listeners ---
    menuBtn.onclick = () => {
        sidebar.classList.toggle('active');
    };

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = link.dataset.section;

            // Update active class
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            // Load content
            loadSection(section);
        });
    });

    notificationBell.addEventListener('click', (e) => {
        e.stopPropagation();
        notificationDropdown.classList.toggle('show');
        if (notificationDropdown.classList.contains('show')) {
            loadNotifications();
        }
    });

    document.addEventListener('click', (e) => {
        if (!notificationBell.contains(e.target) && !notificationDropdown.contains(e.target)) {
            notificationDropdown.classList.remove('show');
        }
    });

    // --- Content Loading ---
    const loadSection = async (section) => {
        if (activeCharts.length > 0) {
            activeCharts.forEach(chart => chart.destroy());
            activeCharts = [];
        }
        mainContent.innerHTML = `<div class="d-flex justify-content-center align-items-center" style="height: 80vh;"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>`;
        pageTitle.textContent = section.charAt(0).toUpperCase() + section.slice(1);

        try {
            let content = '';
            switch (section) {
                case 'dashboard':
                    content = await getDashboardContent();
                    break;
                case 'portfolio':
                    content = await getPortfolioContent();
                    break;
                case 'deposit':
                    content = await getDepositContent();
                    break;
                case 'withdraw':
                    content = await getWithdrawContent();
                    break;
                case 'invest':
                    content = await getInvestContent();
                    break;
                case 'support':
                    content = await getSupportContent();
                    break;
                case 'profile':
                    content = await getProfileContent();
                    break;
                default:
                    content = createAlert('Section not found.', 'warning');
            }
            mainContent.innerHTML = content;
            attachEventListeners(section);
        } catch (error) {
            console.error(`Error loading ${section}:`, error);
            mainContent.innerHTML = createAlert(`Failed to load ${section}. Please try again later.`, 'danger');
        }
    };

    // --- HTML Content Generators ---

    const getDashboardContent = async () => {
        const [statsRes, transactionsRes, analyticsRes] = await Promise.all([
            fetch('/api/dashboard/stats'),
            fetch('/api/dashboard/transactions'),
            fetch('/api/analytics/data') // Fetch data for the chart
        ]);
        if (!statsRes.ok || !transactionsRes.ok || !analyticsRes.ok) throw new Error('Failed to fetch dashboard data');

        const stats = await statsRes.json();
        const transactions = await transactionsRes.json();
        const analyticsData = await analyticsRes.json();

        // Store chart data for initialization
        window.tempChartData = analyticsData;

        return `
            <div class="row">
                <!-- Stat Cards -->
                <div class="col-lg-3 col-md-6 mb-4">${createStatCard('Total Balance', formatCurrency(stats.totalBalance), 'bx-wallet', 'primary')}</div>
                <div class="col-lg-3 col-md-6 mb-4">${createStatCard('Total Invested', formatCurrency(stats.totalInvestment), 'bx-line-chart', 'success')}</div>
                <div class="col-lg-3 col-md-6 mb-4">${createStatCard('Total Profit', formatCurrency(stats.totalProfit), 'bx-trending-up', 'info')}</div>
                <div class="col-lg-3 col-md-6 mb-4">${createStatCard('Active Plans', stats.activePlans, 'bx-rocket', 'warning')}</div>
            </div>

            <div class="row">
                <!-- Portfolio Value Chart -->
                <div class="col-lg-7 mb-4">
                    <div class="card h-100">
                        <div class="card-header"><h5 class="card-title mb-0">Portfolio Value Over Time</h5></div>
                        <div class="card-body">
                            <canvas id="dashboardGrowthChart"></canvas>
                        </div>
                    </div>
                </div>

                <!-- Recent Transactions -->
                <div class="col-lg-5 mb-4">
                    <div class="card h-100">
                        <div class="card-header"><h5 class="card-title mb-0">Recent Transactions</h5></div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr><th>Type</th><th>Amount</th><th>Date</th><th>Status</th></tr>
                                    </thead>
                                    <tbody>
                                        ${transactions.length > 0 ? transactions.map(tx => `
                                            <tr >
                                                <td><span class="badge bg-${tx.type === 'Deposit' ? 'success' : 'primary'} bg-opacity-75">${tx.type}</span></td>
                                                <td>${formatCurrency(tx.amount)}</td>
                                                <td>${new Date(tx.date).toLocaleDateString()}</td>
                                                <td><span class="badge rounded-pill bg-${getStatusClass(tx.status)}">${tx.status}</span></td>
                                            </tr>
                                        `).join('') : `<tr><td colspan="4" class="text-center py-4 text-muted">No recent transactions.</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    };

    const getPortfolioContent = async () => {
        const [investmentsRes, analyticsRes] = await Promise.all([
            fetch('/api/portfolio/investments'),
            fetch('/api/analytics/data')
        ]);
        if (!investmentsRes.ok || !analyticsRes.ok) throw new Error('Failed to fetch portfolio data');
        const investmentsData = await investmentsRes.json();
        const analyticsData = await analyticsRes.json();

        // Store analytics data on a temporary global object to be accessed by the chart initializer
        window.tempChartData = analyticsData;

        return `
            <div class="row">
                <!-- Charts -->
                <div class="col-lg-8 mb-4">
                    <div class="card h-100">
                        <div class="card-header"><h5 class="card-title mb-0">Portfolio Growth</h5></div>
                        <div class="card-body">
                            <canvas id="portfolioGrowthChart"></canvas>
                        </div>
                    </div>
                </div>
                <div class="col-lg-4 mb-4">
                    <div class="card h-100">
                        <div class="card-header"><h5 class="card-title mb-0">Asset Allocation</h5></div>
                        <div class="card-body d-flex align-items-center justify-content-center">
                            <canvas id="assetAllocationChart"></canvas>
                        </div>
                    </div>
                </div>

                <!-- Investments Table -->
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">My Investments</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table">
                                    <thead>
                                        <tr><th>Package</th><th>Amount</th><th>Profit</th><th>Start Date</th><th>End Date</th><th>Status</th><th>Progress</th></tr>
                                    </thead>
                                    <tbody>
                                        ${investmentsData.investments.length > 0 ? investmentsData.investments.map(inv => `
                                            <tr>
                                                <td>${escapeHtml(inv.name)}</td>
                                                <td>${formatCurrency(inv.amount)}</td>
                                                <td>${formatCurrency(inv.profit)}</td>
                                                <td>${new Date(inv.startDate).toLocaleDateString()}</td>
                                                <td>${new Date(inv.endDate).toLocaleDateString()}</td>
                                                <td><span class="badge rounded-pill bg-${getStatusClass(inv.status)}">${inv.status}</span></td>
                                                <td>
                                                    <div class="progress" style="height: 10px;">
                                                        <div class="progress-bar" role="progressbar" style="width: ${inv.progress}%;" aria-valuenow="${inv.progress}" aria-valuemin="0" aria-valuemax="100"></div>
                                                    </div>
                                                    <small>${inv.progress}%</small>
                                                </td>
                                            </div>
                                        `).join('') : `<tr><td colspan="7" class="text-center py-4 text-muted">You have no active investments. <a href="#" class="nav-link-inline" data-section="invest">Make one now!</a></td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    };

    const getDepositContent = async () => {
        const [addressesRes, historyRes] = await Promise.all([
            fetch('/api/deposit-info'),
            fetch('/api/deposits')
        ]);
        if (!addressesRes.ok || !historyRes.ok) throw new Error('Failed to fetch deposit information');
        const addresses = await addressesRes.json();
        const history = await historyRes.json();

        const getTabContent = (key, value) => `
            <div class="text-center p-3">
                <h6 class="text-uppercase">${key} DEPOSIT</h6>
                <p class="text-muted small">Send any amount of ${key.toUpperCase()} to the address below.</p>
                <img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${value}" alt="${key} QR Code" class="img-fluid my-3">
                <div class="input-group">
                    <input type="text" class="form-control" value="${value}" readonly id="wallet-${key}">
                    <button class="btn btn-outline-secondary copy-btn" type="button" data-clipboard-target="#wallet-${key}" title="Copy to Clipboard">
                        <i class='bx bx-copy'></i>
                    </button>
                </div>
            </div>
        `;

        return `
            <div class="row">
                <div class="col-12 mb-4">
                    <div class="card">
                        <div class="card-body p-lg-5">
                            <div class="row g-5">
                                <!-- Left Side: Wallet Info -->
                                <div class="col-lg-6">
                                    <h4 class="mb-4">1. Choose a Method & Send</h4>
                                    <!-- Deposit Method Tabs -->
                                    <ul class="nav nav-pills nav-fill mb-3" id="pills-tab" role="tablist">
                                        ${Object.keys(addresses).map((key, index) => `
                                            <li class="nav-item" role="presentation">
                                                <button class="nav-link ${index === 0 ? 'active' : ''}" id="pills-${key}-tab" data-bs-toggle="pill" data-bs-target="#pills-${key}" type="button" role="tab">${key.toUpperCase()}</button>
                                            </li>
                                        `).join('')}
                                    </ul>
                                    <div class="tab-content" id="pills-tabContent">
                                        ${Object.entries(addresses).map(([key, value], index) => `
                                            <div class="tab-pane fade ${index === 0 ? 'show active' : ''}" id="pills-${key}" role="tabpanel">
                                                ${getTabContent(key, value)}
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>
                                <!-- Right Side: Confirmation Form -->
                                <div class="col-lg-6">
                                    <h4 class="mb-4">2. Confirm Your Deposit</h4>
                                    <p class="text-muted">After sending the funds, fill out this form to have your deposit credited to your account.</p>
                                    <form id="deposit-form">
                                        <div class="mb-3">
                                            <label for="deposit-amount" class="form-label">Amount (USD)</label>
                                            <input type="number" class="form-control" id="deposit-amount" required step="0.01" placeholder="e.g., 500.00">
                                        </div>
                                        <div class="mb-3">
                                            <label for="deposit-method" class="form-label">Method</label>
                                            <select class="form-select" id="deposit-method" required>
                                                ${Object.keys(addresses).map(key => `<option value="${key}">${key.toUpperCase()}</option>`).join('')}
                                            </select>
                                        </div>
                                        <div class="mb-3">
                                            <label for="deposit-txn" class="form-label">Transaction ID / Hash</label>
                                            <input type="text" class="form-control" id="deposit-txn" required placeholder="Enter the transaction hash from your wallet">
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100">Confirm Deposit</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-12 mb-4">
                    <div class="card">
                        <div class="card-header"><h5 class="card-title mb-0">Deposit History</h5></div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead><tr><th>Amount</th><th>Method</th><th>Status</th><th>Date</th></tr></thead>
                                    <tbody>
                                        ${history.length > 0 ? history.map(d => `
                                            <tr>
                                                <td>${formatCurrency(d.amount)}</td>
                                                <td>${d.method.toUpperCase()}</td>
                                                <td><span class="badge rounded-pill bg-${getStatusClass(d.status)} text-capitalize">${d.status}</span></td>
                                                <td>${new Date(d.date).toLocaleDateString()}</td>
                                            </tr>
                                        `).join('') : `<tr><td colspan="4" class="text-center py-4 text-muted">No deposit history.</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    };

    const getWithdrawContent = async () => {
        const [historyRes, statsRes] = await Promise.all([
            fetch('/api/withdrawals'),
            fetch('/api/dashboard/stats') // Fetch stats to get available balance
        ]);
        if (!historyRes.ok || !statsRes.ok) throw new Error('Failed to fetch withdrawal data');
        const history = await historyRes.json();
        const stats = await statsRes.json();

        return `
            <div class="row">
                <div class="col-12 mb-4">
                    <div class="card">
                        <div class="card-header"><h5 class="card-title mb-0">Request Withdrawal</h5></div>
                        <div class="card-body">
                            <div class="alert alert-info d-flex justify-content-between align-items-center">
                                <span>Available for Withdrawal:</span>
                                <strong class="fs-5">${formatCurrency(stats.totalBalance)}</strong>
                            </div>
                            <form id="withdrawal-form">
                                <div class="input-group mb-3">
                                    <span class="input-group-text"><i class='bx bx-dollar'></i></span>
                                    <input type="number" class="form-control" id="withdrawal-amount" required step="0.01" placeholder="Amount (USD)">
                                </div>
                                <div class="input-group mb-3">
                                     <span class="input-group-text"><i class='bx bxl-bitcoin'></i></span>
                                    <select class="form-select" id="withdrawal-method" required title="Withdrawal Method">
                                        <option value="" disabled selected>Select Withdrawal Method</option>
                                        <option value="btc">Bitcoin (BTC)</option>
                                        <option value="ltc">Litecoin (LTC)</option>
                                        <option value="usdt">USDT (ERC20)</option>
                                    </select>
                                </div>
                                <div class="input-group mb-3">
                                    <span class="input-group-text"><i class='bx bx-wallet'></i></span>
                                    <input type="text" class="form-control" id="withdrawal-address" required placeholder="Your Wallet Address">
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Submit Withdrawal Request</button>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="col-12 mb-4">
                    <div class="card">
                        <div class="card-header"><h5 class="card-title mb-0">Withdrawal History</h5></div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead><tr><th>Amount</th><th>Method</th><th>Status</th><th>Date</th></tr></thead>
                                    <tbody>
                                        ${history.length > 0 ? history.map(w => `
                                            <tr>
                                                <td>${formatCurrency(w.amount)}</td>
                                                <td>${w.method.toUpperCase()}</td>
                                                <td><span class="badge rounded-pill bg-${getStatusClass(w.status)} text-capitalize">${w.status}</span></td>
                                                <td>${new Date(w.date).toLocaleDateString()}</td>
                                            </tr>
                                        `).join('') : `<tr><td colspan="4" class="text-center py-4 text-muted">No withdrawal history.</td></tr>`}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    };

    const getInvestContent = async () => {
        const res = await fetch('/api/packages');
        if (!res.ok) throw new Error('Failed to fetch investment packages');
        const packages = await res.json();

        return `
            <div class="row">
                ${packages.map(p => `
                    <div class="col-lg-4 mb-4">
                        <div class="card h-100 text-center package-card">
                            <div class="card-header bg-primary text-white">
                                <h4 class="card-title mb-0">${escapeHtml(p.name)}</h4>
                            </div>
                            <div class="card-body">
                                <h1 class="card-title">${p.roi_percent}%</h1>
                                <p class="text-muted">After ${p.duration_days} Days</p>
                                <ul class="list-group list-group-flush">
                                    <li class="list-group-item">Min: ${formatCurrency(p.min_amount)}</li>
                                    <li class="list-group-item">Max: ${formatCurrency(p.max_amount)}</li>
                                    <li class="list-group-item">${escapeHtml(p.description)}</li>
                                </ul>
                            </div>
                            <div class="card-footer">
                                <form class="invest-form" data-package-id="${p.id}" data-min="${p.min_amount}" data-max="${p.max_amount}">
                                    <div class="input-group">
                                        <span class="input-group-text">$</span>
                                        <input type="number" class="form-control" placeholder="Amount" required min="${p.min_amount}" max="${p.max_amount}">
                                        <button class="btn btn-primary" type="submit">Invest</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    };

    const getProfileContent = async () => {
        const res = await fetch('/api/user/profile');
        if (!res.ok) throw new Error('Failed to fetch profile');
        const profile = await res.json();

        return `
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header"><h5 class="card-title mb-0">My Profile</h5></div>
                        <div class="card-body">
                            <form id="profile-form">
                                <div class="mb-3">
                                    <label class="form-label">Name</label>
                                    <input type="text" class="form-control" value="${escapeHtml(profile.name)}" readonly>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Username</label>
                                    <input type="text" class="form-control" value="${escapeHtml(profile.username)}" readonly>
                                </div>
                                <div class="mb-3">
                                    <label for="profile-email" class="form-label">Email</label>
                                    <input type="email" class="form-control" id="profile-email" value="${escapeHtml(profile.email)}" required>
                                </div>
                                <div class="mb-3">
                                    <label for="profile-phone" class="form-label">Phone Number</label>
                                    <input type="tel" class="form-control" id="profile-phone" value="${escapeHtml(profile.phone_number)}" required>
                                </div>
                                <button type="submit" class="btn btn-primary">Update Profile</button>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header"><h5 class="card-title mb-0">Change Password</h5></div>
                        <div class="card-body">
                            <form id="password-form">
                                <div class="mb-3">
                                    <label for="current-password" class="form-label">Current Password</label>
                                    <input type="password" class="form-control" id="current-password" required>
                                </div>
                                <div class="mb-3">
                                    <label for="new-password" class="form-label">New Password</label>
                                    <input type="password" class="form-control" id="new-password" required>
                                </div>
                                <button type="submit" class="btn btn-primary">Change Password</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        `;
    };

    const getSupportContent = async () => {
        const res = await fetch('/api/support/tickets');
        if (!res.ok) throw new Error('Failed to fetch support tickets');
        const tickets = await res.json();

        return `
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="card-title mb-0">My Support Tickets</h5>
                    <div>
                        <button id="back-to-tickets-btn" class="btn btn-sm btn-outline-secondary" style="display: none;"><i class='bx bx-arrow-back'></i> Back to List</button>
                        <button id="create-new-ticket-btn" class="btn btn-sm btn-primary"><i class='bx bx-plus'></i> New Ticket</button>
                    </div>
                </div>
                <div class="card-body" id="support-content-area">
                    ${generateTicketListHtml(tickets)}
                </div>
            </div>
        `;
    };

    const generateTicketListHtml = (tickets) => {
        if (tickets.length === 0) {
            return `<div class="text-center p-4">You have not created any support tickets yet.</div>`;
        }
        return `
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead><tr><th>ID</th><th>Subject</th><th>Status</th><th>Last Updated</th><th>Actions</th></tr></thead>
                    <tbody>
                        ${tickets.map(t => `
                            <tr>
                                <td>#${t.id}</td>
                                <td>${escapeHtml(t.subject)}</td>
                                <td><span class="badge rounded-pill bg-${getStatusClass(t.status)}">${t.status}</span></td>
                                <td>${new Date(t.updated_at).toLocaleString()}</td>
                                <td><button class="btn btn-sm btn-primary view-ticket-btn" data-id="${t.id}">View</button></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    };

    const generateNewTicketFormHtml = () => {
        return `
            <form id="new-ticket-form">
                <div class="mb-3">
                    <label for="ticket-subject" class="form-label">Subject</label>
                    <input type="text" id="ticket-subject" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="ticket-message" class="form-label">Message</label>
                    <textarea id="ticket-message" class="form-control" rows="5" required placeholder="Please describe your issue in detail..."></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Submit Ticket</button>
            </form>
        `;
    };

    // --- Event Handlers ---
    const attachEventListeners = (section) => {
        if (section === 'deposit') {
            document.querySelectorAll('.copy-btn').forEach(btn => {
                btn.addEventListener('click', handleCopy);
            });
            document.getElementById('deposit-form').addEventListener('submit', handleDepositSubmit);
        }
        if (section === 'withdraw') {
            document.getElementById('withdrawal-form').addEventListener('submit', handleWithdrawalSubmit);
        }
        if (section === 'invest') {
            document.querySelectorAll('.invest-form').forEach(form => {
                form.addEventListener('submit', handleInvestSubmit);
            });
        }
        if (section === 'profile') {
            document.getElementById('profile-form').addEventListener('submit', handleProfileUpdate);
            document.getElementById('password-form').addEventListener('submit', handlePasswordChange);
        }
        if (section === 'dashboard') {
            initializeDashboardChart();
        }
        if (section === 'portfolio') {
            initializePortfolioCharts();
        }
        if (section === 'support') {
            attachSupportEventListeners();
        }
    };

    const handleCopy = (e) => {
        const targetSelector = e.currentTarget.dataset.clipboardTarget;
        const input = document.querySelector(targetSelector);
        navigator.clipboard.writeText(input.value).then(() => {
            showToast('Copied!', 'Address copied to clipboard.', 'success');
        }).catch(err => {
            showToast('Error', 'Could not copy address.', 'danger');
        });
    };

    const handleDepositSubmit = async (e) => {
        e.preventDefault();
        const amount = document.getElementById('deposit-amount').value;
        const method = document.getElementById('deposit-method').value;
        const txn_id = document.getElementById('deposit-txn').value;

        const res = await fetch('/api/deposit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount, method, txn_id })
        });
        const result = await res.json();
        showToast(result.success ? 'Success' : 'Error', result.message, result.success ? 'success' : 'danger');
        if (result.success) {
            e.target.reset();
            loadSection('deposit');
        }
    };

    const handleWithdrawalSubmit = async (e) => {
        e.preventDefault();
        const amount = document.getElementById('withdrawal-amount').value;
        const method = document.getElementById('withdrawal-method').value;
        const wallet_address = document.getElementById('withdrawal-address').value;

        const res = await fetch('/api/withdrawal', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount, method, wallet_address })
        });
        const result = await res.json();
        showToast(result.success ? 'Success' : 'Error', result.message, result.success ? 'success' : 'danger');
        if (result.success) {
            e.target.reset();
            loadSection('withdraw');
        }
    };

    const handleInvestSubmit = async (e) => {
        e.preventDefault();
        const form = e.currentTarget;
        const packageId = form.dataset.packageId;
        const amount = form.querySelector('input').value;

        const res = await fetch('/api/invest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ packageId, amount })
        });
        const result = await res.json();
        showToast(result.success ? 'Success' : 'Error', result.message, result.success ? 'success' : 'danger');
        if (result.success) {
            form.reset();
        }
    };

    const handleProfileUpdate = async (e) => {
        e.preventDefault();
        const email = document.getElementById('profile-email').value;
        const phone_number = document.getElementById('profile-phone').value;

        const res = await fetch('/api/user/profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, phone_number })
        });
        const result = await res.json();
        showToast(result.success ? 'Success' : 'Error', result.message, result.success ? 'success' : 'danger');
    };

    const handlePasswordChange = async (e) => {
        e.preventDefault();
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password').value;

        const res = await fetch('/api/user/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currentPassword, newPassword })
        });
        const result = await res.json();
        showToast(result.success ? 'Success' : 'Error', result.message, result.success ? 'success' : 'danger');
        if (result.success) e.target.reset();
    };

    const attachSupportEventListeners = () => {
        const createBtn = document.getElementById('create-new-ticket-btn');
        const backBtn = document.getElementById('back-to-tickets-btn');
        const supportArea = document.getElementById('support-content-area');

        createBtn.addEventListener('click', () => {
            supportArea.innerHTML = generateNewTicketFormHtml();
            createBtn.style.display = 'none';
            backBtn.style.display = 'inline-block';
            document.getElementById('new-ticket-form').addEventListener('submit', handleNewTicketSubmit);
        });

        backBtn.addEventListener('click', () => loadSection('support'));

        document.querySelectorAll('.view-ticket-btn').forEach(btn => {
            btn.addEventListener('click', (e) => viewTicket(e.currentTarget.dataset.id));
        });
    };

    const handleNewTicketSubmit = async (e) => {
        e.preventDefault();
        const subject = document.getElementById('ticket-subject').value;
        const message = document.getElementById('ticket-message').value;

        const res = await fetch('/api/support/tickets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ subject, message })
        });
        const result = await res.json();
        showToast(result.success ? 'Success' : 'Error', result.message, result.success ? 'success' : 'danger');
        if (result.success) {
            loadSection('support');
        }
    };

    const viewTicket = async (ticketId) => {
        const res = await fetch(`/api/support/tickets/${ticketId}`);
        if (!res.ok) { 
            showToast('Error', 'Could not load ticket details.', 'danger');
            return;
        }
        const data = await res.json();
        const supportArea = document.getElementById('support-content-area');

        document.getElementById('create-new-ticket-btn').style.display = 'none';
        document.getElementById('back-to-tickets-btn').style.display = 'inline-block';

        supportArea.innerHTML = `
            <h5>${escapeHtml(data.ticket.subject)}</h5>
            <p class="text-muted">Status: <span class="badge rounded-pill bg-${getStatusClass(data.ticket.status)}">${data.ticket.status}</span></p>
            <hr>
            <div class="message-thread mb-4" style="max-height: 400px; overflow-y: auto; padding: 1rem; background: #f8f9fa; border-radius: 8px;">
                ${data.messages.map(m => `
                    <div class="message-bubble ${m.is_admin_reply ? 'admin' : 'user'} mb-3">
                        <p class="mb-1">${escapeHtml(m.message).replace(/\n/g, '<br>')}</p>
                        <small class="text-muted">${m.is_admin_reply ? 'Support Team' : 'You'} &bull; ${new Date(m.created_at).toLocaleString()}</small>
                    </div>
                `).join('')}
            </div>
            ${data.ticket.status !== 'Closed' ? `
            <form id="reply-ticket-form" data-ticket-id="${ticketId}">
                <div class="mb-3">
                    <label for="reply-message" class="form-label">Your Reply</label>
                    <textarea id="reply-message" class="form-control" rows="4" required></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Send Reply</button>
            </form>
            ` : '<div class="alert alert-secondary">This ticket is closed. Please create a new one if you need further assistance.</div>'}
        `;
        
        // Attach event listener to the newly created reply form
        const replyForm = document.getElementById('reply-ticket-form');
        if (replyForm) {
            replyForm.addEventListener('submit', handleUserReplySubmit);
        }
    };

    const handleUserReplySubmit = async (e) => {
        e.preventDefault();
        const form = e.currentTarget;
        const ticketId = form.dataset.ticketId;
        const message = document.getElementById('reply-message').value;

        const res = await fetch(`/api/support/tickets/${ticketId}/reply`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        const result = await res.json();
        showToast(result.success ? 'Success' : 'Error', result.message, result.success ? 'success' : 'danger');
        if (result.success) viewTicket(ticketId); // Refresh the ticket view
    };

    // --- Notifications ---
    const updateNotificationCount = async () => {
        const res = await fetch('/api/notifications/count');
        const data = await res.json();
        const countBadge = document.getElementById('notification-count');
        countBadge.textContent = data.count;
        countBadge.style.display = data.count > 0 ? 'block' : 'none';
    };

    const loadNotifications = async () => {
        const list = document.getElementById('notification-list');
        list.innerHTML = '<div class="p-3 text-center">Loading...</div>';
        const res = await fetch('/api/notifications');
        const notifications = await res.json();

        if (notifications.length > 0) {
            list.innerHTML = notifications.map(n => `
                <div class="notification-item ${!n.is_read ? 'unread' : ''}">
                    <p class="mb-0">${escapeHtml(n.message)}</p>
                    <small class="text-muted">${new Date(n.created_at).toLocaleString()}</small>
                </div>
            `).join('');
            // Mark as read after viewing
            fetch('/api/notifications/mark-read', { method: 'POST' });
            setTimeout(updateNotificationCount, 1000); // Update count after a short delay
        } else {
            list.innerHTML = '<div class="p-3 text-center text-muted">No new notifications.</div>';
        }
    };

    // --- Helpers ---
    const formatCurrency = (amount) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
    const escapeHtml = (unsafe) => (unsafe === null || unsafe === undefined) ? '' : unsafe.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    const getStatusClass = (status) => ({ 'completed': 'success', 'active': 'primary', 'pending': 'warning', 'rejected': 'danger', 'open': 'info', 'answered': 'success', 'closed': 'secondary' }[(status || '').toLowerCase()] || 'secondary');
    const createAlert = (message, type = 'info') => `<div class="alert alert-${type}">${message}</div>`;
    const createStatCard = (title, value, icon, color) => `
        <div class="card stat-card h-100">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6 class="text-muted">${title}</h6>
                        <h4 class="mb-0">${value}</h4>
                    </div>
                    <div class="avatar">
                        <div class="avatar-title rounded-circle bg-soft-${color}">
                            <i class='bx ${icon} text-${color}'></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    const showToast = (title, body, type = 'info') => {
        const toastEl = document.getElementById('appToast');
        const toastTitle = document.getElementById('toast-title');
        const toastBody = document.getElementById('toast-body');

        toastEl.classList.remove('bg-success', 'bg-danger', 'bg-info', 'bg-warning');
        toastEl.classList.add(`bg-${type}`, 'text-white');

        toastTitle.textContent = title;
        toastBody.textContent = body;

        const toast = new bootstrap.Toast(toastEl);
        toast.show();
    };

    const initializePortfolioCharts = () => {
        const analyticsData = window.tempChartData;
        if (!analyticsData) return;

        // 1. Portfolio Growth Chart (Line)
        const growthCtx = document.getElementById('portfolioGrowthChart');
        if (growthCtx && analyticsData.portfolioGrowth.labels.length > 0) {
            const gradient = growthCtx.getContext('2d').createLinearGradient(0, 0, 0, growthCtx.offsetHeight);
            gradient.addColorStop(0, 'rgba(217, 119, 6, 0.3)');
            gradient.addColorStop(1, 'rgba(217, 119, 6, 0)');

            const growthChart = new Chart(growthCtx, {
                type: 'line',
                data: {
                    labels: analyticsData.portfolioGrowth.labels,
                    datasets: [{
                        label: 'Portfolio Value',
                        data: analyticsData.portfolioGrowth.data,
                        borderColor: 'var(--primary-color)',
                        tension: 0.1,
                        fill: true,
                        backgroundColor: gradient
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { y: { beginAtZero: true } }
                }
            });
            activeCharts.push(growthChart);
        }

        // 2. Asset Allocation Chart (Doughnut)
        const allocationCtx = document.getElementById('assetAllocationChart');
        if (allocationCtx && analyticsData.assetAllocation.labels.length > 0) {
            const allocationChart = new Chart(allocationCtx, {
                type: 'doughnut',
                data: {
                    labels: analyticsData.assetAllocation.labels,
                    datasets: [{
                        label: 'Allocation',
                        data: analyticsData.assetAllocation.data,
                        backgroundColor: [
                            '#D97706', // Primary Gold
                            '#198754', // Success Green
                            '#FFC107', // Warning Yellow
                            '#FD7E14', // Orange
                            '#6F42C1', // Accent Purple
                            '#DC3545'  // Red
                        ],
                        hoverOffset: 4,
                        borderColor: 'var(--card-bg)' // Match card background for separation
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                }
            });
            activeCharts.push(allocationChart);
        }
        delete window.tempChartData; // Clean up temp data
    };

    const initializeDashboardChart = () => {
        const analyticsData = window.tempChartData;
        if (!analyticsData) return;

        const growthCtx = document.getElementById('dashboardGrowthChart');
        if (growthCtx && analyticsData.portfolioGrowth.labels.length > 0) {
            const gradient = growthCtx.getContext('2d').createLinearGradient(0, 0, 0, growthCtx.offsetHeight);
            gradient.addColorStop(0, 'rgba(217, 119, 6, 0.4)');
            gradient.addColorStop(1, 'rgba(217, 119, 6, 0)');

            const growthChart = new Chart(growthCtx, {
                type: 'line',
                data: {
                    labels: analyticsData.portfolioGrowth.labels,
                    datasets: [{
                        label: 'Total Invested Value',
                        data: analyticsData.portfolioGrowth.data,
                        borderColor: 'var(--primary-color)',
                        tension: 0.2,
                        fill: true,
                        backgroundColor: gradient
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { y: { beginAtZero: true } }
                }
            });
            activeCharts.push(growthChart);
        }
        delete window.tempChartData; // Clean up temp data
    };

    // --- Kick it off ---
    initializeDashboard();
});