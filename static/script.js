document.addEventListener('DOMContentLoaded', function() {

    // ==================== Auth System ====================

    var authScreen = document.getElementById('auth-screen');
    var appLayout = document.getElementById('app-layout');
    var currentUser = null;

    function authFetch(url, opts) {
        opts = opts || {};
        opts.headers = opts.headers || {};
        opts.credentials = 'same-origin';
        return fetch(url, opts).then(function(r) {
            if (r.status === 401 && !url.includes('/auth/')) {
                showAuthScreen();
                return Promise.reject(new Error('Session expired'));
            }
            return r;
        });
    }

    function showAuthScreen() {
        authScreen.style.display = 'flex';
        appLayout.style.display = 'none';
    }

    function showApp(user) {
        currentUser = user;
        authScreen.style.display = 'none';
        appLayout.style.display = '';
        // Update sidebar user info
        if (user) {
            var avatar = document.getElementById('user-avatar');
            var name = document.getElementById('user-display-name');
            var role = document.getElementById('user-role-badge');
            if (avatar) avatar.textContent = (user.display_name || user.username || '?')[0].toUpperCase();
            if (name) name.textContent = user.display_name || user.username;
            if (role) role.textContent = user.role;
        }
    }

    function checkAuth() {
        fetch('/api/v1/auth/me', { credentials: 'same-origin' })
            .then(function(r) {
                if (r.ok) return r.json();
                throw new Error('Not authenticated');
            })
            .then(function(data) {
                if (data.user) {
                    showApp(data.user);
                } else if (data.setup_mode) {
                    // No users — show setup form
                    authScreen.style.display = 'flex';
                    appLayout.style.display = 'none';
                    document.getElementById('auth-login-form').style.display = 'none';
                    document.getElementById('auth-setup-form').style.display = '';
                } else {
                    showAuthScreen();
                }
            })
            .catch(function() {
                // Check if setup mode (no users)
                fetch('/api/v1/auth/me').then(function(r) { return r.json(); })
                    .then(function(data) {
                        if (data.setup_mode) {
                            authScreen.style.display = 'flex';
                            appLayout.style.display = 'none';
                            document.getElementById('auth-login-form').style.display = 'none';
                            document.getElementById('auth-setup-form').style.display = '';
                        } else {
                            showAuthScreen();
                        }
                    })
                    .catch(function() { showAuthScreen(); });
            });
    }

    // Login handler
    document.getElementById('auth-login-btn').addEventListener('click', function() {
        var username = document.getElementById('auth-username').value.trim();
        var password = document.getElementById('auth-password').value;
        var errDiv = document.getElementById('auth-error');
        errDiv.style.display = 'none';

        if (!username || !password) { errDiv.textContent = 'Please enter username and password'; errDiv.style.display = ''; return; }

        fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password }),
            credentials: 'same-origin',
        }).then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
          .then(function(res) {
              if (res.ok) {
                  showApp(res.data.user);
              } else {
                  errDiv.textContent = res.data.error || 'Login failed';
                  errDiv.style.display = '';
              }
          })
          .catch(function() { errDiv.textContent = 'Connection error'; errDiv.style.display = ''; });
    });

    // Enter key on password field
    document.getElementById('auth-password').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') document.getElementById('auth-login-btn').click();
    });

    // Setup handler
    document.getElementById('auth-setup-btn').addEventListener('click', function() {
        var username = document.getElementById('setup-username').value.trim();
        var email = document.getElementById('setup-email').value.trim();
        var password = document.getElementById('setup-password').value;
        var confirm = document.getElementById('setup-password-confirm').value;
        var errDiv = document.getElementById('setup-error');
        errDiv.style.display = 'none';

        if (!username) { errDiv.textContent = 'Username is required'; errDiv.style.display = ''; return; }
        if (password.length < 8) { errDiv.textContent = 'Password must be at least 8 characters'; errDiv.style.display = ''; return; }
        if (password !== confirm) { errDiv.textContent = 'Passwords do not match'; errDiv.style.display = ''; return; }

        fetch('/api/v1/auth/setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password, email: email || null }),
            credentials: 'same-origin',
        }).then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
          .then(function(res) {
              if (res.ok) {
                  showApp(res.data.user);
              } else {
                  errDiv.textContent = res.data.error || 'Setup failed';
                  errDiv.style.display = '';
              }
          })
          .catch(function() { errDiv.textContent = 'Connection error'; errDiv.style.display = ''; });
    });

    // Logout handler
    var logoutBtn = document.getElementById('btn-logout');
    if (logoutBtn) logoutBtn.addEventListener('click', function() {
        fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' })
            .finally(function() {
                currentUser = null;
                showAuthScreen();
                document.getElementById('auth-username').value = '';
                document.getElementById('auth-password').value = '';
            });
    });

    // Initial auth check
    checkAuth();

    var socket = io();

    // ==================== Utility Functions ====================

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function formatDate(dateStr) {
        if (!dateStr) return 'Unknown';
        try {
            var date = new Date(dateStr.replace(' ', 'T'));
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        } catch (e) { return dateStr; }
    }

    function showToast(message, type) {
        type = type || 'info';
        var container = document.getElementById('toast-container');
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(function() { toast.remove(); }, 4000);
    }

    function downloadBlob(content, filename, mime) {
        var blob = new Blob([content], { type: mime });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url; a.download = filename;
        document.body.appendChild(a); a.click();
        document.body.removeChild(a); URL.revokeObjectURL(url);
    }

    function apiFetch(url, options) {
        options = options || {};
        return fetch(url, options)
            .then(function(r) {
                if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || 'Request failed'); });
                return r.json();
            });
    }

    // Source badge helpers
    var sourceLabels = {
        'nuclei': '🔬 Nuclei', 'nvd-local': '📦 NVD', 'nmap-vulscan': '🔍 Nmap',
        'auth-scan': '🔑 Auth', 'exploit-db': '💥 Exploit'
    };

    function renderSourceBadges(sources) {
        var html = '<div class="source-badges">';
        (sources || []).forEach(function(src) {
            var label = sourceLabels[src] || src;
            var cls = src.replace(/[^a-z-]/g, '');
            html += '<span class="source-badge ' + cls + '">' + label + '</span>';
        });
        return html + '</div>';
    }

    function renderAssetBadges(assets) {
        if (!assets || !assets.length) return '';
        var html = '<div class="vuln-assets">';
        assets.slice(0, 5).forEach(function(a) {
            var label = a.port > 0 ? (a.ip + ':' + a.port) : a.ip;
            html += '<span class="vuln-asset-badge">' + escapeHtml(label) + '</span>';
        });
        if (assets.length > 5) html += '<span class="vuln-asset-badge">+' + (assets.length - 5) + ' more</span>';
        return html + '</div>';
    }

    // ==================== Theme Management ====================

    var themeOptions = document.querySelectorAll('.theme-option');
    var currentTheme = localStorage.getItem('theme') || 'light';

    function applyTheme(theme) {
        document.body.className = 'theme-' + theme;
        currentTheme = theme;
        localStorage.setItem('theme', theme);
        // Update theme toggle icon
        var toggleIcon = document.querySelector('.theme-toggle-icon');
        if (toggleIcon) toggleIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
        // Update active state on theme options
        themeOptions.forEach(function(option) {
            option.classList.toggle('active', option.getAttribute('data-theme') === theme);
        });
    }

    applyTheme(currentTheme);

    themeOptions.forEach(function(option) {
        option.addEventListener('click', function() { applyTheme(this.getAttribute('data-theme')); });
    });

    // Theme toggle in sidebar footer
    var themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            applyTheme(currentTheme === 'dark' ? 'light' : 'dark');
        });
    }

    // ==================== Navigation — Sidebar ====================

    var navItems = document.querySelectorAll('.nav-item');
    var pages = document.querySelectorAll('.page');
    var sidebar = document.getElementById('sidebar');
    var hamburger = document.getElementById('hamburger');
    var sidebarClose = document.getElementById('sidebar-close');

    // Create overlay for mobile
    var overlay = document.createElement('div');
    overlay.className = 'sidebar-overlay';
    document.body.appendChild(overlay);

    function navigateTo(pageName) {
        navItems.forEach(function(n) { n.classList.toggle('active', n.getAttribute('data-page') === pageName); });
        pages.forEach(function(p) { p.classList.toggle('active', p.id === 'page-' + pageName); });

        // Close mobile sidebar
        sidebar.classList.remove('open');
        overlay.classList.remove('visible');

        // Load data for the page
        if (pageName === 'dashboard') loadDashboard();
        else if (pageName === 'assets') loadAssets();
        else if (pageName === 'vulns') loadVulnerabilities();
        else if (pageName === 'sites') loadSites();
        else if (pageName === 'schedules') loadSchedules();
        else if (pageName === 'agents') loadAgents();
        else if (pageName === 'sql') setTimeout(initSqlTab, 50);
    }

    navItems.forEach(function(item) {
        item.addEventListener('click', function() { navigateTo(this.getAttribute('data-page')); });
    });

    if (hamburger) hamburger.addEventListener('click', function() {
        sidebar.classList.add('open');
        overlay.classList.add('visible');
    });
    if (sidebarClose) sidebarClose.addEventListener('click', function() {
        sidebar.classList.remove('open');
        overlay.classList.remove('visible');
    });
    overlay.addEventListener('click', function() {
        sidebar.classList.remove('open');
        overlay.classList.remove('visible');
    });

    // ==================== Log Panel ====================

    var logContent = document.getElementById('log-content');
    var logClearBtn = document.getElementById('log-clear');
    var logToggle = document.getElementById('log-toggle');
    var logPanel = document.getElementById('log-panel');
    var logPanelHeader = document.getElementById('log-panel-header');
    var maxLogEntries = 500;
    var logExpanded = localStorage.getItem('logExpanded') !== 'false';

    function updateLogPanel() {
        logPanel.classList.toggle('collapsed', !logExpanded);
        if (logToggle) logToggle.textContent = logExpanded ? '▼' : '▲';
    }
    updateLogPanel();

    if (logToggle) logToggle.addEventListener('click', function(e) {
        e.stopPropagation();
        logExpanded = !logExpanded;
        localStorage.setItem('logExpanded', logExpanded);
        updateLogPanel();
    });

    if (logPanelHeader) logPanelHeader.addEventListener('click', function() {
        logExpanded = !logExpanded;
        localStorage.setItem('logExpanded', logExpanded);
        updateLogPanel();
    });

    function getTimestamp() {
        var now = new Date();
        return now.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(now.getMilliseconds()).padStart(3, '0');
    }

    function addLog(message, level) {
        level = level || 'info';
        if (!logContent) return;
        var emptyState = logContent.querySelector('.log-empty');
        if (emptyState) emptyState.remove();

        var entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.innerHTML = '<span class="log-timestamp">' + getTimestamp() + '</span>' +
            '<span class="log-level ' + level + '">' + level + '</span>' +
            '<span class="log-message">' + escapeHtml(message) + '</span>';
        logContent.appendChild(entry);

        while (logContent.children.length > maxLogEntries) logContent.removeChild(logContent.firstChild);
        logContent.scrollTop = logContent.scrollHeight;
    }

    function clearLogs() {
        if (logContent) logContent.innerHTML = '<div class="log-empty">No log entries yet. Start a scan to see logs.</div>';
    }

    clearLogs();
    if (logClearBtn) logClearBtn.addEventListener('click', clearLogs);

    socket.on('scan_log', function(data) { addLog(data.message, data.level || 'info'); });

    // Site scan events → log panel
    socket.on('site_scan_started', function(data) {
        addLog('Site scan started: ' + (data.site_name || 'Site #' + data.site_id) + ' (' + data.targets_total + ' targets)', 'info');
        if (!logExpanded) { logExpanded = true; localStorage.setItem('logExpanded', true); updateLogPanel(); }
    });
    socket.on('site_scan_progress', function(data) {
        addLog('Scanning target ' + data.current + '/' + data.total + ': ' + data.target, 'info');
    });
    socket.on('site_scan_completed', function(data) {
        var level = data.status === 'success' ? 'success' : (data.status === 'partial' ? 'warning' : 'error');
        addLog('Site scan ' + data.status + ': ' + data.targets_scanned + ' scanned, ' + data.targets_failed + ' failed, ' + data.ports_found + ' ports, ' + data.vulns_found + ' vulns (' + data.duration_seconds + 's)', level);
        if (data.new_vulns > 0) addLog('⚠️ ' + data.new_vulns + ' new vulnerability(ies) found!', 'warning');
        loadSites();
        loadDashboard();
    });

    // ==================== Scan Settings Management ====================

    var defaultSettings = {
        ports: '', scanSpeed: 'T3', hostTimeout: 300, maxHosts: 256, vulscan: false,
        vulnTimeout: 600, severity: 'critical,high,medium,low', rateLimit: 150, templates: ''
    };

    function loadSettings() {
        var saved = localStorage.getItem('scanSettings');
        if (saved) { try { return JSON.parse(saved); } catch (e) {} }
        return defaultSettings;
    }

    function saveSettings(settings) { localStorage.setItem('scanSettings', JSON.stringify(settings)); }

    function getSettingsFromForm() {
        return {
            ports: document.getElementById('setting-ports').value.trim(),
            scanSpeed: document.getElementById('setting-scan-speed').value,
            hostTimeout: parseInt(document.getElementById('setting-host-timeout').value) || 300,
            maxHosts: parseInt(document.getElementById('setting-max-hosts').value) || 256,
            vulscan: document.getElementById('setting-vulscan').checked,
            vulnTimeout: parseInt(document.getElementById('setting-vuln-timeout').value) || 600,
            severity: document.getElementById('setting-severity').value,
            rateLimit: parseInt(document.getElementById('setting-rate-limit').value) || 150,
            templates: document.getElementById('setting-templates').value.trim()
        };
    }

    function applySettingsToForm(settings) {
        document.getElementById('setting-ports').value = settings.ports || '';
        document.getElementById('setting-scan-speed').value = settings.scanSpeed || 'T3';
        document.getElementById('setting-host-timeout').value = settings.hostTimeout || 300;
        document.getElementById('setting-max-hosts').value = settings.maxHosts || 256;
        document.getElementById('setting-vulscan').checked = settings.vulscan || false;
        document.getElementById('setting-vuln-timeout').value = settings.vulnTimeout || 600;
        document.getElementById('setting-severity').value = settings.severity || 'critical,high,medium,low';
        document.getElementById('setting-rate-limit').value = settings.rateLimit || 150;
        document.getElementById('setting-templates').value = settings.templates || '';
    }

    function showSettingsStatus(message, isError) {
        var statusEl = document.getElementById('settings-status');
        if (statusEl) {
            statusEl.textContent = message;
            statusEl.classList.toggle('error', !!isError);
            statusEl.classList.add('visible');
            setTimeout(function() { statusEl.classList.remove('visible'); }, 3000);
        }
    }

    function getScanSettings() { return loadSettings(); }

    var saveSettingsBtn = document.getElementById('save-settings');
    var resetSettingsBtn = document.getElementById('reset-settings');

    if (saveSettingsBtn) {
        applySettingsToForm(loadSettings());
        saveSettingsBtn.addEventListener('click', function() {
            var settings = getSettingsFromForm();
            if (settings.hostTimeout < 30 || settings.hostTimeout > 3600) { showSettingsStatus('Host timeout must be between 30-3600 seconds', true); return; }
            if (settings.maxHosts < 1 || settings.maxHosts > 1024) { showSettingsStatus('Max hosts must be between 1-1024', true); return; }
            if (settings.vulnTimeout < 60 || settings.vulnTimeout > 3600) { showSettingsStatus('Vuln timeout must be between 60-3600 seconds', true); return; }
            if (settings.rateLimit < 10 || settings.rateLimit > 1000) { showSettingsStatus('Rate limit must be between 10-1000 req/sec', true); return; }
            saveSettings(settings);
            showSettingsStatus('Settings saved successfully');
            showToast('Settings saved', 'success');
        });
    }

    if (resetSettingsBtn) {
        resetSettingsBtn.addEventListener('click', function() {
            applySettingsToForm(defaultSettings);
            saveSettings(defaultSettings);
            showSettingsStatus('Settings reset to defaults');
        });
    }

    // ==================== Scan Tab Elements ====================

    var scanForm = document.getElementById('scan-form');
    var progressBar = document.getElementById('progress-bar');
    var progressContainer = document.getElementById('progress-container');
    var progressMessage = document.getElementById('progress-message');
    var scanOutput = document.getElementById('scan-output');
    var portScanBtn = document.getElementById('port-scan-btn');
    var vulnScanBtn = document.getElementById('vuln-scan-btn');
    var fingerprintScanBtn = document.getElementById('fingerprint-scan-btn');
    var stopScanBtn = document.getElementById('stop-scan-btn');
    var assetsList = document.getElementById('assets-list');
    var assetsCount = document.getElementById('assets-count');
    var refreshAssetsBtn = document.getElementById('refresh-assets');
    var vulnsList = document.getElementById('vulns-list');
    var refreshVulnsBtn = document.getElementById('refresh-vulns');
    var vulnFilter = document.getElementById('vuln-filter');

    // ==================== Modals ====================

    var cveModal = document.getElementById('cve-modal');
    var modalBody = document.getElementById('modal-body');
    var modalClose = document.getElementById('modal-close');
    var assetModal = document.getElementById('asset-modal');
    var assetModalBody = document.getElementById('asset-modal-body');
    var assetModalClose = document.getElementById('asset-modal-close');
    var genericModal = document.getElementById('generic-modal');
    var genericModalBody = document.getElementById('generic-modal-body');
    var genericModalClose = document.getElementById('generic-modal-close');

    var storedVulnerabilities = [];

    function showCveModal(vuln) {
        var cvssClass = '';
        if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
            cvssClass = vuln.cvss_score >= 9.0 ? 'critical' : (vuln.cvss_score >= 7.0 ? 'high' : (vuln.cvss_score >= 4.0 ? 'medium' : 'low'));
        }
        var cveId = vuln.cve_id || vuln.vuln_id || '';

        var html = '<div class="modal-header"><div>';
        if (cveId.toUpperCase().indexOf('CVE-') === 0) {
            html += '<h2 class="modal-cve-id"><a href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(cveId) + '" target="_blank" rel="noopener">' + escapeHtml(cveId) + ' ↗</a></h2>';
        } else {
            html += '<h2 class="modal-cve-id">' + escapeHtml(cveId) + '</h2>';
        }
        html += '<div class="modal-badges">';
        html += '<span class="severity-badge ' + vuln.severity + '">' + vuln.severity.toUpperCase() + '</span>';
        if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) html += '<span class="cvss-badge ' + cvssClass + '">CVSS ' + vuln.cvss_score.toFixed(1) + '</span>';
        if (vuln.has_exploit) html += '<span class="exploit-warning">⚠️ Public Exploit</span>';
        if (vuln.cwe_id) html += '<span class="cwe-badge">' + vuln.cwe_id + '</span>';
        html += '</div></div></div>';

        // Detection Sources
        html += '<div class="modal-section"><div class="modal-section-title">Detection Sources</div><div class="modal-sources-grid">';
        (vuln.detection_sources || []).forEach(function(src) {
            var label = sourceLabels[src] || src;
            var cls = src.replace(/[^a-z-]/g, '');
            html += '<div class="modal-source-item"><span class="source-badge ' + cls + '">' + label + '</span><div class="modal-source-detail">';
            if (src === 'nuclei' && vuln.template_id) { html += 'Template: ' + escapeHtml(vuln.template_id); if (vuln.nuclei_scan_date) html += '<br>Scanned: ' + formatDate(vuln.nuclei_scan_date); }
            else if ((src === 'auth-scan' || src === 'nvd-local') && vuln.affected_cpe) html += (src === 'auth-scan' ? 'Package: ' : 'CPE: ') + escapeHtml(vuln.affected_cpe);
            else if (src === 'exploit-db') html += 'Public exploit available';
            else if (src === 'nmap-vulscan') html += 'Service version matching';
            html += '</div></div>';
        });
        html += '</div></div>';

        // Affected Assets
        if (vuln.affected_assets && vuln.affected_assets.length > 0) {
            html += '<div class="modal-section"><div class="modal-section-title">Affected Assets (' + vuln.affected_assets.length + ')</div><div style="display:flex;flex-wrap:wrap;gap:6px">';
            vuln.affected_assets.forEach(function(a) {
                var label = a.port > 0 ? (a.ip + ':' + a.port + '/' + a.protocol) : a.ip;
                html += '<span class="modal-target">' + escapeHtml(label) + '</span>';
            });
            html += '</div></div>';
        }

        // CVSS Details
        if (vuln.cvss_score !== null || vuln.cvss_vector || vuln.cvss_v2_score) {
            html += '<div class="modal-section"><div class="modal-section-title">CVSS Details</div><div class="modal-cvss-details">';
            if (vuln.cvss_v3_score !== null && vuln.cvss_v3_score !== undefined) {
                html += '<div class="modal-cvss-item"><div class="modal-cvss-label">CVSS v3</div><div class="modal-cvss-value ' + cvssClass + '">' + vuln.cvss_v3_score.toFixed(1) + '</div></div>';
            }
            if (vuln.cvss_v2_score !== null && vuln.cvss_v2_score !== undefined) {
                var v2Class = vuln.cvss_v2_score >= 9.0 ? 'critical' : (vuln.cvss_v2_score >= 7.0 ? 'high' : (vuln.cvss_v2_score >= 4.0 ? 'medium' : 'low'));
                html += '<div class="modal-cvss-item"><div class="modal-cvss-label">CVSS v2</div><div class="modal-cvss-value ' + v2Class + '">' + vuln.cvss_v2_score.toFixed(1) + '</div></div>';
            }
            html += '<div class="modal-cvss-item"><div class="modal-cvss-label">Severity</div><div class="modal-cvss-value ' + cvssClass + '">' + vuln.severity.toUpperCase() + '</div></div>';
            html += '</div>';
            if (vuln.cvss_vector) html += '<div class="modal-vector" style="margin-top:10px">' + escapeHtml(vuln.cvss_vector) + '</div>';
            html += '</div>';
        }

        // Affected Software
        if (vuln.affected_cpe) {
            html += '<div class="modal-section"><div class="modal-section-title">Affected Software</div>';
            vuln.affected_cpe.split(',').map(function(s) { return s.trim(); }).filter(Boolean).forEach(function(cpe) {
                html += '<div class="cpe-badge" style="display:block;margin-bottom:4px;white-space:normal;max-width:none">' + escapeHtml(cpe) + '</div>';
            });
            html += '</div>';
        }

        // Description
        html += '<div class="modal-section"><div class="modal-section-title">Description</div><div class="modal-description">' + escapeHtml(vuln.description || 'No description available.') + '</div></div>';

        // Exploit Info
        if (vuln.has_exploit) {
            html += '<div class="modal-section"><div class="modal-section-title">Exploit Information</div><div class="modal-exploit-section"><span class="exploit-warning">⚠️ Public Exploit Available</span><div class="modal-exploit-links">';
            if (vuln.exploit_ids) {
                vuln.exploit_ids.split(',').forEach(function(eid) {
                    eid = eid.trim();
                    if (eid) html += '<a href="https://www.exploit-db.com/exploits/' + encodeURIComponent(eid) + '" target="_blank" rel="noopener">ExploitDB #' + escapeHtml(eid) + '</a>';
                });
            }
            if (vuln.exploit_url) html += '<a href="' + escapeHtml(vuln.exploit_url) + '" target="_blank" rel="noopener">' + escapeHtml(vuln.exploit_url) + '</a>';
            html += '<a href="https://www.exploit-db.com/search?cve=' + encodeURIComponent(cveId) + '" target="_blank" rel="noopener">Search ExploitDB for ' + escapeHtml(cveId) + '</a>';
            html += '</div></div></div>';
        }

        // References
        if (vuln.references && vuln.references.length > 0) {
            html += '<div class="modal-section"><div class="modal-section-title">References (' + vuln.references.length + ')</div><ul class="modal-refs-list">';
            vuln.references.forEach(function(ref) {
                if (ref.url) {
                    html += '<li><a href="' + escapeHtml(ref.url) + '" target="_blank" rel="noopener">' + escapeHtml(ref.url) + '</a>';
                    if (ref.source) html += '<span class="modal-ref-source">(' + escapeHtml(ref.source) + ')</span>';
                    html += '</li>';
                }
            });
            html += '</ul></div>';
        }

        // Dates
        html += '<div class="modal-section"><div class="modal-section-title">Dates</div><div class="modal-dates">';
        if (vuln.published_date) html += '<div class="modal-date-item"><span class="modal-date-label">Published</span><span class="modal-date-value">' + formatDate(vuln.published_date) + '</span></div>';
        if (vuln.last_modified) html += '<div class="modal-date-item"><span class="modal-date-label">Last Modified</span><span class="modal-date-value">' + formatDate(vuln.last_modified) + '</span></div>';
        html += '<div class="modal-date-item"><span class="modal-date-label">Discovered</span><span class="modal-date-value">' + formatDate(vuln.scan_date) + '</span></div>';
        html += '</div></div>';

        modalBody.innerHTML = html;
        cveModal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }

    function closeCveModal() { cveModal.style.display = 'none'; document.body.style.overflow = ''; }
    if (modalClose) modalClose.addEventListener('click', closeCveModal);
    if (cveModal) cveModal.addEventListener('click', function(e) { if (e.target === cveModal) closeCveModal(); });

    // Asset modal
    function showAssetModal(ip) {
        if (!assetModal || !assetModalBody) return;
        assetModalBody.innerHTML = '<div class="asset-modal-loading"><div class="spinner"></div><p>Loading asset details...</p></div>';
        assetModal.style.display = 'flex';
        document.body.style.overflow = 'hidden';

        fetch('/api/asset/' + encodeURIComponent(ip))
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.error) { assetModalBody.innerHTML = '<div class="asset-modal-loading"><p class="error">Error: ' + escapeHtml(data.error) + '</p></div>'; return; }
                renderAssetModal(data.asset);
            })
            .catch(function() { assetModalBody.innerHTML = '<div class="asset-modal-loading"><p class="error">Failed to load asset details</p></div>'; });
    }

    function renderAssetModal(asset) {
        var html = '<div class="asset-modal-header">';
        html += '<h2 class="asset-modal-ip">' + escapeHtml(asset.ip) + '</h2>';
        if (asset.hostname) html += '<p class="asset-modal-hostname">' + escapeHtml(asset.hostname) + '</p>';

        html += '<div class="asset-modal-meta">';
        if (asset.device_type && asset.device_type !== 'unknown') {
            var dtIcons = {'router':'📡','computer':'🖥️','printer':'🖨️','firewall':'🔥','switch':'🔀','iot':'🏠','media device':'📺','phone':'📱','server':'🗄️','game console':'🎮','storage':'💾','access point':'📶'};
            html += '<span class="asset-meta-badge device">' + (dtIcons[asset.device_type] || '❓') + ' ' + escapeHtml(asset.device_type) + '</span>';
        }
        if (asset.os_name) html += '<span class="asset-meta-badge os">' + escapeHtml(asset.os_name) + '</span>';
        if (asset.mac_vendor) html += '<span class="asset-meta-badge">' + escapeHtml(asset.mac_vendor) + '</span>';
        html += '</div>';
        html += '<div class="asset-modal-actions"><button class="btn btn-report" onclick="window.open(\'/report/' + encodeURIComponent(asset.ip) + '\', \'_blank\')">Generate Report</button></div>';
        html += '</div>';

        html += '<div class="asset-modal-grid">';

        // Network Info
        html += '<div class="asset-modal-section"><div class="asset-section-title">Network Information</div><ul class="asset-info-list">';
        html += '<li><span class="asset-info-label">IP Address</span><span class="asset-info-value">' + escapeHtml(asset.ip) + '</span></li>';
        html += '<li><span class="asset-info-label">Hostname</span><span class="asset-info-value' + (asset.hostname ? '' : ' none') + '">' + (asset.hostname ? escapeHtml(asset.hostname) : 'Not resolved') + '</span></li>';
        html += '<li><span class="asset-info-label">Reverse DNS</span><span class="asset-info-value' + (asset.reverse_dns ? '' : ' none') + '">' + (asset.reverse_dns ? escapeHtml(asset.reverse_dns) : 'Not available') + '</span></li>';
        html += '<li><span class="asset-info-label">MAC Address</span><span class="asset-info-value' + (asset.mac_address ? '' : ' none') + '">' + (asset.mac_address ? escapeHtml(asset.mac_address) : 'Not available') + '</span></li>';
        html += '<li><span class="asset-info-label">MAC Vendor</span><span class="asset-info-value' + (asset.mac_vendor ? '' : ' none') + '">' + (asset.mac_vendor ? escapeHtml(asset.mac_vendor) : 'Unknown') + '</span></li>';
        html += '</ul></div>';

        // System Info
        html += '<div class="asset-modal-section"><div class="asset-section-title">System Information</div><ul class="asset-info-list">';
        html += '<li><span class="asset-info-label">Operating System</span><span class="asset-info-value' + (asset.os_name ? '' : ' none') + '">' + (asset.os_name ? escapeHtml(asset.os_name) : 'Unknown') + '</span></li>';
        html += '<li><span class="asset-info-label">OS Family</span><span class="asset-info-value' + (asset.os_family ? '' : ' none') + '">' + (asset.os_family ? escapeHtml(asset.os_family) : 'Unknown') + '</span></li>';
        html += '<li><span class="asset-info-label">Device Type</span><span class="asset-info-value' + (asset.device_type ? '' : ' none') + '">' + (asset.device_type ? escapeHtml(asset.device_type) : 'Unknown') + '</span></li>';
        if (asset.os_accuracy) html += '<li><span class="asset-info-label">Detection Accuracy</span><span class="asset-info-value">' + escapeHtml(asset.os_accuracy) + '%</span></li>';
        html += '</ul></div>';

        // Scan History
        html += '<div class="asset-modal-section"><div class="asset-section-title">Scan History</div>';
        html += '<div class="asset-scan-stats"><div class="asset-stat"><div class="asset-stat-value">' + (asset.scan_count || 0) + '</div><div class="asset-stat-label">Total Scans</div></div>';
        html += '<div class="asset-stat"><div class="asset-stat-value">' + (asset.ports ? asset.ports.length : 0) + '</div><div class="asset-stat-label">Open Ports</div></div></div>';
        html += '<ul class="asset-info-list" style="margin-top:12px"><li><span class="asset-info-label">First Seen</span><span class="asset-info-value">' + (asset.first_seen ? formatDate(asset.first_seen) : 'N/A') + '</span></li>';
        html += '<li><span class="asset-info-label">Last Seen</span><span class="asset-info-value">' + (asset.last_seen ? formatDate(asset.last_seen) : 'N/A') + '</span></li></ul></div>';

        // Authenticated System Info
        if (asset.auth_os) {
            html += '<div class="asset-modal-section"><div class="asset-section-title">System Info (Authenticated)</div><ul class="asset-info-list">';
            if (asset.auth_os.pretty_name) html += '<li><span class="asset-info-label">OS</span><span class="asset-info-value">' + escapeHtml(asset.auth_os.pretty_name) + '</span></li>';
            if (asset.auth_os.distro) html += '<li><span class="asset-info-label">Distribution</span><span class="asset-info-value">' + escapeHtml(asset.auth_os.distro) + '</span></li>';
            if (asset.auth_os.version) html += '<li><span class="asset-info-label">Version</span><span class="asset-info-value">' + escapeHtml(asset.auth_os.version) + '</span></li>';
            if (asset.auth_os.arch) html += '<li><span class="asset-info-label">Architecture</span><span class="asset-info-value">' + escapeHtml(asset.auth_os.arch) + '</span></li>';
            if (asset.auth_os.kernel) html += '<li><span class="asset-info-label">Kernel</span><span class="asset-info-value" style="font-size:11px">' + escapeHtml(asset.auth_os.kernel.substring(0, 80)) + '</span></li>';
            html += '</ul></div>';
        }

        // Agent-Reported System Info
        if (asset.agent_data) {
            var ad = asset.agent_data;
            var si = ad.system_info || {};
            html += '<div class="asset-modal-section"><div class="asset-section-title">Agent-Reported System Info</div><ul class="asset-info-list">';
            if (ad.os_info && ad.os_info.os_name) html += '<li><span class="asset-info-label">OS</span><span class="asset-info-value">' + escapeHtml(ad.os_info.os_name) + '</span></li>';
            if (si.kernel) html += '<li><span class="asset-info-label">Kernel</span><span class="asset-info-value" style="font-size:11px">' + escapeHtml(si.kernel) + '</span></li>';
            if (si.arch) html += '<li><span class="asset-info-label">Architecture</span><span class="asset-info-value">' + escapeHtml(si.arch) + '</span></li>';
            if (si.cpu_count) html += '<li><span class="asset-info-label">CPUs</span><span class="asset-info-value">' + si.cpu_count + '</span></li>';
            if (si.load) html += '<li><span class="asset-info-label">Load</span><span class="asset-info-value">' + escapeHtml(String(si.load)) + '</span></li>';
            if (si.mem_total_mb) html += '<li><span class="asset-info-label">Memory</span><span class="asset-info-value">' + (si.mem_used_mb || 0) + ' / ' + si.mem_total_mb + ' MB</span></li>';
            if (si.disk_pct) html += '<li><span class="asset-info-label">Disk Usage</span><span class="asset-info-value">' + escapeHtml(si.disk_pct) + (si.disk_used_mb ? ' (' + si.disk_used_mb + ' / ' + (si.disk_total_mb || '?') + ' MB)' : '') + '</span></li>';
            if (si.uptime_seconds) {
                var uph = Math.floor(si.uptime_seconds / 3600); var upm = Math.floor((si.uptime_seconds % 3600) / 60);
                html += '<li><span class="asset-info-label">Uptime</span><span class="asset-info-value">' + uph + 'h ' + upm + 'm</span></li>';
            }
            html += '<li><span class="asset-info-label">Packages</span><span class="asset-info-value">' + (ad.package_count || 0) + ' installed</span></li>';
            html += '<li><span class="asset-info-label">Last Report</span><span class="asset-info-value">' + (ad.updated_at ? formatDate(ad.updated_at) : 'N/A') + '</span></li>';
            html += '</ul></div>';

            // Agent packages table (if we have full package list and no auth_os installed_software)
            if (ad.packages && ad.packages.length > 0 && (!asset.installed_software || asset.installed_software.length === 0)) {
                html += '<div class="asset-modal-section full-width"><div class="asset-section-title">Installed Packages — Agent (' + ad.packages.length + ')</div>';
                html += '<div class="software-table-wrapper"><table class="asset-ports-table"><thead><tr><th>Package</th><th>Version</th></tr></thead><tbody>';
                ad.packages.slice(0, 200).forEach(function(pkg) {
                    html += '<tr><td><strong>' + escapeHtml(pkg.name || '') + '</strong></td><td>' + escapeHtml(pkg.version || '') + '</td></tr>';
                });
                html += '</tbody></table>';
                if (ad.packages.length > 200) html += '<p class="text-muted" style="padding:8px">Showing 200 of ' + ad.packages.length + ' packages</p>';
                html += '</div></div>';
            }
        }

        // Vulnerabilities
        html += '<div class="asset-modal-section"><div class="asset-section-title">Vulnerabilities</div>';
        if (asset.vuln_counts && (asset.vuln_counts.critical > 0 || asset.vuln_counts.high > 0 || asset.vuln_counts.medium > 0 || asset.vuln_counts.low > 0 || asset.vuln_counts.info > 0)) {
            html += '<div class="asset-vuln-summary">';
            ['critical','high','medium','low','info'].forEach(function(sev) {
                if (asset.vuln_counts[sev] > 0) html += '<span class="asset-vuln-badge ' + sev + '">' + asset.vuln_counts[sev] + ' ' + sev.charAt(0).toUpperCase() + sev.slice(1) + '</span>';
            });
            html += '</div>';
        } else {
            html += '<p class="asset-no-vulns">No vulnerabilities detected</p>';
        }
        html += '</div>';

        // Technologies
        if (asset.fingerprints && asset.fingerprints.length > 0) {
            html += '<div class="asset-modal-section full-width"><div class="asset-section-title">Identified Technologies</div>';
            html += '<table class="asset-ports-table"><thead><tr><th>Port</th><th>Technology</th><th>Version</th><th>Category</th><th>Vendor</th><th>Confidence</th><th>CPE</th></tr></thead><tbody>';
            asset.fingerprints.forEach(function(fp) {
                var confClass = fp.confidence >= 80 ? 'high-conf' : (fp.confidence >= 50 ? 'med-conf' : 'low-conf');
                html += '<tr><td class="asset-port-number">' + fp.port + '</td><td class="asset-port-service"><strong>' + escapeHtml(fp.name || '') + '</strong></td>';
                html += '<td class="asset-port-product">' + escapeHtml(fp.version || '-') + '</td><td><span class="tech-category-badge">' + escapeHtml(fp.category || '') + '</span></td>';
                html += '<td>' + escapeHtml(fp.vendor || '') + '</td><td><span class="confidence-bar ' + confClass + '">' + fp.confidence + '%</span></td>';
                html += '<td class="asset-port-product">' + escapeHtml(fp.cpe || '-') + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }

        // Ports
        html += '<div class="asset-modal-section full-width"><div class="asset-section-title">Open Ports & Services</div>';
        if (asset.ports && asset.ports.length > 0) {
            html += '<table class="asset-ports-table"><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Identified As</th></tr></thead><tbody>';
            asset.ports.forEach(function(port) {
                var fpInfo = '';
                if (port.fingerprint && port.fingerprint.name) { fpInfo = port.fingerprint.name + (port.fingerprint.version ? ' v' + port.fingerprint.version : ''); }
                html += '<tr><td class="asset-port-number">' + port.port + '</td><td>' + escapeHtml(port.protocol || '') + '</td><td>' + escapeHtml(port.state || '') + '</td>';
                html += '<td class="asset-port-service">' + escapeHtml(port.service || '') + '</td><td class="asset-port-product">' + escapeHtml(port.product || '') + '</td>';
                html += '<td class="asset-port-product">' + escapeHtml(port.version || '') + '</td><td class="asset-port-product">' + (fpInfo ? '<strong>' + escapeHtml(fpInfo) + '</strong>' : '<span class="text-muted">-</span>') + '</td></tr>';
            });
            html += '</tbody></table>';
        } else { html += '<p class="asset-no-vulns">No open ports found</p>'; }
        html += '</div>';

        // Installed Software
        if (asset.installed_software && asset.installed_software.length > 0) {
            html += '<div class="asset-modal-section full-width"><div class="asset-section-title">Installed Software (' + asset.installed_software.length + ' packages)</div>';
            html += '<div class="software-table-wrapper"><table class="asset-ports-table"><thead><tr><th>Package</th><th>Version</th><th>CPE</th></tr></thead><tbody>';
            asset.installed_software.slice(0, 200).forEach(function(pkg) {
                html += '<tr><td><strong>' + escapeHtml(pkg.name) + '</strong></td><td>' + escapeHtml(pkg.version) + '</td><td class="asset-port-product" style="font-size:10px">' + escapeHtml(pkg.cpe || '-') + '</td></tr>';
            });
            html += '</tbody></table>';
            if (asset.installed_software.length > 200) html += '<p class="text-muted" style="padding:8px">Showing 200 of ' + asset.installed_software.length + ' packages</p>';
            html += '</div></div>';
        }

        // CVE Matches
        if (asset.cve_matches && asset.cve_matches.length > 0) {
            html += '<div class="asset-modal-section full-width"><div class="asset-section-title">Known Vulnerabilities (' + asset.cve_matches.length + ')</div>';
            html += '<table class="asset-ports-table"><thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Exploit</th><th>Package</th><th>Description</th></tr></thead><tbody>';
            asset.cve_matches.forEach(function(cve) {
                html += '<tr' + (cve.has_exploit ? ' class="exploit-row"' : '') + '>';
                html += '<td><a href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(cve.cve_id) + '" target="_blank" rel="noopener" class="cve-link">' + escapeHtml(cve.cve_id) + '</a></td>';
                html += '<td><span class="severity-badge ' + (cve.severity || 'info') + '">' + (cve.severity || 'N/A').toUpperCase() + '</span></td>';
                html += '<td>';
                if (cve.cvss_score !== null && cve.cvss_score !== undefined) {
                    var cvssClass = cve.cvss_score >= 9.0 ? 'critical' : (cve.cvss_score >= 7.0 ? 'high' : (cve.cvss_score >= 4.0 ? 'medium' : 'low'));
                    html += '<span class="cvss-badge ' + cvssClass + '">' + cve.cvss_score.toFixed(1) + '</span>';
                } else { html += '-'; }
                html += '</td><td>';
                if (cve.has_exploit) {
                    if (cve.exploit_url) html += '<a href="' + escapeHtml(cve.exploit_url) + '" target="_blank" rel="noopener" class="exploit-link" title="Public exploit">⚠️ Exploit</a>';
                    else html += '<span class="exploit-badge" title="Public exploit">⚠️</span>';
                } else { html += '-'; }
                html += '</td>';
                var affectedPkg = cve.affected_cpe ? cve.affected_cpe.split(':')[4] || '-' : '-';
                html += '<td>' + escapeHtml(affectedPkg) + '</td>';
                html += '<td class="desc-cell" style="max-width:300px">' + escapeHtml((cve.description || '').substring(0, 120)) + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }

        // DNS Aliases
        if (asset.aliases && asset.aliases.length > 0) {
            html += '<div class="asset-modal-section full-width"><div class="asset-section-title">DNS Aliases</div><ul class="asset-info-list">';
            asset.aliases.forEach(function(alias) { html += '<li><span class="asset-info-value">' + escapeHtml(alias) + '</span></li>'; });
            html += '</ul></div>';
        }

        html += '</div>';
        assetModalBody.innerHTML = html;
    }

    function closeAssetModal() { if (assetModal) { assetModal.style.display = 'none'; document.body.style.overflow = ''; } }
    if (assetModalClose) assetModalClose.addEventListener('click', closeAssetModal);
    if (assetModal) assetModal.addEventListener('click', function(e) { if (e.target === assetModal) closeAssetModal(); });

    // Generic modal
    function showGenericModal(html) {
        genericModalBody.innerHTML = html;
        genericModal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }
    function closeGenericModal() { genericModal.style.display = 'none'; document.body.style.overflow = ''; }
    if (genericModalClose) genericModalClose.addEventListener('click', closeGenericModal);
    if (genericModal) genericModal.addEventListener('click', function(e) { if (e.target === genericModal) closeGenericModal(); });

    // Escape key closes modals
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            if (cveModal.style.display === 'flex') closeCveModal();
            if (assetModal && assetModal.style.display === 'flex') closeAssetModal();
            if (genericModal.style.display === 'flex') closeGenericModal();
        }
    });

    // ==================== View Modes ====================

    var assetsViewMode = localStorage.getItem('assetsViewMode') || 'cards';
    var vulnsViewMode = localStorage.getItem('vulnsViewMode') || 'cards';

    document.querySelectorAll('.view-btn').forEach(function(btn) {
        if (btn.getAttribute('data-view') === assetsViewMode) btn.classList.add('active');
        else btn.classList.remove('active');
        btn.addEventListener('click', function() {
            assetsViewMode = this.getAttribute('data-view');
            localStorage.setItem('assetsViewMode', assetsViewMode);
            document.querySelectorAll('.view-btn').forEach(function(b) { b.classList.remove('active'); });
            this.classList.add('active');
            loadAssets();
        });
    });

    document.querySelectorAll('.view-btn-vulns').forEach(function(btn) {
        if (btn.getAttribute('data-view') === vulnsViewMode) btn.classList.add('active');
        else btn.classList.remove('active');
        btn.addEventListener('click', function() {
            vulnsViewMode = this.getAttribute('data-view');
            localStorage.setItem('vulnsViewMode', vulnsViewMode);
            document.querySelectorAll('.view-btn-vulns').forEach(function(b) { b.classList.remove('active'); });
            this.classList.add('active');
            loadVulnerabilities(currentIpFilter);
        });
    });

    // ==================== Scan Operations ====================

    if (scanForm) scanForm.addEventListener('submit', function(e) { e.preventDefault(); startPortScan(); });
    if (fingerprintScanBtn) fingerprintScanBtn.addEventListener('click', function() { startFingerprintScan(); });
    if (vulnScanBtn) vulnScanBtn.addEventListener('click', function() { startVulnScan(); });
    if (stopScanBtn) stopScanBtn.addEventListener('click', function() { stopScan(); });

    function startPortScan() {
        var ip = document.getElementById('ip').value.trim();
        if (!ip) { scanOutput.innerHTML = '<p class="error">Please enter an IP address.</p>'; return; }

        portScanBtn.disabled = true; vulnScanBtn.disabled = true;
        portScanBtn.textContent = 'Scanning...';
        stopScanBtn.style.display = 'inline-block';

        var settings = getScanSettings();
        socket.emit('start_scan', { ip: ip, ports: settings.ports, scan_speed: settings.scanSpeed, host_timeout: settings.hostTimeout, max_hosts: settings.maxHosts, vulscan: settings.vulscan });
        progressContainer.style.display = 'block'; progressBar.value = 10;
        progressMessage.textContent = 'Port scan in progress...';
        scanOutput.innerHTML = '<p>Scanning ' + ip + ' for open ports...</p>';
        addLog('Starting port scan for ' + ip, 'info');
    }

    function startFingerprintScan() {
        var ip = document.getElementById('ip').value.trim();
        if (!ip) { scanOutput.innerHTML = '<p class="error">Please enter an IP address.</p>'; return; }

        portScanBtn.disabled = true; vulnScanBtn.disabled = true;
        fingerprintScanBtn.disabled = true; fingerprintScanBtn.textContent = 'Fingerprinting...';
        stopScanBtn.style.display = 'inline-block';

        socket.emit('start_fingerprint_scan', { ip: ip });
        progressContainer.style.display = 'block'; progressBar.value = 10;
        progressMessage.textContent = 'Fingerprint scan in progress...';
        scanOutput.innerHTML = '<p>Running endpoint fingerprinting on ' + ip + '...</p>';
        addLog('Starting fingerprint scan for ' + ip, 'info');
    }

    // ==================== Scan Profiles ====================

    var selectedProfile = '';
    var profilesLoaded = false;
    var profilesData = {};

    function loadProfiles() {
        if (profilesLoaded) return;
        var dropdown = document.getElementById('profile-dropdown');
        if (!dropdown) return;

        fetch('/api/scan-profiles').then(function(r) { return r.json(); }).then(function(data) {
            if (!data.profiles) return;
            data.profiles.forEach(function(p) {
                profilesData[p.id] = p;
                var opt = document.createElement('option');
                opt.value = p.id; opt.textContent = (p.icon || '📋') + ' ' + p.name; opt.title = p.description || '';
                dropdown.appendChild(opt);
            });
            profilesLoaded = true;
        }).catch(function() {});

        dropdown.addEventListener('change', function() {
            selectedProfile = this.value;
            var authGroup = document.getElementById('auth-credentials-group');
            var profile = profilesData[selectedProfile];
            authGroup.style.display = (profile && profile.auth_required) ? 'block' : 'none';
        });
    }
    loadProfiles();

    function startVulnScan() {
        var ip = document.getElementById('ip').value.trim();
        if (!ip) { scanOutput.innerHTML = '<p class="error">Please enter an IP address.</p>'; return; }

        var profile = profilesData[selectedProfile];
        if (profile && profile.auth_required) { startAuthScan(ip); return; }

        portScanBtn.disabled = true; vulnScanBtn.disabled = true;
        vulnScanBtn.textContent = 'Scanning...'; stopScanBtn.style.display = 'inline-block';

        var settings = getScanSettings();
        var scanData = { ip: ip, vuln_timeout: settings.vulnTimeout, severity: settings.severity, rate_limit: settings.rateLimit, templates: settings.templates, max_hosts: settings.maxHosts };
        if (selectedProfile) scanData.profile = selectedProfile;

        socket.emit('start_vuln_scan', scanData);
        progressContainer.style.display = 'block'; progressBar.value = 10;
        var profileLabel = selectedProfile ? (' [' + selectedProfile + ']') : '';
        progressMessage.textContent = 'Vulnerability scan in progress' + profileLabel + '...';
        scanOutput.innerHTML = '<p>Running Nuclei vulnerability scan on ' + ip + profileLabel + '...</p>';
        addLog('Starting Nuclei vulnerability scan for ' + ip + profileLabel, 'info');
    }

    function startAuthScan(ip) {
        var useAll = document.getElementById('scan-use-all-creds');
        var select = document.getElementById('scan-credential-select');
        var credIds = [];
        if (useAll && useAll.checked) { /* use all */ }
        else if (select) {
            for (var i = 0; i < select.options.length; i++) { if (select.options[i].selected) credIds.push(select.options[i].value); }
        }
        if (!credIds.length && !(useAll && useAll.checked)) { scanOutput.innerHTML = '<p class="error">Please select credentials or check "Use all available".</p>'; return; }

        portScanBtn.disabled = true; vulnScanBtn.disabled = true;
        vulnScanBtn.textContent = 'Scanning...'; stopScanBtn.style.display = 'inline-block';

        socket.emit('start_auth_scan', { ip: ip, credential_ids: credIds, use_all_credentials: useAll ? useAll.checked : false });
        progressContainer.style.display = 'block'; progressBar.value = 10;
        progressMessage.textContent = 'Authenticated scan in progress...';
        scanOutput.innerHTML = '<p>Running smart authenticated scan on ' + ip + '...</p>';
        addLog('Starting smart authenticated scan for ' + ip, 'info');
    }

    function stopScan() {
        addLog('Requesting scan cancellation...', 'warning');
        socket.emit('stop_scan');
        stopScanBtn.disabled = true; stopScanBtn.textContent = 'Stopping...';
    }

    function resetScanButtons() {
        portScanBtn.disabled = false; vulnScanBtn.disabled = false;
        if (fingerprintScanBtn) { fingerprintScanBtn.disabled = false; fingerprintScanBtn.textContent = 'Fingerprint'; }
        portScanBtn.textContent = 'Port Scan'; vulnScanBtn.textContent = 'Vulnerability Scan';
        stopScanBtn.style.display = 'none'; stopScanBtn.disabled = false; stopScanBtn.textContent = 'Stop Scan';
    }

    // ==================== Socket Event Handlers ====================

    socket.on('scan_progress', function(data) {
        var percent = (data.current / data.total) * 100;
        progressBar.value = percent;
        progressMessage.textContent = data.message + ' (' + data.current + '/' + data.total + ')';
        addLog(data.message, 'info');
    });

    socket.on('scan_complete', function(data) {
        progressBar.value = 100;
        var html = '<h3>Port Scan Results for ' + data.target + '</h3>';
        if (data.cancelled) html += '<p class="warning">Scan was cancelled by user.</p>';
        if (data.total > 1) html += '<p class="info">Scanned ' + data.total + ' hosts: ' + data.successful_count + ' successful, ' + data.failed_count + ' failed</p>';

        var hasResults = false;
        data.results.forEach(function(result) {
            if (result.success && result.scan_data && result.scan_data.length > 0) {
                hasResults = true;
                html += '<div class="scan-result-group"><h4>' + result.ip + '</h4>';
                html += '<table><tr><th>Protocol</th><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr>';
                result.scan_data.forEach(function(row) { html += '<tr><td>' + row[0] + '</td><td>' + row[1] + '</td><td>' + row[2] + '</td><td>' + row[3] + '</td><td>' + row[4] + '</td><td>' + row[5] + '</td></tr>'; });
                html += '</table></div>';
            } else if (!result.success) {
                html += '<div class="scan-result-group error-group"><h4>' + result.ip + '</h4><p class="error">' + result.error + '</p></div>';
            }
        });
        if (!hasResults && data.failed_count === 0) html += '<p>No open ports found on any scanned hosts.</p>';
        html += '<p class="success">Scan complete.</p>';
        scanOutput.innerHTML = html;
        addLog('Port scan completed for ' + data.target, 'success');
        resetScanButtons();
        setTimeout(function() { progressContainer.style.display = 'none'; }, 1000);
    });

    socket.on('scan_error', function(data) {
        progressBar.value = 0; progressContainer.style.display = 'none';
        scanOutput.innerHTML = '<p class="error">Error: ' + data.error + '</p>';
        addLog('Scan error: ' + data.error, 'error');
        resetScanButtons();
    });

    socket.on('vuln_scan_progress', function(data) {
        if (data.current && data.total) {
            progressBar.value = (data.current / data.total) * 100;
            progressMessage.textContent = data.message + ' (' + data.current + '/' + data.total + ')';
        } else {
            progressMessage.textContent = data.message;
            progressBar.value = Math.min(progressBar.value + 10, 80);
        }
        addLog(data.message, 'info');
    });

    socket.on('vuln_scan_complete', function(data) {
        progressBar.value = 100;
        var html = '<h3>Vulnerability Scan Results for ' + data.target + '</h3>';
        if (data.cancelled) html += '<p class="warning">Vulnerability scan was cancelled by user.</p>';
        if (data.total > 1) html += '<p class="info">Scanned ' + data.total + ' hosts</p>';

        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            html += '<p class="warning">Found ' + data.total_vulns + ' potential vulnerability finding(s).</p><div class="vuln-results">';
            data.vulnerabilities.forEach(function(vuln) {
                html += '<div class="vuln-item severity-' + vuln.severity + '">';
                html += '<div class="vuln-header"><span class="vuln-id">' + vuln.vuln_id + '</span><div class="vuln-header-right">';
                if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
                    var cvssClass = vuln.cvss_score >= 9.0 ? 'critical' : (vuln.cvss_score >= 7.0 ? 'high' : (vuln.cvss_score >= 4.0 ? 'medium' : 'low'));
                    html += '<span class="cvss-badge ' + cvssClass + '">CVSS ' + vuln.cvss_score.toFixed(1) + '</span>';
                }
                html += '<span class="severity-badge ' + vuln.severity + '">' + vuln.severity.toUpperCase() + '</span></div></div>';
                html += '<div class="vuln-meta">' + vuln.ip + ':' + vuln.port + '/' + vuln.protocol + '</div>';
                if (vuln.cwe_id) html += '<div class="vuln-cwe"><span class="cwe-badge">' + vuln.cwe_id + '</span></div>';
                html += '<div class="vuln-desc">' + escapeHtml(vuln.description) + '</div></div>';
            });
            html += '</div>';
        } else { html += '<p class="success">No vulnerabilities detected.</p>'; }

        scanOutput.innerHTML = html;
        addLog('Vulnerability scan completed for ' + data.target, 'success');
        resetScanButtons();
        setTimeout(function() { progressContainer.style.display = 'none'; }, 1000);
    });

    socket.on('vuln_scan_error', function(data) {
        progressBar.value = 0; progressContainer.style.display = 'none';
        scanOutput.innerHTML = '<p class="error">Vulnerability scan error: ' + data.error + '</p>';
        addLog('Vulnerability scan error: ' + data.error, 'error');
        resetScanButtons();
    });

    socket.on('auth_scan_complete', function(data) {
        progressBar.value = 100;
        var html = '<h3>Authenticated Scan Results for ' + escapeHtml(data.target || data.ip || '') + '</h3>';
        if (data.results && data.results.length > 0) {
            var successful = data.results.filter(function(r) { return r.success; });
            var failed = data.results.filter(function(r) { return !r.success; });
            html += '<p class="info">' + data.successful_count + ' successful, ' + (data.total_count - data.successful_count) + ' failed attempts.</p>';
            if (successful.length > 0) {
                html += '<div class="vuln-results">';
                successful.forEach(function(r) { html += '<div class="scan-result-group"><p class="success">✓ ' + escapeHtml(r.ip) + ':' + r.port + ' via "' + escapeHtml(r.credential) + '": ' + r.packages + ' packages, ' + r.cves + ' CVEs</p></div>'; });
                html += '</div>';
            }
            if (failed.length > 0) {
                html += '<details><summary>' + failed.length + ' failed attempt(s)</summary>';
                failed.forEach(function(r) { html += '<p class="error">✗ ' + escapeHtml(r.ip) + ':' + r.port + ' via "' + escapeHtml(r.credential) + '": ' + escapeHtml(r.error || 'unknown error') + '</p>'; });
                html += '</details>';
            }
        } else if (data.os_info) {
            if (data.os_info.pretty_name) html += '<p class="info">OS: ' + escapeHtml(data.os_info.pretty_name) + '</p>';
            html += '<p class="success">Found ' + (data.package_count || 0) + ' installed packages, ' + (data.cve_count || 0) + ' CVE matches.</p>';
        }
        html += '<p>View full details in the <strong>Asset Details</strong> modal.</p>';
        scanOutput.innerHTML = html;
        addLog('Auth scan complete: ' + (data.successful_count || 0) + ' successful', 'success');
        resetScanButtons();
        setTimeout(function() { progressContainer.style.display = 'none'; }, 1000);
    });

    // ==================== Credentials Management ====================

    var credentialsList = [];
    var credTypeSelect = document.getElementById('cred-type');

    if (credTypeSelect) {
        credTypeSelect.addEventListener('change', function() {
            document.getElementById('cred-key-field').style.display = this.value === 'ssh_key' ? '' : 'none';
            document.getElementById('cred-password-field').style.display = this.value === 'ssh_key' ? 'none' : '';
        });
    }

    function loadCredentials() {
        fetch('/api/credentials').then(function(r) { return r.json(); }).then(function(data) {
            credentialsList = data.credentials || [];
            renderCredentialsList();
            populateCredentialDropdown();
        });
    }

    function renderCredentialsList() {
        var container = document.getElementById('credentials-list');
        if (!container) return;
        if (credentialsList.length === 0) { container.innerHTML = '<p class="empty-state">No credentials configured yet.</p>'; return; }

        var html = '<table class="credentials-table"><thead><tr><th>Name</th><th>Type</th><th>Username</th><th>Details</th><th>Actions</th></tr></thead><tbody>';
        credentialsList.forEach(function(c) {
            var detail = c.cred_type === 'ssh_key' ? ('Key: ' + escapeHtml(c.key_path || '')) : (c.password_set ? 'Password: ••••••••' : 'No password');
            html += '<tr><td><strong>' + escapeHtml(c.name) + '</strong></td><td><span class="tech-category-badge">' + escapeHtml(c.cred_type) + '</span></td>';
            html += '<td>' + escapeHtml(c.username) + '</td><td>' + detail + '</td>';
            html += '<td><button class="btn-small btn-secondary cred-edit-btn" data-id="' + c.id + '">Edit</button> ';
            html += '<button class="btn-small btn-stop cred-delete-btn" data-id="' + c.id + '" data-name="' + escapeHtml(c.name) + '">Delete</button></td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;

        container.querySelectorAll('.cred-edit-btn').forEach(function(btn) { btn.addEventListener('click', function() { editCredential(parseInt(this.getAttribute('data-id'))); }); });
        container.querySelectorAll('.cred-delete-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var id = parseInt(this.getAttribute('data-id'));
                var name = this.getAttribute('data-name');
                if (confirm('Delete credential "' + name + '"?')) {
                    fetch('/api/credentials/' + id, { method: 'DELETE' }).then(function(r) { return r.json(); }).then(function() { loadCredentials(); showToast('Credential deleted', 'success'); });
                }
            });
        });
    }

    function populateCredentialDropdown() {
        var select = document.getElementById('scan-credential-select');
        if (!select) return;
        select.innerHTML = '';
        credentialsList.forEach(function(c) {
            var opt = document.createElement('option');
            opt.value = c.id; opt.textContent = c.name + ' (' + c.cred_type + ' / ' + c.username + ')';
            select.appendChild(opt);
        });
    }

    function editCredential(id) {
        var cred = credentialsList.find(function(c) { return c.id === id; });
        if (!cred) return;
        document.getElementById('cred-edit-id').value = id;
        document.getElementById('cred-name').value = cred.name;
        document.getElementById('cred-type').value = cred.cred_type;
        document.getElementById('cred-username').value = cred.username;
        document.getElementById('cred-key-path').value = cred.key_path || '';
        document.getElementById('cred-password').value = '';
        document.getElementById('cred-form-title').textContent = 'Edit Credential';
        document.getElementById('cred-cancel-btn').style.display = '';
        if (credTypeSelect) credTypeSelect.dispatchEvent(new Event('change'));
    }

    function resetCredForm() {
        document.getElementById('cred-edit-id').value = '';
        document.getElementById('cred-name').value = '';
        document.getElementById('cred-type').value = 'ssh_key';
        document.getElementById('cred-username').value = 'root';
        document.getElementById('cred-key-path').value = '';
        document.getElementById('cred-password').value = '';
        document.getElementById('cred-form-title').textContent = 'Add Credential';
        document.getElementById('cred-cancel-btn').style.display = 'none';
        if (credTypeSelect) credTypeSelect.dispatchEvent(new Event('change'));
    }

    var credSaveBtn = document.getElementById('cred-save-btn');
    if (credSaveBtn) {
        credSaveBtn.addEventListener('click', function() {
            var editId = document.getElementById('cred-edit-id').value;
            var body = { name: document.getElementById('cred-name').value.trim(), cred_type: document.getElementById('cred-type').value, username: document.getElementById('cred-username').value.trim(), key_path: document.getElementById('cred-key-path').value.trim(), password: document.getElementById('cred-password').value };
            if (editId) body.id = parseInt(editId);
            fetch('/api/credentials', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
                .then(function(r) { return r.json(); })
                .then(function(data) { if (data.error) { alert(data.error); } else { resetCredForm(); loadCredentials(); showToast('Credential saved', 'success'); } });
        });
    }

    var credCancelBtn = document.getElementById('cred-cancel-btn');
    if (credCancelBtn) credCancelBtn.addEventListener('click', resetCredForm);

    // Password visibility toggles
    document.querySelectorAll('.btn-toggle-vis').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var input = this.parentElement.querySelector('input');
            input.type = input.type === 'password' ? 'text' : 'password';
            this.textContent = input.type === 'password' ? '👁' : '🙈';
        });
    });

    // NVD API Key
    function loadNvdKey() {
        fetch('/api/settings/nvd-key').then(function(r) { return r.json(); }).then(function(data) {
            var input = document.getElementById('nvd-api-key');
            if (input && data.has_key) input.placeholder = data.masked || '••••••••';
        });
    }

    var nvdKeySaveBtn = document.getElementById('nvd-key-save');
    if (nvdKeySaveBtn) {
        nvdKeySaveBtn.addEventListener('click', function() {
            var key = document.getElementById('nvd-api-key').value.trim();
            fetch('/api/settings/nvd-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: key }) })
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    var status = document.getElementById('nvd-key-status');
                    if (status) { status.textContent = data.success ? 'Saved!' : (data.error || 'Error'); status.classList.add('visible'); setTimeout(function() { status.classList.remove('visible'); }, 3000); }
                    document.getElementById('nvd-api-key').value = '';
                    loadNvdKey();
                });
        });
    }

    // Link to settings credentials from scan page
    var gotoSettingsCreds = document.getElementById('goto-settings-creds');
    if (gotoSettingsCreds) {
        gotoSettingsCreds.addEventListener('click', function(e) {
            e.preventDefault();
            navigateTo('settings');
            setTimeout(function() {
                var section = document.getElementById('settings-credentials-section');
                if (section) section.scrollIntoView({ behavior: 'smooth' });
            }, 100);
        });
    }

    // ==================== NVD Database Sync ====================

    function loadNvdStatus() {
        fetch('/api/nvd-status').then(function(r) { return r.json(); }).then(function(data) {
            var totalEl = document.getElementById('nvd-total-cves');
            var syncEl = document.getElementById('nvd-last-sync');
            if (totalEl) totalEl.textContent = data.total_cves ? data.total_cves.toLocaleString() : '0';
            if (syncEl) syncEl.textContent = data.last_sync ? formatDate(data.last_sync) : 'Never';
        }).catch(function() {});
    }

    var nvdSyncBtn = document.getElementById('nvd-sync-btn');
    var nvdFullSyncBtn = document.getElementById('nvd-full-sync-btn');
    var nvdSyncProgress = document.getElementById('nvd-sync-progress');
    var nvdSyncMessage = document.getElementById('nvd-sync-message');
    var nvdSyncBar = document.getElementById('nvd-sync-bar');

    if (nvdSyncBtn) nvdSyncBtn.addEventListener('click', function() {
        socket.emit('start_nvd_sync', { full: false });
        nvdSyncProgress.style.display = 'block'; nvdSyncBtn.disabled = true; nvdFullSyncBtn.disabled = true;
    });
    if (nvdFullSyncBtn) nvdFullSyncBtn.addEventListener('click', function() {
        if (confirm('Full sync will download ALL year feeds. Continue?')) {
            socket.emit('start_nvd_sync', { full: true });
            nvdSyncProgress.style.display = 'block'; nvdSyncBtn.disabled = true; nvdFullSyncBtn.disabled = true;
        }
    });

    socket.on('nvd_sync_progress', function(data) {
        if (nvdSyncMessage) nvdSyncMessage.textContent = data.message || 'Syncing...';
        if (nvdSyncBar && data.percent !== undefined) nvdSyncBar.value = data.percent;
        if (data.status === 'complete' || data.status === 'error') {
            if (nvdSyncBtn) nvdSyncBtn.disabled = false;
            if (nvdFullSyncBtn) nvdFullSyncBtn.disabled = false;
            setTimeout(function() { if (nvdSyncProgress) nvdSyncProgress.style.display = 'none'; }, 5000);
            loadNvdStatus();
        }
    });

    loadNvdStatus();
    loadCredentials();
    loadNvdKey();

    // ==================== Device Type Filter ====================

    var deviceTypeFilter = document.getElementById('device-type-filter');
    if (deviceTypeFilter) deviceTypeFilter.addEventListener('change', function() { loadAssets(); });

    // ==================== Assets Loading ====================

    function loadAssets() {
        assetsList.innerHTML = '<div style="text-align:center;padding:48px"><div class="spinner"></div><p class="text-muted">Loading assets...</p></div>';

        fetch('/api/assets').then(function(r) { return r.json(); }).then(function(data) {
            if (data.error) { assetsList.innerHTML = '<p class="error">Error loading assets: ' + data.error + '</p>'; return; }

            var assets = data.assets;
            var dtFilter = deviceTypeFilter ? deviceTypeFilter.value : '';
            if (dtFilter) assets = assets.filter(function(a) { return (a.device_type || 'unknown') === dtFilter; });

            assetsCount.textContent = assets.length + ' host(s) found';

            if (assets.length === 0) {
                assetsList.innerHTML = '<div class="empty-state"><span class="empty-state-icon">💻</span>No scanned assets yet. Use the Scan tab to scan a host.</div>';
                return;
            }

            var html = '';
            if (assetsViewMode === 'list') {
                html = '<table class="assets-table"><thead><tr><th>IP Address</th><th>Type</th><th>Hostname</th><th>Ports</th><th>Vulnerabilities</th><th>Last Scan</th><th>Actions</th></tr></thead><tbody>';
                assets.forEach(function(asset) {
                    var vc = asset.vuln_counts || { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
                    var hasVulns = vc.total > 0;
                    var vulnClass = vc.critical > 0 ? 'critical' : (vc.high > 0 ? 'high' : 'medium');
                    html += '<tr>';
                    var dn = asset.hostname ? (escapeHtml(asset.hostname) + ' <span class="text-muted">(' + asset.ip + ')</span>') : asset.ip;
                    html += '<td class="asset-ip-cell" data-ip="' + asset.ip + '"><strong>' + dn + '</strong></td>';
                    html += '<td>' + (asset.device_icon || '') + ' ' + escapeHtml(asset.device_type || '') + '</td>';
                    html += '<td>' + escapeHtml(asset.hostname || asset.reverse_dns || '') + '</td>';
                    html += '<td>' + asset.port_count + '</td><td>';
                    if (hasVulns) {
                        html += '<span class="vuln-badge-small ' + vulnClass + '">' + vc.total + '</span>';
                        if (vc.critical > 0) html += ' <span class="vuln-count-inline critical">' + vc.critical + 'C</span>';
                        if (vc.high > 0) html += ' <span class="vuln-count-inline high">' + vc.high + 'H</span>';
                    } else { html += '<span class="text-muted">None</span>'; }
                    html += '</td><td>' + formatDate(asset.last_scan) + '</td>';
                    html += '<td class="actions-cell"><button class="btn-small btn-rescan" data-ip="' + asset.ip + '">Port</button> <button class="btn-small btn-vuln-scan" data-ip="' + asset.ip + '">Vuln</button>';
                    if (hasVulns) html += ' <button class="btn-small btn-view-vulns" data-ip="' + asset.ip + '">View</button>';
                    html += '</td></tr>';
                });
                html += '</tbody></table>';
            } else {
                html = '<div class="assets-grid">';
                assets.forEach(function(asset) {
                    var vc = asset.vuln_counts || { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
                    var hasVulns = vc.total > 0;
                    html += '<div class="asset-card"><div class="asset-header"><div class="asset-ip-group">';
                    if (asset.device_icon) html += '<span class="asset-device-icon" title="' + escapeHtml(asset.device_type || '') + '">' + asset.device_icon + '</span>';
                    if (asset.hostname) html += '<span class="asset-ip" data-ip="' + asset.ip + '">' + escapeHtml(asset.hostname) + ' <span class="text-muted">(' + asset.ip + ')</span></span>';
                    else html += '<span class="asset-ip" data-ip="' + asset.ip + '">' + asset.ip + '</span>';
                    html += '</div><div class="asset-badges">';
                    if (asset.device_type && asset.device_type !== 'unknown') html += '<span class="asset-device-badge">' + escapeHtml(asset.device_type) + '</span>';
                    html += '<span class="asset-ports">' + asset.port_count + ' port(s)</span>';
                    if (hasVulns) { var vClass = vc.critical > 0 ? 'critical' : (vc.high > 0 ? 'high' : 'medium'); html += '<span class="asset-vulns vuln-badge-' + vClass + '">' + vc.total + ' vuln(s)</span>'; }
                    html += '</div></div>';

                    if (!asset.hostname && asset.reverse_dns) html += '<div class="asset-hostname-line">' + escapeHtml(asset.reverse_dns) + '</div>';
                    if (asset.mac_address) html += '<div class="asset-mac-line">' + escapeHtml(asset.mac_address) + (asset.mac_vendor ? ' (' + escapeHtml(asset.mac_vendor) + ')' : '') + '</div>';

                    if (asset.technologies && asset.technologies.length > 0) {
                        html += '<div class="asset-tech-stack">';
                        asset.technologies.forEach(function(tech) {
                            var confClass = tech.confidence >= 80 ? 'high-conf' : (tech.confidence >= 50 ? 'med-conf' : 'low-conf');
                            html += '<span class="tech-badge ' + confClass + '" title="' + escapeHtml(tech.category) + ' · ' + tech.confidence + '%">' + escapeHtml(tech.name + (tech.version ? ' ' + tech.version : '')) + '</span>';
                        });
                        html += '</div>';
                    }

                    if (hasVulns) {
                        html += '<div class="asset-vuln-summary">';
                        ['critical','high','medium','low'].forEach(function(s) { if (vc[s] > 0) html += '<span class="vuln-mini ' + s + '">' + vc[s] + ' ' + s.charAt(0).toUpperCase() + s.slice(1) + '</span>'; });
                        html += '</div>';
                    }

                    html += '<div class="asset-meta"><span class="asset-date">Last scan: ' + formatDate(asset.last_scan) + '</span></div>';
                    html += '<div class="asset-actions">';
                    html += '<button class="btn-small btn-rescan" data-ip="' + asset.ip + '">Port Scan</button>';
                    html += '<button class="btn-small btn-fingerprint" data-ip="' + asset.ip + '">Fingerprint</button>';
                    html += '<button class="btn-small btn-vuln-scan" data-ip="' + asset.ip + '">Vuln Scan</button>';
                    if (hasVulns) html += '<button class="btn-small btn-view-vulns" data-ip="' + asset.ip + '">View Vulns</button>';
                    html += '<button class="btn-small btn-details" data-ip="' + asset.ip + '">Details</button>';
                    html += '</div></div>';
                });
                html += '</div>';
            }
            assetsList.innerHTML = html;
            bindAssetButtons();
        }).catch(function(error) { assetsList.innerHTML = '<p class="error">Error loading assets: ' + error.message + '</p>'; });
    }

    function bindAssetButtons() {
        document.querySelectorAll('.btn-rescan').forEach(function(btn) { btn.addEventListener('click', function() { switchToScanTab(this.getAttribute('data-ip'), 'port'); }); });
        document.querySelectorAll('.btn-fingerprint').forEach(function(btn) { btn.addEventListener('click', function() { switchToScanTab(this.getAttribute('data-ip'), 'fingerprint'); }); });
        document.querySelectorAll('.btn-vuln-scan').forEach(function(btn) { btn.addEventListener('click', function() { switchToScanTab(this.getAttribute('data-ip'), 'vuln'); }); });
        document.querySelectorAll('.btn-view-vulns').forEach(function(btn) { btn.addEventListener('click', function() { viewVulnerabilitiesForAsset(this.getAttribute('data-ip')); }); });
        document.querySelectorAll('.btn-details').forEach(function(btn) { btn.addEventListener('click', function(e) { e.stopPropagation(); showAssetModal(this.getAttribute('data-ip')); }); });

        document.querySelectorAll('.asset-card').forEach(function(card) {
            card.style.cursor = 'pointer';
            card.addEventListener('click', function(e) {
                if (e.target.tagName === 'BUTTON') return;
                var ip = card.querySelector('.asset-ip');
                if (ip) showAssetModal(ip.getAttribute('data-ip') || ip.textContent);
            });
        });

        document.querySelectorAll('.assets-table tbody tr').forEach(function(row) {
            row.style.cursor = 'pointer';
            row.addEventListener('click', function(e) {
                if (e.target.tagName === 'BUTTON') return;
                var ipCell = row.querySelector('.asset-ip-cell');
                if (ipCell) showAssetModal(ipCell.getAttribute('data-ip'));
            });
        });
    }

    function switchToScanTab(ip, scanType) {
        navigateTo('scan');
        document.getElementById('ip').value = ip;
        if (scanType === 'vuln') startVulnScan();
        else if (scanType === 'fingerprint') startFingerprintScan();
        else startPortScan();
    }

    function viewVulnerabilitiesForAsset(ip) {
        navigateTo('vulns');
        loadVulnerabilities(ip);
    }

    if (refreshAssetsBtn) refreshAssetsBtn.addEventListener('click', loadAssets);

    // ==================== Vulnerabilities Loading ====================

    var currentIpFilter = null;
    var vulnSourceFilter = document.getElementById('vuln-source-filter');
    var vulnExploitFilter = document.getElementById('vuln-exploit-filter');
    var vulnSearchInput = document.getElementById('vuln-search');
    var vulnSearchTimeout = null;

    if (vulnSourceFilter) vulnSourceFilter.addEventListener('change', function() { loadVulnerabilities(currentIpFilter); });
    if (vulnExploitFilter) vulnExploitFilter.addEventListener('change', function() { loadVulnerabilities(currentIpFilter); });
    if (vulnSearchInput) vulnSearchInput.addEventListener('input', function() {
        clearTimeout(vulnSearchTimeout);
        vulnSearchTimeout = setTimeout(function() { loadVulnerabilities(currentIpFilter); }, 400);
    });
    if (vulnFilter) vulnFilter.addEventListener('change', function() { loadVulnerabilities(currentIpFilter); });
    if (refreshVulnsBtn) refreshVulnsBtn.addEventListener('click', function() { loadVulnerabilities(); });

    function loadVulnerabilities(ipFilter) {
        vulnsList.innerHTML = '<div style="text-align:center;padding:48px"><div class="spinner"></div><p class="text-muted">Loading vulnerabilities...</p></div>';

        var params = [];
        if (ipFilter) { params.push('ip=' + encodeURIComponent(ipFilter)); currentIpFilter = ipFilter; } else { currentIpFilter = null; }
        var sourceVal = vulnSourceFilter ? vulnSourceFilter.value : '';
        if (sourceVal) params.push('source=' + encodeURIComponent(sourceVal));
        if (vulnExploitFilter && vulnExploitFilter.checked) params.push('has_exploit=true');
        var searchVal = vulnSearchInput ? vulnSearchInput.value.trim() : '';
        if (searchVal) params.push('search=' + encodeURIComponent(searchVal));

        fetch('/api/vulnerabilities' + (params.length ? '?' + params.join('&') : ''))
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.error) { vulnsList.innerHTML = '<p class="error">Error: ' + data.error + '</p>'; return; }

                var summary = data.summary;
                document.getElementById('total-vulns').textContent = summary.unique_cves || 0;
                document.getElementById('critical-count').textContent = summary.by_severity.critical || 0;
                document.getElementById('high-count').textContent = summary.by_severity.high || 0;
                document.getElementById('medium-count').textContent = summary.by_severity.medium || 0;
                document.getElementById('low-count').textContent = summary.by_severity.low || 0;
                var exploitCountEl = document.getElementById('exploit-count');
                if (exploitCountEl) exploitCountEl.textContent = summary.with_exploits || 0;

                var vulnerabilities = data.vulnerabilities;
                var filterIndicator = '';
                if (currentIpFilter) {
                    filterIndicator = '<div class="filter-indicator"><span>Showing vulnerabilities for: <strong>' + currentIpFilter + '</strong></span><button class="btn-clear-filter" id="clear-ip-filter">Show All</button></div>';
                }

                if (vulnerabilities.length === 0) {
                    vulnsList.innerHTML = filterIndicator + '<div class="empty-state"><span class="empty-state-icon">⚠️</span>No vulnerabilities found' + (currentIpFilter ? ' for ' + currentIpFilter : '') + '</div>';
                    var clearBtn = document.getElementById('clear-ip-filter');
                    if (clearBtn) clearBtn.addEventListener('click', function() { loadVulnerabilities(null); });
                    return;
                }

                renderVulnerabilities(vulnerabilities, filterIndicator);
            })
            .catch(function(error) { vulnsList.innerHTML = '<p class="error">Error: ' + error.message + '</p>'; });
    }

    function renderVulnerabilities(vulnerabilities, filterIndicator) {
        var filterValue = vulnFilter ? vulnFilter.value : '';
        var filtered = filterValue ? vulnerabilities.filter(function(v) { return v.severity === filterValue; }) : vulnerabilities;
        storedVulnerabilities = filtered;

        if (filtered.length === 0) {
            vulnsList.innerHTML = (filterIndicator || '') + '<div class="empty-state"><span class="empty-state-icon">⚠️</span>No vulnerabilities match the selected filter.</div>';
            var clearBtn = document.getElementById('clear-ip-filter');
            if (clearBtn) clearBtn.addEventListener('click', function() { loadVulnerabilities(null); });
            return;
        }

        var html = (filterIndicator || '');

        if (vulnsViewMode === 'list') {
            html += '<table class="vulns-table"><thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Exploit</th><th>Sources</th><th>Assets</th><th>Software</th><th>Description</th><th>Published</th></tr></thead><tbody>';
            filtered.forEach(function(vuln, index) {
                html += '<tr class="severity-row-' + vuln.severity + ' clickable" data-vuln-index="' + index + '">';
                var cveLink = vuln.cve_id.toUpperCase().indexOf('CVE-') === 0
                    ? '<a href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(vuln.cve_id) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">' + escapeHtml(vuln.cve_id) + '</a>'
                    : escapeHtml(vuln.cve_id);
                html += '<td class="vuln-id-cell clickable"><code>' + cveLink + '</code></td>';
                html += '<td><span class="severity-badge ' + vuln.severity + '">' + vuln.severity.toUpperCase() + '</span></td>';
                html += '<td>';
                if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
                    var cvssClass = vuln.cvss_score >= 9.0 ? 'critical' : (vuln.cvss_score >= 7.0 ? 'high' : (vuln.cvss_score >= 4.0 ? 'medium' : 'low'));
                    html += '<span class="cvss-badge ' + cvssClass + '">' + vuln.cvss_score.toFixed(1) + '</span>';
                } else html += '<span class="text-muted">-</span>';
                html += '</td><td>';
                if (vuln.has_exploit) html += '<span class="exploit-warning">⚠️ Exploit</span>';
                else html += '<span class="text-muted">-</span>';
                html += '</td><td>' + renderSourceBadges(vuln.detection_sources) + '</td><td>';
                if (vuln.affected_assets && vuln.affected_assets.length > 0) {
                    var assetStrs = vuln.affected_assets.slice(0, 3).map(function(a) { return a.port > 0 ? (a.ip + ':' + a.port) : a.ip; });
                    html += escapeHtml(assetStrs.join(', '));
                    if (vuln.affected_assets.length > 3) html += ' +' + (vuln.affected_assets.length - 3);
                }
                html += '</td><td class="desc-cell">' + escapeHtml((vuln.affected_cpe || '-').substring(0, 40)) + '</td>';
                html += '<td class="desc-cell">' + escapeHtml((vuln.description || '').substring(0, 80)) + '</td>';
                html += '<td style="white-space:nowrap">' + (vuln.published_date ? formatDate(vuln.published_date).split(' ')[0] : '-') + '</td></tr>';
            });
            html += '</tbody></table>';
        } else {
            html += '<div class="vulns-grid">';
            filtered.forEach(function(vuln, index) {
                html += '<div class="vuln-card clickable severity-' + vuln.severity + '" data-vuln-index="' + index + '">';
                html += '<div class="vuln-header">';
                if (vuln.cve_id.toUpperCase().indexOf('CVE-') === 0) html += '<a href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(vuln.cve_id) + '" target="_blank" rel="noopener" class="vuln-id" onclick="event.stopPropagation()">' + escapeHtml(vuln.cve_id) + '</a>';
                else html += '<span class="vuln-id">' + escapeHtml(vuln.cve_id) + '</span>';
                html += '<div class="vuln-header-right">';
                if (vuln.has_exploit) html += '<span class="exploit-warning">⚠️ Exploit</span>';
                if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
                    var cvssClass = vuln.cvss_score >= 9.0 ? 'critical' : (vuln.cvss_score >= 7.0 ? 'high' : (vuln.cvss_score >= 4.0 ? 'medium' : 'low'));
                    html += '<span class="cvss-badge ' + cvssClass + '">' + vuln.cvss_score.toFixed(1) + '</span>';
                }
                html += '<span class="severity-badge ' + vuln.severity + '">' + vuln.severity.toUpperCase() + '</span></div></div>';
                html += renderSourceBadges(vuln.detection_sources);
                html += renderAssetBadges(vuln.affected_assets);
                if (vuln.affected_cpe) html += '<div class="vuln-cpe"><span class="cpe-badge" title="' + escapeHtml(vuln.affected_cpe) + '">' + escapeHtml(vuln.affected_cpe.substring(0, 60)) + '</span></div>';
                if (vuln.cwe_id) html += '<div class="vuln-cwe"><span class="cwe-badge">' + vuln.cwe_id + '</span></div>';
                var desc = vuln.description || '';
                if (desc.length > 200) html += '<div class="vuln-desc">' + escapeHtml(desc.substring(0, 200)) + '...</div>';
                else if (desc) html += '<div class="vuln-desc">' + escapeHtml(desc) + '</div>';
                html += '<div class="vuln-dates">';
                if (vuln.published_date) html += '<span class="vuln-published">Published: ' + formatDate(vuln.published_date) + '</span>';
                html += '</div></div>';
            });
            html += '</div>';
        }

        vulnsList.innerHTML = html;
        var clearBtn = document.getElementById('clear-ip-filter');
        if (clearBtn) clearBtn.addEventListener('click', function() { loadVulnerabilities(null); });

        document.querySelectorAll('.vuln-card.clickable, .vulns-table tbody tr.clickable').forEach(function(el) {
            el.addEventListener('click', function(e) {
                if (e.target.tagName === 'A') return;
                var index = parseInt(this.getAttribute('data-vuln-index'));
                if (!isNaN(index) && storedVulnerabilities[index]) showCveModal(storedVulnerabilities[index]);
            });
        });
    }

    // ==================== Dashboard ====================

    function loadDashboard() {
        // Fetch assets summary
        fetch('/api/assets').then(function(r) { return r.json(); }).then(function(data) {
            document.getElementById('dash-assets').textContent = (data.assets || []).length;
        }).catch(function() {});

        // Fetch vuln summary
        fetch('/api/vulnerabilities').then(function(r) { return r.json(); }).then(function(data) {
            var s = data.summary || {};
            var bySev = s.by_severity || {};
            document.getElementById('dash-critical').textContent = bySev.critical || 0;
            document.getElementById('dash-high').textContent = bySev.high || 0;
            document.getElementById('dash-medium').textContent = bySev.medium || 0;
        }).catch(function() {});

        // Fetch agents
        fetch('/api/v1/agents').then(function(r) { return r.json(); }).then(function(agents) {
            var active = agents.filter(function(a) { return a.status === 'active'; }).length;
            document.getElementById('dash-agents').textContent = active + '/' + agents.length;

            var statusHtml = '';
            if (agents.length === 0) { statusHtml = '<p class="text-muted">No agents registered</p>'; }
            else {
                var byStatus = { active: 0, stale: 0, offline: 0 };
                agents.forEach(function(a) { byStatus[a.status] = (byStatus[a.status] || 0) + 1; });
                statusHtml = '<div style="display:flex;gap:16px">';
                statusHtml += '<div><span class="status-dot active"></span>' + byStatus.active + ' Active</div>';
                statusHtml += '<div><span class="status-dot stale"></span>' + (byStatus.stale || 0) + ' Stale</div>';
                statusHtml += '<div><span class="status-dot offline"></span>' + (byStatus.offline || 0) + ' Offline</div>';
                statusHtml += '</div>';
                statusHtml += '<table style="margin-top:12px"><thead><tr><th>Hostname</th><th>Status</th><th>Last Checkin</th></tr></thead><tbody>';
                agents.slice(0, 5).forEach(function(a) {
                    statusHtml += '<tr><td>' + escapeHtml(a.hostname || a.ip || '—') + '</td><td><span class="status-dot ' + a.status + '"></span>' + a.status + '</td><td>' + formatDate(a.last_checkin) + '</td></tr>';
                });
                statusHtml += '</tbody></table>';
            }
            document.getElementById('dash-agent-status').innerHTML = statusHtml;
        }).catch(function() { document.getElementById('dash-agents').textContent = '—'; });

        // Fetch schedules
        fetch('/api/v1/schedules').then(function(r) { return r.json(); }).then(function(scheds) {
            document.getElementById('dash-schedules').textContent = scheds.filter(function(s) { return s.enabled; }).length;
        }).catch(function() {});

        // Fetch sites
        fetch('/api/v1/sites').then(function(r) { return r.json(); }).then(function(sites) {
            document.getElementById('dash-sites').textContent = sites.length;
        }).catch(function() {});

        // Fetch recent scan history
        fetch('/api/v1/scan-history?limit=10').then(function(r) { return r.json(); }).then(function(scans) {
            if (!scans || scans.length === 0) { document.getElementById('dash-recent-scans').innerHTML = '<p class="text-muted">No recent scans</p>'; return; }
            var html = '<table><thead><tr><th>Target</th><th>Type</th><th>Status</th><th>Date</th></tr></thead><tbody>';
            scans.forEach(function(s) {
                html += '<tr><td>' + escapeHtml(s.target || '—') + '</td><td>' + escapeHtml(s.scan_type || '—') + '</td>';
                html += '<td><span class="entity-badge">' + escapeHtml(s.status || '—') + '</span></td>';
                html += '<td>' + formatDate(s.started_at || s.created_at) + '</td></tr>';
            });
            html += '</tbody></table>';
            document.getElementById('dash-recent-scans').innerHTML = html;
        }).catch(function() {});
    }

    // ==================== Sites Page ====================

    function loadSites() {
        var container = document.getElementById('sites-list');
        container.innerHTML = '<div style="text-align:center;padding:48px"><div class="spinner"></div></div>';

        fetch('/api/v1/sites').then(function(r) { return r.json(); }).then(function(sites) {
            if (!sites || sites.length === 0) {
                container.innerHTML = '<div class="empty-state"><span class="empty-state-icon">🌐</span>No sites configured yet. Create one to organize your targets.</div>';
                return;
            }
            var html = '<div class="entity-cards">';
            sites.forEach(function(site) {
                var targets = [];
                try { targets = JSON.parse(site.targets_json || '[]'); } catch(e) {}
                html += '<div class="entity-card">';
                html += '<div class="entity-card-header"><div><div class="entity-card-title">' + escapeHtml(site.name) + '</div>';
                html += '<div class="entity-card-meta">' + targets.length + ' target(s) · ' + escapeHtml(site.scan_type || 'full') + ' · ' + (site.scan_count || 0) + ' scans</div>';
                if (site.description) html += '<div class="entity-card-meta">' + escapeHtml(site.description) + '</div>';
                html += '</div>';
                html += '<span class="status-dot ' + (site.schedule_enabled ? 'active' : 'disabled') + '" title="' + (site.schedule_enabled ? 'Enabled' : 'Disabled') + '"></span>';
                html += '</div>';
                if (site.latest_scan) {
                    html += '<div class="entity-card-meta">Last scan: ' + formatDate(site.latest_scan.started_at) + ' — ' + escapeHtml(site.latest_scan.status || '—') + '</div>';
                }
                if (site.next_run) html += '<div class="entity-card-meta">Next run: ' + formatDate(site.next_run) + '</div>';
                html += '<div class="entity-card-actions">';
                html += '<button class="btn-small btn-rescan" onclick="triggerSiteScan(' + site.id + ')">▶ Scan Now</button>';
                html += '<button class="btn-small btn-secondary" onclick="toggleSite(' + site.id + ')">' + (site.schedule_enabled ? 'Disable' : 'Enable') + '</button>';
                html += '<button class="btn-small btn-secondary" onclick="editSite(' + site.id + ')">Edit</button>';
                html += '<button class="btn-small btn-stop" onclick="deleteSite(' + site.id + ', \'' + escapeHtml(site.name) + '\')">Delete</button>';
                html += '</div></div>';
            });
            html += '</div>';
            container.innerHTML = html;
        }).catch(function(err) { container.innerHTML = '<p class="error">Failed to load sites: ' + err.message + '</p>'; });
    }

    window.triggerSiteScan = function(id) {
        fetch('/api/v1/sites/' + id + '/scan', { method: 'POST' }).then(function(r) { return r.json(); })
            .then(function() { showToast('Site scan triggered', 'success'); loadSites(); })
            .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    window.toggleSite = function(id) {
        fetch('/api/v1/sites/' + id + '/toggle', { method: 'POST' }).then(function(r) { return r.json(); })
            .then(function() { showToast('Site toggled', 'success'); loadSites(); })
            .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    window.deleteSite = function(id, name) {
        if (!confirm('Delete site "' + name + '"?')) return;
        fetch('/api/v1/sites/' + id, { method: 'DELETE' }).then(function(r) { return r.json(); })
            .then(function() { showToast('Site deleted', 'success'); loadSites(); })
            .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    window.editSite = function(id) {
        fetch('/api/v1/sites/' + id).then(function(r) { return r.json(); }).then(function(site) {
            showSiteForm(site);
        }).catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    function showSiteForm(site) {
        var isEdit = !!site;
        // to_dict() returns targets/excluded_targets as arrays directly
        var targets = (site && Array.isArray(site.targets)) ? site.targets : [];
        var excluded = (site && Array.isArray(site.excluded_targets)) ? site.excluded_targets : [];
        // Parse scan options from JSON string
        var scanOpts = {};
        try { scanOpts = JSON.parse((site && site.scan_options_json) || '{}') || {}; } catch(e) {}

        var html = '<h2>' + (isEdit ? 'Edit Site' : 'New Site') + '</h2><div class="modal-form">';
        html += '<div><label>Name</label><input type="text" id="site-name" value="' + escapeHtml((site && site.name) || '') + '"></div>';
        html += '<div><label>Description</label><input type="text" id="site-desc" value="' + escapeHtml((site && site.description) || '') + '"></div>';
        html += '<div><label>Targets (one per line)</label><textarea id="site-targets">' + escapeHtml(targets.join('\n')) + '</textarea></div>';
        html += '<div><label>Excluded Targets (one per line)</label><textarea id="site-excluded">' + escapeHtml(excluded.join('\n')) + '</textarea></div>';
        html += '<div><label>Scan Type</label><select id="site-scan-type"><option value="full"' + ((site && site.scan_type === 'full') ? ' selected' : '') + '>Full</option><option value="port"' + ((site && site.scan_type === 'port') ? ' selected' : '') + '>Port Only</option><option value="vuln"' + ((site && site.scan_type === 'vuln') ? ' selected' : '') + '>Vuln Only</option><option value="auth"' + ((site && site.scan_type === 'auth') ? ' selected' : '') + '>Auth Only</option></select></div>';

        // Scan Options section
        html += '<h3 style="margin-top:16px;margin-bottom:8px;">Scan Options</h3>';
        html += '<div class="settings-grid">';
        html += '<div><label>Port Range</label><input type="text" id="site-ports" placeholder="e.g., 1-1000, 22,80,443, or -" value="' + escapeHtml(scanOpts.ports || '') + '"><span class="setting-hint">Use "-" for all ports</span></div>';
        html += '<div><label>Scan Speed</label><select id="site-scan-speed"><option value="T2"' + (scanOpts.scan_speed === 'T2' ? ' selected' : '') + '>T2 - Polite</option><option value="T3"' + ((!scanOpts.scan_speed || scanOpts.scan_speed === 'T3') ? ' selected' : '') + '>T3 - Normal</option><option value="T4"' + (scanOpts.scan_speed === 'T4' ? ' selected' : '') + '>T4 - Aggressive</option><option value="T5"' + (scanOpts.scan_speed === 'T5' ? ' selected' : '') + '>T5 - Insane</option></select></div>';
        html += '<div><label>Host Timeout (sec)</label><input type="number" id="site-host-timeout" min="30" max="3600" value="' + (scanOpts.host_timeout || 300) + '"></div>';
        html += '<div><label>Max Hosts</label><input type="number" id="site-max-hosts" min="1" max="1024" value="' + (scanOpts.max_hosts || 256) + '"></div>';
        html += '<div><label>Vuln Timeout (sec)</label><input type="number" id="site-vuln-timeout" min="60" max="3600" value="' + (scanOpts.vuln_timeout || 600) + '"></div>';
        html += '<div><label>Severity Filter</label><select id="site-severity"><option value="critical,high,medium,low"' + ((!scanOpts.severity || scanOpts.severity === 'critical,high,medium,low') ? ' selected' : '') + '>All Severities</option><option value="critical,high,medium"' + (scanOpts.severity === 'critical,high,medium' ? ' selected' : '') + '>Medium+</option><option value="critical,high"' + (scanOpts.severity === 'critical,high' ? ' selected' : '') + '>High+</option><option value="critical"' + (scanOpts.severity === 'critical' ? ' selected' : '') + '>Critical Only</option></select></div>';
        html += '<div><label>Rate Limit (req/sec)</label><input type="number" id="site-rate-limit" min="10" max="1000" value="' + (scanOpts.rate_limit || 150) + '"></div>';
        html += '<div><label><input type="checkbox" id="site-vulscan"' + (scanOpts.vulscan ? ' checked' : '') + '> Enable Vulscan (NSE)</label></div>';
        html += '</div>';

        html += '<h3 style="margin-top:16px;margin-bottom:8px;">Schedule</h3>';
        html += '<div class="settings-grid">';
        html += '<div><label>Schedule Type</label><select id="site-sched-type"><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select></div>';
        html += '<div><label>Hour (UTC)</label><input type="number" id="site-hour" min="0" max="23" value="' + ((site && site.schedule_hour) || 2) + '"></div>';
        html += '</div>';

        html += '<div class="modal-form-actions">';
        html += '<button class="btn-primary" id="site-save-btn">Save</button>';
        html += '<button class="btn-secondary" onclick="document.getElementById(\'generic-modal\').style.display=\'none\';document.body.style.overflow=\'\'">Cancel</button>';
        html += '</div></div>';

        showGenericModal(html);

        if (site && site.schedule_type) document.getElementById('site-sched-type').value = site.schedule_type;

        document.getElementById('site-save-btn').addEventListener('click', function() {
            var body = {
                name: document.getElementById('site-name').value.trim(),
                description: document.getElementById('site-desc').value.trim(),
                targets: document.getElementById('site-targets').value.trim().split('\n').filter(Boolean),
                excluded_targets: document.getElementById('site-excluded').value.trim().split('\n').filter(Boolean),
                scan_type: document.getElementById('site-scan-type').value,
                schedule_type: document.getElementById('site-sched-type').value,
                schedule_hour: parseInt(document.getElementById('site-hour').value) || 2,
                scan_options: {
                    ports: document.getElementById('site-ports').value.trim(),
                    scan_speed: document.getElementById('site-scan-speed').value,
                    host_timeout: parseInt(document.getElementById('site-host-timeout').value) || 300,
                    max_hosts: parseInt(document.getElementById('site-max-hosts').value) || 256,
                    vuln_timeout: parseInt(document.getElementById('site-vuln-timeout').value) || 600,
                    severity: document.getElementById('site-severity').value,
                    rate_limit: parseInt(document.getElementById('site-rate-limit').value) || 150,
                    vulscan: document.getElementById('site-vulscan').checked
                }
            };
            var method = isEdit ? 'PUT' : 'POST';
            var url = isEdit ? '/api/v1/sites/' + site.id : '/api/v1/sites';
            fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
                .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || 'Failed'); }); return r.json(); })
                .then(function() { closeGenericModal(); showToast('Site saved', 'success'); loadSites(); })
                .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
        });
    }

    document.getElementById('btn-create-site').addEventListener('click', function() { showSiteForm(null); });

    // ==================== Schedules Page ====================

    function loadSchedules() {
        var container = document.getElementById('schedules-list');
        container.innerHTML = '<div style="text-align:center;padding:48px"><div class="spinner"></div></div>';

        fetch('/api/v1/schedules').then(function(r) { return r.json(); }).then(function(scheds) {
            if (!scheds || scheds.length === 0) {
                container.innerHTML = '<div class="empty-state"><span class="empty-state-icon">📅</span>No schedules configured yet.</div>';
                return;
            }
            var html = '<div class="entity-cards">';
            scheds.forEach(function(s) {
                html += '<div class="entity-card"><div class="entity-card-header"><div>';
                html += '<div class="entity-card-title">' + escapeHtml(s.name) + '</div>';
                html += '<div class="entity-card-meta">' + escapeHtml(s.target || '—') + ' · ' + escapeHtml(s.scan_type || 'port') + ' · ' + escapeHtml(s.schedule_type || 'daily') + '</div>';
                html += '</div><span class="status-dot ' + (s.enabled ? 'active' : 'disabled') + '"></span></div>';
                if (s.last_run) html += '<div class="entity-card-meta">Last run: ' + formatDate(s.last_run) + '</div>';
                if (s.next_run) html += '<div class="entity-card-meta">Next run: ' + formatDate(s.next_run) + '</div>';
                html += '<div class="entity-card-actions">';
                html += '<button class="btn-small btn-rescan" onclick="triggerSchedule(' + s.id + ')">▶ Run Now</button>';
                html += '<button class="btn-small btn-secondary" onclick="toggleSchedule(' + s.id + ')">' + (s.enabled ? 'Disable' : 'Enable') + '</button>';
                html += '<button class="btn-small btn-secondary" onclick="editSchedule(' + s.id + ')">Edit</button>';
                html += '<button class="btn-small btn-stop" onclick="deleteSchedule(' + s.id + ', \'' + escapeHtml(s.name) + '\')">Delete</button>';
                html += '</div></div>';
            });
            html += '</div>';
            container.innerHTML = html;
        }).catch(function(err) { container.innerHTML = '<p class="error">Failed to load schedules: ' + err.message + '</p>'; });
    }

    window.triggerSchedule = function(id) {
        fetch('/api/v1/schedules/' + id + '/run', { method: 'POST' }).then(function(r) { return r.json(); })
            .then(function() { showToast('Schedule triggered', 'success'); loadSchedules(); })
            .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    window.toggleSchedule = function(id) {
        fetch('/api/v1/schedules/' + id + '/toggle', { method: 'POST' }).then(function(r) { return r.json(); })
            .then(function() { showToast('Schedule toggled', 'success'); loadSchedules(); })
            .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    window.deleteSchedule = function(id, name) {
        if (!confirm('Delete schedule "' + name + '"?')) return;
        fetch('/api/v1/schedules/' + id, { method: 'DELETE' }).then(function(r) { return r.json(); })
            .then(function() { showToast('Schedule deleted', 'success'); loadSchedules(); })
            .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    window.editSchedule = function(id) {
        fetch('/api/v1/schedules/' + id).then(function(r) { return r.json(); }).then(function(sched) {
            showScheduleForm(sched);
        }).catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    function showScheduleForm(sched) {
        var isEdit = !!sched;
        var html = '<h2>' + (isEdit ? 'Edit Schedule' : 'New Schedule') + '</h2><div class="modal-form">';
        html += '<div><label>Name</label><input type="text" id="sched-name" value="' + escapeHtml((sched && sched.name) || '') + '"></div>';
        html += '<div><label>Target</label><input type="text" id="sched-target" value="' + escapeHtml((sched && sched.target) || '') + '" placeholder="IP, CIDR, or hostname"></div>';
        html += '<div><label>Scan Type</label><select id="sched-scan-type"><option value="port">Port Scan</option><option value="vuln">Vulnerability Scan</option><option value="full">Full (Port + Vuln)</option></select></div>';
        html += '<div><label>Schedule Type</label><select id="sched-type"><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select></div>';
        html += '<div><label>Hour (UTC)</label><input type="number" id="sched-hour" min="0" max="23" value="' + ((sched && sched.schedule_hour) || 2) + '"></div>';
        html += '<div class="modal-form-actions">';
        html += '<button class="btn-primary" id="sched-save-btn">Save</button>';
        html += '<button class="btn-secondary" onclick="document.getElementById(\'generic-modal\').style.display=\'none\';document.body.style.overflow=\'\'">Cancel</button>';
        html += '</div></div>';

        showGenericModal(html);

        if (sched) {
            if (sched.scan_type) document.getElementById('sched-scan-type').value = sched.scan_type;
            if (sched.schedule_type) document.getElementById('sched-type').value = sched.schedule_type;
        }

        document.getElementById('sched-save-btn').addEventListener('click', function() {
            var body = {
                name: document.getElementById('sched-name').value.trim(),
                target: document.getElementById('sched-target').value.trim(),
                scan_type: document.getElementById('sched-scan-type').value,
                schedule_type: document.getElementById('sched-type').value,
                schedule_hour: parseInt(document.getElementById('sched-hour').value) || 2
            };
            var method = isEdit ? 'PUT' : 'POST';
            var url = isEdit ? '/api/v1/schedules/' + sched.id : '/api/v1/schedules';
            fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
                .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || 'Failed'); }); return r.json(); })
                .then(function() { closeGenericModal(); showToast('Schedule saved', 'success'); loadSchedules(); })
                .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
        });
    }

    document.getElementById('btn-create-schedule').addEventListener('click', function() { showScheduleForm(null); });

    // ==================== Agents Page ====================

    function loadAgents() {
        var container = document.getElementById('agents-list');
        container.innerHTML = '<div style="text-align:center;padding:48px"><div class="spinner"></div></div>';

        fetch('/api/v1/agents').then(function(r) { return r.json(); }).then(function(agents) {
            if (!agents || agents.length === 0) {
                container.innerHTML = '<div class="empty-state"><span class="empty-state-icon">🤖</span>No agents registered yet. Install an agent on a host to get started.</div>';
                return;
            }
            var html = '<div class="entity-cards">';
            agents.forEach(function(a) {
                html += '<div class="entity-card"><div class="entity-card-header"><div>';
                html += '<div class="entity-card-title"><span class="status-dot ' + (a.status || 'offline') + '"></span>' + escapeHtml(a.hostname || a.ip || 'Unknown') + '</div>';
                html += '<div class="entity-card-meta">' + escapeHtml(a.ip || '—') + ' · ' + escapeHtml(a.os || '—') + '</div>';
                html += '</div></div>';
                html += '<div class="entity-card-meta">Last checkin: ' + formatDate(a.last_checkin) + '</div>';
                if (a.version) html += '<div class="entity-card-meta">Version: ' + escapeHtml(a.version) + '</div>';
                if (a.package_count) html += '<div class="entity-card-meta">' + a.package_count + ' packages · ' + (a.port_count || 0) + ' ports</div>';
                html += '<div class="entity-card-actions">';
                html += '<button class="btn-small btn-details" onclick="showAgentDetail(' + a.id + ')">Details</button>';
                html += '<button class="btn-small btn-secondary" onclick="regenAgentKey(' + a.id + ')">Regen Key</button>';
                html += '<button class="btn-small btn-stop" onclick="deleteAgent(' + a.id + ', \'' + escapeHtml(a.hostname || '') + '\')">Delete</button>';
                html += '</div></div>';
            });
            html += '</div>';
            container.innerHTML = html;
        }).catch(function(err) { container.innerHTML = '<p class="error">Failed to load agents: ' + err.message + '</p>'; });
    }

    window.showAgentDetail = function(id) {
        fetch('/api/v1/agents/' + id).then(function(r) { return r.json(); }).then(function(agent) {
            var html = '<h2>Agent: ' + escapeHtml(agent.hostname || agent.ip || 'Unknown') + '</h2>';
            html += '<div class="asset-modal-grid">';
            html += '<div class="asset-modal-section"><div class="asset-section-title">System Info</div><ul class="asset-info-list">';
            html += '<li><span class="asset-info-label">Hostname</span><span class="asset-info-value">' + escapeHtml(agent.hostname || '—') + '</span></li>';
            html += '<li><span class="asset-info-label">IP</span><span class="asset-info-value">' + escapeHtml(agent.ip || '—') + '</span></li>';
            html += '<li><span class="asset-info-label">OS</span><span class="asset-info-value">' + escapeHtml(agent.os || '—') + '</span></li>';
            html += '<li><span class="asset-info-label">Status</span><span class="asset-info-value"><span class="status-dot ' + (agent.status || 'offline') + '"></span>' + escapeHtml(agent.status || '—') + '</span></li>';
            html += '<li><span class="asset-info-label">Version</span><span class="asset-info-value">' + escapeHtml(agent.version || '—') + '</span></li>';
            html += '<li><span class="asset-info-label">Last Checkin</span><span class="asset-info-value">' + formatDate(agent.last_checkin) + '</span></li>';
            html += '<li><span class="asset-info-label">Registered</span><span class="asset-info-value">' + formatDate(agent.created_at) + '</span></li>';
            html += '</ul></div>';

            if (agent.latest_report) {
                var r = agent.latest_report;
                html += '<div class="asset-modal-section"><div class="asset-section-title">Latest Report</div><ul class="asset-info-list">';
                html += '<li><span class="asset-info-label">Date</span><span class="asset-info-value">' + formatDate(r.created_at) + '</span></li>';
                html += '<li><span class="asset-info-label">Packages</span><span class="asset-info-value">' + (r.package_count || 0) + '</span></li>';
                html += '<li><span class="asset-info-label">Ports</span><span class="asset-info-value">' + (r.port_count || 0) + '</span></li>';
                html += '<li><span class="asset-info-label">CVE Matches</span><span class="asset-info-value">' + (r.vulns_matched || 0) + '</span></li>';
                html += '</ul></div>';
            }
            html += '</div>';
            showGenericModal(html);
        }).catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    window.regenAgentKey = function(id) {
        if (!confirm('Regenerate agent key? The agent will need to be reconfigured.')) return;
        fetch('/api/v1/agents/' + id + '/generate-key', { method: 'POST' }).then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.agent_key) showToast('New key: ' + data.agent_key, 'info');
                else showToast('Key regenerated', 'success');
            })
            .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    window.deleteAgent = function(id, name) {
        if (!confirm('Delete agent "' + name + '"?')) return;
        fetch('/api/v1/agents/' + id, { method: 'DELETE' }).then(function(r) { return r.json(); })
            .then(function() { showToast('Agent deleted', 'success'); loadAgents(); })
            .catch(function(err) { showToast('Error: ' + err.message, 'error'); });
    };

    // ==================== SQL Tab ====================

    var sqlEditor = null;
    var sqlLastResult = null;
    var sqlInitialized = false;

    function initSqlTab() {
        if (sqlInitialized) return;
        var textarea = document.getElementById('sql-editor');
        if (!textarea || typeof CodeMirror === 'undefined') return;

        sqlEditor = CodeMirror.fromTextArea(textarea, {
            mode: 'text/x-sql', lineNumbers: true, matchBrackets: true,
            autofocus: false, tabSize: 2, indentWithTabs: false, lineWrapping: true
        });
        sqlEditor.setSize('100%', '180px');
        sqlEditor.setOption('extraKeys', { 'Ctrl-Enter': runSqlQuery, 'Cmd-Enter': runSqlQuery });
        sqlInitialized = true;
        renderSqlHistory();
    }

    function runSqlQuery() {
        if (!sqlEditor) return;
        var query = sqlEditor.getValue().trim();
        if (!query) return;

        var statusEl = document.getElementById('sql-status');
        var errorEl = document.getElementById('sql-error');
        var resultsEl = document.getElementById('sql-results-container');
        var csvBtn = document.getElementById('sql-export-csv');
        var jsonBtn = document.getElementById('sql-export-json');

        statusEl.textContent = 'Running...';
        errorEl.style.display = 'none';
        csvBtn.disabled = true; jsonBtn.disabled = true;

        fetch('/api/sql', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: query }) })
            .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function(res) {
                if (!res.ok || res.data.error) {
                    errorEl.textContent = res.data.error || 'Unknown error';
                    errorEl.style.display = 'block'; statusEl.textContent = 'Error';
                    resultsEl.innerHTML = ''; sqlLastResult = null; return;
                }
                var d = res.data;
                sqlLastResult = d;
                addSqlHistory(query);
                statusEl.textContent = d.count + ' row(s) in ' + d.time_ms + 'ms' + (d.truncated ? ' (truncated)' : '');
                csvBtn.disabled = false; jsonBtn.disabled = false;

                if (d.columns.length === 0) { resultsEl.innerHTML = '<p class="empty-state">Query returned no columns.</p>'; return; }

                var html = '<div class="sql-results-scroll"><table class="sql-results-table"><thead><tr>';
                d.columns.forEach(function(col) { html += '<th>' + escapeHtml(col) + '</th>'; });
                html += '</tr></thead><tbody>';
                d.rows.forEach(function(row) {
                    html += '<tr>';
                    row.forEach(function(val) { html += '<td>' + (val === null ? '<span class="text-muted">NULL</span>' : escapeHtml(String(val))) + '</td>'; });
                    html += '</tr>';
                });
                html += '</tbody></table></div>';
                resultsEl.innerHTML = html;
            })
            .catch(function(err) { errorEl.textContent = 'Network error: ' + err.message; errorEl.style.display = 'block'; statusEl.textContent = 'Error'; });
    }

    function getSqlHistory() { try { return JSON.parse(localStorage.getItem('sqlHistory') || '[]'); } catch(e) { return []; } }

    function addSqlHistory(query) {
        var history = getSqlHistory().filter(function(q) { return q !== query; });
        history.unshift(query);
        if (history.length > 10) history = history.slice(0, 10);
        localStorage.setItem('sqlHistory', JSON.stringify(history));
        renderSqlHistory();
    }

    function renderSqlHistory() {
        var container = document.getElementById('sql-history-list');
        if (!container) return;
        var history = getSqlHistory();
        if (history.length === 0) { container.innerHTML = '<p class="text-muted" style="padding:8px;font-size:12px;">No queries yet.</p>'; return; }
        var html = '';
        history.forEach(function(q, i) {
            html += '<div class="sql-history-item" data-index="' + i + '" title="' + escapeHtml(q) + '">' + escapeHtml(q.substring(0, 80)) + (q.length > 80 ? '...' : '') + '</div>';
        });
        container.innerHTML = html;
        container.querySelectorAll('.sql-history-item').forEach(function(el) {
            el.addEventListener('click', function() {
                var idx = parseInt(this.getAttribute('data-index'));
                var h = getSqlHistory();
                if (h[idx] && sqlEditor) sqlEditor.setValue(h[idx]);
            });
        });
    }

    var sqlRunBtn = document.getElementById('sql-run-btn');
    if (sqlRunBtn) sqlRunBtn.addEventListener('click', runSqlQuery);

    var sqlCsvBtn = document.getElementById('sql-export-csv');
    if (sqlCsvBtn) sqlCsvBtn.addEventListener('click', function() {
        if (!sqlLastResult || !sqlLastResult.columns.length) return;
        var d = sqlLastResult;
        var lines = [d.columns.map(function(c) { return '"' + c.replace(/"/g, '""') + '"'; }).join(',')];
        d.rows.forEach(function(row) { lines.push(row.map(function(v) { return v === null ? '' : '"' + String(v).replace(/"/g, '""') + '"'; }).join(',')); });
        downloadBlob(lines.join('\n'), 'query_results.csv', 'text/csv');
    });

    var sqlJsonBtn = document.getElementById('sql-export-json');
    if (sqlJsonBtn) sqlJsonBtn.addEventListener('click', function() {
        if (!sqlLastResult || !sqlLastResult.columns.length) return;
        var d = sqlLastResult;
        var objs = d.rows.map(function(row) { var o = {}; d.columns.forEach(function(col, i) { o[col] = row[i]; }); return o; });
        downloadBlob(JSON.stringify(objs, null, 2), 'query_results.json', 'application/json');
    });

    // ==================== Init: Load Dashboard ====================
    loadDashboard();
});