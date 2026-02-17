document.addEventListener('DOMContentLoaded', function() {
    var socket = io();

    // ==================== Theme Management ====================
    var themeOptions = document.querySelectorAll('.theme-option');
    var currentTheme = localStorage.getItem('theme') || 'light';

    // Apply saved theme on load
    applyTheme(currentTheme);

    function applyTheme(theme) {
        document.body.className = 'theme-' + theme;
        currentTheme = theme;
        localStorage.setItem('theme', theme);

        // Update active state on theme options
        themeOptions.forEach(function(option) {
            if (option.getAttribute('data-theme') === theme) {
                option.classList.add('active');
            } else {
                option.classList.remove('active');
            }
        });
    }

    // Theme option click handlers
    themeOptions.forEach(function(option) {
        option.addEventListener('click', function() {
            var theme = this.getAttribute('data-theme');
            applyTheme(theme);
        });
    });

    // ==================== Scan Settings Management ====================
    var defaultSettings = {
        ports: '',
        scanSpeed: 'T3',
        hostTimeout: 300,
        maxHosts: 256,
        vulnTimeout: 600,
        severity: 'critical,high,medium,low',
        rateLimit: 150,
        templates: ''
    };

    // Load settings from localStorage
    function loadSettings() {
        var saved = localStorage.getItem('scanSettings');
        if (saved) {
            try {
                return JSON.parse(saved);
            } catch (e) {
                return defaultSettings;
            }
        }
        return defaultSettings;
    }

    // Save settings to localStorage
    function saveSettings(settings) {
        localStorage.setItem('scanSettings', JSON.stringify(settings));
    }

    // Get current settings from form
    function getSettingsFromForm() {
        return {
            ports: document.getElementById('setting-ports').value.trim(),
            scanSpeed: document.getElementById('setting-scan-speed').value,
            hostTimeout: parseInt(document.getElementById('setting-host-timeout').value) || 300,
            maxHosts: parseInt(document.getElementById('setting-max-hosts').value) || 256,
            vulnTimeout: parseInt(document.getElementById('setting-vuln-timeout').value) || 600,
            severity: document.getElementById('setting-severity').value,
            rateLimit: parseInt(document.getElementById('setting-rate-limit').value) || 150,
            templates: document.getElementById('setting-templates').value.trim()
        };
    }

    // Apply settings to form
    function applySettingsToForm(settings) {
        document.getElementById('setting-ports').value = settings.ports || '';
        document.getElementById('setting-scan-speed').value = settings.scanSpeed || 'T3';
        document.getElementById('setting-host-timeout').value = settings.hostTimeout || 300;
        document.getElementById('setting-max-hosts').value = settings.maxHosts || 256;
        document.getElementById('setting-vuln-timeout').value = settings.vulnTimeout || 600;
        document.getElementById('setting-severity').value = settings.severity || 'critical,high,medium,low';
        document.getElementById('setting-rate-limit').value = settings.rateLimit || 150;
        document.getElementById('setting-templates').value = settings.templates || '';
    }

    // Show status message
    function showSettingsStatus(message, isError) {
        var statusEl = document.getElementById('settings-status');
        if (statusEl) {
            statusEl.textContent = message;
            statusEl.classList.remove('error');
            if (isError) statusEl.classList.add('error');
            statusEl.classList.add('visible');
            setTimeout(function() {
                statusEl.classList.remove('visible');
            }, 3000);
        }
    }

    // Get current scan settings for sending to backend
    function getScanSettings() {
        return loadSettings();
    }

    // Initialize settings form
    var saveSettingsBtn = document.getElementById('save-settings');
    var resetSettingsBtn = document.getElementById('reset-settings');

    if (saveSettingsBtn) {
        // Load saved settings on page load
        applySettingsToForm(loadSettings());

        saveSettingsBtn.addEventListener('click', function() {
            var settings = getSettingsFromForm();

            // Validate settings
            if (settings.hostTimeout < 30 || settings.hostTimeout > 3600) {
                showSettingsStatus('Host timeout must be between 30-3600 seconds', true);
                return;
            }
            if (settings.maxHosts < 1 || settings.maxHosts > 1024) {
                showSettingsStatus('Max hosts must be between 1-1024', true);
                return;
            }
            if (settings.vulnTimeout < 60 || settings.vulnTimeout > 3600) {
                showSettingsStatus('Vuln timeout must be between 60-3600 seconds', true);
                return;
            }
            if (settings.rateLimit < 10 || settings.rateLimit > 1000) {
                showSettingsStatus('Rate limit must be between 10-1000 req/sec', true);
                return;
            }

            saveSettings(settings);
            showSettingsStatus('Settings saved successfully');
        });
    }

    if (resetSettingsBtn) {
        resetSettingsBtn.addEventListener('click', function() {
            applySettingsToForm(defaultSettings);
            saveSettings(defaultSettings);
            showSettingsStatus('Settings reset to defaults');
        });
    }

    // ==================== Log Window Management ====================
    var logContent = document.getElementById('log-content');
    var logClearBtn = document.getElementById('log-clear');
    var logContainer = document.getElementById('log-container');
    var pageLayout = document.getElementById('page-layout');
    var maxLogEntries = 500;

    // Show split-view (log panel) when on scan tab
    function updateSplitView(tabId) {
        if (tabId === 'scan-tab') {
            pageLayout.classList.add('split-view');
        } else {
            pageLayout.classList.remove('split-view');
        }
    }

    // Initialize split-view for the default active tab
    updateSplitView('scan-tab');

    function getTimestamp() {
        var now = new Date();
        return now.toLocaleTimeString('en-US', { hour12: false }) + '.' +
               String(now.getMilliseconds()).padStart(3, '0');
    }

    function addLog(message, level) {
        level = level || 'info';

        if (!logContent) return;

        // Remove empty state if present
        var emptyState = logContent.querySelector('.log-empty');
        if (emptyState) {
            emptyState.remove();
        }

        var entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.innerHTML = '<span class="log-timestamp">' + getTimestamp() + '</span>' +
                          '<span class="log-level ' + level + '">' + level + '</span>' +
                          '<span class="log-message">' + escapeHtml(message) + '</span>';

        logContent.appendChild(entry);

        // Limit log entries
        while (logContent.children.length > maxLogEntries) {
            logContent.removeChild(logContent.firstChild);
        }

        // Auto-scroll to bottom
        logContent.scrollTop = logContent.scrollHeight;
    }

    function clearLogs() {
        if (logContent) {
            logContent.innerHTML = '<div class="log-empty">No log entries yet. Start a scan to see logs.</div>';
        }
    }

    // Initialize log window
    if (logContent) {
        clearLogs();
    }

    if (logClearBtn) {
        logClearBtn.addEventListener('click', clearLogs);
    }

    // Listen for log events from backend
    socket.on('scan_log', function(data) {
        addLog(data.message, data.level || 'info');
    });

    // ==================== Tab Management ====================
    // Tab elements
    var tabBtns = document.querySelectorAll('.tab-btn');
    var tabContents = document.querySelectorAll('.tab-content');

    // Scan tab elements
    var scanForm = document.getElementById('scan-form');
    var progressBar = document.getElementById('progress-bar');
    var progressContainer = document.getElementById('progress-container');
    var progressMessage = document.getElementById('progress-message');
    var scanOutput = document.getElementById('scan-output');
    var portScanBtn = document.getElementById('port-scan-btn');
    var vulnScanBtn = document.getElementById('vuln-scan-btn');
    var stopScanBtn = document.getElementById('stop-scan-btn');

    // Assets tab elements
    var assetsList = document.getElementById('assets-list');
    var assetsCount = document.getElementById('assets-count');
    var refreshAssetsBtn = document.getElementById('refresh-assets');

    // Vulnerabilities tab elements
    var vulnsList = document.getElementById('vulns-list');
    var refreshVulnsBtn = document.getElementById('refresh-vulns');
    var vulnFilter = document.getElementById('vuln-filter');

    // Modal elements
    var cveModal = document.getElementById('cve-modal');
    var modalBody = document.getElementById('modal-body');
    var modalClose = document.getElementById('modal-close');

    // Store vulnerabilities for modal access
    var storedVulnerabilities = [];

    // Modal functions
    function showCveModal(vuln) {
        var cvssClass = '';
        if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
            cvssClass = vuln.cvss_score >= 9.0 ? 'critical' : (vuln.cvss_score >= 7.0 ? 'high' : (vuln.cvss_score >= 4.0 ? 'medium' : 'low'));
        }

        var html = '<div class="modal-header">';
        html += '<div>';
        html += '<h2 class="modal-cve-id">' + vuln.vuln_id + '</h2>';
        html += '<div class="modal-badges">';
        html += '<span class="severity-badge ' + vuln.severity + '">' + vuln.severity.toUpperCase() + '</span>';
        if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
            html += '<span class="cvss-badge ' + cvssClass + '">CVSS ' + vuln.cvss_score.toFixed(1) + '</span>';
        }
        if (vuln.cwe_id) {
            html += '<span class="cwe-badge">' + vuln.cwe_id + '</span>';
        }
        html += '</div>';
        html += '</div>';
        html += '</div>';

        // Target section
        html += '<div class="modal-section">';
        html += '<div class="modal-section-title">Target</div>';
        html += '<span class="modal-target">' + vuln.ip + ':' + vuln.port + '/' + vuln.protocol + '</span>';
        html += '</div>';

        // CVSS Details section
        if (vuln.cvss_score !== null || vuln.cvss_vector) {
            html += '<div class="modal-section">';
            html += '<div class="modal-section-title">CVSS Details</div>';
            html += '<div class="modal-cvss-details">';
            if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
                html += '<div class="modal-cvss-item">';
                html += '<div class="modal-cvss-label">Base Score</div>';
                html += '<div class="modal-cvss-value ' + cvssClass + '">' + vuln.cvss_score.toFixed(1) + '</div>';
                html += '</div>';
            }
            html += '<div class="modal-cvss-item">';
            html += '<div class="modal-cvss-label">Severity</div>';
            html += '<div class="modal-cvss-value ' + cvssClass + '">' + vuln.severity.toUpperCase() + '</div>';
            html += '</div>';
            html += '</div>';
            if (vuln.cvss_vector) {
                html += '<div class="modal-vector" style="margin-top: 10px;">' + vuln.cvss_vector + '</div>';
            }
            html += '</div>';
        }

        // Description section
        html += '<div class="modal-section">';
        html += '<div class="modal-section-title">Description</div>';
        html += '<div class="modal-description">' + escapeHtml(vuln.description) + '</div>';
        html += '</div>';

        // References section
        if (vuln.references && vuln.references.length > 0) {
            html += '<div class="modal-section">';
            html += '<div class="modal-section-title">References</div>';
            html += '<ul class="modal-refs-list">';
            vuln.references.forEach(function(ref) {
                if (ref.url) {
                    html += '<li>';
                    html += '<a href="' + escapeHtml(ref.url) + '" target="_blank" rel="noopener">' + escapeHtml(ref.url) + '</a>';
                    if (ref.source) {
                        html += '<span class="modal-ref-source">(' + escapeHtml(ref.source) + ')</span>';
                    }
                    html += '</li>';
                }
            });
            html += '</ul>';
            html += '</div>';
        }

        // Dates section
        html += '<div class="modal-section">';
        html += '<div class="modal-section-title">Dates</div>';
        html += '<div class="modal-dates">';
        if (vuln.published_date) {
            html += '<div class="modal-date-item">';
            html += '<span class="modal-date-label">Published</span>';
            html += '<span class="modal-date-value">' + formatDate(vuln.published_date) + '</span>';
            html += '</div>';
        }
        html += '<div class="modal-date-item">';
        html += '<span class="modal-date-label">Discovered</span>';
        html += '<span class="modal-date-value">' + formatDate(vuln.scan_date) + '</span>';
        html += '</div>';
        html += '</div>';
        html += '</div>';

        modalBody.innerHTML = html;
        cveModal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }

    function closeCveModal() {
        cveModal.style.display = 'none';
        document.body.style.overflow = '';
    }

    // Modal event listeners
    if (modalClose) {
        modalClose.addEventListener('click', closeCveModal);
    }

    if (cveModal) {
        cveModal.addEventListener('click', function(e) {
            if (e.target === cveModal) {
                closeCveModal();
            }
        });
    }

    // Close modal on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && cveModal.style.display === 'flex') {
            closeCveModal();
        }
        if (e.key === 'Escape' && assetModal && assetModal.style.display === 'flex') {
            closeAssetModal();
        }
    });

    // Asset Modal elements
    var assetModal = document.getElementById('asset-modal');
    var assetModalBody = document.getElementById('asset-modal-body');
    var assetModalClose = document.getElementById('asset-modal-close');

    function showAssetModal(ip) {
        if (!assetModal || !assetModalBody) return;

        // Show loading state
        assetModalBody.innerHTML = '<div class="asset-modal-loading"><div class="spinner"></div><p>Loading asset details...</p></div>';
        assetModal.style.display = 'flex';
        document.body.style.overflow = 'hidden';

        // Fetch asset details
        fetch('/api/asset/' + encodeURIComponent(ip))
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.error) {
                    assetModalBody.innerHTML = '<div class="asset-modal-loading"><p class="error">Error: ' + escapeHtml(data.error) + '</p></div>';
                    return;
                }
                renderAssetModal(data.asset);
            })
            .catch(function(err) {
                assetModalBody.innerHTML = '<div class="asset-modal-loading"><p class="error">Failed to load asset details</p></div>';
            });
    }

    function renderAssetModal(asset) {
        var html = '<div class="asset-modal-header">';
        html += '<h2 class="asset-modal-ip">' + escapeHtml(asset.ip) + '</h2>';

        if (asset.hostname) {
            html += '<p class="asset-modal-hostname">' + escapeHtml(asset.hostname) + '</p>';
        }

        html += '<div class="asset-modal-meta">';
        if (asset.os_name) {
            html += '<span class="asset-meta-badge os">' + escapeHtml(asset.os_name) + '</span>';
        }
        if (asset.device_type) {
            html += '<span class="asset-meta-badge device">' + escapeHtml(asset.device_type) + '</span>';
        }
        if (asset.mac_vendor) {
            html += '<span class="asset-meta-badge">' + escapeHtml(asset.mac_vendor) + '</span>';
        }
        html += '</div>';

        // Add report generation button
        html += '<div class="asset-modal-actions">';
        html += '<button class="btn btn-report" onclick="window.open(\'/report/' + encodeURIComponent(asset.ip) + '\', \'_blank\')">Generate Report</button>';
        html += '</div>';

        html += '</div>';

        html += '<div class="asset-modal-grid">';

        // Network Info section
        html += '<div class="asset-modal-section">';
        html += '<div class="asset-section-title">Network Information</div>';
        html += '<ul class="asset-info-list">';
        html += '<li><span class="asset-info-label">IP Address</span><span class="asset-info-value">' + escapeHtml(asset.ip) + '</span></li>';
        html += '<li><span class="asset-info-label">Hostname</span><span class="asset-info-value' + (asset.hostname ? '' : ' none') + '">' + (asset.hostname ? escapeHtml(asset.hostname) : 'Not resolved') + '</span></li>';
        html += '<li><span class="asset-info-label">Reverse DNS</span><span class="asset-info-value' + (asset.reverse_dns ? '' : ' none') + '">' + (asset.reverse_dns ? escapeHtml(asset.reverse_dns) : 'Not available') + '</span></li>';
        html += '<li><span class="asset-info-label">MAC Address</span><span class="asset-info-value' + (asset.mac_address ? '' : ' none') + '">' + (asset.mac_address ? escapeHtml(asset.mac_address) : 'Not available') + '</span></li>';
        html += '<li><span class="asset-info-label">MAC Vendor</span><span class="asset-info-value' + (asset.mac_vendor ? '' : ' none') + '">' + (asset.mac_vendor ? escapeHtml(asset.mac_vendor) : 'Unknown') + '</span></li>';
        html += '</ul>';
        html += '</div>';

        // System Info section
        html += '<div class="asset-modal-section">';
        html += '<div class="asset-section-title">System Information</div>';
        html += '<ul class="asset-info-list">';
        html += '<li><span class="asset-info-label">Operating System</span><span class="asset-info-value' + (asset.os_name ? '' : ' none') + '">' + (asset.os_name ? escapeHtml(asset.os_name) : 'Unknown') + '</span></li>';
        html += '<li><span class="asset-info-label">OS Family</span><span class="asset-info-value' + (asset.os_family ? '' : ' none') + '">' + (asset.os_family ? escapeHtml(asset.os_family) : 'Unknown') + '</span></li>';
        html += '<li><span class="asset-info-label">OS Vendor</span><span class="asset-info-value' + (asset.os_vendor ? '' : ' none') + '">' + (asset.os_vendor ? escapeHtml(asset.os_vendor) : 'Unknown') + '</span></li>';
        html += '<li><span class="asset-info-label">Device Type</span><span class="asset-info-value' + (asset.device_type ? '' : ' none') + '">' + (asset.device_type ? escapeHtml(asset.device_type) : 'Unknown') + '</span></li>';
        if (asset.os_accuracy) {
            html += '<li><span class="asset-info-label">Detection Accuracy</span><span class="asset-info-value">' + escapeHtml(asset.os_accuracy) + '%</span></li>';
        }
        html += '</ul>';
        html += '</div>';

        // Scan History section
        html += '<div class="asset-modal-section">';
        html += '<div class="asset-section-title">Scan History</div>';
        html += '<div class="asset-scan-stats">';
        html += '<div class="asset-stat"><div class="asset-stat-value">' + (asset.scan_count || 0) + '</div><div class="asset-stat-label">Total Scans</div></div>';
        html += '<div class="asset-stat"><div class="asset-stat-value">' + (asset.ports ? asset.ports.length : 0) + '</div><div class="asset-stat-label">Open Ports</div></div>';
        html += '</div>';
        html += '<ul class="asset-info-list" style="margin-top: 12px;">';
        html += '<li><span class="asset-info-label">First Seen</span><span class="asset-info-value">' + (asset.first_seen ? formatDate(asset.first_seen) : 'N/A') + '</span></li>';
        html += '<li><span class="asset-info-label">Last Seen</span><span class="asset-info-value">' + (asset.last_seen ? formatDate(asset.last_seen) : 'N/A') + '</span></li>';
        html += '</ul>';
        html += '</div>';

        // Vulnerabilities section
        html += '<div class="asset-modal-section">';
        html += '<div class="asset-section-title">Vulnerabilities</div>';
        if (asset.vuln_counts && (asset.vuln_counts.critical > 0 || asset.vuln_counts.high > 0 || asset.vuln_counts.medium > 0 || asset.vuln_counts.low > 0 || asset.vuln_counts.info > 0)) {
            html += '<div class="asset-vuln-summary">';
            if (asset.vuln_counts.critical > 0) {
                html += '<span class="asset-vuln-badge critical">' + asset.vuln_counts.critical + ' Critical</span>';
            }
            if (asset.vuln_counts.high > 0) {
                html += '<span class="asset-vuln-badge high">' + asset.vuln_counts.high + ' High</span>';
            }
            if (asset.vuln_counts.medium > 0) {
                html += '<span class="asset-vuln-badge medium">' + asset.vuln_counts.medium + ' Medium</span>';
            }
            if (asset.vuln_counts.low > 0) {
                html += '<span class="asset-vuln-badge low">' + asset.vuln_counts.low + ' Low</span>';
            }
            if (asset.vuln_counts.info > 0) {
                html += '<span class="asset-vuln-badge info">' + asset.vuln_counts.info + ' Info</span>';
            }
            html += '</div>';
        } else {
            html += '<p class="asset-no-vulns">No vulnerabilities detected</p>';
        }
        html += '</div>';

        // Identified Technologies section
        if (asset.fingerprints && asset.fingerprints.length > 0) {
            html += '<div class="asset-modal-section full-width">';
            html += '<div class="asset-section-title">Identified Technologies</div>';
            html += '<table class="asset-ports-table">';
            html += '<thead><tr><th>Port</th><th>Technology</th><th>Version</th><th>Category</th><th>Vendor</th><th>Confidence</th><th>CPE</th></tr></thead>';
            html += '<tbody>';
            asset.fingerprints.forEach(function(fp) {
                var confClass = fp.confidence >= 80 ? 'high-conf' : (fp.confidence >= 50 ? 'med-conf' : 'low-conf');
                html += '<tr>';
                html += '<td class="asset-port-number">' + fp.port + '</td>';
                html += '<td class="asset-port-service"><strong>' + escapeHtml(fp.name || '') + '</strong></td>';
                html += '<td class="asset-port-product">' + escapeHtml(fp.version || '-') + '</td>';
                html += '<td><span class="tech-category-badge">' + escapeHtml(fp.category || '') + '</span></td>';
                html += '<td>' + escapeHtml(fp.vendor || '') + '</td>';
                html += '<td><span class="confidence-bar ' + confClass + '">' + fp.confidence + '%</span></td>';
                html += '<td class="asset-port-product">' + escapeHtml(fp.cpe || '-') + '</td>';
                html += '</tr>';
            });
            html += '</tbody></table>';
            html += '</div>';
        }

        // Ports section (full width)
        html += '<div class="asset-modal-section full-width">';
        html += '<div class="asset-section-title">Open Ports & Services</div>';
        if (asset.ports && asset.ports.length > 0) {
            html += '<table class="asset-ports-table">';
            html += '<thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Identified As</th></tr></thead>';
            html += '<tbody>';
            asset.ports.forEach(function(port) {
                var fpInfo = '';
                if (port.fingerprint && port.fingerprint.name) {
                    var verStr = port.fingerprint.version ? ' v' + port.fingerprint.version : '';
                    fpInfo = port.fingerprint.name + verStr;
                }
                html += '<tr>';
                html += '<td class="asset-port-number">' + port.port + '</td>';
                html += '<td>' + escapeHtml(port.protocol || '') + '</td>';
                html += '<td>' + escapeHtml(port.state || '') + '</td>';
                html += '<td class="asset-port-service">' + escapeHtml(port.service || '') + '</td>';
                html += '<td class="asset-port-product">' + escapeHtml(port.product || '') + '</td>';
                html += '<td class="asset-port-product">' + escapeHtml(port.version || '') + '</td>';
                html += '<td class="asset-port-product">' + (fpInfo ? '<strong>' + escapeHtml(fpInfo) + '</strong>' : '<span class="text-muted">-</span>') + '</td>';
                html += '</tr>';
            });
            html += '</tbody></table>';
        } else {
            html += '<p class="asset-no-vulns">No open ports found</p>';
        }
        html += '</div>';

        // DNS Aliases section (if any)
        if (asset.aliases && asset.aliases.length > 0) {
            html += '<div class="asset-modal-section full-width">';
            html += '<div class="asset-section-title">DNS Aliases</div>';
            html += '<ul class="asset-info-list">';
            asset.aliases.forEach(function(alias) {
                html += '<li><span class="asset-info-value">' + escapeHtml(alias) + '</span></li>';
            });
            html += '</ul>';
            html += '</div>';
        }

        html += '</div>'; // Close grid

        assetModalBody.innerHTML = html;
    }

    function closeAssetModal() {
        if (assetModal) {
            assetModal.style.display = 'none';
            document.body.style.overflow = '';
        }
    }

    // Asset modal event listeners
    if (assetModalClose) {
        assetModalClose.addEventListener('click', closeAssetModal);
    }

    if (assetModal) {
        assetModal.addEventListener('click', function(e) {
            if (e.target === assetModal) {
                closeAssetModal();
            }
        });
    }

    // View state (cards or list)
    var assetsViewMode = localStorage.getItem('assetsViewMode') || 'cards';
    var vulnsViewMode = localStorage.getItem('vulnsViewMode') || 'cards';

    // View toggle buttons
    var assetsViewBtns = document.querySelectorAll('.view-btn');
    var vulnsViewBtns = document.querySelectorAll('.view-btn-vulns');

    // Initialize view toggle states
    assetsViewBtns.forEach(function(btn) {
        if (btn.getAttribute('data-view') === assetsViewMode) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
        btn.addEventListener('click', function() {
            assetsViewMode = this.getAttribute('data-view');
            localStorage.setItem('assetsViewMode', assetsViewMode);
            assetsViewBtns.forEach(function(b) { b.classList.remove('active'); });
            this.classList.add('active');
            loadAssets();
        });
    });

    vulnsViewBtns.forEach(function(btn) {
        if (btn.getAttribute('data-view') === vulnsViewMode) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
        btn.addEventListener('click', function() {
            vulnsViewMode = this.getAttribute('data-view');
            localStorage.setItem('vulnsViewMode', vulnsViewMode);
            vulnsViewBtns.forEach(function(b) { b.classList.remove('active'); });
            this.classList.add('active');
            loadVulnerabilities(currentIpFilter);
        });
    });

    // Tab switching
    tabBtns.forEach(function(btn) {
        btn.addEventListener('click', function() {
            var tabId = this.getAttribute('data-tab');

            tabBtns.forEach(function(b) { b.classList.remove('active'); });
            tabContents.forEach(function(c) { c.classList.remove('active'); });

            this.classList.add('active');
            document.getElementById(tabId).classList.add('active');

            // Toggle log panel visibility (only on scan tab)
            updateSplitView(tabId);

            if (tabId === 'assets-tab') {
                loadAssets();
            } else if (tabId === 'vulns-tab') {
                loadVulnerabilities();
            }
        });
    });

    // Port scan form submission
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            startPortScan();
        });
    }

    // Fingerprint scan button
    var fingerprintScanBtn = document.getElementById('fingerprint-scan-btn');
    if (fingerprintScanBtn) {
        fingerprintScanBtn.addEventListener('click', function() {
            startFingerprintScan();
        });
    }

    // Vulnerability scan button
    if (vulnScanBtn) {
        vulnScanBtn.addEventListener('click', function() {
            startVulnScan();
        });
    }

    if (stopScanBtn) {
        stopScanBtn.addEventListener('click', function() {
            stopScan();
        });
    }

    function startPortScan() {
        var ip = document.getElementById('ip').value.trim();

        if (!ip) {
            scanOutput.innerHTML = '<p class="error">Please enter an IP address.</p>';
            return;
        }

        portScanBtn.disabled = true;
        vulnScanBtn.disabled = true;
        portScanBtn.textContent = 'Scanning...';
        stopScanBtn.style.display = 'inline-block';

        var settings = getScanSettings();
        socket.emit('start_scan', {
            ip: ip,
            ports: settings.ports,
            scan_speed: settings.scanSpeed,
            host_timeout: settings.hostTimeout,
            max_hosts: settings.maxHosts
        });
        progressContainer.style.display = 'block';
        progressBar.value = 10;
        progressMessage.textContent = 'Port scan in progress...';
        scanOutput.innerHTML = '<p>Scanning ' + ip + ' for open ports...</p>';

        addLog('Starting port scan for ' + ip, 'info');
        if (settings.ports) {
            addLog('Port range: ' + settings.ports + ', Speed: ' + settings.scanSpeed + ', Timeout: ' + settings.hostTimeout + 's', 'debug');
        }
    }

    // ==================== Scan Profiles ====================
    var selectedProfile = '';
    var profilesLoaded = false;

    function loadProfiles() {
        if (profilesLoaded) return;
        fetch('/api/scan-profiles')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                var container = document.getElementById('profile-selector');
                if (!container || !data.profiles) return;

                var html = '<div class="profile-chips">';
                html += '<button type="button" class="profile-chip active" data-profile="">';
                html += '<span class="profile-icon">⚙️</span>';
                html += '<span class="profile-name">Custom</span>';
                html += '</button>';

                data.profiles.forEach(function(p) {
                    html += '<button type="button" class="profile-chip" data-profile="' + p.id + '" title="' + escapeHtml(p.description) + '">';
                    html += '<span class="profile-icon">' + (p.icon || '📋') + '</span>';
                    html += '<span class="profile-name">' + escapeHtml(p.name) + '</span>';
                    html += '</button>';
                });
                html += '</div>';

                container.innerHTML = html;
                profilesLoaded = true;

                // Bind click handlers
                container.querySelectorAll('.profile-chip').forEach(function(chip) {
                    chip.addEventListener('click', function() {
                        container.querySelectorAll('.profile-chip').forEach(function(c) { c.classList.remove('active'); });
                        this.classList.add('active');
                        selectedProfile = this.getAttribute('data-profile');
                    });
                });
            })
            .catch(function(err) {
                var container = document.getElementById('profile-selector');
                if (container) container.innerHTML = '<span class="text-muted">Could not load profiles</span>';
            });
    }

    // Load profiles on page load
    loadProfiles();

    function startVulnScan() {
        var ip = document.getElementById('ip').value.trim();

        if (!ip) {
            scanOutput.innerHTML = '<p class="error">Please enter an IP address.</p>';
            return;
        }

        portScanBtn.disabled = true;
        vulnScanBtn.disabled = true;
        vulnScanBtn.textContent = 'Scanning...';
        stopScanBtn.style.display = 'inline-block';

        var settings = getScanSettings();
        var scanData = {
            ip: ip,
            vuln_timeout: settings.vulnTimeout,
            severity: settings.severity,
            rate_limit: settings.rateLimit,
            templates: settings.templates,
            max_hosts: settings.maxHosts
        };

        if (selectedProfile) {
            scanData.profile = selectedProfile;
        }

        socket.emit('start_vuln_scan', scanData);
        progressContainer.style.display = 'block';
        progressBar.value = 10;

        var profileLabel = selectedProfile ? (' [' + selectedProfile + ']') : '';
        progressMessage.textContent = 'Vulnerability scan in progress' + profileLabel + ' (this may take several minutes)...';
        scanOutput.innerHTML = '<p>Running Nuclei vulnerability scan on ' + ip + profileLabel + '...</p>' +
            '<p class="info">Note: Vulnerability scans use Nuclei templates and may take several minutes.</p>';

        addLog('Starting Nuclei vulnerability scan for ' + ip + profileLabel, 'info');
        if (selectedProfile) {
            addLog('Using scan profile: ' + selectedProfile, 'info');
        }
        addLog('Severity: ' + settings.severity + ', Rate limit: ' + settings.rateLimit + ' req/sec, Timeout: ' + settings.vulnTimeout + 's', 'debug');
    }

    function stopScan() {
        addLog('Requesting scan cancellation...', 'warning');
        socket.emit('stop_scan');
        stopScanBtn.disabled = true;
        stopScanBtn.textContent = 'Stopping...';
    }

    function startFingerprintScan() {
        var ip = document.getElementById('ip').value.trim();

        if (!ip) {
            scanOutput.innerHTML = '<p class="error">Please enter an IP address.</p>';
            return;
        }

        portScanBtn.disabled = true;
        vulnScanBtn.disabled = true;
        fingerprintScanBtn.disabled = true;
        fingerprintScanBtn.textContent = 'Fingerprinting...';
        stopScanBtn.style.display = 'inline-block';

        socket.emit('start_fingerprint_scan', { ip: ip });
        progressContainer.style.display = 'block';
        progressBar.value = 10;
        progressMessage.textContent = 'Fingerprint scan in progress...';
        scanOutput.innerHTML = '<p>Running endpoint fingerprinting on ' + ip + '...</p>' +
            '<p class="info">Probing HTTP headers, TLS certs, favicons, and service banners to identify technologies.</p>';

        addLog('Starting fingerprint scan for ' + ip, 'info');
    }

    function resetScanButtons() {
        portScanBtn.disabled = false;
        vulnScanBtn.disabled = false;
        if (fingerprintScanBtn) {
            fingerprintScanBtn.disabled = false;
            fingerprintScanBtn.textContent = 'Fingerprint';
        }
        portScanBtn.textContent = 'Port Scan';
        vulnScanBtn.textContent = 'Vulnerability Scan';
        stopScanBtn.style.display = 'none';
        stopScanBtn.disabled = false;
        stopScanBtn.textContent = 'Stop Scan';
    }

    // Port scan progress (for CIDR scans)
    socket.on('scan_progress', function(data) {
        var percent = (data.current / data.total) * 100;
        progressBar.value = percent;
        progressMessage.textContent = data.message + ' (' + data.current + '/' + data.total + ')';
        addLog(data.message, 'info');
    });

    // Port scan complete (handles both single IP and CIDR)
    socket.on('scan_complete', function(data) {
        progressBar.value = 100;

        var html = '<h3>Port Scan Results for ' + data.target + '</h3>';

        if (data.cancelled) {
            html += '<p class="warning">Scan was cancelled by user.</p>';
        }

        if (data.total > 1) {
            html += '<p class="info">Scanned ' + data.total + ' hosts: ' +
                data.successful_count + ' successful, ' + data.failed_count + ' failed</p>';
        }

        var hasResults = false;
        data.results.forEach(function(result) {
            if (result.success && result.scan_data && result.scan_data.length > 0) {
                hasResults = true;
                html += '<div class="scan-result-group">';
                html += '<h4>' + result.ip + '</h4>';
                html += '<table><tr><th>Protocol</th><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr>';
                result.scan_data.forEach(function(row) {
                    html += '<tr><td>' + row[0] + '</td><td>' + row[1] + '</td><td>' + row[2] + '</td><td>' + row[3] + '</td><td>' + row[4] + '</td><td>' + row[5] + '</td></tr>';
                });
                html += '</table>';
                html += '</div>';
            } else if (!result.success) {
                html += '<div class="scan-result-group error-group">';
                html += '<h4>' + result.ip + '</h4>';
                html += '<p class="error">' + result.error + '</p>';
                html += '</div>';
            }
        });

        if (!hasResults && data.failed_count === 0) {
            html += '<p>No open ports found on any scanned hosts.</p>';
        }

        html += '<p class="success">Scan complete.</p>';
        scanOutput.innerHTML = html;

        addLog('Port scan completed for ' + data.target + ': ' + data.successful_count + ' successful, ' + data.failed_count + ' failed', 'success');

        resetScanButtons();
        setTimeout(function() {
            progressContainer.style.display = 'none';
        }, 1000);
    });

    socket.on('scan_error', function(data) {
        progressBar.value = 0;
        progressContainer.style.display = 'none';
        scanOutput.innerHTML = '<p class="error">Error: ' + data.error + '</p>';
        addLog('Scan error: ' + data.error, 'error');
        resetScanButtons();
    });

    // Vulnerability scan progress (for CIDR scans)
    socket.on('vuln_scan_progress', function(data) {
        if (data.current && data.total) {
            var percent = (data.current / data.total) * 100;
            progressBar.value = Math.min(percent, 90);
            progressMessage.textContent = data.message + ' (' + data.current + '/' + data.total + ')';
        } else {
            progressMessage.textContent = data.message;
            progressBar.value = Math.min(progressBar.value + 10, 80);
        }
        addLog(data.message, 'info');
    });

    // Vulnerability scan complete (handles both single IP and CIDR)
    socket.on('vuln_scan_complete', function(data) {
        progressBar.value = 100;

        var html = '<h3>Vulnerability Scan Results for ' + data.target + '</h3>';

        if (data.cancelled) {
            html += '<p class="warning">Vulnerability scan was cancelled by user.</p>';
        }

        if (data.total > 1) {
            html += '<p class="info">Scanned ' + data.total + ' hosts: ' +
                data.successful_count + ' successful, ' + data.failed_count + ' failed</p>';
        }

        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            html += '<p class="warning">Found ' + data.total_vulns + ' potential vulnerability finding(s).</p>';
            html += '<div class="vuln-results">';

            data.vulnerabilities.forEach(function(vuln) {
                html += '<div class="vuln-item severity-' + vuln.severity + '">';
                html += '<div class="vuln-header">';
                html += '<span class="vuln-id">' + vuln.vuln_id + '</span>';
                html += '<div class="vuln-header-right">';
                if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
                    var cvssClass = vuln.cvss_score >= 9.0 ? 'critical' : (vuln.cvss_score >= 7.0 ? 'high' : (vuln.cvss_score >= 4.0 ? 'medium' : 'low'));
                    html += '<span class="cvss-badge ' + cvssClass + '">CVSS ' + vuln.cvss_score.toFixed(1) + '</span>';
                }
                html += '<span class="severity-badge ' + vuln.severity + '">' + vuln.severity.toUpperCase() + '</span>';
                html += '</div>';
                html += '</div>';
                html += '<div class="vuln-meta">' + vuln.ip + ':' + vuln.port + '/' + vuln.protocol + '</div>';
                if (vuln.cwe_id) {
                    html += '<div class="vuln-cwe"><span class="cwe-badge">' + vuln.cwe_id + '</span></div>';
                }
                html += '<div class="vuln-desc">' + escapeHtml(vuln.description) + '</div>';
                html += '</div>';
            });

            html += '</div>';
        } else {
            html += '<p class="success">No vulnerabilities detected.</p>';
        }

        scanOutput.innerHTML = html;

        var vulnCount = data.vulnerabilities ? data.vulnerabilities.length : 0;
        addLog('Vulnerability scan completed for ' + data.target + ': ' + vulnCount + ' vulnerabilities found', vulnCount > 0 ? 'warning' : 'success');

        resetScanButtons();

        setTimeout(function() {
            progressContainer.style.display = 'none';
        }, 1000);
    });

    socket.on('vuln_scan_error', function(data) {
        progressBar.value = 0;
        progressContainer.style.display = 'none';
        scanOutput.innerHTML = '<p class="error">Vulnerability scan error: ' + data.error + '</p>';
        addLog('Vulnerability scan error: ' + data.error, 'error');
        resetScanButtons();
    });

    // Assets loading
    function loadAssets() {
        assetsList.innerHTML = '<p class="loading">Loading assets...</p>';

        fetch('/api/assets')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.error) {
                    assetsList.innerHTML = '<p class="error">Error loading assets: ' + data.error + '</p>';
                    return;
                }

                var assets = data.assets;
                assetsCount.textContent = assets.length + ' host(s) found';

                if (assets.length === 0) {
                    assetsList.innerHTML = '<p class="empty-state">No scanned assets yet. Use the Scan tab to scan a host.</p>';
                    return;
                }

                var html = '';

                if (assetsViewMode === 'list') {
                    // List view
                    html = '<table class="assets-table">';
                    html += '<thead><tr><th>IP Address</th><th>Ports</th><th>Vulnerabilities</th><th>Last Scan</th><th>Actions</th></tr></thead>';
                    html += '<tbody>';
                    assets.forEach(function(asset) {
                        var vulnCounts = asset.vuln_counts || { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
                        var hasVulns = vulnCounts.total > 0;
                        var vulnClass = vulnCounts.critical > 0 ? 'critical' : (vulnCounts.high > 0 ? 'high' : 'medium');

                        html += '<tr>';
                        html += '<td class="asset-ip-cell"><strong>' + asset.ip + '</strong></td>';
                        html += '<td>' + asset.port_count + '</td>';
                        html += '<td>';
                        if (hasVulns) {
                            html += '<span class="vuln-badge-small ' + vulnClass + '">' + vulnCounts.total + '</span>';
                            if (vulnCounts.critical > 0) html += ' <span class="vuln-count-inline critical">' + vulnCounts.critical + 'C</span>';
                            if (vulnCounts.high > 0) html += ' <span class="vuln-count-inline high">' + vulnCounts.high + 'H</span>';
                            if (vulnCounts.medium > 0) html += ' <span class="vuln-count-inline medium">' + vulnCounts.medium + 'M</span>';
                        } else {
                            html += '<span class="text-muted">None</span>';
                        }
                        html += '</td>';
                        html += '<td>' + formatDate(asset.last_scan) + '</td>';
                        html += '<td class="actions-cell">';
                        html += '<button class="btn-small btn-rescan" data-ip="' + asset.ip + '">Port</button>';
                        html += '<button class="btn-small btn-vuln-scan" data-ip="' + asset.ip + '">Vuln</button>';
                        if (hasVulns) {
                            html += '<button class="btn-small btn-view-vulns" data-ip="' + asset.ip + '">View</button>';
                        }
                        html += '</td>';
                        html += '</tr>';
                    });
                    html += '</tbody></table>';
                } else {
                    // Card view
                    html = '<div class="assets-grid">';
                    assets.forEach(function(asset) {
                        var vulnCounts = asset.vuln_counts || { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
                        var hasVulns = vulnCounts.total > 0;

                        html += '<div class="asset-card">';
                        html += '<div class="asset-header">';
                        html += '<span class="asset-ip">' + asset.ip + '</span>';
                        html += '<div class="asset-badges">';
                        html += '<span class="asset-ports">' + asset.port_count + ' port(s)</span>';
                        if (hasVulns) {
                            var vulnClass = vulnCounts.critical > 0 ? 'critical' : (vulnCounts.high > 0 ? 'high' : 'medium');
                            html += '<span class="asset-vulns vuln-badge-' + vulnClass + '">' + vulnCounts.total + ' vuln(s)</span>';
                        }
                        html += '</div>';
                        html += '</div>';

                        // Technology fingerprint badges
                        if (asset.technologies && asset.technologies.length > 0) {
                            html += '<div class="asset-tech-stack">';
                            asset.technologies.forEach(function(tech) {
                                var verStr = tech.version ? ' ' + tech.version : '';
                                var confClass = tech.confidence >= 80 ? 'high-conf' : (tech.confidence >= 50 ? 'med-conf' : 'low-conf');
                                html += '<span class="tech-badge ' + confClass + '" title="' + escapeHtml(tech.category) + ' · ' + tech.confidence + '% confidence">';
                                html += escapeHtml(tech.name + verStr);
                                html += '</span>';
                            });
                            html += '</div>';
                        }

                        if (hasVulns) {
                            html += '<div class="asset-vuln-summary">';
                            if (vulnCounts.critical > 0) html += '<span class="vuln-mini critical">' + vulnCounts.critical + ' Critical</span>';
                            if (vulnCounts.high > 0) html += '<span class="vuln-mini high">' + vulnCounts.high + ' High</span>';
                            if (vulnCounts.medium > 0) html += '<span class="vuln-mini medium">' + vulnCounts.medium + ' Medium</span>';
                            if (vulnCounts.low > 0) html += '<span class="vuln-mini low">' + vulnCounts.low + ' Low</span>';
                            html += '</div>';
                        }

                        html += '<div class="asset-meta">';
                        html += '<span class="asset-date">Last scan: ' + formatDate(asset.last_scan) + '</span>';
                        html += '</div>';
                        html += '<div class="asset-actions">';
                        html += '<button class="btn-small btn-rescan" data-ip="' + asset.ip + '">Port Scan</button>';
                        html += '<button class="btn-small btn-fingerprint" data-ip="' + asset.ip + '">Fingerprint</button>';
                        html += '<button class="btn-small btn-vuln-scan" data-ip="' + asset.ip + '">Vuln Scan</button>';
                        if (hasVulns) {
                            html += '<button class="btn-small btn-view-vulns" data-ip="' + asset.ip + '">View Vulns</button>';
                        }
                        html += '<button class="btn-small btn-details" data-ip="' + asset.ip + '">Details</button>';
                        html += '</div>';
                        html += '<div class="asset-details" id="details-' + asset.ip.replace(/\./g, '-') + '" style="display:none;">';
                        if (asset.ports.length > 0) {
                            html += '<table class="ports-table">';
                            html += '<tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>';
                            asset.ports.forEach(function(port) {
                                html += '<tr>';
                                html += '<td>' + port.port + '/' + port.protocol + '</td>';
                                html += '<td>' + port.state + '</td>';
                                html += '<td>' + port.service + '</td>';
                                html += '<td>' + (port.product || '') + ' ' + (port.version || '') + '</td>';
                                html += '</tr>';
                            });
                            html += '</table>';
                        }
                        html += '</div>';
                        html += '</div>';
                    });
                    html += '</div>';
                }

                assetsList.innerHTML = html;

                // Event listeners for asset buttons
                document.querySelectorAll('.btn-rescan').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        switchToScanTab(this.getAttribute('data-ip'), 'port');
                    });
                });

                document.querySelectorAll('.btn-fingerprint').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        switchToScanTab(this.getAttribute('data-ip'), 'fingerprint');
                    });
                });

                document.querySelectorAll('.btn-vuln-scan').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        switchToScanTab(this.getAttribute('data-ip'), 'vuln');
                    });
                });

                document.querySelectorAll('.btn-view-vulns').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        viewVulnerabilitiesForAsset(this.getAttribute('data-ip'));
                    });
                });

                document.querySelectorAll('.btn-details').forEach(function(btn) {
                    btn.addEventListener('click', function(e) {
                        e.stopPropagation();
                        showAssetModal(this.getAttribute('data-ip'));
                    });
                });

                // Make asset cards and IPs clickable to open modal
                document.querySelectorAll('.asset-card').forEach(function(card) {
                    card.style.cursor = 'pointer';
                    card.addEventListener('click', function(e) {
                        // Don't trigger if clicking on a button
                        if (e.target.tagName === 'BUTTON') return;
                        var ip = card.querySelector('.asset-ip');
                        if (ip) {
                            showAssetModal(ip.textContent);
                        }
                    });
                });

                // Make table rows clickable in list view
                document.querySelectorAll('.assets-table tbody tr').forEach(function(row) {
                    row.style.cursor = 'pointer';
                    row.addEventListener('click', function(e) {
                        // Don't trigger if clicking on a button
                        if (e.target.tagName === 'BUTTON') return;
                        var ipCell = row.querySelector('.asset-ip-cell strong');
                        if (ipCell) {
                            showAssetModal(ipCell.textContent);
                        }
                    });
                });
            })
            .catch(function(error) {
                assetsList.innerHTML = '<p class="error">Error loading assets: ' + error.message + '</p>';
            });
    }

    // Vulnerabilities loading
    var currentIpFilter = null;  // Track current IP filter for vulnerabilities

    function loadVulnerabilities(ipFilter) {
        vulnsList.innerHTML = '<p class="loading">Loading vulnerabilities...</p>';

        // Build URL with optional IP filter
        var url = '/api/vulnerabilities';
        if (ipFilter) {
            url += '?ip=' + encodeURIComponent(ipFilter);
            currentIpFilter = ipFilter;
        } else {
            currentIpFilter = null;
        }

        fetch(url)
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.error) {
                    vulnsList.innerHTML = '<p class="error">Error loading vulnerabilities: ' + data.error + '</p>';
                    return;
                }

                // Update summary
                var summary = data.summary;
                document.getElementById('total-vulns').textContent = summary.total;
                document.getElementById('critical-count').textContent = summary.by_severity.critical || 0;
                document.getElementById('high-count').textContent = summary.by_severity.high || 0;
                document.getElementById('medium-count').textContent = summary.by_severity.medium || 0;
                document.getElementById('low-count').textContent = summary.by_severity.low || 0;

                var vulnerabilities = data.vulnerabilities;

                // Show filter indicator if filtering by IP
                var filterIndicator = '';
                if (currentIpFilter) {
                    filterIndicator = '<div class="filter-indicator">' +
                        '<span>Showing vulnerabilities for: <strong>' + currentIpFilter + '</strong></span>' +
                        '<button class="btn-clear-filter" id="clear-ip-filter">Show All</button>' +
                        '</div>';
                }

                if (vulnerabilities.length === 0) {
                    vulnsList.innerHTML = filterIndicator +
                        '<p class="empty-state">No vulnerabilities found' +
                        (currentIpFilter ? ' for ' + currentIpFilter : '') +
                        '. Run a vulnerability scan from the Scan tab.</p>';

                    // Add clear filter listener
                    var clearBtn = document.getElementById('clear-ip-filter');
                    if (clearBtn) {
                        clearBtn.addEventListener('click', function() {
                            loadVulnerabilities(null);
                        });
                    }
                    return;
                }

                renderVulnerabilities(vulnerabilities, filterIndicator);
            })
            .catch(function(error) {
                vulnsList.innerHTML = '<p class="error">Error loading vulnerabilities: ' + error.message + '</p>';
            });
    }

    function renderVulnerabilities(vulnerabilities, filterIndicator) {
        var filterValue = vulnFilter ? vulnFilter.value : '';

        var filtered = vulnerabilities;
        if (filterValue) {
            filtered = vulnerabilities.filter(function(v) {
                return v.severity === filterValue;
            });
        }

        // Store filtered vulnerabilities for modal access
        storedVulnerabilities = filtered;

        if (filtered.length === 0) {
            vulnsList.innerHTML = (filterIndicator || '') +
                '<p class="empty-state">No vulnerabilities match the selected filter.</p>';

            // Add clear filter listener
            var clearBtn = document.getElementById('clear-ip-filter');
            if (clearBtn) {
                clearBtn.addEventListener('click', function() {
                    loadVulnerabilities(null);
                });
            }
            return;
        }

        var html = (filterIndicator || '');

        if (vulnsViewMode === 'list') {
            // List view
            html += '<table class="vulns-table">';
            html += '<thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Target</th><th>CWE</th><th>Description</th></tr></thead>';
            html += '<tbody>';
            filtered.forEach(function(vuln, index) {
                html += '<tr class="severity-row-' + vuln.severity + ' clickable" data-vuln-index="' + index + '">';
                html += '<td class="vuln-id-cell clickable"><code>' + vuln.vuln_id + '</code></td>';
                html += '<td><span class="severity-badge ' + vuln.severity + '">' + vuln.severity.toUpperCase() + '</span></td>';
                html += '<td>';
                if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
                    var cvssClass = vuln.cvss_score >= 9.0 ? 'critical' : (vuln.cvss_score >= 7.0 ? 'high' : (vuln.cvss_score >= 4.0 ? 'medium' : 'low'));
                    html += '<span class="cvss-badge ' + cvssClass + '">' + vuln.cvss_score.toFixed(1) + '</span>';
                } else {
                    html += '<span class="text-muted">-</span>';
                }
                html += '</td>';
                html += '<td class="target-cell">' + vuln.ip + ':' + vuln.port + '</td>';
                html += '<td>' + (vuln.cwe_id || '<span class="text-muted">-</span>') + '</td>';
                html += '<td class="desc-cell">' + escapeHtml(vuln.description.substring(0, 100)) + '...</td>';
                html += '</tr>';
            });
            html += '</tbody></table>';
        } else {
            // Card view
            html += '<div class="vulns-grid">';
            filtered.forEach(function(vuln, index) {
                html += '<div class="vuln-card clickable severity-' + vuln.severity + '" data-vuln-index="' + index + '">';
                html += '<div class="vuln-header">';
                html += '<span class="vuln-id">' + vuln.vuln_id + '</span>';
                html += '<div class="vuln-header-right">';
                if (vuln.cvss_score !== null && vuln.cvss_score !== undefined) {
                    var cvssClass = vuln.cvss_score >= 9.0 ? 'critical' : (vuln.cvss_score >= 7.0 ? 'high' : (vuln.cvss_score >= 4.0 ? 'medium' : 'low'));
                    html += '<span class="cvss-badge ' + cvssClass + '">CVSS ' + vuln.cvss_score.toFixed(1) + '</span>';
                }
                html += '<span class="severity-badge ' + vuln.severity + '">' + vuln.severity.toUpperCase() + '</span>';
                html += '</div>';
                html += '</div>';
                html += '<div class="vuln-target">' + vuln.ip + ':' + vuln.port + '/' + vuln.protocol + '</div>';

                if (vuln.cwe_id) {
                    html += '<div class="vuln-cwe"><span class="cwe-badge">' + vuln.cwe_id + '</span></div>';
                }

                if (vuln.cvss_vector) {
                    html += '<div class="vuln-vector"><code>' + vuln.cvss_vector + '</code></div>';
                }

                html += '<div class="vuln-desc">' + escapeHtml(vuln.description) + '</div>';

                if (vuln.references && vuln.references.length > 0) {
                    html += '<div class="vuln-refs">';
                    html += '<span class="refs-label">References:</span>';
                    html += '<ul class="refs-list">';
                    vuln.references.forEach(function(ref) {
                        if (ref.url) {
                            html += '<li><a href="' + escapeHtml(ref.url) + '" target="_blank" rel="noopener">' + escapeHtml(ref.source || ref.url) + '</a></li>';
                        }
                    });
                    html += '</ul>';
                    html += '</div>';
                }

                html += '<div class="vuln-dates">';
                if (vuln.published_date) {
                    html += '<span class="vuln-published">Published: ' + formatDate(vuln.published_date) + '</span>';
                }
                html += '<span class="vuln-found">Found: ' + formatDate(vuln.scan_date) + '</span>';
                html += '</div>';
                html += '</div>';
            });
            html += '</div>';
        }

        vulnsList.innerHTML = html;

        // Add clear filter listener after rendering
        var clearBtn = document.getElementById('clear-ip-filter');
        if (clearBtn) {
            clearBtn.addEventListener('click', function() {
                loadVulnerabilities(null);
            });
        }

        // Add click handlers for vulnerability cards/rows
        document.querySelectorAll('.vuln-card.clickable, .vulns-table tbody tr.clickable').forEach(function(el) {
            el.addEventListener('click', function(e) {
                // Don't open modal if clicking on a link
                if (e.target.tagName === 'A') return;

                var index = parseInt(this.getAttribute('data-vuln-index'));
                if (!isNaN(index) && storedVulnerabilities[index]) {
                    showCveModal(storedVulnerabilities[index]);
                }
            });
        });
    }

    function viewVulnerabilitiesForAsset(ip) {
        // Switch to vulnerabilities tab and filter by IP
        tabBtns.forEach(function(b) { b.classList.remove('active'); });
        tabContents.forEach(function(c) { c.classList.remove('active'); });

        document.querySelector('[data-tab="vulns-tab"]').classList.add('active');
        document.getElementById('vulns-tab').classList.add('active');

        // Load vulnerabilities filtered by IP
        loadVulnerabilities(ip);
    }

    // Filter change handler
    if (vulnFilter) {
        vulnFilter.addEventListener('change', function() {
            loadVulnerabilities(currentIpFilter);
        });
    }

    // Helper functions
    function formatDate(dateStr) {
        if (!dateStr) return 'Unknown';
        try {
            var date = new Date(dateStr.replace(' ', 'T'));
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        } catch (e) {
            return dateStr;
        }
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function toggleDetails(ip) {
        var detailsId = 'details-' + ip.replace(/\./g, '-');
        var details = document.getElementById(detailsId);
        if (details) {
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }
    }

    function switchToScanTab(ip, scanType) {
        tabBtns.forEach(function(b) { b.classList.remove('active'); });
        tabContents.forEach(function(c) { c.classList.remove('active'); });

        document.querySelector('[data-tab="scan-tab"]').classList.add('active');
        document.getElementById('scan-tab').classList.add('active');

        document.getElementById('ip').value = ip;

        if (scanType === 'vuln') {
            startVulnScan();
        } else if (scanType === 'fingerprint') {
            startFingerprintScan();
        } else {
            startPortScan();
        }
    }

    // Refresh buttons
    if (refreshAssetsBtn) {
        refreshAssetsBtn.addEventListener('click', loadAssets);
    }

    if (refreshVulnsBtn) {
        refreshVulnsBtn.addEventListener('click', loadVulnerabilities);
    }
});
