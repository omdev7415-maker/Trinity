// content.js — DefendLink AI Content Script
// Runs on every webpage. Detects links, shows inline badges, intercepts dangerous clicks.

(function() {
    'use strict';

    let extensionEnabled = true;
    let activeBadge = null;
    let hideTimeout = null;
    const scannedLinks = new WeakMap(); // Track scanned links

    // Check if extension is toggled on/off
    chrome.runtime.sendMessage({ type: "GET_STATUS" }, (res) => {
        if (res) extensionEnabled = res.enabled;
    });

    /* =============================================
       BADGE MANAGEMENT
    ============================================= */
    function createBadge() {
        const badge = document.createElement('div');
        badge.id = 'dl-floating-badge';
        badge.classList.add('dl-badge');
        document.body.appendChild(badge);
        return badge;
    }

    function getBadge() {
        return document.getElementById('dl-floating-badge') || createBadge();
    }

    function showBadge(x, y, state, text) {
        const badge = getBadge();
        badge.className = `dl-badge dl-${state}`;
        
        if (state === 'scanning') {
            badge.innerHTML = `<span class="dl-spinner"></span> ${text}`;
        } else if (state === 'safe') {
            badge.innerHTML = `✅ ${text}`;
        } else if (state === 'suspicious') {
            badge.innerHTML = `⚠️ ${text}`;
        } else if (state === 'malicious') {
            badge.innerHTML = `🛑 ${text}`;
        } else if (state === 'offline') {
            badge.innerHTML = `⚪ ${text}`;
        }

        // Position above the cursor
        const bx = Math.min(x, window.innerWidth - 280);
        const by = Math.max(y - 44, 8);
        badge.style.left = `${bx}px`;
        badge.style.top = `${by}px`;

        clearTimeout(hideTimeout);
        requestAnimationFrame(() => badge.classList.add('dl-visible'));
    }

    function hideBadge(delay = 400) {
        hideTimeout = setTimeout(() => {
            const badge = getBadge();
            badge.classList.remove('dl-visible');
        }, delay);
    }

    /* =============================================
       DANGER MODAL (click intercept)
    ============================================= */
    function showDangerModal(url, data, proceedCallback) {
        const overlay = document.createElement('div');
        overlay.className = 'dl-overlay';
        
        const flagsHtml = data.flags && data.flags.length > 0
            ? `<ul>${data.flags.slice(0, 4).map(f => `<li>${f}</li>`).join('')}</ul>`
            : 'No specific threat flags recorded.';
        
        overlay.innerHTML = `
            <div class="dl-modal">
                <div class="dl-modal-icon">🛡️</div>
                <h2>THREAT DETECTED</h2>
                <div class="dl-modal-score">${data.score}</div>
                <div class="dl-modal-score-label">/ 100 Risk Score</div>
                <div class="dl-modal-url">${url}</div>
                <div class="dl-modal-flags">${flagsHtml}</div>
                <div class="dl-modal-buttons">
                    <button class="dl-btn-cancel" id="dl-btn-block">🛑 Block This Site</button>
                    <button class="dl-btn-proceed" id="dl-btn-proceed">Proceed Anyway →</button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        document.getElementById('dl-btn-block').addEventListener('click', () => {
            overlay.remove();
        });

        document.getElementById('dl-btn-proceed').addEventListener('click', () => {
            overlay.remove();
            proceedCallback();
        });

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.remove();
        });
    }

    /* =============================================
       LINK SCANNING ENGINE
    ============================================= */
    function isValidUrl(href) {
        if (!href) return false;
        if (href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) return false;
        try {
            const u = new URL(href);
            return u.protocol === 'http:' || u.protocol === 'https:';
        } catch {
            return false;
        }
    }

    function scanUrl(url, callback) {
        chrome.runtime.sendMessage({ type: "SCAN_URL", url: url }, (res) => {
            if (chrome.runtime.lastError || !res) {
                callback('offline', null);
                return;
            }
            if (res.status === 'ok') {
                callback('ok', res.data);
            } else {
                callback('offline', null);
            }
        });
    }

    function getState(score) {
        if (score < 20) return 'safe';
        if (score < 65) return 'suspicious';
        return 'malicious';
    }

    /* =============================================
       EVENT LISTENERS
    ============================================= */
    let currentHoverUrl = null;
    let scanDebounce = null;

    document.addEventListener('mouseover', (e) => {
        if (!extensionEnabled) return;
        
        const link = e.target.closest('a[href]');
        if (!link) return;
        
        const href = link.href;
        if (!isValidUrl(href)) return;
        if (href === currentHoverUrl) return;
        
        currentHoverUrl = href;
        clearTimeout(scanDebounce);
        
        // Show scanning badge immediately
        showBadge(e.clientX, e.clientY, 'scanning', 'Scanning...');
        
        // Debounce actual scan by 300ms to avoid excessive requests
        scanDebounce = setTimeout(() => {
            scanUrl(href, (status, data) => {
                if (currentHoverUrl !== href) return; // Link changed, abort
                
                if (status === 'offline') {
                    showBadge(e.clientX, e.clientY, 'offline', 'Engine offline');
                    return;
                }
                
                const state = getState(data.score);
                let label = '';
                if (state === 'safe') label = `Safe (${data.score}/100)`;
                else if (state === 'suspicious') label = `Suspicious — Score: ${data.score}`;
                else label = `THREAT — Score: ${data.score}`;
                
                showBadge(e.clientX, e.clientY, state, label);
                
                // Apply link outline on page
                link.classList.remove('dl-link-malicious', 'dl-link-suspicious');
                if (state === 'malicious') link.classList.add('dl-link-malicious');
                else if (state === 'suspicious') link.classList.add('dl-link-suspicious');
                
                scannedLinks.set(link, { state, data });
            });
        }, 300);
        
    // Update badge position on mouse move
    }, { passive: true });

    document.addEventListener('mousemove', (e) => {
        const badge = document.getElementById('dl-floating-badge');
        if (badge && badge.classList.contains('dl-visible')) {
            const bx = Math.min(e.clientX, window.innerWidth - 280);
            const by = Math.max(e.clientY - 44, 8);
            badge.style.left = `${bx}px`;
            badge.style.top = `${by}px`;
        }
    }, { passive: true });

    document.addEventListener('mouseout', (e) => {
        const link = e.target.closest('a[href]');
        if (link) {
            currentHoverUrl = null;
            clearTimeout(scanDebounce);
            hideBadge(600);
        }
    }, { passive: true });

    /* =============================================
       CLICK INTERCEPT — Block Malicious Links
    ============================================= */
    document.addEventListener('click', (e) => {
        if (!extensionEnabled) return;
        
        const link = e.target.closest('a[href]');
        if (!link) return;
        
        const scanned = scannedLinks.get(link);
        if (!scanned) return; // Not yet scanned, allow through
        
        if (scanned.state === 'malicious') {
            e.preventDefault();
            e.stopImmediatePropagation();
            
            hideBadge(0);
            showDangerModal(link.href, scanned.data, () => {
                window.open(link.href, '_blank', 'noopener,noreferrer');
            });
        }
    }, true); // Capture phase so we intercept before other listeners

    /* =============================================
       LISTEN FOR TOGGLE FROM POPUP
    ============================================= */
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.type === "TOGGLE_ENABLED") {
            extensionEnabled = msg.enabled;
            if (!extensionEnabled) {
                hideBadge(0);
                // Remove all link highlights
                document.querySelectorAll('.dl-link-malicious, .dl-link-suspicious').forEach(el => {
                    el.classList.remove('dl-link-malicious', 'dl-link-suspicious');
                });
            }
        }
    });

})();
