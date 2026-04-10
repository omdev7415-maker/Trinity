document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('enable-toggle');
    const statusPill = document.getElementById('status-pill');
    const statusText = document.getElementById('status-text');
    const openDashBtn = document.getElementById('open-dashboard');

    // Check engine health
    fetch('http://localhost:8000/api/history?limit=1')
        .then(res => {
            if (res.ok) {
                statusPill.className = 'status-pill online';
                statusText.textContent = 'Engine online & ready';
            } else {
                throw new Error();
            }
        })
        .catch(() => {
            statusPill.className = 'status-pill offline';
            statusText.textContent = 'Engine offline — start python main.py';
        });

    // Load saved toggle state
    chrome.storage.local.get(['enabled'], (res) => {
        toggle.checked = res.enabled !== false;
    });

    // Persist and broadcast toggle
    toggle.addEventListener('change', () => {
        const enabled = toggle.checked;
        chrome.storage.local.set({ enabled });
        
        // Broadcast to all active tabs
        chrome.tabs.query({ active: true }, (tabs) => {
            tabs.forEach(tab => {
                chrome.tabs.sendMessage(tab.id, { type: "TOGGLE_ENABLED", enabled }).catch(() => {});
            });
        });
    });

    // Open main dashboard
    openDashBtn.addEventListener('click', () => {
        chrome.tabs.create({ url: 'http://localhost:8000/' });
    });
});
