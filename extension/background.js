// background.js — Service Worker
// Handles all API communication with the local DefendLink engine

const API_BASE = "http://localhost:8000";
const cache = new Map(); // In-memory scan cache to avoid duplicate requests

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "SCAN_URL") {
        const url = msg.url;

        // Return cached result immediately
        if (cache.has(url)) {
            sendResponse({ status: "ok", data: cache.get(url) });
            return true;
        }

        // Call DefendLink API
        fetch(`${API_BASE}/api/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ urls: [url] })
        })
        .then(res => res.json())
        .then(data => {
            if (data.results && data.results.length > 0) {
                const result = data.results[0].analysis;
                cache.set(url, result);
                sendResponse({ status: "ok", data: result });
            } else {
                sendResponse({ status: "error", message: "No results from engine." });
            }
        })
        .catch(err => {
            sendResponse({ status: "offline", message: "DefendLink engine is not running." });
        });

        return true; // Keep message channel open for async response
    }

    if (msg.type === "GET_STATUS") {
        chrome.storage.local.get(["enabled"], (res) => {
            sendResponse({ enabled: res.enabled !== false });
        });
        return true;
    }

    if (msg.type === "SET_STATUS") {
        chrome.storage.local.set({ enabled: msg.enabled });
        sendResponse({ ok: true });
        return true;
    }
});
