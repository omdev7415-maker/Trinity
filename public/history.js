document.addEventListener("DOMContentLoaded", () => {
    fetchHistory();
    document.getElementById("refresh-btn").addEventListener("click", fetchHistory);

    async function fetchHistory() {
        try {
            const btn = document.getElementById("refresh-btn");
            btn.innerHTML = `<i data-lucide="refresh-cw" class="lucide-refresh-cw" style="animation: spin 1s infinite linear;"></i> Refreshing...`;
            
            const res = await fetch("/api/history?limit=50");
            const data = await res.json();
            const tbody = document.getElementById("history-tbody");
            tbody.innerHTML = '';
            
            if (!data.history || data.history.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 20px; color: var(--text-muted);">No historical logs found.</td></tr>';
                btn.innerHTML = `<i data-lucide="refresh-cw"></i> Refresh`;
                lucide.createIcons();
                return;
            }
            
            data.history.forEach(item => {
                let color = "var(--safe)";
                const verdict = item.verdict || "Unknown";
                if (verdict === "Suspicious" || verdict.toLowerCase().includes("unknown")) color = "var(--suspicious)";
                if (verdict === "Malicious" || verdict === "Error") color = "var(--malicious)";
                
                tbody.innerHTML += `
                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.03)'" onmouseout="this.style.background='transparent'">
                        <td style="padding: 15px 10px; color: var(--text-main); word-break: break-all;">${item.url}</td>
                        <td style="padding: 15px 10px; color: var(--text-muted);">${item.timestamp}</td>
                        <td style="padding: 15px 10px; color: ${color}; font-weight: bold;">${item.score}/100</td>
                        <td style="padding: 15px 10px;">
                            <span style="background: rgba(255,255,255,0.05); padding: 4px 10px; border-radius: 12px; font-size: 0.75rem; border: 1px solid ${color}; color: ${color};">${verdict.toUpperCase()}</span>
                        </td>
                    </tr>
                `;
            });
            
            btn.innerHTML = `<i data-lucide="refresh-cw"></i> Refresh`;
            lucide.createIcons();
        } catch(e) {
            console.error("Error fetching history", e);
            document.getElementById("history-tbody").innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 20px; color: var(--malicious);">Database connection failed.</td></tr>';
        }
    }
});
