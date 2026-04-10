document.addEventListener("DOMContentLoaded", () => {
    // Initialize Particles.js
    if (window.particlesJS) {
        particlesJS("particles-js", {
            "particles": {
                "number": { "value": 80, "density": { "enable": true, "value_area": 800 } },
                "color": { "value": "#6366f1" },
                "shape": { "type": "circle" },
                "opacity": { "value": 0.5, "random": true, "anim": { "enable": true, "speed": 1 } },
                "size": { "value": 3, "random": true },
                "line_linked": { "enable": true, "distance": 150, "color": "#6366f1", "opacity": 0.4, "width": 1 },
                "move": { "enable": true, "speed": 2, "direction": "none", "random": true, "straight": false, "out_mode": "out", "bounce": false }
            },
            "interactivity": {
                "detect_on": "canvas",
                "events": { "onhover": { "enable": true, "mode": "grab" }, "onclick": { "enable": true, "mode": "push" }, "resize": true },
                "modes": { "grab": { "distance": 140, "line_linked": { "opacity": 1 } }, "push": { "particles_nb": 4 } }
            },
            "retina_detect": true
        });
    }

    fetchHistory();

    // Sidebar Toggle Logic
    const sidebarToggle = document.getElementById("sidebar-toggle");
    const appLayout = document.getElementById("app-layout");
    
    if (sidebarToggle && appLayout) {
        sidebarToggle.addEventListener("click", () => {
            appLayout.classList.toggle("sidebar-collapsed");
        });
    }

    // Modes & Toggles
    const modeUrlBtn = document.getElementById("mode-url");
    const modeAiBtn = document.getElementById("mode-ai");
    const modeFileBtn = document.getElementById("mode-file");
    const analyzingForm = document.getElementById("analyze-form");
    const emailForm = document.getElementById("analyze-email-form");
    const fileForm = document.getElementById("analyze-file-form");
    const resultsDashboard = document.getElementById("results-dashboard");
    const aiResultsDashboard = document.getElementById("ai-results-dashboard");

    function setModeButtonStyles(activeBtn) {
        [modeUrlBtn, modeAiBtn, modeFileBtn].forEach(btn => {
            if(btn === activeBtn) {
                btn.style.background = "var(--secondary)";
                btn.style.border = "none";
            } else {
                btn.style.background = "transparent";
                btn.style.border = "1px solid var(--secondary)";
            }
        });
    }

    modeUrlBtn.addEventListener("click", () => {
        setModeButtonStyles(modeUrlBtn);
        analyzingForm.classList.remove("hidden");
        emailForm.classList.add("hidden");
        fileForm.classList.add("hidden");
        aiResultsDashboard.classList.add("hidden");
    });

    modeFileBtn.addEventListener("click", () => {
        setModeButtonStyles(modeFileBtn);
        fileForm.classList.remove("hidden");
        emailForm.classList.add("hidden");
        analyzingForm.classList.add("hidden");
        resultsDashboard.classList.add("hidden");
        aiResultsDashboard.classList.add("hidden");
    });

    modeAiBtn.addEventListener("click", () => {
        setModeButtonStyles(modeAiBtn);
        emailForm.classList.remove("hidden");
        fileForm.classList.add("hidden");
        analyzingForm.classList.add("hidden");
        resultsDashboard.classList.add("hidden");
    });

    async function fetchHistory() {
        try {
            const res = await fetch("/api/history");
            const data = await res.json();
            const listEl = document.getElementById("history-list");
            if (!listEl) return;
            listEl.innerHTML = '';

            if (!data.history || data.history.length === 0) {
                listEl.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-muted); font-size: 0.9rem;">No scans yet.</div>';
                return;
            }

            const totalScansEl = document.getElementById("global-threats-counter");
            if(totalScansEl) totalScansEl.textContent = data.history.length;

            data.history.forEach(item => {
                let classState = "safe";
                if (item.verdict === "Suspicious" || item.verdict.toLowerCase().includes("unknown")) classState = "suspicious";
                if (item.verdict === "Malicious" || item.verdict === "Error") classState = "malicious";

                listEl.innerHTML += `
                    <div class="history-item ${classState}" onclick="document.getElementById('url-input').value = '${item.url === 'AI Message Analysis' ? '' : item.url}'; if('${item.url}' !== 'AI Message Analysis' && '${item.url}' !== 'File Upload') document.getElementById('analyze-form').dispatchEvent(new Event('submit', {cancelable: true, bubbles: true}));">
                        <div style="font-weight: 600; font-size: 0.85rem; color: var(--text-main); word-break: break-all; word-wrap: break-word; white-space: normal; line-height: 1.4; margin-bottom: 8px;" title="${item.url}">${item.url}</div>
                        <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted); align-items: center;">
                            <span style="font-weight: bold; text-transform: uppercase;">${item.score} Risk</span>
                            <span>${item.timestamp.split(' ')[1]}</span>
                        </div>
                    </div>
                `;
            });
        } catch (e) {
            console.error("Failed to load history", e);
        }
    }

    const form = document.getElementById("analyze-form");
    const input = document.getElementById("url-input");
    const btnText = document.getElementById("url-btn-text");
    const btnIcon = document.getElementById("url-btn-icon");
    const loader = document.getElementById("url-loader");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const url = input.value.trim();
        if (!url) return;

        // UI Loading State
        btnText.textContent = "Running Deep Scan...";
        btnIcon.classList.add("hidden");
        loader.classList.remove("hidden");
        document.getElementById("results-dashboard").classList.add("hidden");

        try {
            const res = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ urls: [url] })
            });
            const data = await res.json();

            if (data.results && data.results.length > 0) {
                renderDashboard(data.results[0].analysis, data.results[0].ai_summary);
                fetchHistory(); // Update sidebar live
            }
        } catch (error) {
            alert("Check failed. Please ensure the backend server is running.");
        } finally {
            // Restore UI
            btnText.textContent = "Initiate Scan";
            btnIcon.classList.remove("hidden");
            loader.classList.add("hidden");
        }
    });

    // Email Analyzer Logic
    emailForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const msg = document.getElementById("email-input").value.trim();
        if (!msg) return;

        const emBtnText = document.getElementById("email-btn-text");
        const emBtnIcon = document.getElementById("email-btn-icon");
        const emLoader = document.getElementById("email-loader");

        emBtnText.textContent = "AI Analyst Reviewing...";
        emBtnIcon.classList.add("hidden");
        emLoader.classList.remove("hidden");
        aiResultsDashboard.classList.add("hidden");

        try {
            const res = await fetch("/api/analyze-email", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: msg })
            });
            const data = await res.json();
            renderAiDashboard(data);
            fetchHistory(); // Update sidebar live
        } catch (error) {
            console.error("AI Scan Error:", error);
            alert("AI Scan failed: " + error.message);
        } finally {
            emBtnText.textContent = "Analyze Psychological Threat";
            emBtnIcon.classList.remove("hidden");
            emLoader.classList.add("hidden");
        }
    });

    // File Analyzer Logic
    const fileInput = document.getElementById("file-input");
    const fileSubmitBtn = document.getElementById("analyze-file-btn");
    const fileNameDisplay = document.getElementById("file-name-display");
    
    fileInput.addEventListener("change", (e) => {
        const file = e.target.files[0];
        if (file) {
            if (file.size > 20 * 1024 * 1024) {
                alert("File size exceeds 20MB limit.");
                fileInput.value = "";
                fileNameDisplay.textContent = "Drag & Drop or Click to Upload";
                fileSubmitBtn.disabled = true;
                return;
            }
            fileNameDisplay.textContent = file.name;
            fileSubmitBtn.disabled = false;
        } else {
            fileNameDisplay.textContent = "Drag & Drop or Click to Upload";
            fileSubmitBtn.disabled = true;
        }
    });

    fileForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const file = fileInput.files[0];
        if (!file) return;

        const fBtnText = document.getElementById("file-btn-text");
        const fBtnIcon = document.getElementById("file-btn-icon");
        const fLoader = document.getElementById("file-loader");

        fBtnText.textContent = "Scanning Payload...";
        fBtnIcon.classList.add("hidden");
        fLoader.classList.remove("hidden");
        resultsDashboard.classList.add("hidden");

        const formData = new FormData();
        formData.append("file", file);

        try {
            const res = await fetch("/api/analyze-file", {
                method: "POST",
                body: formData
            });
            const data = await res.json();
            
            if (data.analysis) {
                renderDashboard(data.analysis, data.ai_summary);
                fetchHistory(); // Update sidebar live
            }
        } catch (error) {
            console.error("File Scan Error:", error);
            alert("File scan failed: " + error.message);
        } finally {
            fBtnText.textContent = "Extract & Scan Payload";
            fBtnIcon.classList.remove("hidden");
            fLoader.classList.add("hidden");
        }
    });

    function renderAiDashboard(data) {
        aiResultsDashboard.classList.remove("hidden");

        const { risk, score, tactics, verdict } = data;
        let color = "#a855f7"; // purple
        if (risk === "Malicious") color = "var(--malicious)";
        else if (risk === "Suspicious") color = "var(--suspicious)";
        else if (risk === "Safe") color = "var(--safe)";

        const badge = document.getElementById("ai-risk-badge");
        badge.textContent = risk.toUpperCase();
        badge.className = `badge ${risk.toLowerCase()}`;
        if (risk === "Error") badge.style.background = "#555";

        const scoreEl = document.getElementById("ai-score-value");
        scoreEl.textContent = score;
        scoreEl.style.color = color;

        document.getElementById("ai-verdict-text").textContent = verdict;

        const chipsContainer = document.getElementById("ai-tactics-chips");
        chipsContainer.innerHTML = '';
        if (tactics && tactics.length > 0) {
            tactics.forEach(t => {
                chipsContainer.innerHTML += `<div style="background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); border-radius: 15px; padding: 5px 15px; font-size: 0.9rem; color: white;">${t}</div>`;
            });
        } else {
            chipsContainer.innerHTML = `<div style="background: rgba(16, 185, 129, 0.2); border: 1px solid var(--safe); border-radius: 15px; padding: 5px 15px; font-size: 0.9rem; color: var(--safe);">None Detected</div>`;
        }
    }

    function renderDashboard(analysis, aiSummary = null) {
        document.getElementById("results-dashboard").classList.remove("hidden");

        const { risk, score, flags, details } = analysis;

        // Colors map
        const colors = {
            "Safe": "#10b981",
            "Suspicious": "#f59e0b",
            "Malicious": "#ef4444"
        };
        const color = colors[risk] || "#6366f1";

        // Badge
        const badge = document.getElementById("risk-badge");
        badge.textContent = risk;
        badge.className = `badge ${risk.toLowerCase()}`;

        // Progress Ring
        const circle = document.getElementById("score-ring");
        const radius = circle.r.baseVal.value;
        const circumference = radius * 2 * Math.PI;
        circle.style.strokeDasharray = `${circumference} ${circumference}`;
        circle.style.strokeDashoffset = circumference;
        circle.style.stroke = color;

        const offset = circumference - (score / 100) * circumference;
        // Small timeout for animation
        setTimeout(() => {
            circle.style.strokeDashoffset = offset;
        }, 100);

        document.getElementById("score-value").textContent = score;

        // Flags
        const flagsContainer = document.getElementById("threat-flags");
        flagsContainer.innerHTML = '';
        if (flags.length === 0) {
            flagsContainer.innerHTML = `<div class="flag-item"><i data-lucide="check-circle" style="color:var(--safe)"></i> <span>File clean. No threats detected by our engine.</span></div>`;
        } else {
            flags.forEach(flag => {
                const isCritical = flag.toLowerCase().includes("malicious") || flag.toLowerCase().includes("database") || flag.toLowerCase().includes("phishing") || flag.toLowerCase().includes("dga") || flag.toLowerCase().includes("executable");
                flagsContainer.innerHTML += `
                    <div class="flag-item ${isCritical ? 'critical' : ''}">
                        <i data-lucide="${isCritical ? 'alert-triangle' : 'info'}" style="color:${isCritical ? 'var(--malicious)' : 'var(--suspicious)'}"></i>
                        <span>${flag}</span>
                    </div>
                `;
            });
        }

        // Safe Routing Injection
        const safeAction = document.getElementById("safe-action-container");
        const proceedLink = document.getElementById("proceed-link");
        if (score < 20) {
            safeAction.style.display = "flex";
            let trueUrl = details.domain ? (details.domain.startsWith('http') ? details.domain : 'https://' + details.domain) : '#';
            proceedLink.href = trueUrl;
        } else {
            safeAction.style.display = "none";
        }

        // Standard Details Mapping (Adaptive for URL or File)
        document.getElementById("intel-domain").parentElement.querySelector('span').innerHTML = details.filename ? "File Name" : "Domain";
        document.getElementById("intel-domain").textContent = details.domain || details.filename || "N/A";
        document.getElementById("intel-domain").style.maxWidth = "70%";

        const trustEl = document.getElementById("intel-trust");
        trustEl.parentElement.querySelector('span').innerHTML = details.filename ? "Size / State" : "Global Trust";
        trustEl.textContent = details.global_trust || (details.size ? `${(details.size/1024).toFixed(2)} KB` : "Untrusted / Unknown");
        trustEl.style.color = details.global_trust && details.global_trust.includes("Top 100k") ? "var(--safe)" : "var(--text-main)";

        document.getElementById("intel-registrar").parentElement.querySelector('span').innerHTML = details.filename ? "File Type" : "Registrar";
        document.getElementById("intel-registrar").textContent = details.registrar || details.file_type || "Unknown";
        
        document.getElementById("intel-age").parentElement.querySelector('span').innerHTML = details.filename ? "Entropy" : "Age Status";
        document.getElementById("intel-age").textContent = details.entropy ? `${details.entropy} Shannon` : "Inspected Live";

        // Highlight young domains manually from flags
        if (flags && !details.filename) {
            flags.forEach(f => {
                if (f.includes("days ago")) {
                    document.getElementById("intel-age").innerHTML = `<span style="color:var(--malicious)">${f.split('(')[1].replace(')', '')}</span>`;
                }
            });
        }

        document.getElementById("intel-ip").parentElement.querySelector('span').innerHTML = details.filename ? "MD5 Hash" : "Resolved IP";
        document.getElementById("intel-ip").textContent = details.ip || details.md5 || "Unresolved";
        
        document.getElementById("intel-location").parentElement.querySelector('span').innerHTML = details.filename ? "SHA-256" : "Server Loc";
        document.getElementById("intel-location").textContent = details.server_location || details.sha256 || "Unknown";
        if(details.filename) document.getElementById("intel-location").style.fontSize = "0.75rem";
        else document.getElementById("intel-location").style.fontSize = "1rem";
        
        document.getElementById("intel-redirects").parentElement.querySelector('span').innerHTML = details.filename ? "VT Scans" : "Redirects";
        document.getElementById("intel-redirects").textContent = details.filename ? `${(details.vt_stats && details.vt_stats.scans) || 0} Vendors`  : (details.redirects > 1 ? `${details.redirects} hops` : "Direct");

        // Deep Intel Mapping

        // SSL rendering
        const sslEl = document.getElementById("intel-ssl");
        sslEl.textContent = details.ssl_trust || "Unknown";
        if (details.ssl_trust && (details.ssl_trust.includes("Expired") || details.ssl_trust.includes("Refused"))) {
            sslEl.style.color = "var(--malicious)";
        } else {
            sslEl.style.color = "var(--text-main)";
        }

        // DNS rendering
        const dnsEl = document.getElementById("intel-dns");
        dnsEl.textContent = details.dns_integrity || "Unknown";
        if (details.dns_integrity && details.dns_integrity.includes("No MX")) {
            dnsEl.style.color = "var(--malicious)";
        } else {
            dnsEl.style.color = "var(--text-main)";
        }

        // Entropy rendering
        const entropyEl = document.getElementById("intel-entropy");
        const entropy = details.entropy_score !== undefined ? details.entropy_score : (details.entropy !== undefined ? details.entropy : 0);
        entropyEl.textContent = entropy.toFixed(2);
        if (entropy > 3.8) {
            entropyEl.style.color = "var(--malicious)";
        } else if (entropy > 3.0) {
            entropyEl.style.color = "var(--suspicious)";
        } else {
            entropyEl.style.color = "var(--text-main)";
        }

        // NLP rendering
        const nlpEl = document.getElementById("intel-nlp");
        nlpEl.textContent = details.nlp_deception_score > 0 ? `${details.nlp_deception_score} Phishing Triggers Found` : "Clear. 0 Triggers.";
        if (details.nlp_deception_score > 2) {
            nlpEl.style.color = "var(--malicious)";
        } else {
            nlpEl.style.color = "var(--text-main)";
        }

        // Phase 3 Features: Evasion & Payload Intel
        const punyEl = document.getElementById("intel-puny");
        punyEl.textContent = details.punycode_detected ? "DETECTED (IDN Spoofing)" : "Clear";
        punyEl.style.color = details.punycode_detected ? "var(--malicious)" : "var(--text-main)";

        const brandEl = document.getElementById("intel-brand");
        brandEl.textContent = (details.brand_impersonation && details.brand_impersonation !== "None") ? details.brand_impersonation : "None Detected";
        brandEl.style.color = (details.brand_impersonation && details.brand_impersonation !== "None") ? "var(--malicious)" : "var(--text-main)";

        const jsEl = document.getElementById("intel-js");
        jsEl.textContent = details.js_evasion_score > 0 ? `Obfuscated (${details.js_evasion_score} blocks)` : "Standard Baseline";
        jsEl.style.color = details.js_evasion_score > 0 ? "var(--suspicious)" : "var(--text-main)";

        const payloadEl = document.getElementById("intel-payload");
        payloadEl.textContent = details.payload_type || "Standard Webpage";
        if (details.payload_type && details.payload_type.includes("Executable")) {
            payloadEl.style.color = "var(--malicious)";
        } else if (details.payload_type && details.payload_type.includes("Parked")) {
            payloadEl.style.color = "var(--suspicious)";
        } else {
            payloadEl.style.color = "var(--text-main)";
        }

        // VirusTotal Rendering
        if (details.vt_stats) {
            document.getElementById("vt-scans").textContent = details.vt_stats.scans > 0 ? `${details.vt_stats.scans} Global Vendors` : "No VT Data";

            const vtMalEl = document.getElementById("vt-malicious");
            vtMalEl.textContent = details.vt_stats.malicious;
            vtMalEl.style.color = details.vt_stats.malicious > 0 ? "var(--malicious)" : "var(--safe)";

            const vtSusEl = document.getElementById("vt-suspicious");
            vtSusEl.textContent = details.vt_stats.suspicious;
            vtSusEl.style.color = details.vt_stats.suspicious > 0 ? "var(--suspicious)" : "var(--text-main)";

            const vtVerdictEl = document.getElementById("vt-verdict");
            if (details.vt_stats.scans === 0) {
                vtVerdictEl.textContent = "Unscanned";
                vtVerdictEl.style.color = "var(--text-main)";
            } else if (details.vt_stats.malicious >= 3) {
                vtVerdictEl.textContent = "Malware Consensus";
                vtVerdictEl.style.color = "var(--malicious)";
            } else if (details.vt_stats.malicious > 0 || details.vt_stats.suspicious > 1) {
                vtVerdictEl.textContent = "Suspicious Flagging";
                vtVerdictEl.style.color = "var(--suspicious)";
            } else {
                vtVerdictEl.textContent = "Clean / Harmless";
                vtVerdictEl.style.color = "var(--safe)";
            }
        }

        // AI Summary Rendering
        const aiSummaryContainer = document.getElementById("ai-summary-container");
        if (aiSummary) {
            aiSummaryContainer.style.display = "block";
            document.getElementById("ai-summary-type").textContent = aiSummary.threat_type || (score > 20 ? "Threat Detected" : "Safe Link");
            document.getElementById("ai-summary-description").textContent = aiSummary.user_summary || (score > 20 ? "Our AI analyst has flagged this link. Proceed with extreme caution." : "AI verified this link as safe and trustworthy.");
            
            const sevBadge = document.getElementById("ai-summary-severity");
            sevBadge.textContent = (aiSummary.severity || risk).toUpperCase();
            
            // Color severity badge and panel
            const sev = (aiSummary.severity || risk).toLowerCase();
            const aiSummaryHeaderH3 = document.getElementById('ai-summary-title') || aiSummaryContainer.querySelector('h3');
            if (sev.includes("critical") || sev.includes("high") || sev === "malicious") {
                sevBadge.style.background = "var(--malicious)";
                aiSummaryContainer.style.borderLeftColor = "var(--malicious)";
                aiSummaryHeaderH3.style.color = "var(--malicious)";
            } else if (sev.includes("medium") || sev === "suspicious") {
                sevBadge.style.background = "var(--suspicious)";
                aiSummaryContainer.style.borderLeftColor = "var(--suspicious)";
                aiSummaryHeaderH3.style.color = "var(--suspicious)";
            } else {
                sevBadge.style.background = "var(--safe)";
                aiSummaryContainer.style.borderLeftColor = "var(--safe)";
                aiSummaryHeaderH3.style.color = "var(--safe)";
            }
        } else {
            aiSummaryContainer.style.display = "none";
        }

        // Refresh icons since dom was updated
        lucide.createIcons();

        // Scroll down slightly so dashboard is in full view on mobile
        window.scrollBy({ top: 450, behavior: 'smooth' });
    }
});
