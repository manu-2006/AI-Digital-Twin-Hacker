// =============================
// 🔥 GLOBALS
// =============================
let chartInstance = null;
let loaderInterval = null;


// =============================
// 🔥 START SCAN
// =============================
document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("scanBtn");
    if (btn) btn.addEventListener("click", startScan);
});

async function startScan() {
    const url = shortenURL(document.getElementById("url").value);
    if (!url) return alert("Enter a valid URL");

    const loader = document.getElementById("scanLoader");
    const loaderText = document.getElementById("loaderText");
    const btn = document.getElementById("scanBtn");

    loader.style.display = "flex";
    btn.disabled = true;
    btn.innerText = "Scanning...";

    startLoaderAnimation(loaderText);

    try {

        updateLoaderStep(loaderText, "Initializing scan...");
        await delay(700);

        updateLoaderStep(loaderText, "Scanning ports...");
        await delay(700);

        updateLoaderStep(loaderText, "Analyzing vulnerabilities...");
        await delay(700);

        updateLoaderStep(loaderText, "Ai Recommendations... ");
        await delay(700);

        updateLoaderStep(loaderText, "Predicting attacks...");
        await delay(700);

        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const data = await res.json();

        if (!data.success) {
            throw new Error(data.error || "Scan failed");
        }

        updateLoaderStep(loaderText, "Finalizing report...");
        await delay(600);

        renderAll(data);
        showActionButtons();

    } catch (err) {
        alert("Scan failed");
        console.error(err);
    } finally {
        stopLoaderAnimation();
        loader.style.display = "none";
        btn.disabled = false;
        btn.innerText = "🚀 Start Scan";
    }
}


// =============================
// 🔥 LOADER TEXT ANIMATION
// =============================
function startLoaderAnimation(el) {
    let dots = 0;

    loaderInterval = setInterval(() => {
        dots = (dots + 1) % 4;
        const base = el.getAttribute("data-base") || "Scanning";
        el.innerText = base + ".".repeat(dots);
    }, 400);
}

function stopLoaderAnimation() {
    clearInterval(loaderInterval);
}

function updateLoaderStep(el, text) {
    el.setAttribute("data-base", text.replace("...", ""));
    el.innerText = text;
}


// =============================
// 🔥 RENDER ALL
// =============================
function renderAll(data) {

    renderList("ports", data.ports || []);
    renderVulns(data.vulnerabilities || []);
    renderList("admin", data.admin_panels || []);

    renderPredicted(data.vulnerabilities || []);
    renderAttackTime(data.vulnerabilities || []);
    renderAttackPaths(data);

    renderAIAdvice(data);

    const cvss = calculateCVSS(data);
    setRisk(cvss);
    setRiskBreakdown(data);

    renderChart(data);
}


// =============================
// 🔥 CVSS STYLE SCORE
// =============================
function calculateCVSS(data) {

    let total = 0;
    let count = 0;

    (data.vulnerabilities || []).forEach(v => {
        const vLower = v.toLowerCase();

        let score = 3;

        if (vLower.includes("xss")) score = 9;
        else if (vLower.includes("admin")) score = 8.5;
        else if (vLower.includes("sql")) score = 9.5;
        else if (vLower.includes("csrf")) score = 8;
        else if (vLower.includes("header")) score = 4;
        else if (vLower.includes("cookie")) score = 5.5;

        total += score;
        count++;
    });

    if (count === 0) return 10;

    let avg = total / count;
    return Math.round(avg * 10);
}


// =============================
// 🔥 RISK UI
// =============================
function setRisk(score) {

    const label = document.getElementById("riskLabel");
    const bar = document.getElementById("riskFill");

    let level = "LOW";
    let color = "#22c55e";

    if (score >= 85) {
        level = "CRITICAL";
        color = "#ef4444";
    } else if (score >= 70) {
        level = "HIGH";
        color = "#f97316";
    } else if (score >= 40) {
        level = "MEDIUM";
        color = "#eab308";
    }

    label.innerText = `${score}% - ${level}`;
    bar.style.width = score + "%";
    bar.style.background = color;
}


// =============================
// 🔥 RISK BREAKDOWN
// =============================
function setRiskBreakdown(data) {

    const el = document.getElementById("riskExplanation");
    if (!el) return;

    el.innerHTML = `
        <div class="list-item">Vulnerabilities: ${(data.vulnerabilities || []).length}</div>
        <div class="list-item">Open Ports: ${(data.ports || []).length}</div>
        <div class="list-item">Admin Panels: ${(data.admin_panels || []).length}</div>
    `;
}


// =============================
// 🔥 ATTACK PATHS
// =============================
function renderAttackPaths(data) {

    const el = document.getElementById("attackPaths");
    el.innerHTML = "";

    let paths = [];

    if ((data.vulnerabilities || []).some(v => v.toLowerCase().includes("xss"))) {
        paths.push(["Inject script", "Steal cookies", "Hijack session"]);
    }

    if ((data.ports || []).length > 3) {
        paths.push(["Scan ports", "Exploit service", "Gain access"]);
    }

    if ((data.admin_panels || []).length > 0) {
        paths.push(["Find admin panel", "Brute force", "Admin access"]);
    }

    if (paths.length === 0) {
        el.innerHTML = `<div class="list-item">No attack paths generated</div>`;
        return;
    }

    paths.forEach((p, i) => {

        let block = `<div class="attack-path">
            <div class="attack-header">Path ${i+1}</div>
            <div class="attack-steps">`;

        p.forEach(step => {
            block += `<div class="attack-step">➤ ${step}</div>`;
        });

        block += `</div></div>`;

        el.innerHTML += block;
    });
}


// =============================
// 🔥 DOWNLOAD REPORT (UPGRADED)
// =============================
function downloadReport() {

    const url = document.getElementById("url").value;
    const risk = document.getElementById("riskLabel").innerText;

    const ports = document.getElementById("ports").innerHTML;
    const vulns = document.getElementById("vulns").innerHTML;
    const admin = document.getElementById("admin").innerHTML;
    const attacks = document.getElementById("attackPaths").innerHTML;
    const advice = document.getElementById("aiAdvice").innerHTML;

const reportHTML = `
<html>
<head>
<title>Security Report</title>

<style>
body {
    font-family: Inter;
    background: #0b1220;
    color: #e5e7eb;
    padding: 40px;
}

.container {
    max-width: 1100px;
    margin: auto;
}

h1 {
    color: #6366f1;
}

.card {
    background: #111827;
    border-radius: 14px;
    padding: 20px;
    margin-bottom: 20px;
    border: 1px solid #1f2937;
}

.risk {
    font-size: 26px;
    font-weight: bold;
}

.low { color:#22c55e; }
.medium { color:#eab308; }
.high { color:#f97316; }
.critical { color:#ef4444; }

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    padding: 10px;
    border-bottom: 1px solid #1f2937;
    text-align: left;
}

.badge {
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 12px;
}

.badge.low { background:#064e3b; }
.badge.medium { background:#78350f; }
.badge.high { background:#7c2d12; }
.badge.critical { background:#7f1d1d; }

.step {
    margin: 5px 0;
    padding: 6px;
    background: rgba(255,255,255,0.05);
    border-radius: 6px;
}
</style>
</head>

<body>

<div class="container">

<h1>🛡 AI Digital Twin Security Report</h1>

<div class="card">
<h3>Target</h3>
<p>${shortenURL(url)}</p>
</div>

<div class="card">
<h3>Risk Score</h3>
<div class="risk">${risk}</div>
</div>

<div class="card">
<h3>Vulnerabilities</h3>
<table>
<tr><th>Name</th><th>Severity</th></tr>
${[...document.querySelectorAll("#vulns .list-item")].map(v => {
    const text = v.innerText;
    let sev = "low";
    if (text.includes("CRITICAL")) sev="critical";
    else if (text.includes("HIGH")) sev="high";
    else if (text.includes("MEDIUM")) sev="medium";
    return `<tr>
        <td>${text}</td>
        <td><span class="badge ${sev}">${sev.toUpperCase()}</span></td>
    </tr>`;
}).join("")}
</table>
</div>

<div class="card">
<h3>Attack Paths</h3>
${document.getElementById("attackPaths").innerHTML}
</div>

<div class="card">
<h3>Recommendations</h3>
${document.getElementById("aiAdvice").innerHTML}
</div>

</div>

<!-- 🔥 PROFESSIONAL FOOTER -->
<div style="
    margin-top:50px;
    padding-top:20px;
    border-top:1px solid #1f2937;
    color:#9ca3af;
    font-size:13px;
">

    <div style="
        display:flex;
        justify-content:space-between;
        flex-wrap:wrap;
        gap:10px;
    ">

        <div>
            <strong style="color:#e5e7eb;">Generated On:</strong><br>
            ${new Date().toLocaleString()}
        </div>

        <div>
            <strong style="color:#e5e7eb;">Tool:</strong><br>
            AI Digital Twin Hacker v1.0
        </div>

        <div>
            <strong style="color:#e5e7eb;">Scan Type:</strong><br>
            Automated Web Security Scan
        </div>

    </div>

    <div style="
        margin-top:20px;
        text-align:center;
        font-size:12px;
    ">
        © ${new Date().getFullYear()} AI Digital Twin Hacker | Developed by <b style="color:#6366f1;">Manu</b>
    </div>

</div>

</body>
</html>
`;

    const blob = new Blob([reportHTML], { type: "text/html" });
    const a = document.createElement("a");

    a.href = URL.createObjectURL(blob);
    a.download = "security-report.html";
    a.click();
}


// =============================
// 🔥 HELPERS
// =============================
function renderList(id, items) {
    const el = document.getElementById(id);
    el.innerHTML = "";

    if (!items.length) {
        el.innerHTML = `<div class="list-item">No data</div>`;
        return;
    }

    items.forEach(i => {
        el.innerHTML += `<div class="list-item">${i}</div>`;
    });
}

function renderVulns(vulns) {
    const box = document.getElementById("vulns");
    box.innerHTML = "";

    if (!vulns.length) {
        box.innerHTML = `<div class="list-item">No vulnerabilities found</div>`;
        return;
    }

    vulns.forEach(v => {
        const sev = getSeverity(v);
        box.innerHTML += `<div class="list-item">${v} <span class="badge ${sev}">${sev.toUpperCase()}</span></div>`;
    });
}

function getSeverity(v) {
    v = v.toLowerCase();
    if (v.includes("xss")) return "critical";
    if (v.includes("admin")) return "high";
    if (v.includes("cookie")) return "medium";
    return "low";
}

function renderChart(data) {
    const ctx = document.getElementById("chart");

    if (chartInstance) chartInstance.destroy();

    chartInstance = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Ports", "Vulnerabilities", "Admin"],
            datasets: [{
                label: "Scan Data",
                data: [
                    (data.ports || []).length,
                    (data.vulnerabilities || []).length,
                    (data.admin_panels || []).length
                ]
            }]
        }
    });
}

function renderPredicted(vulns) {
    const el = document.getElementById("predictedAttacks");
    el.innerHTML = "";

    vulns.forEach(v => {
        let prob = 50;
        if (v.toLowerCase().includes("xss")) prob = 75;
        if (v.toLowerCase().includes("admin")) prob = 80;
        el.innerHTML += `<div class="list-item">${v} (${prob}%)</div>`;
    });
}

function renderAttackTime(vulns) {
    const el = document.getElementById("attackTimeList");
    el.innerHTML = "";

    vulns.forEach(v => {
        let time = "5-10 mins";
        if (v.toLowerCase().includes("xss")) time = "2-5 mins";
        if (v.toLowerCase().includes("admin")) time = "1-3 mins";
        el.innerHTML += `<div class="list-item">${v} (${time})</div>`;
    });
}

function renderAIAdvice(data) {
    const el = document.getElementById("aiAdvice");
    el.innerHTML = `
        <div class="list-item">Enable security headers</div>
        <div class="list-item">Sanitize inputs</div>
        <div class="list-item">Protect admin panels</div>
    `;
}

function showActionButtons() {
    const el = document.getElementById("actionButtons");
    if (el) el.classList.add("show");
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// =============================
// 🔥 PARTICLES INIT (FIX)
// =============================
document.addEventListener("DOMContentLoaded", () => {

    if (window.particlesJS) {
        particlesJS("particles-js", {
            particles: {
                number: { value: 60 },
                color: { value: "#6366f1" },
                shape: { type: "circle" },
                opacity: { value: 0.3 },
                size: { value: 2 },
                line_linked: {
                    enable: true,
                    distance: 150,
                    color: "#6366f1",
                    opacity: 0.2,
                    width: 1
                },
                move: {
                    enable: true,
                    speed: 1
                }
            },
            interactivity: {
                events: {
                    onhover: { enable: true, mode: "grab" }
                }
            }
        });
    }
});

function shortenURL(url) {
    try {
        const u = new URL(url);
        return u.origin;
    } catch {
        return url.slice(0, 50) + "...";
    }
}

document.getElementById("url").value = shortenURL(url);