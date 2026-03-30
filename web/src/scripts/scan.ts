// @ts-nocheck
// ── Elements ──
const fileInput = document.getElementById("file-input");
const fileName = document.getElementById("file-name");
const dropZone = document.getElementById("drop-zone");
const page = document.getElementById("page");
const shell = document.getElementById("shell");
const sidebar = document.getElementById("sidebar");
const overlay = document.getElementById("sidebar-overlay");
const toggleBtn = document.getElementById("toggle-sidebar");
const historyEl = document.getElementById("history-list");
const emptyEl = document.getElementById("history-empty");
const submitBtn = document.getElementById("submit-btn");
const cancelBtn = document.getElementById("cancel-btn");
const loading = document.getElementById("loading");
const progressEl = document.getElementById("upload-progress");
const progressFill = document.getElementById("progress-fill");
const progressLabel = document.getElementById("progress-label");
const progressPct = document.getElementById("progress-pct");
const results = document.getElementById("results");
const scanMsgEl = document.getElementById("scan-msg");

// ── Sidebar toggle ──
const isMobile = () => window.innerWidth <= 768;

document
    .querySelector(".sidebar-head")
    .addEventListener("click", () => {
        window.location.href = "/";
    });

toggleBtn.addEventListener("click", () => {
    if (isMobile()) {
        shell.classList.toggle("sidebar-open");
    } else {
        shell.classList.toggle("sidebar-collapsed");
        localStorage.setItem(
"pavise-sidebar",
shell.classList.contains("sidebar-collapsed")
    ? "collapsed"
    : "open",
        );
    }
});
overlay.addEventListener("click", () =>
    shell.classList.remove("sidebar-open"),
);

cancelBtn.addEventListener("click", () => {
    if (activeAbort) activeAbort.abort();
});

if (
    !isMobile() &&
    localStorage.getItem("pavise-sidebar") === "collapsed"
) {
    shell.classList.add("sidebar-collapsed");
}

// ── View switching ──
const views = document.querySelectorAll(".view");
const navItems = document.querySelectorAll(".nav-item[data-view]");

function switchView(viewId) {
    views.forEach((v) =>
        v.classList.toggle("active", v.id === "view-" + viewId),
    );
    navItems.forEach((n) =>
        n.classList.toggle("active", n.dataset.view === viewId),
    );
    if (isMobile()) shell.classList.remove("sidebar-open");
}

navItems.forEach((n) =>
    n.addEventListener("click", () => switchView(n.dataset.view)),
);

// ── File validation ──
const MAX_FILE_SIZE = 15 * 1024 * 1024 * 1024; // 15 GB
function validateFile(file) {
    if (!file) return null;
    if (!file.name.toLowerCase().endsWith('.ipa')) {
        return 'Only .ipa files are supported.';
    }
    if (file.size === 0) {
        return 'File is empty.';
    }
    if (file.size > MAX_FILE_SIZE) {
        return 'File exceeds the 15 GB size limit.';
    }
    return null;
}

function setFileState(file) {
    const name = file?.name ?? '';
    fileName.textContent = name;
    dropZone.classList.toggle('has-file', !!name);
}

// ── File handling ──
fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    const err = validateFile(file);
    if (err) {
        results.innerHTML = `<div class="error-card"><span class="error-icon" aria-hidden="true">\u2717</span><span class="error-msg">${escapeHtml(err)}</span></div>`;
        page.classList.add("has-results");
        fileInput.value = '';
        setFileState(null);
        return;
    }
    setFileState(file);
});

dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
});
dropZone.addEventListener("dragleave", () =>
    dropZone.classList.remove("drag-over"),
);
dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    if (e.dataTransfer.files.length) {
        const file = e.dataTransfer.files[0];
        const err = validateFile(file);
        if (err) {
results.innerHTML = `<div class="error-card"><span class="error-icon" aria-hidden="true">\u2717</span><span class="error-msg">${escapeHtml(err)}</span></div>`;
page.classList.add("has-results");
return;
        }
        fileInput.files = e.dataTransfer.files;
        setFileState(file);
    }
});

// ── Phase animation during scan ──
let phaseInterval = null;
let msgInterval = null;
let currentPhase = 0;
let currentMsgIdx = 0;
const phases = document.querySelectorAll(".scan-phase");

const phaseMessages = [
    [
        "Streaming IPA to analysis pipeline...",
        "Computing SHA-256...",
    ],
    [
        "Inflating ZIP archive...",
        "Locating Mach-O binaries...",
        "Reading Info.plist...",
    ],
    [
        "Parsing Mach-O load commands...",
        "Checking PIE and stack canaries...",
        "Inspecting encryption flags...",
        "Extracting symbol table...",
    ],
    [
        "Running secret pattern matching...",
        "Scanning for hardcoded credentials...",
        "Checking URL schemes...",
        "Analyzing embedded strings...",
    ],
    [
        "Computing OWASP M-series scores...",
        "Grading security posture...",
        "Building findings summary...",
    ],
];

function updateScanMsg(text) {
    scanMsgEl.style.opacity = "0";
    setTimeout(() => {
        scanMsgEl.textContent = text;
        scanMsgEl.style.opacity = "1";
    }, 160);
}

function startPhases() {
    currentPhase = 0;
    currentMsgIdx = 0;
    phases.forEach((p) => p.classList.remove("active", "done"));
    phases[0].classList.add("active");
    updateScanMsg(phaseMessages[0][0]);

    phaseInterval = setInterval(() => {
        if (currentPhase < phases.length) {
phases[currentPhase].classList.remove("active");
phases[currentPhase].classList.add("done");
        }
        currentPhase++;
        currentMsgIdx = 0;
        if (currentPhase < phases.length) {
phases[currentPhase].classList.add("active");
const msgs = phaseMessages[currentPhase];
if (msgs && msgs[0]) updateScanMsg(msgs[0]);
        }
    }, 600);

    msgInterval = setInterval(() => {
        const msgs = phaseMessages[currentPhase] || [];
        if (msgs.length > 1) {
currentMsgIdx = (currentMsgIdx + 1) % msgs.length;
updateScanMsg(msgs[currentMsgIdx]);
        }
    }, 1500);
}

function stopPhases() {
    clearInterval(phaseInterval);
    clearInterval(msgInterval);
    phases.forEach((p) => {
        p.classList.remove("active");
        p.classList.add("done");
    });
    scanMsgEl.style.opacity = "0";
}

// ── Helpers ──
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    if (bytes < 1073741824)
        return (bytes / 1048576).toFixed(1) + " MB";
    return (bytes / 1073741824).toFixed(2) + " GB";
}

function setProgress(pct, label) {
    progressFill.style.width = pct + "%";
    progressPct.textContent = Math.round(pct) + "%";
    if (label) progressLabel.textContent = label;
}

// ── Chunked upload + scan ──
const CHUNK_SIZE = 50 * 1024 * 1024; // 50 MB
const CHUNK_MAX_RETRIES = 3;
let activeAbort = null;

async function fetchWithRetry(url, opts, retries = CHUNK_MAX_RETRIES) {
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
const res = await fetch(url, opts);
if (res.ok || res.status < 500) return res;
if (attempt === retries) return res;
        } catch (err) {
if (err.name === 'AbortError') throw err;
if (attempt === retries) throw new Error('Network error: check your connection and try again.');
        }
        await new Promise(r => setTimeout(r, 100 * Math.pow(2, attempt)));
    }
}

async function uploadChunked(file, signal) {
    // 1. Init upload session
    const initRes = await fetch("/api/upload", { method: "POST", signal });
    if (!initRes.ok) throw new Error("Failed to init upload");
    const { upload_id } = await initRes.json();

    // 2. Upload chunks with retry
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = file.slice(start, end);

        const res = await fetchWithRetry(`/api/upload/${upload_id}/${i}`, {
method: "PUT",
body: chunk,
headers: { "Content-Type": "application/octet-stream" },
signal,
        });

        if (!res.ok) {
const msg = await res.text();
throw new Error(`Chunk ${i} failed: ${msg}`);
        }

        const uploaded = end;
        const pct = (uploaded / file.size) * 100;
        setProgress(
pct,
`Uploading ${formatBytes(uploaded)} / ${formatBytes(file.size)}`,
        );
    }

    // 3. Trigger scan
    setProgress(100, "Scanning...");
    const scanRes = await fetch(`/api/upload/${upload_id}/scan`, {
        method: "POST",
        signal,
    });
    if (!scanRes.ok) {
        const msg = await scanRes.text();
        throw new Error(msg);
    }
    return scanRes.text();
}

// ── Form submission ──
let scanInProgress = false;
document
    .getElementById("scan-form")
    .addEventListener("submit", async (e) => {
        e.preventDefault();
        if (scanInProgress) return;
        const file = fileInput.files[0];
        if (!file) return;

        const fileErr = validateFile(file);
        if (fileErr) {
results.innerHTML = `<div class="error-card"><span class="error-icon" aria-hidden="true">\u2717</span><span class="error-msg">${escapeHtml(fileErr)}</span></div>`;
page.classList.add("has-results");
return;
        }

        scanInProgress = true;
        activeAbort = new AbortController();
        submitBtn.disabled = true;
        cancelBtn.removeAttribute("hidden");
        loading.classList.add("active");
        progressEl.classList.add("active");
        results.setAttribute("aria-busy", "true");
        setProgress(0, "Starting upload...");
        startPhases();

        try {
const html = await uploadChunked(file, activeAbort.signal);
results.innerHTML = sanitizeHtml(html);
page.classList.add("has-results");

// Pulse first few critical/high findings to draw the eye
results
    .querySelectorAll(".sev-high")
    .forEach((badge, i) => {
        if (i >= 4) return;
        const row = badge.closest(".finding-row");
        if (row) {
setTimeout(
    () => {
        row.classList.add("crit-attn");
        row.addEventListener(
            "animationend",
            () =>
                row.classList.remove(
                    "crit-attn",
                ),
            { once: true },
        );
    },
    700 + i * 120,
);
        }
    });

// Extract scan info for history
const resultCard =
    results.querySelector(".result-card");
if (resultCard) {
    const appName =
        resultCard
.querySelector(".app-name")
?.childNodes[0]?.textContent?.trim() ||
        "Unknown";
    const grade =
        resultCard
.querySelector(".grade")
?.textContent?.trim() || "?";
    const score =
        resultCard
.querySelector(".score-num")
?.childNodes[0]?.textContent?.trim() || "0";
    const jsonLink =
        resultCard.querySelector(".btn-json");
    const scanId = jsonLink
        ? jsonLink.getAttribute("href").split("/")[3]
        : null;
    if (scanId) {
        addToHistory({
id: scanId,
name: appName,
grade,
score,
ts: Date.now(),
        });
    }
}
        } catch (err) {
if (err.name === 'AbortError') return;
const msg = !navigator.onLine
    ? 'You appear to be offline. Check your connection and try again.'
    : err.message;
results.innerHTML = `<div class="error-card"><span class="error-icon" aria-hidden="true">\u2717</span><span class="error-msg">${escapeHtml(msg)}</span></div>`;
page.classList.add("has-results");
        } finally {
scanInProgress = false;
activeAbort = null;
submitBtn.disabled = false;
cancelBtn.setAttribute("hidden", "");
loading.classList.remove("active");
progressEl.classList.remove("active");
results.removeAttribute("aria-busy");
stopPhases();
        }
    });

// ── Scan history (localStorage) ──
const HISTORY_KEY = "pavise-history";
const MAX_HISTORY = 50;

function getHistory() {
    try {
        return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch {
        return [];
    }
}

function saveHistory(items) {
    localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(items.slice(0, MAX_HISTORY)),
    );
}

function addToHistory(entry) {
    const items = getHistory().filter((h) => h.id !== entry.id);
    items.unshift(entry);
    saveHistory(items);
    renderHistory();
}

function formatTimeAgo(ts) {
    const diff = Date.now() - ts;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return mins + "m ago";
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + "h ago";
    const days = Math.floor(hrs / 24);
    if (days < 30) return days + "d ago";
    return new Date(ts).toLocaleDateString();
}

function gradeClass(g) {
    const l = g.toLowerCase();
    if (l === "a") return "hg-a";
    if (l === "b") return "hg-b";
    if (l === "c") return "hg-c";
    if (l === "d") return "hg-d";
    return "hg-f";
}

function renderHistory() {
    const items = getHistory();
    emptyEl.style.display = items.length ? "none" : "block";

    const frag = document.createDocumentFragment();
    items.forEach((item) => {
        const btn = document.createElement("button");
        btn.className = "history-item";
        btn.setAttribute(
            "aria-label",
            `Grade ${item.grade} — ${item.name}, scanned ${formatTimeAgo(item.ts)}`,
        );
        btn.innerHTML = `
          <span class="history-grade ${gradeClass(item.grade)}" aria-hidden="true">${item.grade}</span>
          <div class="history-meta">
<div class="history-name">${escapeHtml(item.name)}</div>
<div class="history-time">${formatTimeAgo(item.ts)}</div>
          </div>
        `;
        btn.addEventListener("click", () =>
            loadHistoryScan(item.id),
        );
        frag.appendChild(btn);
    });
    historyEl.replaceChildren(emptyEl, frag);
}

function escapeHtml(s) {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Sanitize server-returned HTML before injection to prevent XSS from
// any attacker-controlled data embedded in scan results (app names, paths, etc.)
function sanitizeHtml(html: string): string {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    doc.querySelectorAll('script, object, embed, iframe, base').forEach(el => el.remove());
    doc.querySelectorAll('*').forEach(el => {
        for (const attr of Array.from(el.attributes)) {
            if (/^on/i.test(attr.name) || (attr.name === 'href' && /^\s*javascript:/i.test(attr.value))) {
                el.removeAttribute(attr.name);
            }
        }
    });
    return doc.body.innerHTML;
}

function loadHistoryScan(id) {
    switchView("scan");
    results.innerHTML =
        '<div style="display:flex;align-items:center;gap:0.65rem;padding:1.5rem 0;color:var(--text-dim);font-size:0.85rem;"><div class="spinner"></div>Loading scan...</div>';
    page.classList.add("has-results");

    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 15000);

    fetch("/api/scan/" + encodeURIComponent(id), { signal: ctrl.signal })
        .then((r) => {
if (!r.ok) throw new Error("Scan expired");
return r.text();
        })
        .then((html) => {
results.innerHTML = sanitizeHtml(html);
        })
        .catch((err) => {
const msg = err.name === 'AbortError'
    ? 'Request timed out. Please try again.'
    : !navigator.onLine
    ? 'You appear to be offline. Check your connection and try again.'
    : 'Scan result has expired. Re-upload the file to scan again.';
results.innerHTML =
    `<div class="error-card"><span class="error-icon" aria-hidden="true">\u2717</span><span class="error-msg">${escapeHtml(msg)}</span></div>`;
        })
        .finally(() => clearTimeout(timeout));
}

renderHistory();

// ── Pick up results from landing page ──
(function checkLandingResult() {
    let landingHtml;
    try { landingHtml = sessionStorage.getItem('pavise-landing-result'); } catch { return; }
    if (landingHtml) {
        try {
sessionStorage.removeItem('pavise-landing-result');
sessionStorage.removeItem('pavise-landing-file');
        } catch { /* storage unavailable */ }
        results.innerHTML = sanitizeHtml(landingHtml);
        page.classList.add('has-results');
        // Extract scan info for history
        const resultCard = results.querySelector('.result-card');
        if (resultCard) {
const appName = resultCard.querySelector('.app-name')?.childNodes[0]?.textContent?.trim() || 'Unknown';
const grade = resultCard.querySelector('.grade')?.textContent?.trim() || '?';
const score = resultCard.querySelector('.score-num')?.childNodes[0]?.textContent?.trim() || '0';
const jsonLink = resultCard.querySelector('.btn-json');
const scanId = jsonLink ? jsonLink.getAttribute('href').split('/')[3] : null;
if (scanId) {
    addToHistory({ id: scanId, name: appName, grade, score, ts: Date.now() });
}
        }
    }
})();

// ── Keyboard shortcut: U to open file picker ──
document.addEventListener("keydown", (e) => {
    if (e.key !== "u" && e.key !== "U") return;
    const active = document.activeElement;
    if (
        active &&
        (active.tagName === "INPUT" ||
active.tagName === "TEXTAREA" ||
active.isContentEditable)
    )
        return;
    if (
        document
.getElementById("view-scan")
.classList.contains("active")
    ) {
        e.preventDefault();
        fileInput.click();
    }
});

// ── Theme toggle ──
const themeToggle = document.getElementById("theme-toggle");
function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("pavise-theme", theme);
}
themeToggle.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme");
    setTheme(current === "dark" ? "light" : "dark");
});
// Init theme from localStorage or system preference
(function() {
    const stored = localStorage.getItem("pavise-theme");
    if (stored) {
        setTheme(stored);
    } else if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
        setTheme("dark");
    }
})();

// ── Console easter egg ──
console.log(
    "%c⬡ Pavise%c  iOS Security Analyzer\n%cParsing Mach-O since 2024. Built with Rust.\ngithub.com/ahmetmutlugun",
    "color:#3b82f6;font-size:15px;font-weight:900;letter-spacing:-0.02em;",
    "color:#8b949e;font-size:12px;font-weight:600;",
    "color:#4a5568;font-size:11px;line-height:1.6;",
);
