// @ts-nocheck
// ── Nav scroll effect ──
const nav = document.getElementById('nav');
const onScroll = () => nav.classList.toggle('scrolled', window.scrollY > 10);
window.addEventListener('scroll', onScroll, { passive: true });
onScroll();

// ── Intersection Observer for fade-up ──
const fadeEls = document.querySelectorAll('.fade-up');
const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
entry.target.classList.add('visible');
observer.unobserve(entry.target);
        }
    });
}, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });
fadeEls.forEach(el => observer.observe(el));

// ── Upload handling ──
const fileInput = document.getElementById('landing-file-input');
const fileNameEl = document.getElementById('landing-file-name');
const uploadZone = document.getElementById('upload-zone');
const submitBtn = document.getElementById('landing-submit-btn');
const loadingEl = document.getElementById('landing-loading');
const progressEl = document.getElementById('landing-progress');
const progressFill = document.getElementById('landing-progress-fill');
const progressLabel = document.getElementById('landing-progress-label');
const progressPct = document.getElementById('landing-progress-pct');
const scanMsgEl = document.getElementById('landing-scan-msg');
const errorEl = document.getElementById('landing-error');

// ── File validation ──
const MAX_FILE_SIZE = 15 * 1024 * 1024 * 1024; // 15 GB
function validateFile(file) {
    if (!file) return null;
    if (!file.name.toLowerCase().endsWith('.ipa')) return 'Only .ipa files are supported.';
    if (file.size === 0) return 'File is empty.';
    if (file.size > MAX_FILE_SIZE) return 'File exceeds the 15 GB size limit.';
    return null;
}

fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    const err = validateFile(file);
    if (err) {
        errorEl.textContent = err;
        fileInput.value = '';
        fileNameEl.textContent = '';
        uploadZone.classList.remove('has-file');
        return;
    }
    fileNameEl.textContent = file?.name ?? '';
    uploadZone.classList.toggle('has-file', !!file);
    errorEl.textContent = '';
});

uploadZone.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('drag-over');
    if (e.dataTransfer.files.length) {
        const file = e.dataTransfer.files[0];
        const err = validateFile(file);
        if (err) {
errorEl.textContent = err;
return;
        }
        fileInput.files = e.dataTransfer.files;
        fileNameEl.textContent = file.name;
        uploadZone.classList.toggle('has-file', !!file.name);
        errorEl.textContent = '';
    }
});

// ── Helpers ──
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
}
function setProgress(pct, label) {
    progressFill.style.width = pct + '%';
    progressPct.textContent = Math.round(pct) + '%';
    if (label) progressLabel.textContent = label;
}
function escapeHtml(s) {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ── Phase animation ──
let phaseInterval = null, msgInterval = null, currentPhase = 0, currentMsgIdx = 0;
const phases = document.querySelectorAll('#landing-loading .scan-phase');
const phaseMessages = [
    ['Streaming IPA to analysis pipeline...', 'Computing SHA-256...'],
    ['Inflating ZIP archive...', 'Locating Mach-O binaries...', 'Reading Info.plist...'],
    ['Parsing Mach-O load commands...', 'Checking PIE and stack canaries...', 'Inspecting encryption flags...'],
    ['Running secret pattern matching...', 'Scanning for hardcoded credentials...', 'Analyzing embedded strings...'],
    ['Computing OWASP M-series scores...', 'Grading security posture...', 'Building findings summary...'],
];
function updateScanMsg(text) {
    scanMsgEl.style.opacity = '0';
    setTimeout(() => { scanMsgEl.textContent = text; scanMsgEl.style.opacity = '1'; }, 160);
}
function startPhases() {
    currentPhase = 0; currentMsgIdx = 0;
    phases.forEach(p => p.classList.remove('active', 'done'));
    phases[0].classList.add('active');
    updateScanMsg(phaseMessages[0][0]);
    phaseInterval = setInterval(() => {
        if (currentPhase < phases.length) { phases[currentPhase].classList.remove('active'); phases[currentPhase].classList.add('done'); }
        currentPhase++; currentMsgIdx = 0;
        if (currentPhase < phases.length) { phases[currentPhase].classList.add('active'); const msgs = phaseMessages[currentPhase]; if (msgs?.[0]) updateScanMsg(msgs[0]); }
    }, 600);
    msgInterval = setInterval(() => {
        const msgs = phaseMessages[currentPhase] || [];
        if (msgs.length > 1) { currentMsgIdx = (currentMsgIdx + 1) % msgs.length; updateScanMsg(msgs[currentMsgIdx]); }
    }, 1500);
}
function stopPhases() {
    clearInterval(phaseInterval); clearInterval(msgInterval);
    phases.forEach(p => { p.classList.remove('active'); p.classList.add('done'); });
    scanMsgEl.style.opacity = '0';
}

// ── Chunked upload ──
const CHUNK_SIZE = 50 * 1024 * 1024;
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
    const initRes = await fetch('/api/upload', { method: 'POST', signal });
    if (!initRes.ok) throw new Error('Failed to init upload');
    const { upload_id } = await initRes.json();
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = file.slice(start, end);
        const res = await fetchWithRetry(`/api/upload/${upload_id}/${i}`, { method: 'PUT', body: chunk, headers: { 'Content-Type': 'application/octet-stream' }, signal });
        if (!res.ok) { const msg = await res.text(); throw new Error(`Chunk ${i} failed: ${msg}`); }
        setProgress((end / file.size) * 100, `Uploading ${formatBytes(end)} / ${formatBytes(file.size)}`);
    }
    setProgress(100, 'Scanning...');
    const scanRes = await fetch(`/api/upload/${upload_id}/scan`, { method: 'POST', signal });
    if (!scanRes.ok) { const msg = await scanRes.text(); throw new Error(msg); }
    return { html: await scanRes.text(), upload_id };
}

// ── Form submit: upload, then redirect to /scan with results ──
let scanInProgress = false;
document.getElementById('landing-scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (scanInProgress) return;
    const file = fileInput.files[0];
    if (!file) return;

    const fileErr = validateFile(file);
    if (fileErr) { errorEl.textContent = fileErr; return; }

    scanInProgress = true;
    activeAbort = new AbortController();
    submitBtn.disabled = true;
    loadingEl.classList.add('active');
    progressEl.classList.add('active');
    errorEl.textContent = '';
    setProgress(0, 'Starting upload...');
    startPhases();

    try {
        const { html } = await uploadChunked(file, activeAbort.signal);
        // Store result HTML in sessionStorage, then redirect to /scan
        try {
sessionStorage.setItem('pavise-landing-result', html);
sessionStorage.setItem('pavise-landing-file', file.name);
        } catch { /* storage full or unavailable — fall through to redirect */ }
        window.location.href = '/scan';
    } catch (err) {
        if (err.name === 'AbortError') return;
        errorEl.textContent = !navigator.onLine
? 'You appear to be offline. Check your connection and try again.'
: err.message;
    } finally {
        scanInProgress = false;
        activeAbort = null;
        submitBtn.disabled = false;
        loadingEl.classList.remove('active');
        progressEl.classList.remove('active');
        stopPhases();
    }
});

// ── Hamburger toggle ──
const hamburger = document.getElementById('nav-hamburger');
const navLinks = document.querySelector('.nav-links');
hamburger.addEventListener('click', () => navLinks.classList.toggle('open'));

// ── Theme toggle ──
const themeToggle = document.getElementById('theme-toggle');
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('pavise-theme', theme);
}
themeToggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    setTheme(current === 'dark' ? 'light' : 'dark');
});
(function() {
    const stored = localStorage.getItem('pavise-theme');
    if (stored) setTheme(stored);
    else if (window.matchMedia('(prefers-color-scheme: dark)').matches) setTheme('dark');
})();

// ── Smooth scroll for anchor links ──
document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', (e) => {
        const target = document.querySelector(a.getAttribute('href'));
        if (target) {
e.preventDefault();
target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});
