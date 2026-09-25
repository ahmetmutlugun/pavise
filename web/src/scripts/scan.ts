// Scan page: upload + scan flow, live status, result interactions, history.
//
// Status shown to the user is always derived from what is actually
// happening: upload progress comes from XHR byte counts, the analyse step is
// an honest indeterminate wait (with elapsed time) on the scan request, and
// busy/failed/cancelled states come from the server's status codes.

const $ = <T extends HTMLElement = HTMLElement>(id: string) =>
    document.getElementById(id) as T;

// ── Elements ──
const fileInput = $<HTMLInputElement>("file-input");
const fileName = $("file-name");
const dropZone = $("drop-zone");
const dropHint = $("drop-hint");
const page = $("page");
const shell = $("shell");
const overlay = $("sidebar-overlay");
const toggleBtn = $("toggle-sidebar");
const historyEl = $("history-list");
const emptyEl = $("history-empty");
const submitBtn = $<HTMLButtonElement>("submit-btn");
const cancelBtn = $<HTMLButtonElement>("cancel-btn");
const statusEl = $("scan-status");
const progressTrack = $("progress-track");
const progressFill = $("progress-fill");
const progressLabel = $("progress-label");
const progressDetail = $("progress-detail");
const alertEl = $("scan-alert");
const results = $("results");
const eyebrow = $("scan-eyebrow");
const eyebrowText = $("eyebrow-text");
const topbarStatus = $("topbar-status");
const topbarStatusText = $("topbar-status-text");
const crumb = $("crumb-current");

/** Server results live this long (`RESULT_TTL` in src/server/mod.rs). */
const RESULT_TTL_MS = 60 * 60 * 1000;
/** Fallback when the page is not served by pavise-server (e.g. `vite dev`). */
const DEFAULT_MAX_UPLOAD = 512 * 1024 * 1024;
const CHUNK_SIZE = 50 * 1024 * 1024;
const CHUNK_MAX_RETRIES = 3;
/** Busy (503) scan responses are retried for up to about a minute. */
const BUSY_MAX_RETRIES = 20;

const MAX_UPLOAD_BYTES = (() => {
    const v = document
        .querySelector('meta[name="pavise-max-upload-bytes"]')
        ?.getAttribute("content");
    const n = v ? Number(v) : NaN;
    return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_UPLOAD;
})();

// ── Storage (may throw in private modes) ──
function storageGet(key: string): string | null {
    try {
        return localStorage.getItem(key);
    } catch {
        return null;
    }
}
function storageSet(key: string, value: string) {
    try {
        localStorage.setItem(key, value);
    } catch {
        /* storage unavailable */
    }
}

// ── Sidebar ──
const isMobile = () => window.innerWidth <= 768;

document.querySelector(".sidebar-head")?.addEventListener("click", () => {
    window.location.href = "/";
});

toggleBtn.addEventListener("click", () => {
    if (isMobile()) {
        shell.classList.toggle("sidebar-open");
    } else {
        shell.classList.toggle("sidebar-collapsed");
        storageSet(
            "pavise-sidebar",
            shell.classList.contains("sidebar-collapsed") ? "collapsed" : "open",
        );
    }
});
overlay.addEventListener("click", () => shell.classList.remove("sidebar-open"));

if (!isMobile() && storageGet("pavise-sidebar") === "collapsed") {
    shell.classList.add("sidebar-collapsed");
}

// ── View switching ──
const views = document.querySelectorAll<HTMLElement>(".view");
const navItems = document.querySelectorAll<HTMLElement>(".nav-item[data-view]");

function switchView(viewId: string) {
    views.forEach((v) => v.classList.toggle("active", v.id === "view-" + viewId));
    navItems.forEach((n) => n.classList.toggle("active", n.dataset.view === viewId));
    if (isMobile()) shell.classList.remove("sidebar-open");
}
navItems.forEach((n) =>
    n.addEventListener("click", () => switchView(n.dataset.view ?? "scan")),
);

// ── Helpers ──
function formatBytes(bytes: number): string {
    // "512 MB", not "512.0 MB".
    const fmt = (n: number, digits: number) => String(Number(n.toFixed(digits)));
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return fmt(bytes / 1024, 1) + " KB";
    if (bytes < 1073741824) return fmt(bytes / 1048576, 1) + " MB";
    return fmt(bytes / 1073741824, 2) + " GB";
}

function formatSeconds(ms: number): string {
    return (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + " s";
}

function escapeHtml(s: string): string {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// Sanitize server-returned HTML before injection to prevent XSS from
// any attacker-controlled data embedded in scan results (app names, paths, etc.)
function sanitizeHtml(html: string): string {
    const doc = new DOMParser().parseFromString(html, "text/html");
    doc.querySelectorAll("script, object, embed, iframe, base, form, style, link, meta").forEach((el) =>
        el.remove(),
    );
    doc.querySelectorAll("*").forEach((el) => {
        for (const attr of Array.from(el.attributes)) {
            if (
                /^on/i.test(attr.name) ||
                ((attr.name === "href" || attr.name === "src") &&
                    /^\s*(javascript|data):/i.test(attr.value))
            ) {
                el.removeAttribute(attr.name);
            }
        }
    });
    return doc.body.innerHTML;
}

/** Error text from a server response: an error fragment or plain text. */
function responseMessage(body: string, status: number): string {
    const text = /<[a-z]/i.test(body)
        ? new DOMParser()
              .parseFromString(body, "text/html")
              .querySelector(".error-msg")?.textContent
        : body;
    const msg = (text ?? "").trim();
    if (msg) return msg;
    if (status === 429) return "Too many requests. Wait a minute and try again.";
    if (status >= 500) return "The server hit an error. Try again shortly.";
    return `Request failed (HTTP ${status}).`;
}

class HttpError extends Error {
    constructor(
        message: string,
        readonly status: number,
    ) {
        super(message);
    }
}

const isAbort = (err: unknown) =>
    err instanceof DOMException && err.name === "AbortError";

const sleep = (ms: number, signal: AbortSignal) =>
    new Promise<void>((resolve, reject) => {
        const t = setTimeout(resolve, ms);
        signal.addEventListener(
            "abort",
            () => {
                clearTimeout(t);
                reject(new DOMException("Aborted", "AbortError"));
            },
            { once: true },
        );
    });

// ── Page state (eyebrow, topbar, crumb) ──
type PageState = "idle" | "ready" | "uploading" | "analysing" | "done" | "error" | "cancelled";

function setPageState(state: PageState, text: string) {
    page.dataset.state = state;
    topbarStatusText.textContent = text;
    topbarStatus.dataset.state = state;
    eyebrow.dataset.state = state;
    eyebrowText.textContent = text;
}

function showAlert(msg: string | null) {
    alertEl.hidden = !msg;
    alertEl.textContent = msg ?? "";
}

// ── File selection ──
function validateFile(file: File | undefined): string | null {
    if (!file) return null;
    if (!file.name.toLowerCase().endsWith(".ipa")) return "Only .ipa files are supported.";
    if (file.size === 0) return "This file is empty.";
    if (file.size > MAX_UPLOAD_BYTES) {
        return `This file is ${formatBytes(file.size)}; the limit is ${formatBytes(MAX_UPLOAD_BYTES)}.`;
    }
    return null;
}

dropHint.textContent = `Up to ${formatBytes(MAX_UPLOAD_BYTES)} · ARM64 / ARM64e · deleted after the scan`;

function selectFile(file: File | undefined) {
    const err = validateFile(file);
    if (!file || err) {
        fileInput.value = "";
        fileName.textContent = "";
        dropZone.classList.remove("has-file");
        if (err) {
            showAlert(err);
            setPageState("error", "File rejected");
        }
        return;
    }
    showAlert(null);
    fileName.textContent = `${file.name} · ${formatBytes(file.size)}`;
    dropZone.classList.add("has-file");
    setPageState("ready", "File ready · press Scan");
}

fileInput.addEventListener("change", () => selectFile(fileInput.files?.[0]));

// dragenter/dragleave fire for every child; count them so the highlight
// doesn't flicker while the pointer moves across the zone.
let dragDepth = 0;
dropZone.addEventListener("dragenter", (e) => {
    e.preventDefault();
    dragDepth++;
    dropZone.classList.add("drag-over");
});
dropZone.addEventListener("dragover", (e) => e.preventDefault());
dropZone.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) dropZone.classList.remove("drag-over");
});
dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    dropZone.classList.remove("drag-over");
    const files = e.dataTransfer?.files;
    if (!files?.length || scanInProgress) return;
    const file = files[0];
    if (!validateFile(file)) {
        const dt = new DataTransfer();
        dt.items.add(file);
        fileInput.files = dt.files;
    }
    selectFile(file);
});

// ── Status panel ──
type Step = "upload" | "analyse" | "results";
type StepState = "pending" | "active" | "done" | "failed";
const steps = Array.from(statusEl.querySelectorAll<HTMLElement>(".step"));

function setStep(step: Step, state: StepState) {
    const el = steps.find((s) => s.dataset.step === step);
    if (el) el.dataset.state = state;
}

function resetSteps() {
    steps.forEach((s) => (s.dataset.state = "pending"));
}

/** `pct` = null shows an indeterminate bar. */
function setProgress(pct: number | null, label: string, detail = "") {
    statusEl.classList.toggle("indeterminate", pct === null);
    if (pct === null) {
        progressFill.style.width = "";
        progressTrack.removeAttribute("aria-valuenow");
    } else {
        progressFill.style.width = pct + "%";
        progressTrack.setAttribute("aria-valuenow", String(Math.round(pct)));
    }
    progressLabel.textContent = label;
    progressDetail.textContent = detail;
}

// ── Chunked upload ──
interface XhrResult {
    status: number;
    body: string;
}

/** PUT with upload progress (fetch can't report request-body progress). */
function putWithProgress(
    url: string,
    body: Blob,
    signal: AbortSignal,
    onProgress: (loaded: number) => void,
): Promise<XhrResult> {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("PUT", url);
        xhr.setRequestHeader("Content-Type", "application/octet-stream");
        xhr.upload.onprogress = (e) => onProgress(e.loaded);
        xhr.onload = () => resolve({ status: xhr.status, body: xhr.responseText });
        xhr.onerror = () => reject(new TypeError("Network error"));
        xhr.onabort = () => reject(new DOMException("Aborted", "AbortError"));
        const abort = () => xhr.abort();
        signal.addEventListener("abort", abort, { once: true });
        xhr.onloadend = () => signal.removeEventListener("abort", abort);
        xhr.send(body);
    });
}

async function putChunk(
    uploadId: string,
    index: number,
    chunk: Blob,
    signal: AbortSignal,
    onProgress: (loaded: number) => void,
) {
    for (let attempt = 0; ; attempt++) {
        let res: XhrResult | null = null;
        try {
            res = await putWithProgress(`/api/upload/${uploadId}/${index}`, chunk, signal, onProgress);
        } catch (err) {
            if (isAbort(err)) throw err;
            if (attempt >= CHUNK_MAX_RETRIES) {
                throw new Error("Upload interrupted. Check your connection and try again.");
            }
        }
        if (res) {
            if (res.status >= 200 && res.status < 300) return;
            // The server stored this chunk but the response was lost: a retry
            // is told it already has it.
            const expected = /Expected chunk index (\d+)/.exec(res.body);
            if (res.status === 400 && expected && Number(expected[1]) === index + 1) return;
            if (res.status < 500 || attempt >= CHUNK_MAX_RETRIES) {
                throw new HttpError(responseMessage(res.body, res.status), res.status);
            }
        }
        onProgress(0);
        await sleep(250 * 2 ** attempt, signal);
    }
}

async function upload(file: File, signal: AbortSignal): Promise<string> {
    const initRes = await fetch("/api/upload", { method: "POST", signal });
    if (!initRes.ok) {
        throw new HttpError(responseMessage(await initRes.text(), initRes.status), initRes.status);
    }
    const init = (await initRes.json()) as { upload_id: string; chunk_size?: number };
    const chunkSize = init.chunk_size && init.chunk_size > 0 ? init.chunk_size : CHUNK_SIZE;

    const started = performance.now();
    const report = (sent: number) => {
        const pct = (sent / file.size) * 100;
        const secs = (performance.now() - started) / 1000;
        const rate = secs > 0.5 ? ` · ${formatBytes(sent / secs)}/s` : "";
        setProgress(
            pct,
            `Uploading ${formatBytes(sent)} of ${formatBytes(file.size)}`,
            `${Math.floor(pct)}%${rate}`,
        );
        setPageState("uploading", `Uploading · ${Math.floor(pct)}%`);
    };
    report(0);

    const total = Math.max(1, Math.ceil(file.size / chunkSize));
    for (let i = 0; i < total; i++) {
        const start = i * chunkSize;
        const chunk = file.slice(start, Math.min(start + chunkSize, file.size));
        await putChunk(init.upload_id, i, chunk, signal, (loaded) =>
            report(start + Math.min(loaded, chunk.size)),
        );
    }
    report(file.size);
    return init.upload_id;
}

/** Ask the server to scan an uploaded file; retries while it is busy. */
async function runScan(uploadId: string, signal: AbortSignal): Promise<string> {
    const started = performance.now();
    let waitNote = "";
    const tick = () =>
        setProgress(
            null,
            waitNote || "Analysing binary, manifests and resources",
            formatSeconds(performance.now() - started),
        );
    tick();
    const timer = setInterval(tick, 100);
    try {
        for (let attempt = 1; ; attempt++) {
            const res = await fetch(`/api/upload/${uploadId}/scan`, { method: "POST", signal });
            const body = await res.text();
            if (res.ok) return body;
            if (res.status !== 503 || attempt > BUSY_MAX_RETRIES) {
                throw new HttpError(responseMessage(body, res.status), res.status);
            }
            // All scan slots are taken; the upload is kept server-side.
            const wait = Math.min(10, Math.max(1, Number(res.headers.get("Retry-After")) || 3));
            for (let s = wait; s > 0; s--) {
                waitNote = `Server busy · retrying in ${s} s (attempt ${attempt} of ${BUSY_MAX_RETRIES})`;
                tick();
                await sleep(1000, signal);
            }
            waitNote = "";
        }
    } finally {
        clearInterval(timer);
    }
}

// ── Form submission ──
let scanInProgress = false;
let activeAbort: AbortController | null = null;

cancelBtn.addEventListener("click", () => activeAbort?.abort());

function setBusy(busy: boolean) {
    scanInProgress = busy;
    submitBtn.disabled = busy;
    fileInput.disabled = busy;
    dropZone.classList.toggle("busy", busy);
    cancelBtn.hidden = !busy;
    results.classList.toggle("is-stale", busy);
    results.setAttribute("aria-busy", String(busy));
}

$("scan-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (scanInProgress) return;
    const file = fileInput.files?.[0];
    if (!file) {
        showAlert("Choose an .ipa file first.");
        return;
    }
    const fileErr = validateFile(file);
    if (fileErr) {
        showAlert(fileErr);
        return;
    }

    const ctrl = new AbortController();
    activeAbort = ctrl;
    let step: Step = "upload";
    setBusy(true);
    showAlert(null);
    resetSteps();
    statusEl.hidden = false;
    statusEl.dataset.state = "running";
    setStep("upload", "active");

    try {
        const uploadId = await upload(file, ctrl.signal);
        setStep("upload", "done");
        step = "analyse";
        setStep("analyse", "active");
        setPageState("analysing", "Analysing");
        const html = await runScan(uploadId, ctrl.signal);
        setStep("analyse", "done");
        step = "results";
        showResult(html, true);
        setStep("results", "done");
        const rs = results.querySelector<HTMLElement>(".rs");
        const cached = !!rs?.querySelector(".rs-cached");
        setProgress(100, cached ? "Done · identical file scanned earlier, cached result shown" : "Scan complete", "");
        statusEl.dataset.state = "done";
        // Nothing left to act on; the result speaks for itself.
        setTimeout(() => {
            if (!scanInProgress && statusEl.dataset.state === "done") statusEl.hidden = true;
        }, 2500);
    } catch (err) {
        setStep(step, "failed");
        statusEl.dataset.state = "failed";
        if (isAbort(err)) {
            setProgress(0, "Scan cancelled", "");
            setPageState("cancelled", "Cancelled");
        } else {
            const msg = !navigator.onLine
                ? "You appear to be offline. Check your connection and try again."
                : err instanceof Error
                  ? err.message
                  : String(err);
            // Keep the bar where it stopped; the failed step is marked.
            statusEl.classList.remove("indeterminate");
            if (step !== "upload") progressFill.style.width = "100%";
            progressLabel.textContent = step === "upload" ? "Upload failed" : "Scan failed";
            progressDetail.textContent = "";
            showAlert(msg);
            setPageState("error", step === "upload" ? "Upload failed" : "Scan failed");
        }
    } finally {
        activeAbort = null;
        setBusy(false);
    }
});

// ── Results ──
function showResult(html: string, fresh: boolean) {
    results.innerHTML = sanitizeHtml(html);
    const rs = results.querySelector<HTMLElement>(".rs");
    if (!rs) {
        // An error fragment (e.g. an expired scan).
        page.classList.toggle("has-results", !!results.firstElementChild);
        return;
    }
    page.classList.add("has-results");
    const entry: HistoryEntry = {
        id: rs.dataset.scanId ?? "",
        name: rs.dataset.name || "Unknown",
        grade: rs.dataset.grade || "?",
        score: rs.dataset.score || "0",
        ts: Date.now(),
    };
    crumb.textContent = entry.name;
    document.title = `${entry.name} · Grade ${entry.grade} — Pavise`;
    setPageState("done", `Scan complete · Grade ${entry.grade}`);
    if (fresh && entry.id) addToHistory(entry);
    markActiveHistory(entry.id);
    rs.scrollIntoView({ behavior: "smooth", block: "start" });
}

// Filters, expand-all and downloads (event delegation: the fragment is
// replaced wholesale on every scan).
results.addEventListener("click", (e) => {
    const target = e.target as HTMLElement;

    const filter = target.closest<HTMLButtonElement>(".rs-filter");
    if (filter && !filter.disabled) {
        const list = results.querySelector<HTMLElement>(".rs-list");
        if (list) list.dataset.filter = filter.dataset.filter ?? "all";
        results
            .querySelectorAll(".rs-filter")
            .forEach((b) => b.setAttribute("aria-pressed", String(b === filter)));
        return;
    }

    const expand = target.closest<HTMLButtonElement>("[data-expand]");
    if (expand) {
        const open = expand.getAttribute("aria-pressed") !== "true";
        results.querySelectorAll<HTMLDetailsElement>(".rs-card").forEach((d) => (d.open = open));
        expand.setAttribute("aria-pressed", String(open));
        expand.textContent = open ? "Collapse all" : "Expand all";
        return;
    }

    const dl = target.closest<HTMLAnchorElement>("a[data-download]");
    if (dl) {
        e.preventDefault();
        download(dl);
    }
});

/** Fetch a report so errors and PDF render time are visible, not a broken file. */
async function download(link: HTMLAnchorElement) {
    if (link.getAttribute("aria-busy") === "true") return;
    const kind = link.dataset.download === "pdf" ? "PDF" : "JSON";
    const label = link.querySelector(".rs-btn-label");
    const original = label?.textContent ?? "";
    const status = results.querySelector<HTMLElement>(".rs-dl-status");
    const setStatus = (msg: string | null, isError = false) => {
        if (!status) return;
        status.hidden = !msg;
        status.textContent = msg ?? "";
        status.classList.toggle("error", isError);
    };

    link.setAttribute("aria-busy", "true");
    if (label) label.textContent = kind === "PDF" ? "Rendering PDF…" : "Preparing…";
    setStatus(kind === "PDF" ? "Rendering the PDF report — this takes a few seconds." : null);
    try {
        const res = await fetch(link.href);
        if (!res.ok) {
            const msg = responseMessage(await res.text(), res.status);
            throw new Error(res.status === 404 ? "This scan has expired. Upload the file again to rescan." : msg);
        }
        const blob = await res.blob();
        const name =
            /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") ?? "")?.[1] ??
            `pavise-report.${kind.toLowerCase()}`;
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10_000);
        setStatus(null);
    } catch (err) {
        setStatus(
            `${kind} download failed: ${err instanceof Error ? err.message : String(err)}`,
            true,
        );
    } finally {
        link.removeAttribute("aria-busy");
        if (label) label.textContent = original;
    }
}

// ── Scan history (localStorage) ──
interface HistoryEntry {
    id: string;
    name: string;
    grade: string;
    score: string;
    ts: number;
    /** Set once the server reported the result gone. */
    expired?: boolean;
}

const HISTORY_KEY = "pavise-history";
const MAX_HISTORY = 50;

function getHistory(): HistoryEntry[] {
    try {
        const items = JSON.parse(storageGet(HISTORY_KEY) ?? "[]");
        return Array.isArray(items) ? items : [];
    } catch {
        return [];
    }
}

function saveHistory(items: HistoryEntry[]) {
    storageSet(HISTORY_KEY, JSON.stringify(items.slice(0, MAX_HISTORY)));
}

function addToHistory(entry: HistoryEntry) {
    // Rescanning the same build (e.g. a cached hit) replaces its old entry.
    const same = (h: HistoryEntry) =>
        h.id === entry.id ||
        (h.name === entry.name && h.grade === entry.grade && h.score === entry.score);
    const items = getHistory().filter((h) => !same(h));
    items.unshift(entry);
    saveHistory(items);
    renderHistory();
}

function markExpired(id: string) {
    saveHistory(getHistory().map((h) => (h.id === id ? { ...h, expired: true } : h)));
    renderHistory();
}

const isExpired = (h: HistoryEntry) => h.expired || Date.now() - h.ts > RESULT_TTL_MS;

function formatTimeAgo(ts: number): string {
    const mins = Math.floor((Date.now() - ts) / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return mins + "m ago";
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + "h ago";
    const days = Math.floor(hrs / 24);
    if (days < 30) return days + "d ago";
    return new Date(ts).toLocaleDateString();
}

function gradeClass(g: string): string {
    const l = g.charAt(0).toLowerCase();
    return ["a", "b", "c", "d"].includes(l) ? "hg-" + l : "hg-f";
}

let activeHistoryId: string | null = null;

function markActiveHistory(id: string | null) {
    activeHistoryId = id;
    historyEl
        .querySelectorAll<HTMLElement>(".history-item")
        .forEach((b) => b.classList.toggle("active", b.dataset.id === id));
}

function renderHistory() {
    const items = getHistory();
    emptyEl.style.display = items.length ? "none" : "";

    const frag = document.createDocumentFragment();
    items.forEach((item) => {
        const expired = isExpired(item);
        const when = formatTimeAgo(item.ts);
        const btn = document.createElement("button");
        btn.className = "history-item" + (expired ? " expired" : "");
        btn.dataset.id = item.id;
        btn.title = expired ? "Result expired on the server (kept for 1 hour)" : "Open this result";
        btn.setAttribute(
            "aria-label",
            `Grade ${item.grade}, ${item.name}, scanned ${when}${expired ? ", expired" : ""}`,
        );
        btn.innerHTML = `
          <span class="history-grade ${gradeClass(item.grade)}" aria-hidden="true">${escapeHtml(item.grade)}</span>
          <div class="history-meta">
            <div class="history-name">${escapeHtml(item.name)}</div>
            <div class="history-time">${escapeHtml(when)}${expired ? ' · <span class="history-expired">expired</span>' : ""}</div>
          </div>
        `;
        btn.addEventListener("click", () => loadHistoryScan(item));
        frag.appendChild(btn);
    });
    historyEl.replaceChildren(emptyEl, frag);
    markActiveHistory(activeHistoryId);
}

function loadHistoryScan(item: HistoryEntry) {
    if (scanInProgress) return;
    switchView("scan");
    showAlert(null);
    statusEl.hidden = true;
    markActiveHistory(item.id);
    results.innerHTML =
        '<div class="rs-loading"><div class="spinner"></div>Loading scan…</div>';
    page.classList.add("has-results");

    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 15000);

    fetch("/api/scan/" + encodeURIComponent(item.id), { signal: ctrl.signal })
        .then(async (r) => {
            const body = await r.text();
            if (r.status === 404) markExpired(item.id);
            if (!r.ok) throw new HttpError(responseMessage(body, r.status), r.status);
            showResult(body, false);
        })
        .catch((err) => {
            const msg = isAbort(err)
                ? "Request timed out. Please try again."
                : !navigator.onLine
                  ? "You appear to be offline. Check your connection and try again."
                  : err instanceof Error
                    ? err.message
                    : String(err);
            results.innerHTML = `<div class="error-card" role="alert"><span class="error-icon" aria-hidden="true">✗</span><span class="error-msg">${escapeHtml(msg)}</span></div>`;
            crumb.textContent = item.name;
            setPageState("error", "Result unavailable");
        })
        .finally(() => clearTimeout(timeout));
}

renderHistory();
// Expiry is time-based; keep the labels honest while the page stays open.
setInterval(renderHistory, 60_000);
setPageState("idle", "Ready");

// ── Keyboard shortcut: U to open file picker ──
document.addEventListener("keydown", (e) => {
    if (e.key !== "u" && e.key !== "U") return;
    if (e.metaKey || e.ctrlKey || e.altKey || scanInProgress) return;
    const active = document.activeElement as HTMLElement | null;
    if (
        active &&
        (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.isContentEditable)
    )
        return;
    if ($("view-scan").classList.contains("active")) {
        e.preventDefault();
        fileInput.click();
    }
});

// ── Console easter egg ──
console.log(
    "%c⬡ Pavise%c  iOS Security Analyzer\n%cParsing Mach-O since 2024. Built with Rust.\ngithub.com/ahmetmutlugun",
    "color:#4ec98a;font-size:15px;font-weight:900;letter-spacing:-0.02em;",
    "color:#8b949e;font-size:12px;font-weight:600;",
    "color:#4a5568;font-size:11px;line-height:1.6;",
);

export {};
