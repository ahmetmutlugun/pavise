// @ts-nocheck
import { initDitheringShader } from "./dithering-shader";

// ── Nav scroll effect ──
const nav = document.getElementById("nav");
const onScroll = () => nav?.classList.toggle("scrolled", window.scrollY > 10);
window.addEventListener("scroll", onScroll, { passive: true });
onScroll();

// ── Halftone shield ──
// The hero mark: a pavise (tall ridged shield) rendered as a halftone. The
// central ridge splits it into a lit left facet and a shaded right facet, and
// a scan band sweeps down, turning the dots it passes mint.
(function renderHalftoneShield() {
  const svg = document.getElementById("halftone-shield");
  if (!svg) return;
  const accent = "#28e99f";
  const color = "#1c1b2a";
  const cream = "#ebebeb";
  // Same silhouette as the logo (viewBox 0 0 100 128), scaled 3.4× about x=50.
  const shieldPath =
    "M 180 29.6 L 309.2 63.6 L 292.2 356 Q 288.8 383.2 265 396.8 L 180 437.6 L 95 396.8 Q 71.2 383.2 67.8 356 L 50.8 63.6 Z";
  const ridgeX = 180;
  const top = 29.6,
    bottom = 437.6;
  const step = 9;
  const lightX = 110,
    lightY = 90;
  const dots = [];
  for (let y = top; y < bottom; y += step) {
    const row = Math.round((y - top) / step);
    const ox = row % 2 === 0 ? 0 : step / 2;
    for (let x = 50; x < 312; x += step) {
      const px = x + ox;
      const t = Math.min(1, Math.hypot(px - lightX, y - lightY) / 330);
      let r =
        px < ridgeX
          ? 0.35 + Math.pow(t, 1.1) * 3.2 // lit facet
          : 1.2 + Math.pow(t, 0.9) * 2.9; // shaded facet
      // Specular strip along the lit side of the ridge.
      if (px > ridgeX - 16 && px < ridgeX) r *= 0.45;
      r = Math.min(r, step / 2 - 0.4);
      dots.push(`<circle cx="${px}" cy="${y.toFixed(1)}" r="${r.toFixed(2)}"/>`);
    }
  }

  const reduceMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)",
  ).matches;
  const band = 70;
  const sweep = `values="${top - band};${bottom};${bottom}" keyTimes="0;0.8;1" dur="5s" repeatCount="indefinite"`;
  const bandAnim = reduceMotion
    ? ""
    : `<animate attributeName="y" ${sweep}/>`;
  const lineAnim = reduceMotion
    ? ""
    : `<animateTransform attributeName="transform" type="translate" values="0 ${top - band / 2};0 ${bottom + band / 2};0 ${bottom + band / 2}" keyTimes="0;0.8;1" dur="5s" repeatCount="indefinite"/>`;
  const restY = 250; // band position when motion is reduced

  svg.innerHTML = `
        <defs>
            <clipPath id="ps-shield"><path d="${shieldPath}"/></clipPath>
            <linearGradient id="ps-band-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stop-color="#fff" stop-opacity="0"/>
                <stop offset="0.5" stop-color="#fff" stop-opacity="1"/>
                <stop offset="1" stop-color="#fff" stop-opacity="0"/>
            </linearGradient>
            <mask id="ps-scan" maskUnits="userSpaceOnUse" x="0" y="0" width="360" height="460">
                <rect x="0" y="${restY - band / 2}" width="360" height="${band}" fill="url(#ps-band-grad)">${bandAnim}</rect>
            </mask>
        </defs>
        <path d="${shieldPath}" fill="none" stroke="${accent}" stroke-width="2" transform="translate(8,8)" opacity="0.85"/>
        <path d="${shieldPath}" fill="${cream}"/>
        <g clip-path="url(#ps-shield)">
            <rect x="0" y="0" width="360" height="460" fill="${accent}" opacity="0.22" mask="url(#ps-scan)"/>
            <rect x="${ridgeX}" y="0" width="180" height="460" fill="${color}" opacity="0.05"/>
            <g id="ps-dots" fill="${color}">${dots.join("")}</g>
            <use href="#ps-dots" fill="${accent}" mask="url(#ps-scan)"/>
        </g>
        <path d="${shieldPath}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/>
        <line x1="${ridgeX}" y1="${top}" x2="${ridgeX}" y2="${bottom}" stroke="${accent}" stroke-width="3"/>
        <g transform="translate(0,${reduceMotion ? restY : top - band / 2})">
            ${lineAnim}
            <line x1="34" y1="0" x2="326" y2="0" stroke="${accent}" stroke-width="1.25" opacity="0.9"/>
            <line x1="34" y1="-5" x2="34" y2="5" stroke="${color}" stroke-width="1" opacity="0.5"/>
            <line x1="326" y1="-5" x2="326" y2="5" stroke="${color}" stroke-width="1" opacity="0.5"/>
        </g>
        <path d="M ${ridgeX} 148 L ${ridgeX + 16} 166 L ${ridgeX} 184 L ${ridgeX - 16} 166 Z" fill="${accent}" stroke="${cream}" stroke-width="5" paint-order="stroke" stroke-linejoin="round"/>
    `;
})();

// ── CTA binary scan ──
// A dim hexdump of a Mach-O fills the band. A mint beam sweeps left→right,
// lighting the bytes it passes; some bytes are "caught" — boxed in a severity
// colour with the finding that tripped them — then fade. The centre is masked
// so the headline stays readable. Static frame under reduced motion; paused
// while offscreen.
(function renderCtaScan() {
  const canvas = document.getElementById("cta-scan") as HTMLCanvasElement | null;
  const ctx = canvas?.getContext("2d");
  if (!canvas || !ctx) return;

  const MINT = "40,233,159";
  const FINDINGS: [string, string][] = [
    ["SECRET · AKIA…", "255,93,79"],
    ["ATS · ARBITRARY LOADS", "255,178,63"],
    ["WEAK HASH · MD5", "255,178,63"],
    ["TRACKER · SDK", "255,138,253"],
    ["CERT · DISTRUSTED CA", "255,93,79"],
    ["FIREBASE · OPEN DB", "255,93,79"],
    ["DEBUG LOG · NSLog", "113,173,255"],
    ["PIE ✓", MINT],
    ["STACK CANARY ✓", MINT],
  ];
  const CW = 30, CH = 26, PERIOD = 7000, FADE = 2600;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const mono = getComputedStyle(document.documentElement).getPropertyValue("--font-mono") || "monospace";
  const hex = () => ((Math.random() * 256) | 0).toString(16).padStart(2, "0").toUpperCase();

  let W = 0, H = 0, cols = 0, rows = 0;
  let bytes: string[] = [];
  let hits: { c: number; r: number; label: string; rgb: string; at: number }[] = [];
  let mask: number[] = [];
  let lastCol = -1;

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    // Mobile URL-bar show/hide fires resize without changing the band; keep state.
    if (canvas!.clientWidth === W && canvas!.clientHeight === H && canvas!.width === W * dpr) return false;
    W = canvas!.clientWidth; H = canvas!.clientHeight;
    canvas!.width = W * dpr; canvas!.height = H * dpr;
    ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    cols = Math.ceil(W / CW) + 1; rows = Math.ceil(H / CH) + 1;
    bytes = Array.from({ length: cols * rows }, hex);
    // Elliptical mask: ~0.15 behind the headline, 1 at the edges.
    mask = [];
    for (let r = 0; r < rows; r++)
      for (let c = 0; c < cols; c++) {
        const dx = (c * CW - W / 2) / (Math.min(W, 1100) / 2);
        const dy = (r * CH - H / 2) / (H / 2.1);
        const d = Math.hypot(dx, dy);
        mask.push(Math.min(1, Math.max(0.15, (d - 0.55) * 1.6)));
      }
    hits = [];
    return true;
  }

  function spawnHits(col: number, now: number) {
    for (let r = 0; r < rows; r++) {
      const i = r * cols + col;
      if (hits.length >= 6 || mask[i] < 0.6 || Math.random() > 0.06) continue;
      if (col + 9 > cols) continue; // leave room for the label
      if (hits.some((h) => Math.abs(h.r - r) < 3 && Math.abs(h.c - col) < 9)) continue;
      const [label, rgb] = FINDINGS[(Math.random() * FINDINGS.length) | 0];
      hits.push({ c: col, r, label, rgb, at: now });
    }
  }

  function draw(now: number) {
    const t = reduceMotion ? 0.62 : (now % PERIOD) / PERIOD;
    const beamX = t * (W + 240) - 120;
    const col = Math.floor(beamX / CW);
    if (!reduceMotion && col !== lastCol && col >= 0 && col < cols) {
      spawnHits(col, now);
      lastCol = col;
      // Bytes behind the beam re-randomise slowly, so the dump feels live.
      for (let k = 0; k < 6; k++) {
        const i = (Math.random() * bytes.length) | 0;
        const r = (i / cols) | 0, c = i % cols;
        if (!hits.some((h) => h.r === r && (h.c === c || h.c + 1 === c))) bytes[i] = hex();
      }
    }
    hits = hits.filter((h) => reduceMotion || now - h.at < FADE);

    ctx!.clearRect(0, 0, W, H);
    ctx!.font = `500 11px ${mono}`;
    ctx!.textBaseline = "middle";
    for (let r = 0; r < rows; r++) {
      const y = r * CH + CH / 2;
      for (let c = 0; c < cols; c++) {
        const i = r * cols + c;
        const x = c * CW + 4;
        const behind = beamX - x; // >0 once the beam has passed
        const glow = behind > 0 && behind < 260 ? 1 - behind / 260 : 0;
        const a = (0.07 + glow * 0.5) * mask[i];
        ctx!.fillStyle = glow > 0.02 ? `rgba(${MINT},${a})` : `rgba(244,244,246,${a})`;
        ctx!.fillText(bytes[i], x, y);
      }
    }

    // Beam: soft trailing gradient + crisp leading line.
    const g = ctx!.createLinearGradient(beamX - 220, 0, beamX, 0);
    g.addColorStop(0, `rgba(${MINT},0)`);
    g.addColorStop(1, `rgba(${MINT},0.07)`);
    ctx!.fillStyle = g;
    ctx!.fillRect(beamX - 220, 0, 220, H);
    ctx!.fillStyle = `rgba(${MINT},0.55)`;
    ctx!.fillRect(beamX, 0, 1.5, H);

    // Caught bytes: box + label, fading out.
    ctx!.font = `600 10px ${mono}`;
    for (const h of hits) {
      const life = reduceMotion ? 0.2 : (now - h.at) / FADE;
      const a = life < 0.08 ? life / 0.08 : 1 - Math.max(0, life - 0.55) / 0.45;
      const x = h.c * CW, y = h.r * CH;
      ctx!.strokeStyle = `rgba(${h.rgb},${a})`;
      ctx!.lineWidth = 1.2;
      ctx!.strokeRect(x + 0.5, y + 3.5, CW * 2 - 2, CH - 7);
      ctx!.fillStyle = `rgba(${h.rgb},${a})`;
      ctx!.font = `600 11px ${mono}`;
      ctx!.fillText(bytes[h.r * cols + h.c], x + 4, y + CH / 2);
      ctx!.fillText(bytes[h.r * cols + h.c + 1] ?? "", x + CW + 4, y + CH / 2);
      ctx!.font = `600 10px ${mono}`;
      const tw = ctx!.measureText(h.label).width;
      ctx!.fillStyle = `rgba(28,27,42,${a * 0.9})`;
      ctx!.fillRect(x + CW * 2 + 4, y + 5, tw + 12, CH - 10);
      ctx!.fillStyle = `rgba(${h.rgb},${a})`;
      ctx!.fillText(h.label, x + CW * 2 + 10, y + CH / 2);
    }
  }

  resize();
  if (reduceMotion) {
    // A few representative catches on the static frame.
    for (let k = 0; k < 40 && hits.length < 6; k++) spawnHits((Math.random() * cols) | 0, 0);
    draw(0);
    window.addEventListener("resize", () => {
      if (!resize()) return;
      for (let k = 0; k < 40 && hits.length < 6; k++) spawnHits((Math.random() * cols) | 0, 0);
      draw(0);
    });
    return;
  }

  let raf = 0, visible = false;
  const loop = (now: number) => { draw(now); raf = requestAnimationFrame(loop); };
  new IntersectionObserver(([e]) => {
    visible = e.isIntersecting;
    cancelAnimationFrame(raf);
    if (visible) raf = requestAnimationFrame(loop);
  }).observe(canvas);
  window.addEventListener("resize", () => {
    if (resize() && !visible) draw(performance.now());
  });
})();

// ── Compliance marquee ──
(function renderComplianceStrip() {
  const el = document.getElementById("compliance-strip");
  if (!el) return;
  const items = [
    ["OWASP MOBILE TOP 10", "2024"],
    ["OWASP MASVS", "v2"],
    ["CWE", "IDS"],
    ["SARIF", "2.1.0"],
    ["GITHUB", "CODE SCANNING"],
    ["PDF · HTML · JSON", "REPORTS"],
  ];
  const seq = () => {
    let out = '<span class="tag">▸ FINDINGS MAP TO</span>';
    for (const [t, v] of items) {
      out += `<span><b>${t}</b>&nbsp;&nbsp;<i>${v}</i></span><span class="sep">/</span>`;
    }
    return out;
  };
  el.innerHTML = seq() + seq();
})();

// ── Dithering wave band — DISABLED (commented out)
// (function initWaveBand() {
//     const canvas = document.getElementById('wave-shader') as HTMLCanvasElement | null;
//     if (!canvas) return;
//     const handle = initDitheringShader({
//         canvas,
//         colorBack: '#1c1b2a',
//         colorFront: '#28e99f',
//         shape: 'wave',
//         type: '8x8',
//         params: { speed: 0.55, pxSize: 3, waveAmp: 1.0, bandWidth: 1.4 },
//     });
//
//     const panel = document.getElementById('wave-panel');
//     if (!panel) return;
//
//     const format = (key: string, v: number) => key === 'pxSize' ? String(Math.round(v)) : v.toFixed(2);
//
//     panel.querySelectorAll<HTMLInputElement>('input[type="range"][data-param]').forEach((input) => {
//         const key = input.dataset.param as keyof typeof handle.params;
//         const valEl = panel.querySelector<HTMLElement>(`[data-val="${key}"]`);
//         const sync = () => {
//             const v = parseFloat(input.value);
//             handle.params[key] = v;
//             if (valEl) valEl.textContent = format(key, v);
//         };
//         input.addEventListener('input', sync);
//         sync();
//     });
//
//     const toggle = document.getElementById('wave-panel-toggle');
//     const body = document.getElementById('wave-panel-body');
//     toggle?.addEventListener('click', () => {
//         const collapsed = panel.classList.toggle('collapsed');
//         toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
//         if (body) body.style.display = collapsed ? 'none' : '';
//     });
// })();
// END Dithering wave band — DISABLED

// ── Hamburger toggle ──
const hamburger = document.getElementById("nav-hamburger");
const navLinks = document.querySelector(".nav-links");
if (hamburger && navLinks) {
  hamburger.addEventListener("click", () => navLinks.classList.toggle("open"));
}

// ── Smooth scroll for anchor links ──
document.querySelectorAll('a[href^="#"]').forEach((a) => {
  a.addEventListener("click", (e) => {
    const href = a.getAttribute("href");
    if (!href || href === "#") return;
    const target = document.querySelector(href);
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });
});
