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
  const accent = "#6fe3a8";
  const color = "#1c1b2a";
  const cream = "#ece6d8";
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

// ── CTA decorative wave lines ──
(function renderCtaLines() {
  const svg = document.getElementById("cta-lines");
  if (!svg) return;
  const W = 1440;
  const H = 600;
  const paths: string[] = [];
  const N = 32;
  for (let i = 0; i < N; i++) {
    const offset = i * 7;
    const baseY = 200 + offset;
    const amp1 = 70 - (i % 5) * 8;
    const amp2 = 35 + (i % 4) * 6;
    const phase = (i * 0.7) % (Math.PI * 2);
    const segs = 8;
    const pts: string[] = [];
    for (let s = 0; s <= segs; s++) {
      const x = (W / segs) * s;
      const y =
        baseY +
        Math.sin((s / segs) * Math.PI * 2 + phase) * amp1 +
        Math.cos((s / segs) * Math.PI * 5 + phase * 1.3) * amp2;
      pts.push(`${s === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`);
    }
    const opacity = (0.08 + (i % 4) * 0.05).toFixed(3);
    const stroke =
      i % 6 === 0 ? "#6fe3a8" : i % 6 === 3 ? "#ece6d8" : "#6fe3a8";
    const width = i % 6 === 0 ? 1.4 : 0.8;
    paths.push(
      `<path d="${pts.join(" ")}" fill="none" stroke="${stroke}" stroke-width="${width}" opacity="${opacity}" stroke-linecap="round"/>`,
    );
  }
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.innerHTML = paths.join("");
})();

// ── Compliance marquee ──
(function renderComplianceStrip() {
  const el = document.getElementById("compliance-strip");
  if (!el) return;
  const items = [
    ["OWASP MASVS", "L1·L2"],
    ["CWE", "v4.13"],
    ["SOC 2", "TYPE II"],
    ["ISO 27001", "ANNEX A"],
    ["GDPR", "ART. 32"],
    ["NIST", "800-218"],
    ["PCI DSS", "v4.0"],
    ["HIPAA", "TECH SAFEGUARDS"],
  ];
  const seq = () => {
    let out = '<span class="tag">▸ EVIDENCE READY FOR</span>';
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
//         colorFront: '#6fe3a8',
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
