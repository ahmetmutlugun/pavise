// @ts-nocheck
import { initDitheringShader } from "./dithering-shader";

// ── Nav scroll effect ──
const nav = document.getElementById("nav");
const onScroll = () => nav?.classList.toggle("scrolled", window.scrollY > 10);
window.addEventListener("scroll", onScroll, { passive: true });
onScroll();

// ── Halftone shield ──
(function renderHalftoneShield() {
  const svg = document.getElementById("halftone-shield");
  if (!svg) return;
  const accent = "#6fe3a8";
  const color = "#1c1b2a";
  const shieldPath =
    "M 70 30 Q 70 22 78 22 L 282 22 Q 290 22 290 30 L 290 260 Q 290 360 180 446 Q 70 360 70 260 Z";
  const step = 9;
  const lightX = 130,
    lightY = 100;
  const dots = [];
  for (let y = 24; y < 444; y += step) {
    for (let x = 70; x < 292; x += step) {
      const ox = Math.floor((y - 24) / step) % 2 === 0 ? 0 : step / 2;
      const px = x + ox;
      const dx = px - lightX,
        dy = y - lightY;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const t = Math.min(1, dist / 280);
      const r = 0.3 + Math.pow(t, 1.05) * 3.6;
      dots.push(
        `<circle cx="${px}" cy="${y}" r="${r.toFixed(2)}" fill="${color}"/>`,
      );
    }
  }
  svg.innerHTML = `
        <defs><clipPath id="ps-shield"><path d="${shieldPath}"/></clipPath></defs>
        <path d="${shieldPath}" fill="none" stroke="${accent}" stroke-width="2" transform="translate(8,8)" opacity="0.85"/>
        <g clip-path="url(#ps-shield)">
            <rect x="70" y="22" width="220" height="424" fill="${accent}" opacity="0.04"/>
            ${dots.join("")}
        </g>
        <path d="${shieldPath}" fill="none" stroke="${color}" stroke-width="1.5" opacity="0.95"/>
        <line x1="180" y1="38" x2="180" y2="440" stroke="${color}" stroke-width="1" opacity="0.15" stroke-dasharray="2 3"/>
        <g transform="translate(180,200)">
            <line x1="0" y1="-30" x2="0" y2="30" stroke="${accent}" stroke-width="3"/>
            <circle cx="0" cy="0" r="5" fill="${accent}"/>
        </g>
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
