# SEO Audit Report — Pavise

**Project Location:** `/Users/etka/Documents/Projects/pavise/`
**Frontend Stack:** Vite.js (Static SPA, 2 HTML entry points: `index.html`, `scan.html`)
**Audit Date:** 2026-03-29

---

## Critical Issues (Fix Immediately)

### 1. Wrong Canonical Tag on Scanner Page

**File:** `web/scan.html`, Line 8
**Current:**
```html
<link rel="canonical" href="https://pavise.app/" />
```
**Fix:**
```html
<link rel="canonical" href="https://pavise.app/scan" />
```
**Impact:** As-is, this tells search engines the scanner page is a duplicate of the homepage, causing it to be deindexed and lose its own ranking potential.

---

## High Priority

### 2. Duplicate Meta Tags on Scanner Page

`scan.html` has identical `<title>`, `<meta name="description">`, `og:title`, `og:description`, and `og:url` as `index.html`. Every tag needs a page-specific value.

**Suggested replacements for `scan.html`:**

```html
<title>Pavise IPA Scanner — Analyze iOS Apps for Security Issues</title>
<meta name="description" content="Upload your iOS IPA file for instant security analysis. Detect hardcoded secrets, binary weaknesses, tracker SDKs, and OWASP Mobile Top 10 vulnerabilities." />

<meta property="og:url" content="https://pavise.app/scan" />
<meta property="og:title" content="Pavise IPA Scanner — iOS Security Analysis" />
<meta property="og:description" content="Upload your IPA for instant static analysis. Detect secrets, binary issues, and OWASP vulnerabilities in seconds." />

<meta name="twitter:title" content="Pavise IPA Scanner — iOS Security Analysis" />
<meta name="twitter:description" content="Upload your iOS IPA for instant security analysis. Free and open source." />
```

### 3. Missing `og:image` and `twitter:image`

Neither page has a social preview image. Without it, shares on Twitter/X, LinkedIn, Slack, iMessage etc. show no visual.

Add to both pages (create the images first):
```html
<meta property="og:image" content="https://pavise.app/og-image.png" />
<meta property="og:image:width" content="1200" />
<meta property="og:image:height" content="630" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:image" content="https://pavise.app/og-image.png" />
```

Also change the Twitter card type from `summary` to `summary_large_image` for better engagement.

Required image assets:
- `public/og-image.png` — 1200×630px (shared by OG + Twitter)

### 4. Missing `robots.txt`

No `robots.txt` file exists. Search engines will crawl without guidance.

**Create `web/public/robots.txt`:**
```
User-agent: *
Allow: /
Disallow: /api/

Sitemap: https://pavise.app/sitemap.xml
```

### 5. Missing `sitemap.xml`

No sitemap exists. Helps search engines discover and prioritize both pages.

**Create `web/public/sitemap.xml`:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://pavise.app/</loc>
    <lastmod>2026-03-29</lastmod>
    <changefreq>monthly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://pavise.app/scan</loc>
    <lastmod>2026-03-29</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>
```

Also add a sitemap reference in both `<head>` sections:
```html
<link rel="sitemap" type="application/xml" href="/sitemap.xml" />
```

---

## Medium Priority

### 6. Semantic HTML — Missing `<main>` and `<header>` on Homepage

`index.html` wraps content in `<section>` elements but has no `<main>` or `<header>`. `scan.html` has `<main id="main-content">` (good). Apply the same pattern to `index.html`.

```html
<!-- index.html: wrap the nav -->
<header>
  <nav>...</nav>
</header>

<!-- index.html: wrap the page body -->
<main>
  <section id="hero">...</section>
  <section id="features">...</section>
  ...
</main>
```

### 7. Heading Hierarchy on Scanner Page

`scan.html`'s only `<h1>` is inside the "About" tab, which is hidden on page load. The primary Scan tab view has no `<h1>`.

Add a visually hidden `<h1>` to the scan view so search engines and screen readers see it:
```html
<h1 class="sr-only">iOS IPA Security Scanner</h1>
```

(`.sr-only` = `position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0,0,0,0)`)

### 8. Missing 404 Page

No `404.html` exists. Users hitting bad URLs see a blank or server default page.

**Create `web/public/404.html`** with Pavise branding, a clear message, and a link back to `/`.

### 9. Structured Data Enhancements

Both pages have a valid `WebApplication` JSON-LD block — that's good. Two additions would improve richness:

**a) Add `screenshot`:**
```json
"screenshot": "https://pavise.app/screenshot.png"
```

**b) Add `potentialAction` for the upload flow:**
```json
"potentialAction": {
  "@type": "Action",
  "name": "Analyze IPA",
  "target": "https://pavise.app/scan"
}
```

### 10. Back-Link from Scanner to Homepage

`scan.html`'s footer has no link back to `/`. Add one to aid navigation and internal linking signals:
```html
<a href="/">← Pavise Home</a>
```

---

## Low Priority / Nice-to-Have

### 11. Twitter Creator Tag

Add if there's an associated Twitter/X account:
```html
<meta name="twitter:creator" content="@ahmetmutlugun" />
```

### 12. DNS Prefetch for Analytics

`stats.pavise.app` loads the analytics script. Add a prefetch hint to reduce DNS lookup time:
```html
<link rel="dns-prefetch" href="//stats.pavise.app" />
```

### 13. Prefetch Scanner Page from Homepage

Improves perceived load time when users click "Open Scanner":
```html
<!-- in index.html <head> -->
<link rel="prefetch" as="document" href="/scan" />
```

### 14. SVG Accessibility

Decorative SVGs should be hidden from screen readers; functional/informational ones should have a `<title>`. Current SVGs have neither.

```html
<!-- Decorative SVG -->
<svg aria-hidden="true" focusable="false">...</svg>

<!-- Informational SVG -->
<svg role="img" aria-labelledby="icon-title-1">
  <title id="icon-title-1">Upload file</title>
  ...
</svg>
```

### 15. Build-Time SEO Validation

No automated checks exist. Consider a small `scripts/validate-seo.mjs` that runs after `vite build` and checks:
- Each page has exactly one `<h1>`
- Meta descriptions are 120–160 chars
- Canonical tags match expected URLs
- `og:image` is present

---

## Summary Scorecard

| Category | Score | Primary Issue |
|---|---|---|
| Canonical Tags | 25/100 | `scan.html` points to homepage |
| Social Sharing | 50/100 | No OG/Twitter images; duplicate tags |
| Site Infrastructure | 55/100 | No sitemap, no robots.txt |
| Meta Tags | 85/100 | Duplicate content on scan page |
| Schema.org | 78/100 | Valid but sparse |
| Semantic HTML | 75/100 | Missing `<main>` / `<header>` on index |
| Heading Hierarchy | 75/100 | Hidden h1 on scan page |
| Performance Hints | 70/100 | Only preconnect; missing prefetch/preload |
| URL Structure | 95/100 | Clean, no issues |
| SSR/SSG | 90/100 | Static HTML is crawler-friendly |
| **Overall** | **72/100** | |

---

## Prioritised Action List

1. Fix canonical tag in `scan.html` (line 8) — **one-line change, critical**
2. Create `public/robots.txt`
3. Create `public/sitemap.xml`
4. Update all duplicate meta/OG/Twitter tags in `scan.html`
5. Create `og-image.png` (1200×630) and wire up `og:image` + `twitter:image`
6. Add `<main>` and `<header>` to `index.html`
7. Add `.sr-only` `<h1>` to scan view in `scan.html`
8. Create `public/404.html`
9. Add structured data enhancements (screenshot, potentialAction)
10. Add DNS prefetch and page prefetch hints
