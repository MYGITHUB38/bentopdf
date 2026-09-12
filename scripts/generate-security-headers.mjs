#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

const isolatedPages = JSON.parse(
  readFileSync(
    join(repoRoot, 'src/js/config/cross-origin-isolated-pages.json'),
    'utf-8'
  )
).pages;

function originOf(urlStr) {
  if (!urlStr) return null;
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

function uniq(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

const DEFAULT_WASM_ORIGINS = {
  pymupdf: 'https://cdn.jsdelivr.net',
  gs: 'https://cdn.jsdelivr.net',
  cpdf: 'https://cdn.jsdelivr.net',
};
const DEFAULT_CORS_PROXY_ORIGIN =
  'https://bentopdf-cors-proxy.bentopdf.workers.dev';
const DEFAULT_OCR_FONT_CDN_ORIGIN = 'https://rawcdn.githack.com';

const wasmOrigins = [
  originOf(process.env.VITE_WASM_PYMUPDF_URL) || DEFAULT_WASM_ORIGINS.pymupdf,
  originOf(process.env.VITE_WASM_GS_URL) || DEFAULT_WASM_ORIGINS.gs,
  originOf(process.env.VITE_WASM_CPDF_URL) || DEFAULT_WASM_ORIGINS.cpdf,
];

const tesseractOrigins = uniq([
  originOf(process.env.VITE_TESSERACT_WORKER_URL),
  originOf(process.env.VITE_TESSERACT_CORE_URL),
  originOf(process.env.VITE_TESSERACT_LANG_URL),
]);

const corsProxyOrigin =
  originOf(process.env.VITE_CORS_PROXY_URL) || DEFAULT_CORS_PROXY_ORIGIN;

const ocrFontOrigin =
  originOf(process.env.VITE_OCR_FONT_BASE_URL) || DEFAULT_OCR_FONT_CDN_ORIGIN;

const googleScriptOrigins = [
  'https://accounts.google.com',
  'https://apis.google.com',
];
const googleConnectOrigins = [
  'https://accounts.google.com',
  'https://www.googleapis.com',
];
const googleFrameOrigins = [
  'https://accounts.google.com',
  'https://docs.google.com',
  'https://drive.google.com',
];

const scriptOrigins = uniq([
  ...wasmOrigins,
  ...tesseractOrigins,
  ...googleScriptOrigins,
]);
const connectOrigins = uniq([
  ...wasmOrigins,
  ...tesseractOrigins,
  corsProxyOrigin,
  ocrFontOrigin,
  ...googleConnectOrigins,
]);
const fontOrigins = uniq([ocrFontOrigin].filter(Boolean));

const githubStarsDisabled =
  process.env.DISABLE_GITHUB_STARS === 'true' ||
  process.env.SIMPLE_MODE === 'true';
const githubApiSource = githubStarsDisabled ? '' : ' https://api.github.com';

const directives = [
  `default-src 'self'`,
  `script-src 'self' 'wasm-unsafe-eval' 'unsafe-eval' blob: ${scriptOrigins.join(' ')}`.trim(),
  `worker-src 'self' blob:`,
  `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
  `img-src 'self' data: blob: https:`,
  `font-src 'self' data: https://fonts.gstatic.com ${fontOrigins.join(' ')}`.trim(),
  `connect-src 'self' blob:${githubApiSource} https://fonts.gstatic.com ${connectOrigins.join(' ')}`.trim(),
  `object-src 'none'`,
  `base-uri 'self'`,
  `frame-src 'self' blob: ${googleFrameOrigins.join(' ')}`.trim(),
  `frame-ancestors 'self'`,
  `form-action 'self'`,
];

const docsDirectives = [
  `default-src 'self'`,
  `script-src 'self' 'unsafe-inline' ${scriptOrigins.join(' ')}`.trim(),
  `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
  `img-src 'self' data: blob: https:`,
  `font-src 'self' data: https://fonts.gstatic.com ${fontOrigins.join(' ')}`.trim(),
  `connect-src 'self'${githubApiSource} https://fonts.gstatic.com ${connectOrigins.join(' ')}`.trim(),
  `object-src 'none'`,
  `base-uri 'self'`,
  `frame-src 'self' blob: ${googleFrameOrigins.join(' ')}`.trim(),
  `frame-ancestors 'self'`,
  `form-action 'self'`,
];

const csp = directives.join('; ');
const docsCsp = docsDirectives.join('; ');

// COOP and COEP both differ between page families, and both only make sense on
// the pages that need cross-origin isolation:
//  - COOP 'same-origin' is the only value that grants isolation, and therefore
//    SharedArrayBuffer, which LibreOffice WASM and the TIFF encoder require
//    (MDN, Window.crossOriginIsolated). Everywhere else 'same-origin-allow-popups'
//    keeps the Google sign-in popup working.
//  - COEP is REQUIRED for isolation, but it also blocks any cross-origin iframe
//    whose document does not send COEP of its own -- and the Google Picker
//    (docs.google.com) sends none. 'credentialless' does not help: it exempts
//    no-cors subresources, not nested documents. So COEP is emitted ONLY on the
//    isolated pages; sent site-wide it silently breaks the Drive file picker.
// The page list lives in src/js/config/cross-origin-isolated-pages.json and is
// shared with the runtime, so the two can never drift apart.
function commonHeaders(coop, coep) {
  const coepHeader = coep
    ? `add_header Cross-Origin-Embedder-Policy "${coep}" always;
`
    : '';
  return `add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()" always;
add_header Cross-Origin-Opener-Policy "${coop}" always;
${coepHeader}add_header Cross-Origin-Resource-Policy "cross-origin" always;
`;
}

const contents = `add_header Content-Security-Policy "${csp}" always;
${commonHeaders('same-origin-allow-popups', null)}`;

const docsContents = `add_header Content-Security-Policy "${docsCsp}" always;
${commonHeaders('same-origin-allow-popups', null)}`;

const isolatedContents = `# Pages requiring SharedArrayBuffer: COOP must be exactly "same-origin".
# Generated from src/js/config/cross-origin-isolated-pages.json -- do not edit.
add_header Content-Security-Policy "${csp}" always;
${commonHeaders('same-origin', 'credentialless')}`;

// nginx: one location block matching the isolated pages, with or without a
// language prefix (/fr/word-to-pdf.html) and with or without the .html suffix.
// The named capture drives a fallback to the base page, so a language-prefixed
// URL still resolves when the build target did not pre-render the /fr/ pages --
// and it resolves inside THIS location, which is what keeps COOP "same-origin"
// on it. Falling through to the generic language block would have served it
// with "same-origin-allow-popups" and silently cost the page its isolation.
const isolatedAlternation = isolatedPages
  .map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  .join('|');
const isolatedLocation = `# Generated by scripts/generate-security-headers.mjs -- do not edit.
# Pages needing SharedArrayBuffer must be served with COOP "same-origin".
# The regex is quoted: nginx reads an unquoted { in a directive value as the
# start of a block, truncating the pattern and failing "nginx -t".
location ~ "^/(?:[a-z]{2}(?:-[A-Za-z]{2})?/)?(?<isolatedpage>${isolatedAlternation})(?:\\.html)?$" {
    include /etc/nginx/security-headers-isolated.conf;
    try_files $uri $uri/ $uri.html /$isolatedpage /$isolatedpage.html =404;
    expires 5m;
}
`;

// Apache: a managed block inside .htaccess, rewritten in place so the page list
// can never drift from the JSON source of truth.
const HTACCESS_BEGIN = '# BEGIN cross-origin-isolated pages (generated)';
const HTACCESS_END = '# END cross-origin-isolated pages (generated)';
const htaccessBlock = `${HTACCESS_BEGIN}
# Pages needing SharedArrayBuffer: COOP must be exactly "same-origin".
# Source of truth: src/js/config/cross-origin-isolated-pages.json
<IfModule mod_headers.c>
<FilesMatch "^(?:${isolatedAlternation})\\.html$">
Header always set Cross-Origin-Opener-Policy "same-origin"
Header always set Cross-Origin-Embedder-Policy "credentialless"
</FilesMatch>
</IfModule>
${HTACCESS_END}`;

const htaccessPath = join(repoRoot, '.htaccess');
let htaccess = readFileSync(htaccessPath, 'utf-8');
// The markers contain parentheses; unescaped they would become capture groups
// and the block would never be found, so the generator would append a fresh
// copy on every build.
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const blockRegex = new RegExp(
  `${escapeRegex(HTACCESS_BEGIN)}[\\s\\S]*?${escapeRegex(HTACCESS_END)}`,
  'm'
);
if (blockRegex.test(htaccess)) {
  htaccess = htaccess.replace(blockRegex, htaccessBlock);
} else {
  // First run: insert right after the main security-headers <IfModule> block.
  // Tolerates CRLF, which Windows checkouts still produce for tracked configs.
  const anchor = /<\/IfModule>\r?\n/;
  const found = anchor.exec(htaccess);
  if (!found) {
    throw new Error('.htaccess: could not find the security headers block');
  }
  const cut = found.index + found[0].length;
  htaccess = `${htaccess.slice(0, cut)}\n${htaccessBlock}\n${htaccess.slice(cut)}`;
}
writeFileSync(htaccessPath, htaccess);

const outPath = join(repoRoot, 'security-headers.conf');
const docsOutPath = join(repoRoot, 'security-headers-docs.conf');
const isolatedOutPath = join(repoRoot, 'security-headers-isolated.conf');
const isolatedLocationPath = join(repoRoot, 'nginx-isolated-location.conf');
writeFileSync(outPath, contents);
writeFileSync(docsOutPath, docsContents);
writeFileSync(isolatedOutPath, isolatedContents);
writeFileSync(isolatedLocationPath, isolatedLocation);
console.log(
  `[security-headers] wrote ${outPath} with ${scriptOrigins.length} script-src / ${connectOrigins.length} connect-src origin(s)`
);
console.log(`[security-headers] wrote ${docsOutPath} (docs CSP)`);
console.log(
  `[security-headers] wrote ${isolatedOutPath} (COOP same-origin for ${isolatedPages.length} page(s))`
);
