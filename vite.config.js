import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

// `npm run build`        -> dist/ folder for any static host
// `npm run build:single` -> one self-contained HTML file (opens from disk)

// Content Security Policy for production builds only (the dev server needs
// websockets for HMR). Everything attacker-controlled in a PE goes through
// text nodes; this makes sure a future slip cannot load or run anything from
// outside the page: no remote scripts, no connections. (frame-ancestors is header-only, so it is not set here.)
// 'unsafe-inline' is required because the theme bootstrap and, in the
// single-file build, the whole bundle are inline scripts.
const CSP = [
  "default-src 'none'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' data: blob:",
  "worker-src 'self' blob: data:",
  "base-uri 'none'",
].join('; ');

const cspPlugin = {
  name: 'peek-csp',
  apply: 'build',
  transformIndexHtml(html) {
    return html.replace('<meta charset="UTF-8" />', `<meta charset="UTF-8" />\n  <meta http-equiv="Content-Security-Policy" content="${CSP}" />`);
  },
};

export default defineConfig(({ mode }) => ({
  base: './',
  plugins: mode === 'single' ? [cspPlugin, viteSingleFile()] : [cspPlugin],
  build: { outDir: mode === 'single' ? 'dist-single' : 'dist' },
}));
