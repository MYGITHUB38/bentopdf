/**
 * Cross-origin isolation policy.
 *
 * Two requirements pull the `Cross-Origin-Opener-Policy` header in opposite
 * directions:
 *
 *  - LibreOffice WASM and the TIFF encoder need `SharedArrayBuffer`, which the
 *    browser only exposes to a cross-origin-isolated document. Isolation
 *    requires COOP `same-origin` exactly -- `same-origin-allow-popups` does not
 *    qualify (MDN, Window.crossOriginIsolated).
 *  - The Google Identity Services sign-in popup needs `window.opener`, which
 *    COOP `same-origin` severs.
 *
 * The site therefore serves `same-origin-allow-popups` by default and
 * `same-origin` on the pages listed in cross-origin-isolated-pages.json. On
 * those pages the Google Drive button is not shown: the popup could not
 * complete there anyway, and an inert button is worse than no button.
 */

import isolatedPages from './cross-origin-isolated-pages.json';
import { getToolIdFromPath } from '../utils/disabled-tools.js';

export const CROSS_ORIGIN_ISOLATED_PAGES: readonly string[] =
  isolatedPages.pages;

/** True when the given tool page is served with COOP `same-origin`. */
export function isCrossOriginIsolatedPage(toolId: string | null): boolean {
  if (!toolId) return false;
  return CROSS_ORIGIN_ISOLATED_PAGES.includes(toolId);
}

/** True when the page currently displayed is one of them. */
export function isCurrentPageCrossOriginIsolated(): boolean {
  return isCrossOriginIsolatedPage(getToolIdFromPath());
}
