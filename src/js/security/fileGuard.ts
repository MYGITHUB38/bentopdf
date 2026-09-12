/**
 * Centralised file-intake security guard.
 *
 * Every tool page (112 of them) wires its own `#file-input` and its own drop
 * zone; there is no shared intake helper to hook into. Instead of touching each
 * page, this module installs a single pair of capture-phase listeners on
 * `document`. Capture always runs before the target phase, whatever order the
 * listeners were registered in, so the guard sees a file selection before any
 * tool logic does.
 *
 * Design rules:
 *  - Fail OPEN. Any unexpected error lets the files through with a console
 *    warning. A guard that blocks everything on a bug is worse than no guard.
 *  - Feature-detected. Without `DataTransfer` (and `DragEvent` for drops) the
 *    corresponding interceptor is not installed at all.
 *  - Re-entrant safe. The replayed event is a new object, tagged before dispatch
 *    so the guard lets it through untouched.
 */

import { showAlert, showLoader, hideLoader } from '../ui.js';
import { t } from '../i18n/index.js';
import { getToolIdFromPath } from '../utils/disabled-tools.js';
import { validateFilesSecurity } from './fileValidator.js';
import { setInputFiles } from '../utils/set-input-files.js';

/** Events the guard has already validated and replayed. */
const replayedEvents = new WeakSet<Event>();

let installed = false;

const IMAGE_SOURCES = [
  'jpg',
  'jpeg',
  'png',
  'webp',
  'bmp',
  'heic',
  'tiff',
  'svg',
  'image',
];

const IMAGE_ACCEPT_TOKENS = new Set([
  'image/*',
  'image/png',
  'image/jpeg',
  'image/jpg',
  'image/gif',
  'image/webp',
  'image/bmp',
  'image/tiff',
  'image/svg+xml',
  'image/heic',
  'image/heif',
  'image/avif',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.bmp',
  '.tif',
  '.tiff',
  '.svg',
  '.heic',
  '.heif',
  '.avif',
]);

const PDF_ACCEPT_TOKENS = new Set(['application/pdf', '.pdf']);

/**
 * Expected file type for a tool, derived from the tool id rather than from a
 * hand-maintained list that goes stale the moment a tool is added.
 *
 * Convention in this codebase: `<source>-to-pdf` consumes `<source>`, and
 * `pdf-to-<target>` (or any other id) consumes a PDF. Returning `undefined`
 * means "no signature enforcement" — executables, XXE and zip bombs are still
 * rejected, only the format match is skipped.
 */
export function expectedTypeForTool(toolId: string | null): string | undefined {
  if (!toolId) return undefined;

  const toPdf = toolId.match(/^(.+)-to-pdf$/);
  if (toPdf) {
    const source = toPdf[1];
    if (IMAGE_SOURCES.includes(source)) return 'image';
    // epub / cbz / txt / markdown / html / csv / xml / word / excel ... : the
    // validator has no reliable signature for several of these, and enforcing
    // 'pdf' here is exactly the bug this function replaces.
    return undefined;
  }

  // Everything else in this app operates on an existing PDF.
  return 'pdf';
}

/**
 * What a tool consumes, expressed as an `accept`-style list.
 *
 * Most tool pages leave their file input without an `accept` attribute, so any
 * consumer that relies on it (the Google Picker filters its view from it) falls
 * back to a default that shows PDFs only -- and an epub-to-pdf page then offers
 * no EPUB at all. Same naming convention as expectedTypeForTool: `<source>-to-pdf`
 * consumes `<source>`, anything else consumes a PDF. An empty string means
 * "unknown, do not filter", which is the safe answer: the security guard and the
 * tool still validate whatever comes back.
 */
export function acceptHintForTool(toolId: string | null): string {
  if (!toolId) return '';

  const toPdf = toolId.match(/^(.+)-to-pdf$/);
  if (!toPdf) return 'application/pdf';

  const source = toPdf[1];
  if (IMAGE_SOURCES.includes(source)) return 'image/*';

  const EXPLICIT: Record<string, string> = {
    word: '.docx,.doc',
    excel: '.xlsx,.xls',
    powerpoint: '.pptx,.ppt',
    markdown: '.md',
  };
  if (EXPLICIT[source]) return EXPLICIT[source];

  // epub, cbz, txt, csv, xml, odt, rtf... : the extension is the tool prefix.
  return `.${source}`;
}

/**
 * Expected type for one specific input.
 *
 * A page can carry several file inputs with unrelated purposes -- the document
 * itself, a signing certificate, a workflow JSON, an attachment of any kind.
 * The input's own `accept` attribute states what it wants, so it wins; the tool
 * id is only consulted for the main document input when `accept` says nothing.
 * Anything we cannot classify with confidence gets no signature enforcement,
 * never a wrong one.
 */
export function expectedTypeForInput(
  input: HTMLInputElement,
  toolId: string | null
): string | undefined {
  const accept = input.accept
    .split(',')
    .map((token) => token.trim().toLowerCase())
    .filter(Boolean);

  if (accept.length > 0) {
    if (accept.every((token) => IMAGE_ACCEPT_TOKENS.has(token))) return 'image';
    if (accept.every((token) => PDF_ACCEPT_TOKENS.has(token))) return 'pdf';
    return undefined;
  }

  // No `accept`: only the main document input is covered by the tool
  // convention. A secondary input stays unconstrained.
  return input.id === 'file-input' ? expectedTypeForTool(toolId) : undefined;
}

function isFileInput(target: EventTarget | null): target is HTMLInputElement {
  return (
    target instanceof HTMLInputElement &&
    target.type === 'file' &&
    !target.dataset.skipSecurityGuard
  );
}

function reportRejections(
  rejected: Array<{ file: File; reason: string }>
): void {
  if (rejected.length === 0) return;
  const details = rejected
    .map((r) => `• ${r.file.name}: ${r.reason}`)
    .join('\n');
  showAlert(
    t('security.rejectedTitle'),
    `${t('security.rejectedIntro')}\n${details}`
  );
}

/**
 * Runs the validation and hands the surviving files back to the page by
 * replaying the original interaction.
 */
async function validateAndReplay(
  files: File[],
  expectedType: string | undefined,
  replay: (validFiles: File[]) => void
): Promise<void> {
  let validFiles: File[];
  try {
    showLoader(t('security.checking'));
    const result = await validateFilesSecurity(files, { expectedType });
    validFiles = result.validFiles;
    reportRejections(result.rejectedFiles);
  } catch (err) {
    // Fail open: a broken guard must not make the application unusable.
    console.warn('[FileGuard] Validation failed, letting files through:', err);
    validFiles = files;
  } finally {
    hideLoader();
  }

  if (validFiles.length === 0) return;
  try {
    replay(validFiles);
  } catch (err) {
    console.error('[FileGuard] Could not replay the file selection:', err);
  }
}

function onChangeCapture(event: Event): void {
  if (replayedEvents.has(event)) return;
  const input = event.target;
  if (!isFileInput(input)) return;

  const files = Array.from(input.files ?? []);
  if (files.length === 0) return;

  // Synchronous: nothing downstream must see the files before validation.
  event.stopImmediatePropagation();
  event.preventDefault();

  const expectedType = expectedTypeForInput(input, getToolIdFromPath());
  void validateAndReplay(files, expectedType, (validFiles) => {
    setInputFiles(input, validFiles);

    const replayEvent = new Event('change', {
      bubbles: true,
      cancelable: true,
    });
    replayedEvents.add(replayEvent);
    input.dispatchEvent(replayEvent);
  });
}

function onDropCapture(event: DragEvent): void {
  if (replayedEvents.has(event)) return;
  const dropped = Array.from(event.dataTransfer?.files ?? []);
  if (dropped.length === 0) return;

  const target = event.target as Element | null;
  event.stopImmediatePropagation();
  event.preventDefault();

  // No expected type on a drop. A drop zone carries no `accept`, and a page may
  // hold several file inputs with unrelated purposes -- guessing which one the
  // zone stands for would apply the wrong format check. Executables, XXE and
  // zip bombs are still rejected; only the format match is skipped, and the
  // file picker path (which does know its input) still covers the normal case.
  void validateAndReplay(dropped, undefined, (validFiles) => {
    const transfer = new DataTransfer();
    validFiles.forEach((file) => transfer.items.add(file));

    const replayEvent = new DragEvent('drop', {
      dataTransfer: transfer,
      bubbles: true,
      cancelable: true,
    });
    replayedEvents.add(replayEvent);
    (target ?? document.body).dispatchEvent(replayEvent);
  });
}

/**
 * Installs the guard. Safe to call more than once; only the first call binds.
 */
export function installFileSecurityGuard(): void {
  if (installed) return;
  if (typeof document === 'undefined') return;

  if (typeof DataTransfer === 'undefined') {
    console.warn(
      '[FileGuard] DataTransfer is unavailable; file security guard not installed.'
    );
    return;
  }

  installed = true;
  document.addEventListener('change', onChangeCapture, true);

  if (typeof DragEvent === 'function') {
    document.addEventListener('drop', onDropCapture as EventListener, true);
  } else {
    console.warn(
      '[FileGuard] DragEvent is unavailable; drag-and-drop is not guarded.'
    );
  }
}

/** Test helper: removes the listeners and resets the installed flag. */
export function uninstallFileSecurityGuard(): void {
  if (!installed) return;
  document.removeEventListener('change', onChangeCapture, true);
  document.removeEventListener('drop', onDropCapture as EventListener, true);
  installed = false;
}
