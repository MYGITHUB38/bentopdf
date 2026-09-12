import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  expectedTypeForTool,
  expectedTypeForInput,
  acceptHintForTool,
  installFileSecurityGuard,
  uninstallFileSecurityGuard,
} from '../js/security/fileGuard';
import {
  isCrossOriginIsolatedPage,
  CROSS_ORIGIN_ISOLATED_PAGES,
} from '../js/config/cross-origin';
import { setInputFiles } from '../js/utils/set-input-files';

const PDF_BYTES = new Uint8Array([
  0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37,
]); // %PDF-1.7
const PNG_BYTES = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
]);
const EXE_BYTES = new Uint8Array([
  0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
]); // MZ

function makeFile(name: string, bytes: Uint8Array, type = ''): File {
  return new File([bytes.buffer as ArrayBuffer], name, { type });
}

function setPath(pathname: string): void {
  window.history.replaceState({}, '', pathname);
}

describe('expectedTypeForTool', () => {
  it('expects a PDF for tools that operate on an existing PDF', () => {
    expect(expectedTypeForTool('merge')).toBe('pdf');
    expect(expectedTypeForTool('compress')).toBe('pdf');
    expect(expectedTypeForTool('pdf-to-tiff')).toBe('pdf');
    expect(expectedTypeForTool('add-watermark')).toBe('pdf');
  });

  it('expects an image for the image converters', () => {
    for (const tool of [
      'jpg-to-pdf',
      'png-to-pdf',
      'webp-to-pdf',
      'svg-to-pdf',
      'bmp-to-pdf',
      'heic-to-pdf',
      'tiff-to-pdf',
      'image-to-pdf',
    ]) {
      expect(expectedTypeForTool(tool)).toBe('image');
    }
  });

  it('enforces no signature for formats the validator cannot identify', () => {
    // The bug this replaces marked these as PDF and rejected their own input.
    for (const tool of [
      'word-to-pdf',
      'excel-to-pdf',
      'epub-to-pdf',
      'cbz-to-pdf',
      'txt-to-pdf',
      'markdown-to-pdf',
      'html-to-pdf',
      'csv-to-pdf',
      'xml-to-pdf',
    ]) {
      expect(expectedTypeForTool(tool)).toBeUndefined();
    }
  });

  it('enforces nothing when the page is not a tool page', () => {
    expect(expectedTypeForTool(null)).toBeUndefined();
    expect(expectedTypeForTool('')).toBeUndefined();
  });
});

describe('expectedTypeForInput', () => {
  function input(attrs: { id?: string; accept?: string }): HTMLInputElement {
    const el = document.createElement('input');
    el.type = 'file';
    if (attrs.id) el.id = attrs.id;
    if (attrs.accept) el.accept = attrs.accept;
    return el;
  }

  it('lets the accept attribute decide, whatever the tool is', () => {
    expect(expectedTypeForInput(input({ accept: 'image/*' }), 'merge')).toBe(
      'image'
    );
    expect(
      expectedTypeForInput(input({ accept: 'application/pdf' }), 'png-to-pdf')
    ).toBe('pdf');
    expect(expectedTypeForInput(input({ accept: '.png,.jpg' }), 'merge')).toBe(
      'image'
    );
  });

  it('enforces nothing for a secondary input the tool convention would mislabel', () => {
    // Signing certificate, workflow import, arbitrary attachment: all of these
    // live on pages whose tool id means "PDF".
    expect(
      expectedTypeForInput(
        input({ accept: '.pfx,.p12,.pem' }),
        'digital-sign-pdf'
      )
    ).toBeUndefined();
    expect(
      expectedTypeForInput(input({ accept: '.json' }), 'pdf-workflow')
    ).toBeUndefined();
    expect(
      expectedTypeForInput(input({ id: 'attachment-input' }), 'add-attachments')
    ).toBeUndefined();
  });

  it('falls back to the tool convention only for the main document input', () => {
    expect(expectedTypeForInput(input({ id: 'file-input' }), 'merge')).toBe(
      'pdf'
    );
    expect(
      expectedTypeForInput(input({ id: 'file-input' }), 'png-to-pdf')
    ).toBe('image');
    expect(
      expectedTypeForInput(input({ id: 'file-input' }), 'word-to-pdf')
    ).toBeUndefined();
  });

  it('enforces nothing on a mixed accept list', () => {
    expect(
      expectedTypeForInput(
        input({ accept: 'application/pdf,image/*' }),
        'merge'
      )
    ).toBeUndefined();
  });
});

describe('acceptHintForTool', () => {
  it('gives the source format of a converter, so a picker does not show PDFs only', () => {
    expect(acceptHintForTool('epub-to-pdf')).toBe('.epub');
    expect(acceptHintForTool('cbz-to-pdf')).toBe('.cbz');
    expect(acceptHintForTool('txt-to-pdf')).toBe('.txt');
    expect(acceptHintForTool('xml-to-pdf')).toBe('.xml');
  });

  it('maps the office converters to their real extensions', () => {
    expect(acceptHintForTool('word-to-pdf')).toBe('.docx,.doc');
    expect(acceptHintForTool('excel-to-pdf')).toBe('.xlsx,.xls');
    expect(acceptHintForTool('powerpoint-to-pdf')).toBe('.pptx,.ppt');
  });

  it('groups every image converter under image/*', () => {
    for (const tool of [
      'jpg-to-pdf',
      'png-to-pdf',
      'heic-to-pdf',
      'image-to-pdf',
    ]) {
      expect(acceptHintForTool(tool)).toBe('image/*');
    }
  });

  it('expects a PDF for tools that operate on one', () => {
    expect(acceptHintForTool('merge')).toBe('application/pdf');
    expect(acceptHintForTool('pdf-to-tiff')).toBe('application/pdf');
  });

  it('returns nothing rather than a wrong filter when the tool is unknown', () => {
    expect(acceptHintForTool(null)).toBe('');
    expect(acceptHintForTool('')).toBe('');
  });
});

describe('cross-origin isolated pages', () => {
  it('lists the tools that need SharedArrayBuffer', () => {
    expect(isCrossOriginIsolatedPage('word-to-pdf')).toBe(true);
    expect(isCrossOriginIsolatedPage('pdf-to-tiff')).toBe(true);
    expect(isCrossOriginIsolatedPage('merge')).toBe(false);
    expect(isCrossOriginIsolatedPage(null)).toBe(false);
  });

  it('keeps the list free of duplicates', () => {
    expect(new Set(CROSS_ORIGIN_ISOLATED_PAGES).size).toBe(
      CROSS_ORIGIN_ISOLATED_PAGES.length
    );
  });
});

describe('installFileSecurityGuard', () => {
  let input: HTMLInputElement;
  let seen: File[][];

  beforeEach(() => {
    document.body.innerHTML = '';
    input = document.createElement('input');
    input.type = 'file';
    input.id = 'file-input';
    input.multiple = true;
    document.body.appendChild(input);

    seen = [];
    input.addEventListener('change', (event) => {
      const target = event.target as HTMLInputElement;
      seen.push(Array.from(target.files ?? []));
    });

    installFileSecurityGuard();
  });

  afterEach(() => {
    uninstallFileSecurityGuard();
    vi.restoreAllMocks();
    setPath('/');
  });

  function selectFiles(files: File[]): void {
    setInputFiles(input, files);
    input.dispatchEvent(
      new Event('change', { bubbles: true, cancelable: true })
    );
  }

  it('replays a clean selection to the page handler', async () => {
    setPath('/merge.html');
    selectFiles([makeFile('a.pdf', PDF_BYTES)]);

    // The page must not see the first event.
    expect(seen).toHaveLength(0);

    await vi.waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0].map((f) => f.name)).toEqual(['a.pdf']);
  });

  it('drops an executable before the tool sees it', async () => {
    setPath('/merge.html');
    selectFiles([
      makeFile('a.pdf', PDF_BYTES),
      makeFile('payload.exe', EXE_BYTES),
    ]);

    await vi.waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0].map((f) => f.name)).toEqual(['a.pdf']);
  });

  it('never replays when every file was rejected', async () => {
    setPath('/merge.html');
    selectFiles([makeFile('payload.exe', EXE_BYTES)]);

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(seen).toHaveLength(0);
  });

  it('rejects a PNG on a tool that expects a PDF', async () => {
    setPath('/merge.html');
    selectFiles([makeFile('picture.png', PNG_BYTES)]);

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(seen).toHaveLength(0);
  });

  it('accepts a PNG on an image converter', async () => {
    setPath('/png-to-pdf.html');
    selectFiles([makeFile('picture.png', PNG_BYTES)]);

    await vi.waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0].map((f) => f.name)).toEqual(['picture.png']);
  });

  it('accepts a PNG mislabelled as .pdf on an image converter, and the reverse is refused', async () => {
    setPath('/png-to-pdf.html');
    selectFiles([makeFile('picture.pdf', PNG_BYTES)]);
    await vi.waitFor(() => expect(seen).toHaveLength(1));

    seen.length = 0;
    setPath('/merge.html');
    selectFiles([makeFile('document.pdf', PNG_BYTES)]);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(seen).toHaveLength(0);
  });

  it('ignores inputs that opted out', async () => {
    setPath('/merge.html');
    input.dataset.skipSecurityGuard = 'true';
    selectFiles([makeFile('payload.exe', EXE_BYTES)]);

    // Passed straight through, in the original event.
    expect(seen).toHaveLength(1);
    delete input.dataset.skipSecurityGuard;
  });

  it('guards a drop: executables are removed, format is not enforced', async () => {
    setPath('/merge.html');
    const zone = document.createElement('div');
    zone.id = 'drop-zone';
    document.body.appendChild(zone);

    const dropped: File[][] = [];
    zone.addEventListener('drop', (event) => {
      const files = Array.from((event as DragEvent).dataTransfer?.files ?? []);
      dropped.push(files);
    });

    const transfer = new DataTransfer();
    // A PNG on a PDF tool: kept, because a drop zone cannot tell us which of a
    // page's inputs it stands for. The executable is removed all the same.
    [
      makeFile('picture.png', PNG_BYTES),
      makeFile('payload.exe', EXE_BYTES),
    ].forEach((f) => transfer.items.add(f));
    zone.dispatchEvent(
      new DragEvent('drop', {
        dataTransfer: transfer,
        bubbles: true,
        cancelable: true,
      })
    );

    expect(dropped).toHaveLength(0);
    await vi.waitFor(() => expect(dropped).toHaveLength(1));
    expect(dropped[0].map((f) => f.name)).toEqual(['picture.png']);
  });

  it('is idempotent: installing twice does not double-handle an event', async () => {
    setPath('/merge.html');
    installFileSecurityGuard();
    selectFiles([makeFile('a.pdf', PDF_BYTES)]);

    await vi.waitFor(() => expect(seen).toHaveLength(1));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(seen).toHaveLength(1);
  });
});
