import { afterEach, vi } from 'vitest';

class TestDOMMatrix {
  a = 1;
  b = 0;
  c = 0;
  d = 1;
  e = 0;
  f = 0;
}

if (typeof globalThis.DOMMatrix === 'undefined') {
  globalThis.DOMMatrix = TestDOMMatrix as unknown as typeof DOMMatrix;
}

const hasDom = typeof window !== 'undefined';

afterEach(() => {
  if (!hasDom) return;
  document.body.innerHTML = '';
  document.head.innerHTML = '';
});

global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}));

if (hasDom) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation((query) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}

global.IntersectionObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}));

// jsdom implements neither DataTransfer nor DragEvent. Both are required to
// exercise the file-intake security guard (src/js/security/fileGuard.ts), which
// replays a validated selection through them. Minimal stand-ins, behaviourally
// faithful for what the guard uses: an ordered FileList and the dataTransfer
// carried by a drop event.
if (hasDom && typeof (globalThis as any).DataTransfer === 'undefined') {
  class FileListStub extends Array<File> {
    item(index: number): File | null {
      return this[index] ?? null;
    }
  }

  class DataTransferStub {
    private readonly _files = new FileListStub();

    readonly items = {
      add: (file: File): void => {
        this._files.push(file);
      },
      clear: (): void => {
        this._files.length = 0;
      },
    };

    get files(): FileList {
      return this._files as unknown as FileList;
    }
  }

  (globalThis as any).DataTransfer = DataTransferStub;

  class DragEventStub extends Event {
    readonly dataTransfer: DataTransfer | null;

    constructor(
      type: string,
      init: EventInit & { dataTransfer?: DataTransfer } = {}
    ) {
      super(type, init);
      this.dataTransfer = init.dataTransfer ?? null;
    }
  }

  (globalThis as any).DragEvent = DragEventStub;
}
