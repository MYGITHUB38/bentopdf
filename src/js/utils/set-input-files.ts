/**
 * Replaces the selection of a file input.
 *
 * `input.files = ...` is the standard way and works in every current browser,
 * but it needs a genuine `FileList`, which cannot be constructed directly. The
 * accepted route is a `DataTransfer`. Where that is unavailable or the setter
 * refuses the value (older engines, jsdom), the property is redefined instead,
 * which is enough for code that only ever reads `input.files`.
 */
export function setInputFiles(input: HTMLInputElement, files: File[]): void {
  if (typeof DataTransfer !== 'undefined') {
    try {
      const transfer = new DataTransfer();
      files.forEach((file) => transfer.items.add(file));
      input.files = transfer.files;
      return;
    } catch {
      // Fall through to the property redefinition below.
    }
  }

  Object.defineProperty(input, 'files', {
    value: Object.assign([...files], {
      item: (index: number) => files[index] ?? null,
    }),
    configurable: true,
    writable: true,
  });
}
