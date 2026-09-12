import JSZip from 'jszip';

export interface DetectedFileType {
  type: string;
  isExecutable: boolean;
  mimeType?: string;
  description?: string;
}

export interface SecurityValidationOptions {
  expectedType?: string; // 'pdf', 'image', 'epub', 'zip', 'svg', 'xml', 'office', etc.
  maxFileSizeBytes?: number;
  skipArchiveDeepInspection?: boolean;
}

export interface SecurityValidationResult {
  valid: boolean;
  sanitizedFilename: string;
  detectedType: string;
  reason?: string;
}

// ==========================================
// 1. Magic Bytes & Binary Inspection
// ==========================================

export function detectMagicBytes(
  data: ArrayBuffer | Uint8Array
): DetectedFileType {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const len = bytes.length;

  if (len < 2) {
    return { type: 'unknown', isExecutable: false };
  }

  // 1. Executables & Binaries (Hard Blocks)
  // Windows PE (EXE, DLL, SYS) - 'MZ'
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
    return {
      type: 'executable_pe',
      isExecutable: true,
      description: 'Windows Executable (PE / MZ)',
    };
  }

  // Linux ELF - '\x7FELF'
  if (
    len >= 4 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46
  ) {
    return {
      type: 'executable_elf',
      isExecutable: true,
      description: 'Linux Executable (ELF)',
    };
  }

  // macOS Mach-O (32-bit & 64-bit, LE & BE)
  if (len >= 4) {
    const b0 = bytes[0];
    const b1 = bytes[1];
    const b2 = bytes[2];
    const b3 = bytes[3];

    if (
      (b0 === 0xfe && b1 === 0xed && b2 === 0xfa && b3 === 0xce) ||
      (b0 === 0xce && b1 === 0xfa && b2 === 0xed && b3 === 0xfe) ||
      (b0 === 0xfe && b1 === 0xed && b2 === 0xfa && b3 === 0xcf) ||
      (b0 === 0xcf && b1 === 0xfa && b2 === 0xed && b3 === 0xfe) ||
      (b0 === 0xca && b1 === 0xfe && b2 === 0xba && b3 === 0xbe) // Universal Mach-O
    ) {
      return {
        type: 'executable_macho',
        isExecutable: true,
        description: 'macOS Mach-O Binary',
      };
    }
  }

  // Script Executables: Shebang '#!'
  if (bytes[0] === 0x23 && bytes[1] === 0x21) {
    return {
      type: 'script_shebang',
      isExecutable: true,
      description: 'Unix Shell Script',
    };
  }

  // DOS Batch Script: '@echo'
  if (len >= 5) {
    const textPreview = String.fromCharCode(
      ...bytes.slice(0, 10)
    ).toLowerCase();
    if (textPreview.startsWith('@echo')) {
      return {
        type: 'script_batch',
        isExecutable: true,
        description: 'Windows Batch Script',
      };
    }
  }

  // 2. Safe Document & Image Formats
  // PDF: %PDF- (Check first 1024 bytes per PDF standard)
  const maxSearch = Math.min(len, 1024);
  for (let i = 0; i <= maxSearch - 5; i++) {
    if (
      bytes[i] === 0x25 && // %
      bytes[i + 1] === 0x50 && // P
      bytes[i + 2] === 0x44 && // D
      bytes[i + 3] === 0x46 && // F
      bytes[i + 4] === 0x2d // -
    ) {
      return {
        type: 'pdf',
        isExecutable: false,
        mimeType: 'application/pdf',
        description: 'Portable Document Format (PDF)',
      };
    }
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    len >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return {
      type: 'png',
      isExecutable: false,
      mimeType: 'image/png',
      description: 'PNG Image',
    };
  }

  // JPEG: FF D8 FF
  if (len >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return {
      type: 'jpeg',
      isExecutable: false,
      mimeType: 'image/jpeg',
      description: 'JPEG Image',
    };
  }

  // GIF: GIF87a or GIF89a
  if (
    len >= 6 &&
    bytes[0] === 0x47 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x38
  ) {
    return {
      type: 'gif',
      isExecutable: false,
      mimeType: 'image/gif',
      description: 'GIF Image',
    };
  }

  // WebP: RIFF....WEBP
  if (
    len >= 12 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return {
      type: 'webp',
      isExecutable: false,
      mimeType: 'image/webp',
      description: 'WebP Image',
    };
  }

  // BMP: BM (0x42, 0x4D)
  if (bytes[0] === 0x42 && bytes[1] === 0x4d) {
    return {
      type: 'bmp',
      isExecutable: false,
      mimeType: 'image/bmp',
      description: 'Bitmap Image',
    };
  }

  // TIFF: II*\0 (Intel LE) or MM\0* (Motorola BE)
  if (
    (len >= 4 &&
      bytes[0] === 0x49 &&
      bytes[1] === 0x49 &&
      bytes[2] === 0x2a &&
      bytes[3] === 0x00) ||
    (len >= 4 &&
      bytes[0] === 0x4d &&
      bytes[1] === 0x4d &&
      bytes[2] === 0x00 &&
      bytes[3] === 0x2a)
  ) {
    return {
      type: 'tiff',
      isExecutable: false,
      mimeType: 'image/tiff',
      description: 'TIFF Image',
    };
  }

  // ZIP Archive / EPUB / Office Open XML / CBZ: PK\x03\x04 or PK\x05\x06
  if (
    len >= 4 &&
    bytes[0] === 0x50 &&
    bytes[1] === 0x4b &&
    ((bytes[2] === 0x03 && bytes[3] === 0x04) ||
      (bytes[2] === 0x05 && bytes[3] === 0x06) ||
      (bytes[2] === 0x07 && bytes[3] === 0x08))
  ) {
    return {
      type: 'zip',
      isExecutable: false,
      mimeType: 'application/zip',
      description: 'ZIP Archive',
    };
  }

  // ISO Base Media File Format (HEIC / HEIF / AVIF): "ftyp" box at offset 4,
  // brand at offset 8. Without this branch heic-to-pdf inputs are reported as
  // 'unknown' and rejected by an expectedType of 'image'.
  if (
    len >= 12 &&
    bytes[4] === 0x66 && // f
    bytes[5] === 0x74 && // t
    bytes[6] === 0x79 && // y
    bytes[7] === 0x70 // p
  ) {
    const brand = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
    const heifBrands = [
      'heic',
      'heix',
      'heim',
      'heis',
      'hevc',
      'hevx',
      'mif1',
      'msf1',
    ];
    if (heifBrands.includes(brand)) {
      return {
        type: 'heic',
        isExecutable: false,
        mimeType: 'image/heic',
        description: 'High Efficiency Image File (HEIC/HEIF)',
      };
    }
    if (brand === 'avif' || brand === 'avis') {
      return {
        type: 'avif',
        isExecutable: false,
        mimeType: 'image/avif',
        description: 'AV1 Image File (AVIF)',
      };
    }
  }

  // Text / XML / SVG inspection
  const headText = new TextDecoder('utf-8', { fatal: false })
    .decode(bytes.slice(0, Math.min(len, 256)))
    .trim();
  if (
    headText.startsWith('<?xml') ||
    headText.includes('<svg') ||
    headText.startsWith('<html')
  ) {
    const isSvg = headText.includes('<svg');
    return {
      type: isSvg ? 'svg' : 'xml',
      isExecutable: false,
      mimeType: isSvg ? 'image/svg+xml' : 'application/xml',
      description: isSvg ? 'Scalable Vector Graphics (SVG)' : 'XML Document',
    };
  }

  return {
    type: 'unknown',
    isExecutable: false,
  };
}

export function isExecutableBinary(data: ArrayBuffer | Uint8Array): boolean {
  return detectMagicBytes(data).isExecutable;
}

// ==========================================
// 2. XML External Entity (XXE) & SVG Defense
// ==========================================

export function inspectXmlSafety(
  xmlContent: string,
  options?: { isSvg?: boolean }
): { safe: boolean; reason?: string } {
  if (!xmlContent || typeof xmlContent !== 'string') {
    return { safe: true };
  }

  // 1. XXE - Parameter Entity declarations (% name)
  const parameterEntityRegex = /<!ENTITY\s+%\s+[\w.-]+/i;
  if (parameterEntityRegex.test(xmlContent)) {
    return {
      safe: false,
      reason: 'XXE Protection: Parameter Entity declaration detected.',
    };
  }

  // 2. XXE - External Entity with SYSTEM identifier
  const systemEntityRegex =
    /<!ENTITY\s+(?:%\s+)?[\w.-]+\s+SYSTEM\s+["'][^"']+["']/i;
  if (systemEntityRegex.test(xmlContent)) {
    return {
      safe: false,
      reason:
        'XXE Protection: XML External Entity with SYSTEM identifier detected.',
    };
  }

  // 3. XXE - External Entity with PUBLIC identifier
  const publicEntityRegex =
    /<!ENTITY\s+(?:%\s+)?[\w.-]+\s+PUBLIC\s+["'][^"']+["']/i;
  if (publicEntityRegex.test(xmlContent)) {
    return {
      safe: false,
      reason:
        'XXE Protection: XML External Entity with PUBLIC identifier detected.',
    };
  }

  // 4. XML Entity Bomb / Billion Laughs (Nested Entity Expansions)
  // Check if multiple <!ENTITY ... "&...;"> occur
  const entityWithEntityRefRegex =
    /<!ENTITY\s+[\w.-]+\s+["'][^"']*&[\w.-]+;[^"']*["']/gi;
  const matches = xmlContent.match(entityWithEntityRefRegex);
  if (matches && matches.length >= 2) {
    return {
      safe: false,
      reason:
        'Entity Bomb / Billion Laughs: Cascading nested entity expansion detected.',
    };
  }

  // 5. SVG XSS & Active Scripting
  const isSvg = options?.isSvg || /<svg[\s>]/i.test(xmlContent);
  if (isSvg) {
    // Check for <script> tags
    if (/<script[\s>]/i.test(xmlContent)) {
      return {
        safe: false,
        reason: 'SVG XSS Protection: Embedded <script> tag detected.',
      };
    }

    // Check for inline event handlers (onload, onerror, onclick, onbegin, etc.)
    const eventHandlerRegex = /\bon[a-z]{3,20}\s*=/i;
    if (eventHandlerRegex.test(xmlContent)) {
      return {
        safe: false,
        reason: 'SVG XSS Protection: Inline event handler attribute detected.',
      };
    }

    // Check for javascript: or data:text/html URIs in href or xlink:href
    const jsUriRegex =
      /(?:href|xlink:href|action|src)\s*=\s*["']\s*(?:javascript:|data:text\/html)/i;
    if (jsUriRegex.test(xmlContent)) {
      return {
        safe: false,
        reason: 'SVG XSS Protection: Dangerous javascript: URI detected.',
      };
    }

    // Check for malicious foreignObject containing script or event handlers
    if (/<foreignObject[\s>]/i.test(xmlContent)) {
      const foreignObjectContent = xmlContent.match(
        /<foreignObject[\s\S]*?<\/foreignObject>/gi
      );
      if (foreignObjectContent) {
        for (const fo of foreignObjectContent) {
          if (
            /<script[\s>]/i.test(fo) ||
            eventHandlerRegex.test(fo) ||
            jsUriRegex.test(fo)
          ) {
            return {
              safe: false,
              reason:
                'SVG XSS Protection: Malicious <foreignObject> content detected.',
            };
          }
        }
      }
    }
  }

  return { safe: true };
}

// ==========================================
// 3. Filename Sanitization & Path Traversal
// ==========================================

export function sanitizeFilename(rawName: string): string {
  if (!rawName) return 'unnamed_file';

  // Strip HTML tags (<script>...</script>, <img>, etc.) before processing path separators
  let name = rawName.replace(/<[^>]*>/g, '');

  // Extract basename (strip Unix or Windows path separators)
  name = name.replace(/^.*[\\/]/, '');

  // Strip null bytes and non-printable ASCII control characters (0x00 - 0x1F, 0x7F)
  name = name.replace(/[\x00-\x1f\x7f]/g, '');

  // Strip path traversal sequences
  name = name.replace(/\.\.+[/\\]/g, '');

  // Strip dangerous characters for HTML/DOM injection (<, >, ", ', `, semicolons)
  name = name.replace(/[<>"'`]/g, '');

  // Trim whitespace
  name = name.trim();

  // If name became empty after stripping, assign default
  if (!name) name = 'sanitized_file';

  // Truncate excessively long filenames (max 255 chars) while preserving extension
  if (name.length > 255) {
    const lastDot = name.lastIndexOf('.');
    if (lastDot > 0 && lastDot > name.length - 15) {
      const ext = name.slice(lastDot);
      const base = name.slice(0, 255 - ext.length);
      name = `${base}${ext}`;
    } else {
      name = name.slice(0, 255);
    }
  }

  return name;
}

// ==========================================
// 4. Archive Security (Zip Slip & Zip Bomb)
// ==========================================

const MAX_UNCOMPRESSED_ARCHIVE_SIZE = 500 * 1024 * 1024; // 500 MB
const MAX_ARCHIVE_ENTRIES = 10000;
const MAX_COMPRESSION_RATIO = 100; // 100:1

export async function inspectArchiveSafety(
  archiveData: ArrayBuffer | Uint8Array | Blob
): Promise<{ safe: boolean; reason?: string }> {
  try {
    const zip = new JSZip();
    const loaded = await zip.loadAsync(archiveData);

    let totalUncompressedSize = 0;
    let entryCount = 0;

    const entries = Object.keys(loaded.files);
    if (entries.length > MAX_ARCHIVE_ENTRIES) {
      return {
        safe: false,
        reason: `Decompression Bomb: Archive entry count (${entries.length}) exceeds maximum limit (${MAX_ARCHIVE_ENTRIES}).`,
      };
    }

    for (const filename of entries) {
      entryCount++;

      // 1. Zip Slip Protection (Directory Traversal)
      if (
        filename.includes('../') ||
        filename.includes('..\\') ||
        filename.startsWith('/') ||
        filename.startsWith('\\') ||
        /^[a-zA-Z]:[\\/]/.test(filename)
      ) {
        return {
          safe: false,
          reason: `Zip Slip Protection: Directory traversal or absolute path detected in archive entry "${filename}".`,
        };
      }

      const fileEntry = loaded.files[filename];
      if (!fileEntry.dir) {
        // Approximate size check via internal metadata if available
        // @ts-expect-error JSZip internal metadata
        const uncompressed = fileEntry._data?.uncompressedSize || 0;
        totalUncompressedSize += uncompressed;

        // Inspect XML/XHTML files within EPUB / Office docs for XXE
        if (
          filename.endsWith('.xml') ||
          filename.endsWith('.opf') ||
          filename.endsWith('.ncx') ||
          filename.endsWith('.xhtml') ||
          filename.endsWith('.html') ||
          filename.endsWith('.svg')
        ) {
          try {
            const text = await fileEntry.async('string');
            const xmlCheck = inspectXmlSafety(text, {
              isSvg: filename.endsWith('.svg'),
            });
            if (!xmlCheck.safe) {
              return {
                safe: false,
                reason: `Archive Entry "${filename}" security violation: ${xmlCheck.reason}`,
              };
            }
          } catch {
            // Ignore text read error for binary-wrapped entries
          }
        }
      }
    }

    if (totalUncompressedSize > MAX_UNCOMPRESSED_ARCHIVE_SIZE) {
      return {
        safe: false,
        reason: `Decompression Bomb: Total uncompressed size (${Math.round(totalUncompressedSize / (1024 * 1024))}MB) exceeds 500MB safety threshold.`,
      };
    }

    return { safe: true };
  } catch (err: any) {
    return {
      safe: false,
      reason: `Corrupt or invalid archive structure: ${err.message || String(err)}`,
    };
  }
}

// ==========================================
// 5. Master File Security Validator
// ==========================================

export async function validateFileSecurity(
  file: File,
  options?: SecurityValidationOptions
): Promise<SecurityValidationResult> {
  const sanitizedFilename = sanitizeFilename(file.name);

  // 1. File Size Verification (1 GB absolute upper limit for client-side processing)
  const maxSizeBytes = options?.maxFileSizeBytes || 1024 * 1024 * 1024;
  if (file.size > maxSizeBytes) {
    return {
      valid: false,
      sanitizedFilename,
      detectedType: 'oversized',
      reason: `File size exceeds safety limit of ${Math.round(maxSizeBytes / (1024 * 1024))}MB.`,
    };
  }

  // 2. Read file header (first 8 KB for magic bytes & structure analysis)
  const headerSlice = await file
    .slice(0, Math.min(file.size, 8192))
    .arrayBuffer();
  const magic = detectMagicBytes(headerSlice);

  // 3. Immediate Executable Rejection
  if (magic.isExecutable) {
    return {
      valid: false,
      sanitizedFilename,
      detectedType: magic.type,
      reason: `Security Block: Dangerous executable or binary format detected (${magic.description || magic.type}).`,
    };
  }

  const expected = options?.expectedType?.toLowerCase();

  // 4. Expected Type Validation
  if (expected === 'pdf') {
    if (magic.type !== 'pdf') {
      return {
        valid: false,
        sanitizedFilename,
        detectedType: magic.type,
        reason: `Invalid PDF: File signature does not match PDF standard (detected: ${magic.type}).`,
      };
    }
  } else if (expected === 'image') {
    const validImageTypes = [
      'png',
      'jpeg',
      'gif',
      'webp',
      'bmp',
      'tiff',
      'svg',
      'heic',
      'avif',
    ];
    if (!validImageTypes.includes(magic.type)) {
      return {
        valid: false,
        sanitizedFilename,
        detectedType: magic.type,
        reason: `Invalid Image: File signature is not a recognized image format (detected: ${magic.type}).`,
      };
    }
  }

  // 5. XML / SVG Deep Inspection
  if (
    magic.type === 'svg' ||
    magic.type === 'xml' ||
    expected === 'svg' ||
    expected === 'xml'
  ) {
    const fullText = await file.text();
    const xmlCheck = inspectXmlSafety(fullText, {
      isSvg: magic.type === 'svg' || expected === 'svg',
    });
    if (!xmlCheck.safe) {
      return {
        valid: false,
        sanitizedFilename,
        detectedType: magic.type,
        reason: xmlCheck.reason,
      };
    }
  }

  // 6. Archive Deep Inspection (EPUB, ZIP, CBZ, Office)
  if (
    magic.type === 'zip' ||
    expected === 'epub' ||
    expected === 'zip' ||
    expected === 'cbz'
  ) {
    if (!options?.skipArchiveDeepInspection) {
      const buffer = await file.arrayBuffer();
      const archiveCheck = await inspectArchiveSafety(buffer);
      if (!archiveCheck.safe) {
        return {
          valid: false,
          sanitizedFilename,
          detectedType: 'zip',
          reason: archiveCheck.reason,
        };
      }
    }
  }

  return {
    valid: true,
    sanitizedFilename,
    detectedType: magic.type,
  };
}

export async function validateFilesSecurity(
  files: File[],
  options?: SecurityValidationOptions
): Promise<{
  validFiles: File[];
  rejectedFiles: Array<{ file: File; reason: string }>;
}> {
  const validFiles: File[] = [];
  const rejectedFiles: Array<{ file: File; reason: string }> = [];

  for (const f of files) {
    const res = await validateFileSecurity(f, options);
    if (res.valid) {
      // Re-wrap with sanitized filename if modified
      if (res.sanitizedFilename !== f.name) {
        const cleanFile = new File([f], res.sanitizedFilename, {
          type: f.type,
          lastModified: f.lastModified,
        });
        validFiles.push(cleanFile);
      } else {
        validFiles.push(f);
      }
    } else {
      rejectedFiles.push({
        file: f,
        reason: res.reason || 'Security check failed',
      });
    }
  }

  return { validFiles, rejectedFiles };
}
