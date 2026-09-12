import { showLoader, hideLoader, showAlert } from '../ui.js';
import { state } from '../state.js';
import { t } from '../i18n/index.js';
import {
  validateFileSecurity,
  validateFilesSecurity,
  sanitizeFilename,
} from '../security/fileValidator.js';
import { fetchWithTimeout } from '../utils/fetch-with-timeout.js';
import { isCurrentPageCrossOriginIsolated } from '../config/cross-origin.js';
import { setInputFiles } from '../utils/set-input-files.js';
import { acceptHintForTool } from '../security/fileGuard.js';
import { getToolIdFromPath } from '../utils/disabled-tools.js';

// Storage keys
const STORAGE_CLIENT_ID = 'bentopdf_gdrive_client_id';
const STORAGE_API_KEY = 'bentopdf_gdrive_api_key';
const STORAGE_APP_ID = 'bentopdf_gdrive_app_id';

// Google API URLs
const GIS_SCRIPT_URL = 'https://accounts.google.com/gsi/client';
const GAPI_SCRIPT_URL = 'https://apis.google.com/js/api.js';
// Least privilege: `drive.file` only grants access to the files the user picks
// through the Google Picker, not to their whole Drive. It requires the Picker to
// be built with the application's App ID -- see requireGoogleAppId() below.
const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive.file';

interface TokenState {
  accessToken: string;
  expiresAt: number;
}

const STORAGE_OAUTH_TOKEN = 'bentopdf_gdrive_oauth_token';

let cachedToken: TokenState | null = null;
let scriptsLoadedPromise: Promise<void> | null = null;
let activeTargetInput: HTMLInputElement | null = null;

/**
 * The access token is kept in memory and mirrored to sessionStorage.
 *
 * BentoPDF is a multi-page application: every tool is its own HTML document, so
 * an in-memory-only token is lost on each navigation and the user faces a
 * sign-in window per tool. That is unusable.
 *
 * sessionStorage is readable by any script in the page, which is a real cost.
 * It is accepted here because the scope is `drive.file`: the token grants access
 * only to the files the user picked through the Picker, never to the rest of the
 * Drive. The storage is tab-scoped and dies with the tab; `disconnectGoogleDrive`
 * revokes the token outright.
 */
export function getCachedToken(): TokenState | null {
  if (cachedToken && Date.now() < cachedToken.expiresAt) {
    return cachedToken;
  }
  try {
    const raw = sessionStorage.getItem(STORAGE_OAUTH_TOKEN);
    if (raw) {
      const parsed = JSON.parse(raw) as TokenState;
      if (parsed.accessToken && Date.now() < parsed.expiresAt) {
        cachedToken = parsed;
        return cachedToken;
      }
      // Expired: do not leave a dead token lying around.
      sessionStorage.removeItem(STORAGE_OAUTH_TOKEN);
    }
  } catch {
    // Storage unavailable or corrupt: fall back to in-memory only.
  }
  return null;
}

export function saveCachedToken(token: TokenState): void {
  cachedToken = token;
  try {
    sessionStorage.setItem(STORAGE_OAUTH_TOKEN, JSON.stringify(token));
  } catch {
    // Quota or private mode: the in-memory copy still serves this page.
  }
}

export function clearCachedToken(): void {
  cachedToken = null;
  try {
    sessionStorage.removeItem(STORAGE_OAUTH_TOKEN);
  } catch {
    // Nothing to clear.
  }
}

export function isGoogleDriveConnected(): boolean {
  return Boolean(getCachedToken());
}

// ==========================================
// 1. Credentials and Settings Helpers
// ==========================================

export function getGoogleClientId(): string {
  return (
    localStorage.getItem(STORAGE_CLIENT_ID)?.trim() ||
    (import.meta.env.VITE_GOOGLE_CLIENT_ID || '').trim()
  );
}

export function getGoogleApiKey(): string {
  return (
    localStorage.getItem(STORAGE_API_KEY)?.trim() ||
    (import.meta.env.VITE_GOOGLE_API_KEY || '').trim()
  );
}

export function getGoogleAppId(): string {
  const customAppId =
    localStorage.getItem(STORAGE_APP_ID)?.trim() ||
    (import.meta.env.VITE_GOOGLE_APP_ID || '').trim();
  if (customAppId) return customAppId;

  // Derive project number from standard Client ID (e.g. 123456789-xyz.apps.googleusercontent.com)
  const clientId = getGoogleClientId();
  const match = clientId.match(/^(\d+)-/);
  return match ? match[1] : '';
}

/**
 * App ID, or a clear error explaining what to configure.
 *
 * The `drive.file` scope only grants access to files chosen through a Picker
 * that carries this application's App ID, so an absent one is a configuration
 * error, not something to work around.
 */
export function requireGoogleAppId(): string {
  const appId = getGoogleAppId();
  if (!appId) {
    throw new Error(t('security.driveAppIdRequired'));
  }
  return appId;
}

export function isGoogleDriveConfigured(): boolean {
  return Boolean(getGoogleClientId() && getGoogleApiKey() && getGoogleAppId());
}

export function saveGoogleCredentials(
  clientId: string,
  apiKey: string,
  appId: string = ''
): void {
  localStorage.setItem(STORAGE_CLIENT_ID, clientId.trim());
  localStorage.setItem(STORAGE_API_KEY, apiKey.trim());
  if (appId.trim()) {
    localStorage.setItem(STORAGE_APP_ID, appId.trim());
  } else {
    localStorage.removeItem(STORAGE_APP_ID);
  }
}

export function clearGoogleCredentials(): void {
  localStorage.removeItem(STORAGE_CLIENT_ID);
  localStorage.removeItem(STORAGE_API_KEY);
  localStorage.removeItem(STORAGE_APP_ID);
  clearCachedToken();
  updateNavbarGoogleDriveUI();
}

export function disconnectGoogleDrive(): void {
  const currentToken = getCachedToken();
  if (currentToken?.accessToken && (window as any).google?.accounts?.oauth2) {
    try {
      (window as any).google.accounts.oauth2.revoke(
        currentToken.accessToken,
        () => {
          console.debug('[GoogleDrive] Access token revoked.');
        }
      );
    } catch (e) {
      console.warn('[GoogleDrive] Revocation error:', e);
    }
  }
  clearCachedToken();
  updateNavbarGoogleDriveUI();
}

// ==========================================
// 2. Dynamic Google Scripts Loading
// ==========================================

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[src="${src}"]`);
    if (existing) {
      resolve();
      return;
    }
    const script = document.createElement('script');
    script.src = src;
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () =>
      reject(new Error(`Failed to load Google script: ${src}`));
    document.head.appendChild(script);
  });
}

export function loadGoogleScripts(): Promise<void> {
  if (scriptsLoadedPromise) return scriptsLoadedPromise;

  scriptsLoadedPromise = (async () => {
    // 1. Load Google Identity Services (GIS)
    await loadScript(GIS_SCRIPT_URL);

    // 2. Load Google API Client (gapi)
    await loadScript(GAPI_SCRIPT_URL);

    // 3. Load GAPI Picker module
    await new Promise<void>((resolve, reject) => {
      const gapi = (window as any).gapi;
      if (!gapi) {
        reject(new Error('Google API client (gapi) not available.'));
        return;
      }
      gapi.load('picker', {
        callback: () => resolve(),
        onerror: () =>
          reject(new Error('Failed to load Google Picker module.')),
      });
    });
  })();

  return scriptsLoadedPromise;
}

// ==========================================
// 3. OAuth 2.0 Authentication
// ==========================================

let tokenClientInstance: any = null;

export async function requestGoogleAccessToken(
  forceConsent = false
): Promise<string> {
  const clientId = getGoogleClientId();
  if (!clientId) {
    throw new Error('Google Client ID is not configured.');
  }

  // Check the in-memory token
  const existing = getCachedToken();
  if (existing && !forceConsent) {
    return existing.accessToken;
  }

  await loadGoogleScripts();

  const google = (window as any).google;
  if (!google?.accounts?.oauth2) {
    throw new Error('Google Identity Services not available.');
  }

  return new Promise((resolve, reject) => {
    let resolved = false;
    let pendingErrorTimer: any = null;

    // Safety timeout after 45 seconds to prevent indefinite loading spinner
    const globalTimeout = setTimeout(() => {
      if (resolved) return;
      resolved = true;
      console.warn('[GoogleDrive] Authorization request timed out.');
      reject(new Error(t('security.driveTimeout')));
    }, 45000);

    const onTokenSuccess = (tokenResponse: any) => {
      clearTimeout(globalTimeout);
      if (pendingErrorTimer) {
        clearTimeout(pendingErrorTimer);
        pendingErrorTimer = null;
      }
      if (resolved) return;
      resolved = true;

      if (tokenResponse.error) {
        reject(
          new Error(
            tokenResponse.error_description ||
              tokenResponse.error ||
              'Google auth error'
          )
        );
        return;
      }

      const expiresIn = Number(tokenResponse.expires_in) || 3600;
      saveCachedToken({
        accessToken: tokenResponse.access_token,
        expiresAt: Date.now() + (expiresIn - 60) * 1000,
      });
      updateNavbarGoogleDriveUI();
      resolve(tokenResponse.access_token);
    };

    const onTokenError = (err: any) => {
      console.warn('[GoogleDrive] Auth error_callback received:', err);

      // If GIS reports popup_closed, the window might have closed right after completing OAuth,
      // but before the postMessage event is delivered to the main window.
      // Wait 1200ms to allow onTokenSuccess to process before failing.
      if (err?.type === 'popup_closed') {
        if (pendingErrorTimer) clearTimeout(pendingErrorTimer);
        pendingErrorTimer = setTimeout(() => {
          clearTimeout(globalTimeout);
          if (resolved) return;
          resolved = true;
          console.error(
            '[GoogleDrive] Timeout reached after popup_closed without token.'
          );
          reject(
            new Error(
              "La fenêtre de connexion a été fermée avant la fin de l'autorisation.\n\n" +
                'Points à vérifier dans votre console Google Cloud :\n' +
                '1. Si votre application est en mode « En test », votre adresse Gmail DOIT être ajoutée dans « Utilisateurs test » (Écran de consentement OAuth).\n' +
                "2. L'URL « http://localhost:5173 » (sans slash à la fin) doit être dans « Origines JavaScript autorisées ».\n" +
                '3. Si Google affiche « Application non validée », cliquez sur « Paramètres avancés » puis « Accéder à BentoPDF ».'
            )
          );
        }, 1200);
        return;
      }

      clearTimeout(globalTimeout);
      if (resolved) return;
      resolved = true;
      reject(
        new Error(
          err?.message ||
            'Google authorization was cancelled or popup was blocked by browser.'
        )
      );
    };

    // Initialize token client once or re-use with updated callbacks
    if (!tokenClientInstance || tokenClientInstance._clientId !== clientId) {
      tokenClientInstance = google.accounts.oauth2.initTokenClient({
        client_id: clientId,
        scope: DRIVE_SCOPE,
        callback: onTokenSuccess,
        error_callback: onTokenError,
      });
      tokenClientInstance._clientId = clientId;
    } else {
      tokenClientInstance.callback = onTokenSuccess;
      tokenClientInstance.error_callback = onTokenError;
    }

    console.debug('[GoogleDrive] Requesting access token via GIS...');
    tokenClientInstance.requestAccessToken({
      prompt: forceConsent ? 'consent' : '',
    });
  });
}

// ==========================================
// 4. File Downloading and Tool Ingestion
// ==========================================

async function downloadGoogleDriveFile(
  doc: { id: string; name: string; mimeType: string },
  accessToken: string
): Promise<File> {
  let downloadUrl: string;
  let filename = doc.name;
  let mimeType = doc.mimeType;

  // Handle Google Workspace native documents by exporting them to PDF
  if (doc.mimeType === 'application/vnd.google-apps.document') {
    downloadUrl = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(doc.id)}/export?mimeType=application/pdf`;
    if (!filename.toLowerCase().endsWith('.pdf')) filename += '.pdf';
    mimeType = 'application/pdf';
  } else if (doc.mimeType === 'application/vnd.google-apps.spreadsheet') {
    downloadUrl = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(doc.id)}/export?mimeType=application/pdf`;
    if (!filename.toLowerCase().endsWith('.pdf')) filename += '.pdf';
    mimeType = 'application/pdf';
  } else if (doc.mimeType === 'application/vnd.google-apps.presentation') {
    downloadUrl = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(doc.id)}/export?mimeType=application/pdf`;
    if (!filename.toLowerCase().endsWith('.pdf')) filename += '.pdf';
    mimeType = 'application/pdf';
  } else {
    // Regular binary file
    downloadUrl = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(doc.id)}?alt=media`;
  }

  const response = await fetchWithTimeout(downloadUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
    timeoutMs: 120_000, // large PDFs on a slow link still need to finish
  });

  if (!response.ok) {
    throw new Error(
      `Failed to download ${doc.name} (Status: ${response.status} ${response.statusText})`
    );
  }

  const blob = await response.blob();
  const cleanFilename = sanitizeFilename(filename);
  const file = new File([blob], cleanFilename, {
    type: mimeType || blob.type || 'application/pdf',
    lastModified: Date.now(),
  });

  const securityCheck = await validateFileSecurity(file);
  if (!securityCheck.valid) {
    throw new Error(
      t('security.driveFileBlocked', {
        name: cleanFilename,
        reason: securityCheck.reason,
      })
    );
  }

  return file;
}

export async function injectFilesIntoTarget(
  files: File[],
  targetInput?: HTMLInputElement | null
): Promise<void> {
  if (files.length === 0) return;

  const { validFiles, rejectedFiles } = await validateFilesSecurity(files);
  if (rejectedFiles.length > 0) {
    const errorDetails = rejectedFiles
      .map((r) => `• ${r.file.name}: ${r.reason}`)
      .join('\n');
    showAlert(
      t('security.rejectedTitle'),
      `${t('security.rejectedIntro')}\n${errorDetails}`
    );
  }

  if (validFiles.length === 0) return;

  const fileInput =
    targetInput ||
    activeTargetInput ||
    (document.getElementById('file-input') as HTMLInputElement | null);

  if (!fileInput) {
    console.warn(
      '[GoogleDrive] No file input found on page. Appending to state.files.'
    );
    state.files = [...state.files, ...validFiles];
    return;
  }

  try {
    // A multi-file input keeps what it already holds; a single-file one is
    // replaced outright.
    const existing =
      fileInput.multiple && fileInput.files ? Array.from(fileInput.files) : [];
    setInputFiles(fileInput, [...existing, ...validFiles]);

    // Dispatch standard 'change' event which triggers the tool's handler
    fileInput.dispatchEvent(new Event('change', { bubbles: true }));

    // Sync state.files as well
    if (fileInput.multiple) {
      state.files = Array.from(fileInput.files || validFiles);
    } else {
      state.files = [validFiles[0]];
    }
  } catch (err) {
    console.error('[GoogleDrive] Error injecting files into input:', err);
    // Fallback: direct state assignment
    state.files = [...state.files, ...validFiles];
  }
}

// ==========================================
// 5. Google Picker Dialog
// ==========================================

export async function openGooglePicker(
  targetInput?: HTMLInputElement | null
): Promise<void> {
  activeTargetInput = targetInput || null;

  if (!isGoogleDriveConfigured()) {
    showGoogleDriveConfigModal(() => openGooglePicker(targetInput));
    return;
  }

  const apiKey = getGoogleApiKey();

  try {
    showLoader('Connecting to Google Drive...');
    const accessToken = await requestGoogleAccessToken();
    console.debug(
      '[GoogleDrive] Access token received, hiding loader and building Google Picker...'
    );
    hideLoader();

    const google = (window as any).google;
    if (!google?.picker) {
      throw new Error('Google Picker API is not ready.');
    }

    const fileInput =
      targetInput ||
      (document.getElementById('file-input') as HTMLInputElement | null);
    const isMultiple = fileInput ? fileInput.multiple : true;
    // Le champ ne porte pas toujours d'attribut accept : sans repli, le Picker
    // n'afficherait que des PDF, y compris sur une page epub-to-pdf.
    const accept = fileInput?.accept || acceptHintForTool(getToolIdFromPath());

    const docsView = new google.picker.DocsView();
    docsView.setIncludeFolders(true);

    // Intelligent MIME filtering based on tool's accept attribute
    let viewTitle = 'Fichiers compatibles';
    if (accept) {
      const parts = accept.split(',').map((p: string) => p.trim());
      const hasPdf = parts.some(
        (p: string) => p.includes('pdf') || p === '*/*'
      );
      const hasImages = parts.some((p: string) => p.startsWith('image/'));
      const hasEpub = parts.some((p: string) => p.includes('epub'));

      if (hasPdf && !hasImages) {
        // Include PDF + exportable Google Docs + folders
        viewTitle = 'Documents PDF';
        docsView.setMimeTypes(
          'application/pdf,application/vnd.google-apps.document,application/vnd.google-apps.spreadsheet,application/vnd.google-apps.presentation,application/vnd.google-apps.folder'
        );
      } else if (hasImages && !hasPdf) {
        viewTitle = 'Images';
        docsView.setMimeTypes(
          'image/png,image/jpeg,image/webp,image/gif,image/bmp,image/tiff,image/svg+xml,application/vnd.google-apps.folder'
        );
      } else if (hasEpub) {
        viewTitle = 'Fichiers EPUB';
        docsView.setMimeTypes(
          'application/epub+zip,application/x-epub+zip,application/zip,application/x-zip-compressed,application/vnd.google-apps.folder'
        );
      } else {
        // For specialized file formats (Word, Excel, text, etc.):
        // Note: Do not include 'application/octet-stream' in setMimeTypes as Google Drive search chokes on it.
        const validMimes = new Set<string>();
        validMimes.add('application/vnd.google-apps.folder');

        for (const p of parts) {
          const clean = p.toLowerCase().trim();
          if (clean.includes('/') && !clean.startsWith('.')) {
            validMimes.add(clean);
          } else if (clean === '.epub' || clean === 'epub') {
            validMimes.add('application/epub+zip');
            validMimes.add('application/x-epub+zip');
            validMimes.add('application/zip');
            validMimes.add('application/x-zip-compressed');
          } else if (clean === '.cbz' || clean === 'cbz') {
            validMimes.add('application/vnd.comicbook+zip');
            validMimes.add('application/zip');
            validMimes.add('application/x-zip-compressed');
          } else if (clean === '.docx' || clean === '.doc') {
            validMimes.add(
              'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            );
            validMimes.add('application/msword');
            validMimes.add('application/vnd.google-apps.document');
          } else if (clean === '.xlsx' || clean === '.xls') {
            validMimes.add(
              'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            );
            validMimes.add('application/vnd.ms-excel');
            validMimes.add('application/vnd.google-apps.spreadsheet');
          } else if (clean === '.pptx' || clean === '.ppt') {
            validMimes.add(
              'application/vnd.openxmlformats-officedocument.presentationml.presentation'
            );
            validMimes.add('application/vnd.ms-powerpoint');
            validMimes.add('application/vnd.google-apps.presentation');
          }
        }
        if (validMimes.size > 1 && !parts.includes('*/*')) {
          docsView.setMimeTypes(Array.from(validMimes).join(','));
        }
      }
    } else {
      // Default: PDF + Google Workspace documents + folders
      docsView.setMimeTypes(
        'application/pdf,application/vnd.google-apps.document,application/vnd.google-apps.spreadsheet,application/vnd.google-apps.presentation,application/vnd.google-apps.folder'
      );
    }

    console.debug('[GoogleDrive] Initializing PickerBuilder...');
    const pickerBuilder = new google.picker.PickerBuilder()
      .setOAuthToken(accessToken)
      .setDeveloperKey(apiKey)
      .addView(docsView)
      .setCallback(async (data: any) => {
        console.debug('[GoogleDrive] Picker action:', data.action);
        if (data.action === google.picker.Action.PICKED) {
          const docs = data[google.picker.Response.DOCUMENTS] || [];
          if (docs.length === 0) return;

          showLoader(
            t('upload.downloadingFromDrive') ||
              (docs.length > 1
                ? `Downloading ${docs.length} files from Google Drive...`
                : 'Downloading file from Google Drive...')
          );

          try {
            const downloadedFiles: File[] = [];
            for (const doc of docs) {
              const file = await downloadGoogleDriveFile(doc, accessToken);
              downloadedFiles.push(file);
            }
            await injectFilesIntoTarget(downloadedFiles, targetInput);
          } catch (downloadErr: any) {
            console.error('[GoogleDrive] Download error:', downloadErr);
            showAlert(
              'Google Drive Download Error',
              downloadErr.message ||
                'An error occurred while downloading files from Google Drive.'
            );
          } finally {
            hideLoader();
          }
        } else if (data.action === google.picker.Action.CANCEL) {
          hideLoader();
        }
      });

    // Mandatory with the `drive.file` scope: the App ID is what tells Drive to
    // grant this application access to the files the user picks. Without it,
    // downloads fail with a 404 even though the Picker succeeded.
    //
    // The Drive SDK must be enabled on the Google Cloud project, otherwise
    // docs.google.com refuses the Picker iframe -- hence the explicit error
    // rather than a silent fallback to a broader scope.
    pickerBuilder.setAppId(requireGoogleAppId());

    if (isMultiple) {
      pickerBuilder.enableFeature(google.picker.Feature.MULTISELECT_ENABLED);
    }

    const origin = window.location.protocol + '//' + window.location.host;
    pickerBuilder.setOrigin(origin);

    pickerBuilder.setTitle('Select PDF or documents from Google Drive');

    // Make sure loader is definitely closed before showing picker
    hideLoader();

    console.debug('[GoogleDrive] Building and showing picker dialog...');
    const picker = pickerBuilder.build();
    picker.setVisible(true);

    // Google Picker creates .picker-dialog and .picker-dialog-bg.
    // Force their CSS z-index and visibility to ensure they are above any BentoPDF modals or loaders.
    if (!document.getElementById('gdrive-picker-style')) {
      const style = document.createElement('style');
      style.id = 'gdrive-picker-style';
      style.textContent = `
        .picker-dialog {
          z-index: 100000 !important;
          position: fixed !important;
        }
        .picker-dialog-bg {
          z-index: 99999 !important;
          position: fixed !important;
        }
      `;
      document.head.appendChild(style);
    }
  } catch (err: any) {
    hideLoader();
    console.error('[GoogleDrive] Open picker error:', err);
    showAlert(
      'Google Drive Connection Error',
      err.message ||
        'Could not open Google Drive. Please check your credentials and popup blocker settings.'
    );
  }
}

// ==========================================
// 6. Google Drive Configuration Modal
// ==========================================

export function showGoogleDriveConfigModal(onSuccess?: () => void): void {
  let modal = document.getElementById('gdrive-config-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'gdrive-config-modal';
    modal.className =
      'fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4';
    modal.innerHTML = `
      <div class="bg-gray-800 w-full max-w-lg rounded-2xl border border-gray-700 shadow-2xl flex flex-col overflow-hidden text-gray-200">
        <!-- Header -->
        <div class="p-5 border-b border-gray-700 flex justify-between items-center bg-gray-850">
          <div class="flex items-center gap-3">
            <div class="p-2 bg-gray-900 rounded-xl border border-gray-700">
              <svg class="w-6 h-6" viewBox="0 0 87.3 78" xmlns="http://www.w3.org/2000/svg">
                <path d="m6.6 66.85 3.85 6.65c.8 1.4 1.95 2.5 3.3 3.3l13.75-23.8H0c0 1.55.4 3.1 1.2 4.5z" fill="#0066da"/>
                <path d="m43.65 25-13.75-23.8c-1.35.8-2.5 1.9-3.3 3.3l-25.4 44c-.8 1.4-1.2 2.95-1.2 4.5h27.5z" fill="#00ac47"/>
                <path d="m73.55 76.8c1.35-.8 2.5-1.9 3.3-3.3l1.6-2.75 7.65-13.25c.8-1.4 1.2-2.95 1.2-4.5h-27.502l5.852 11.5z" fill="#ea4335"/>
                <path d="m43.65 25 13.75-23.8c-1.35-.8-2.9-1.2-4.5-1.2h-18.5c-1.6 0-3.15.45-4.5 1.2z" fill="#00832d"/>
                <path d="m59.8 53h-32.3l-13.75 23.8c1.35.8 2.9 1.2 4.5 1.2h50.8c1.6 0 3.15-.45 4.5-1.2z" fill="#26842a"/>
                <path d="m73.4 26.5-12.7-22c-.8-1.4-1.95-2.5-3.3-3.3l-13.75 23.8 16.15 28h27.45c0-1.55-.4-3.1-1.2-4.5z" fill="#ffba00"/>
              </svg>
            </div>
            <div>
              <h3 class="text-lg font-bold text-white">Google Drive Integration</h3>
              <p class="text-xs text-gray-400">Import files securely directly from your Google Drive</p>
            </div>
          </div>
          <button id="gdrive-modal-close-btn" class="text-gray-400 hover:text-white transition-colors p-1.5 rounded-lg hover:bg-gray-700">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        <!-- Body -->
        <div class="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
          <div class="p-3.5 bg-indigo-950/40 border border-indigo-500/30 rounded-xl text-xs text-indigo-200 leading-relaxed">
            <span class="font-semibold text-indigo-100">🔒 100% Client-Side & Private:</span>
            Authentication and file downloads happen entirely inside your browser. No files or tokens pass through any external server.
          </div>

          <div class="space-y-3">
            <div>
              <label for="gdrive-client-id-input" class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">
                Google Client ID <span class="text-red-400">*</span>
              </label>
              <input
                type="text"
                id="gdrive-client-id-input"
                placeholder="e.g. 123456789-abcdef.apps.googleusercontent.com"
                class="w-full bg-gray-900 border border-gray-700 rounded-lg px-3.5 py-2.5 text-sm text-white focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
              />
            </div>

            <div>
              <label for="gdrive-api-key-input" class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">
                Google API Key <span class="text-red-400">*</span>
              </label>
              <input
                type="text"
                id="gdrive-api-key-input"
                placeholder="e.g. AIzaSyD..."
                class="w-full bg-gray-900 border border-gray-700 rounded-lg px-3.5 py-2.5 text-sm text-white focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
              />
            </div>

            <div>
              <label for="gdrive-app-id-input" class="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">
                Google Project / App ID <span class="text-gray-500">(Optional)</span>
              </label>
              <input
                type="text"
                id="gdrive-app-id-input"
                placeholder="Auto-detected from Client ID if blank"
                class="w-full bg-gray-900 border border-gray-700 rounded-lg px-3.5 py-2 text-sm text-white focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-colors"
              />
            </div>
          </div>

          <!-- Quick Guide Accordion -->
          <details class="bg-gray-900/80 border border-gray-700 rounded-xl p-3 text-xs text-gray-300 group">
            <summary class="font-medium cursor-pointer flex justify-between items-center text-indigo-300 hover:text-indigo-200 select-none">
              <span>📖 How to create your free Google API credentials</span>
              <svg class="w-4 h-4 transition-transform group-open:rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
              </svg>
            </summary>
            <ol class="list-decimal list-inside space-y-1.5 mt-3 text-gray-400 pl-1">
              <li>Open <a href="https://console.cloud.google.com/apis/credentials" target="_blank" rel="noopener noreferrer" class="text-indigo-400 underline hover:text-indigo-300">Google Cloud Console</a> and select or create a project.</li>
              <li>Go to <strong>Enabled APIs & Services</strong> and enable: <em>Google Drive API</em> and <em>Google Picker API</em>.</li>
              <li>Go to <strong>Credentials</strong> &gt; <strong>Create Credentials</strong> &gt; <strong>OAuth client ID</strong>.</li>
              <li>Select <em>Web application</em>, add your URL (e.g. <code class="text-indigo-300 bg-gray-800 px-1 py-0.5 rounded">${window.location.origin}</code>) under <strong>Authorized JavaScript origins</strong>.</li>
              <li>Create an <strong>API key</strong> under Credentials.</li>
              <li>Paste the Client ID and API Key above!</li>
            </ol>
          </details>
        </div>

        <!-- Footer -->
        <div class="p-5 border-t border-gray-700 bg-gray-850 flex justify-between items-center">
          <button
            id="gdrive-modal-clear-btn"
            type="button"
            class="px-4 py-2 text-xs font-semibold text-red-400 hover:text-red-300 hover:bg-red-950/30 rounded-lg transition-colors border border-transparent hover:border-red-800/40 cursor-pointer"
          >
            Clear
          </button>
          <div class="flex gap-3">
            <button
              id="gdrive-modal-cancel-btn"
              type="button"
              class="px-4 py-2 text-sm font-semibold text-gray-300 hover:text-white bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              id="gdrive-modal-save-btn"
              type="button"
              class="px-5 py-2 text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg shadow transition-colors flex items-center gap-2 cursor-pointer"
            >
              <span>Save & Connect</span>
            </button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    // Event listeners
    const closeBtn = document.getElementById('gdrive-modal-close-btn');
    const cancelBtn = document.getElementById('gdrive-modal-cancel-btn');
    const saveBtn = document.getElementById('gdrive-modal-save-btn');
    const clearBtn = document.getElementById('gdrive-modal-clear-btn');

    const closeModal = () => {
      modal?.classList.add('hidden');
    };

    closeBtn?.addEventListener('click', closeModal);
    cancelBtn?.addEventListener('click', closeModal);
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });

    clearBtn?.addEventListener('click', () => {
      clearGoogleCredentials();
      (
        document.getElementById('gdrive-client-id-input') as HTMLInputElement
      ).value = '';
      (
        document.getElementById('gdrive-api-key-input') as HTMLInputElement
      ).value = '';
      (
        document.getElementById('gdrive-app-id-input') as HTMLInputElement
      ).value = '';
      updateSettingsStatus();
    });

    saveBtn?.addEventListener('click', () => {
      const clientId = (
        document.getElementById('gdrive-client-id-input') as HTMLInputElement
      )?.value.trim();
      const apiKey = (
        document.getElementById('gdrive-api-key-input') as HTMLInputElement
      )?.value.trim();
      const appId = (
        document.getElementById('gdrive-app-id-input') as HTMLInputElement
      )?.value.trim();

      if (!clientId || !apiKey) {
        showAlert(
          'Missing Credentials',
          'Please enter both a Google Client ID and an API Key.'
        );
        return;
      }

      saveGoogleCredentials(clientId, apiKey, appId);
      closeModal();
      updateSettingsStatus();

      if (onSuccess) {
        onSuccess();
      }
    });
  }

  // Pre-fill existing values
  const clientIdInput = document.getElementById(
    'gdrive-client-id-input'
  ) as HTMLInputElement;
  const apiKeyInput = document.getElementById(
    'gdrive-api-key-input'
  ) as HTMLInputElement;
  const appIdInput = document.getElementById(
    'gdrive-app-id-input'
  ) as HTMLInputElement;

  if (clientIdInput) clientIdInput.value = getGoogleClientId();
  if (apiKeyInput) apiKeyInput.value = getGoogleApiKey();
  if (appIdInput) appIdInput.value = getGoogleAppId();

  modal.classList.remove('hidden');
}

// ==========================================
// 7. Inject Google Drive Buttons into DOM
// ==========================================

const GOOGLE_DRIVE_SVG = `
<svg class="w-4 h-4 flex-shrink-0" viewBox="0 0 87.3 78" xmlns="http://www.w3.org/2000/svg">
  <path d="m6.6 66.85 3.85 6.65c.8 1.4 1.95 2.5 3.3 3.3l13.75-23.8H0c0 1.55.4 3.1 1.2 4.5z" fill="#0066da"/>
  <path d="m43.65 25-13.75-23.8c-1.35.8-2.5 1.9-3.3 3.3l-25.4 44c-.8 1.4-1.2 2.95-1.2 4.5h27.5z" fill="#00ac47"/>
  <path d="m73.55 76.8c1.35-.8 2.5-1.9 3.3-3.3l1.6-2.75 7.65-13.25c.8-1.4 1.2-2.95 1.2-4.5h-27.502l5.852 11.5z" fill="#ea4335"/>
  <path d="m43.65 25 13.75-23.8c-1.35-.8-2.9-1.2-4.5-1.2h-18.5c-1.6 0-3.15.45-4.5 1.2z" fill="#00832d"/>
  <path d="m59.8 53h-32.3l-13.75 23.8c1.35.8 2.9 1.2 4.5 1.2h50.8c1.6 0 3.15-.45 4.5-1.2z" fill="#26842a"/>
  <path d="m73.4 26.5-12.7-22c-.8-1.4-1.95-2.5-3.3-3.3l-13.75 23.8 16.15 28h27.45c0-1.55-.4-3.1-1.2-4.5z" fill="#ffba00"/>
</svg>
`;

function injectDropzoneButton(dropZone: HTMLElement): void {
  if (dropZone.querySelector('.gdrive-dropzone-action')) return;

  const targetInput = dropZone.querySelector(
    'input[type="file"]'
  ) as HTMLInputElement | null;

  const actionContainer = document.createElement('div');
  actionContainer.className =
    'gdrive-dropzone-action relative z-20 mt-3 pointer-events-auto flex items-center justify-center';

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className =
    'gdrive-btn group flex items-center gap-2 px-3.5 py-1.5 bg-gray-800/90 hover:bg-gray-700/95 border border-gray-600/80 hover:border-indigo-500/80 text-gray-200 hover:text-white rounded-lg text-xs font-semibold shadow-sm transition-all duration-150 cursor-pointer';
  btn.title = 'Import files directly from Google Drive';
  btn.innerHTML = `
    ${GOOGLE_DRIVE_SVG}
    <span>Google Drive</span>
  `;

  // Crucial: Stop propagation and prevent default so click doesn't trigger the hidden local file input
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    e.preventDefault();
    openGooglePicker(targetInput);
  });

  actionContainer.appendChild(btn);

  // If there's an inner container (with icon and paragraphs), append inside it or to dropZone
  const inner = dropZone.firstElementChild;
  if (inner && inner !== targetInput) {
    inner.appendChild(actionContainer);
  } else {
    dropZone.appendChild(actionContainer);
  }
}

function injectFileControlsButton(fileControls: HTMLElement): void {
  if (fileControls.querySelector('#gdrive-add-more-btn')) return;

  const addMoreBtn = fileControls.querySelector('#add-more-btn');
  if (!addMoreBtn) return;

  const gdriveBtn = document.createElement('button');
  gdriveBtn.id = 'gdrive-add-more-btn';
  gdriveBtn.type = 'button';
  gdriveBtn.className =
    'btn bg-gray-700 hover:bg-gray-600 text-white font-semibold px-4 py-2 rounded-lg flex items-center gap-2 cursor-pointer transition-colors';
  gdriveBtn.innerHTML = `
    ${GOOGLE_DRIVE_SVG}
    <span>Google Drive</span>
  `;

  gdriveBtn.addEventListener('click', (e) => {
    e.preventDefault();
    const fileInput = document.getElementById(
      'file-input'
    ) as HTMLInputElement | null;
    openGooglePicker(fileInput);
  });

  // Insert right next to Add More button
  addMoreBtn.insertAdjacentElement('afterend', gdriveBtn);
}

export function updateNavbarGoogleDriveUI(): void {
  const container = document.getElementById('nav-gdrive-container');
  if (!container) return;

  const isConfigured = isGoogleDriveConfigured();
  const token = isConfigured ? getCachedToken() : null;
  const targetState = !isConfigured
    ? 'not-configured'
    : token
      ? 'connected'
      : 'disconnected';

  // Prevent DOM mutation loop if navbar is already in desired state
  if (container.dataset.gdriveState === targetState) {
    return;
  }
  container.dataset.gdriveState = targetState;

  if (!isConfigured) {
    container.innerHTML = `
      <button
        id="nav-gdrive-config-btn"
        type="button"
        class="inline-flex items-center gap-1.5 text-xs font-medium text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 border border-gray-700 px-2.5 py-1 rounded-lg transition-colors cursor-pointer"
        title="Configurer Google Drive"
      >
        ${GOOGLE_DRIVE_SVG}
        <span>Configurer Drive</span>
      </button>
    `;
    document
      .getElementById('nav-gdrive-config-btn')
      ?.addEventListener('click', () => {
        showGoogleDriveConfigModal();
      });
    return;
  }

  if (token) {
    container.innerHTML = `
      <div class="inline-flex items-center gap-2 bg-gray-800/90 border border-emerald-500/30 pl-2.5 pr-1.5 py-1 rounded-full text-xs shadow-sm">
        <span class="flex items-center gap-1.5 font-medium text-emerald-400">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          Drive connecté
        </span>
        <button
          id="nav-gdrive-logout-btn"
          type="button"
          title="Se déconnecter de Google Drive"
          class="text-gray-400 hover:text-red-400 hover:bg-gray-700/60 p-0.5 rounded-full transition-colors cursor-pointer"
        >
          <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path>
            <line x1="12" y1="2" x2="12" y2="12"></line>
          </svg>
        </button>
      </div>
    `;
    document
      .getElementById('nav-gdrive-logout-btn')
      ?.addEventListener('click', () => {
        disconnectGoogleDrive();
      });
  } else {
    container.innerHTML = `
      <button
        id="nav-gdrive-login-btn"
        type="button"
        class="inline-flex items-center gap-2 text-xs font-semibold bg-gray-800 hover:bg-gray-700 text-gray-200 hover:text-white border border-gray-600 hover:border-indigo-500 px-3 py-1.5 rounded-lg shadow-sm transition-all duration-150 cursor-pointer"
        title="Connecter Google Drive pour tous les outils"
      >
        ${GOOGLE_DRIVE_SVG}
        <span>Connexion Google Drive</span>
      </button>
    `;
    document
      .getElementById('nav-gdrive-login-btn')
      ?.addEventListener('click', async () => {
        const btn = document.getElementById(
          'nav-gdrive-login-btn'
        ) as HTMLButtonElement | null;
        if (btn) {
          btn.disabled = true;
          btn.innerHTML = `
            <span class="w-3.5 h-3.5 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin"></span>
            <span>Connexion...</span>
          `;
        }
        try {
          await requestGoogleAccessToken();
        } catch (err: any) {
          console.warn('[GoogleDrive] Login error from navbar:', err);
          updateNavbarGoogleDriveUI();
        }
      });
  }
}

export function scanAndInjectGoogleDriveUI(): void {
  // 1. All drop zones
  const dropZones = document.querySelectorAll<HTMLElement>(
    '#drop-zone, [id^="drop-zone"], [id$="-drop-zone"]'
  );
  dropZones.forEach((dz) => injectDropzoneButton(dz));

  // 2. Multi-file controls
  const fileControlsList =
    document.querySelectorAll<HTMLElement>('#file-controls');
  fileControlsList.forEach((fc) => injectFileControlsButton(fc));

  // 3. Navbar Google Drive session button & status
  updateNavbarGoogleDriveUI();
}

// ==========================================
// 8. Settings Modal Integration
// ==========================================

function updateSettingsStatus(): void {
  const statusEl = document.getElementById('gdrive-settings-status');
  if (!statusEl) return;

  const isConfigured = isGoogleDriveConfigured();
  if (isConfigured) {
    statusEl.innerHTML = `
      <span class="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2.5 py-1 rounded-full">
        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
        Configured & Ready
      </span>
    `;
  } else {
    statusEl.innerHTML = `
      <span class="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400 bg-amber-950/40 border border-amber-500/30 px-2.5 py-1 rounded-full">
        <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
        Not Configured
      </span>
    `;
  }
}

export function setupSettingsGoogleDriveTab(): void {
  const settingsModal = document.getElementById('shortcuts-modal');
  if (!settingsModal) return;

  // Add Google Drive Tab button if not present
  const tabsContainer = settingsModal.querySelector(
    '.flex.border-b.border-gray-700'
  );
  if (tabsContainer && !document.getElementById('gdrive-tab-btn')) {
    const gdriveTabBtn = document.createElement('button');
    gdriveTabBtn.id = 'gdrive-tab-btn';
    gdriveTabBtn.type = 'button';
    gdriveTabBtn.className =
      'flex-1 py-3 text-sm font-medium text-gray-300 hover:text-white flex items-center justify-center gap-1.5 cursor-pointer transition-colors';
    gdriveTabBtn.innerHTML = `
      ${GOOGLE_DRIVE_SVG}
      <span>Google Drive</span>
    `;
    tabsContainer.appendChild(gdriveTabBtn);

    // Create tab content container
    const shortcutsContent = document.getElementById('shortcuts-tab-content');
    const preferencesContent = document.getElementById(
      'preferences-tab-content'
    );

    const gdriveContent = document.createElement('div');
    gdriveContent.id = 'gdrive-tab-content';
    gdriveContent.className = 'hidden p-6 overflow-y-auto flex-grow space-y-4';
    gdriveContent.innerHTML = `
      <div class="flex items-center justify-between pb-3 border-b border-gray-700">
        <div>
          <h4 class="text-lg font-semibold text-white">Google Drive Configuration</h4>
          <p class="text-xs text-gray-400">Connect Google Drive to import files directly into any PDF tool.</p>
        </div>
        <div id="gdrive-settings-status"></div>
      </div>

      <div class="space-y-4">
        <div>
          <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">
            Google Client ID
          </label>
          <input
            type="text"
            id="gdrive-settings-client-id"
            placeholder="e.g. 123456789-abcdef.apps.googleusercontent.com"
            class="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:ring-indigo-500 focus:border-indigo-500"
          />
        </div>

        <div>
          <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">
            Google API Key
          </label>
          <input
            type="text"
            id="gdrive-settings-api-key"
            placeholder="e.g. AIzaSyD..."
            class="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:ring-indigo-500 focus:border-indigo-500"
          />
        </div>

        <div>
          <label class="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">
            App ID / Project Number (Optional)
          </label>
          <input
            type="text"
            id="gdrive-settings-app-id"
            placeholder="e.g. 123456789"
            class="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:ring-indigo-500 focus:border-indigo-500"
          />
        </div>

        <div class="flex gap-3 pt-2">
          <button
            id="gdrive-settings-save-btn"
            type="button"
            class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg transition-colors cursor-pointer"
          >
            Save Credentials
          </button>
          <button
            id="gdrive-settings-disconnect-btn"
            type="button"
            class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 hover:text-white text-sm font-semibold rounded-lg transition-colors cursor-pointer"
          >
            Disconnect & Revoke Token
          </button>
          <button
            id="gdrive-settings-clear-btn"
            type="button"
            class="px-4 py-2 text-red-400 hover:text-red-300 text-sm font-semibold rounded-lg transition-colors cursor-pointer"
          >
            Clear All
          </button>
        </div>
      </div>
    `;

    preferencesContent?.insertAdjacentElement('afterend', gdriveContent);

    // Tab switching wiring
    const shortcutsTabBtn = document.getElementById('shortcuts-tab-btn');
    const preferencesTabBtn = document.getElementById('preferences-tab-btn');
    const shortcutsFooter = document.getElementById('shortcuts-tab-footer');
    const preferencesFooter = document.getElementById('preferences-tab-footer');
    const resetShortcutsBtn = document.getElementById('reset-shortcuts-btn');

    gdriveTabBtn.addEventListener('click', () => {
      // Highlight gdrive tab
      gdriveTabBtn.classList.add('bg-indigo-600', 'text-white');
      gdriveTabBtn.classList.remove('text-gray-300');
      shortcutsTabBtn?.classList.remove('bg-indigo-600', 'text-white');
      shortcutsTabBtn?.classList.add('text-gray-300');
      preferencesTabBtn?.classList.remove('bg-indigo-600', 'text-white');
      preferencesTabBtn?.classList.add('text-gray-300');

      // Show content
      gdriveContent.classList.remove('hidden');
      shortcutsContent?.classList.add('hidden');
      preferencesContent?.classList.add('hidden');
      shortcutsFooter?.classList.add('hidden');
      preferencesFooter?.classList.add('hidden');
      resetShortcutsBtn?.classList.add('hidden');

      // Pre-fill inputs
      (
        document.getElementById('gdrive-settings-client-id') as HTMLInputElement
      ).value = getGoogleClientId();
      (
        document.getElementById('gdrive-settings-api-key') as HTMLInputElement
      ).value = getGoogleApiKey();
      (
        document.getElementById('gdrive-settings-app-id') as HTMLInputElement
      ).value = getGoogleAppId();
      updateSettingsStatus();
    });

    // Reset styles on clicking other tabs
    shortcutsTabBtn?.addEventListener('click', () => {
      gdriveTabBtn.classList.remove('bg-indigo-600', 'text-white');
      gdriveTabBtn.classList.add('text-gray-300');
      gdriveContent.classList.add('hidden');
    });

    preferencesTabBtn?.addEventListener('click', () => {
      gdriveTabBtn.classList.remove('bg-indigo-600', 'text-white');
      gdriveTabBtn.classList.add('text-gray-300');
      gdriveContent.classList.add('hidden');
    });

    // Save button
    document
      .getElementById('gdrive-settings-save-btn')
      ?.addEventListener('click', () => {
        const cid = (
          document.getElementById(
            'gdrive-settings-client-id'
          ) as HTMLInputElement
        )?.value.trim();
        const akey = (
          document.getElementById('gdrive-settings-api-key') as HTMLInputElement
        )?.value.trim();
        const aid = (
          document.getElementById('gdrive-settings-app-id') as HTMLInputElement
        )?.value.trim();

        if (!cid || !akey) {
          showAlert(
            'Missing Fields',
            'Please enter both a Google Client ID and an API Key.'
          );
          return;
        }

        saveGoogleCredentials(cid, akey, aid);
        updateSettingsStatus();
        showAlert(
          'Saved',
          'Google Drive credentials saved successfully!',
          'success'
        );
      });

    // Disconnect button
    document
      .getElementById('gdrive-settings-disconnect-btn')
      ?.addEventListener('click', () => {
        disconnectGoogleDrive();
        showAlert(
          'Disconnected',
          'Disconnected from Google Drive and session token revoked.'
        );
      });

    // Clear button
    document
      .getElementById('gdrive-settings-clear-btn')
      ?.addEventListener('click', () => {
        clearGoogleCredentials();
        (
          document.getElementById(
            'gdrive-settings-client-id'
          ) as HTMLInputElement
        ).value = '';
        (
          document.getElementById('gdrive-settings-api-key') as HTMLInputElement
        ).value = '';
        (
          document.getElementById('gdrive-settings-app-id') as HTMLInputElement
        ).value = '';
        updateSettingsStatus();
        showAlert('Cleared', 'Google Drive credentials have been cleared.');
      });
  }
}

let isGoogleDriveInitialized = false;
let mutationDebounceTimer: any = null;

export function initGoogleDrive(): void {
  if (isGoogleDriveInitialized) return;

  // Pages served with COOP `same-origin` keep SharedArrayBuffer and lose the
  // OAuth popup. Showing a Drive button there would offer a sign-in that cannot
  // complete.
  if (isCurrentPageCrossOriginIsolated()) {
    console.debug(
      '[GoogleDrive] Skipped: this page is cross-origin isolated for WASM threading.'
    );
    return;
  }

  isGoogleDriveInitialized = true;

  // Initial scan
  scanAndInjectGoogleDriveUI();
  setupSettingsGoogleDriveTab();

  // Watch for dynamic DOM changes (debounced with 300ms delay to prevent mutation loops)
  const observer = new MutationObserver(() => {
    if (mutationDebounceTimer) return;
    mutationDebounceTimer = setTimeout(() => {
      mutationDebounceTimer = null;
      scanAndInjectGoogleDriveUI();
      setupSettingsGoogleDriveTab();
    }, 300);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });

  // Pre-load Google scripts in background if already configured
  if (isGoogleDriveConfigured()) {
    loadGoogleScripts().catch((err) =>
      console.warn('[GoogleDrive] Background script pre-load warning:', err)
    );
  }
}
