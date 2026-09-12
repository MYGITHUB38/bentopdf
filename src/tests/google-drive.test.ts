import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  saveGoogleCredentials,
  getGoogleClientId,
  getGoogleApiKey,
  getGoogleAppId,
  isGoogleDriveConfigured,
  requireGoogleAppId,
  clearGoogleCredentials,
  injectFilesIntoTarget,
  scanAndInjectGoogleDriveUI,
  setupSettingsGoogleDriveTab,
  saveCachedToken,
  getCachedToken,
  clearCachedToken,
  isGoogleDriveConnected,
  updateNavbarGoogleDriveUI,
} from '../js/integrations/googleDrive';
import { state } from '../js/state';

describe('Google Drive Integration', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    clearCachedToken();
    document.body.innerHTML = '';
    state.files = [];
    vi.stubEnv('VITE_GOOGLE_CLIENT_ID', '');
    vi.stubEnv('VITE_GOOGLE_API_KEY', '');
    vi.stubEnv('VITE_GOOGLE_APP_ID', '');
  });

  describe('Credentials Management', () => {
    it('returns empty when no credentials are configured', () => {
      expect(isGoogleDriveConfigured()).toBe(false);
      expect(getGoogleClientId()).toBe('');
      expect(getGoogleApiKey()).toBe('');
    });

    it('saves and retrieves Google credentials correctly', () => {
      saveGoogleCredentials(
        '123456789-test.apps.googleusercontent.com',
        'AIzaSyTestApiKey',
        '123456789'
      );
      expect(isGoogleDriveConfigured()).toBe(true);
      expect(getGoogleClientId()).toBe(
        '123456789-test.apps.googleusercontent.com'
      );
      expect(getGoogleApiKey()).toBe('AIzaSyTestApiKey');
      expect(getGoogleAppId()).toBe('123456789');
    });

    it('derives app ID automatically from client ID if app ID is omitted', () => {
      saveGoogleCredentials(
        '987654321-example.apps.googleusercontent.com',
        'AIzaSyTestApiKey'
      );
      expect(getGoogleAppId()).toBe('987654321');
    });

    it('clears credentials from storage', () => {
      saveGoogleCredentials(
        '123456789-test.apps.googleusercontent.com',
        'AIzaSyTestApiKey',
        '123456789'
      );
      expect(isGoogleDriveConfigured()).toBe(true);
      clearGoogleCredentials();
      expect(isGoogleDriveConfigured()).toBe(false);
      expect(getGoogleClientId()).toBe('');
      expect(getGoogleApiKey()).toBe('');
    });

    it('is not configured without an app ID, which the drive.file scope requires', () => {
      // A client ID with no numeric project prefix leaves nothing to derive.
      saveGoogleCredentials('client-id', 'AIzaSyTestApiKey');
      expect(getGoogleAppId()).toBe('');
      expect(isGoogleDriveConfigured()).toBe(false);
    });

    it('requireGoogleAppId throws rather than falling back to a broader scope', () => {
      saveGoogleCredentials('client-id', 'AIzaSyTestApiKey');
      expect(() => requireGoogleAppId()).toThrow();

      saveGoogleCredentials(
        '123456789-test.apps.googleusercontent.com',
        'AIzaSyTestApiKey'
      );
      expect(requireGoogleAppId()).toBe('123456789');
    });
  });

  describe('Access token handling', () => {
    it('survives a page navigation: the token is mirrored to sessionStorage', () => {
      // BentoPDF is multi-page; without this the user faces a sign-in window per
      // tool. sessionStorage is tab-scoped and dies with the tab.
      saveCachedToken({
        accessToken: 'ya29.test-token',
        expiresAt: Date.now() + 60_000,
      });

      expect(getCachedToken()?.accessToken).toBe('ya29.test-token');
      expect(isGoogleDriveConnected()).toBe(true);

      const persisted = Object.keys(sessionStorage).some((key) =>
        (sessionStorage.getItem(key) || '').includes('ya29.test-token')
      );
      expect(persisted).toBe(true);

      clearCachedToken();
      expect(getCachedToken()).toBeNull();
      expect(isGoogleDriveConnected()).toBe(false);
      const stillThere = Object.keys(sessionStorage).some((key) =>
        (sessionStorage.getItem(key) || '').includes('ya29.test-token')
      );
      expect(stillThere).toBe(false);
    });

    it('never persists to localStorage, which would outlive the tab', () => {
      saveCachedToken({
        accessToken: 'ya29.long-lived',
        expiresAt: Date.now() + 60_000,
      });
      const inLocal = Object.keys(localStorage).some((key) =>
        (localStorage.getItem(key) || '').includes('ya29.long-lived')
      );
      expect(inLocal).toBe(false);
      clearCachedToken();
    });

    it('treats an expired token as absent and clears the stale copy', () => {
      saveCachedToken({
        accessToken: 'ya29.stale',
        expiresAt: Date.now() - 1,
      });
      expect(getCachedToken()).toBeNull();

      const leftover = Object.keys(sessionStorage).some((key) =>
        (sessionStorage.getItem(key) || '').includes('ya29.stale')
      );
      expect(leftover).toBe(false);
    });
  });

  describe('File Injection into Tool', () => {
    it('injects files into file input and dispatches change event', async () => {
      const container = document.createElement('div');
      container.innerHTML = `
        <div id="drop-zone">
          <input id="file-input" type="file" multiple accept="application/pdf" />
        </div>
      `;
      document.body.appendChild(container);

      const fileInput = document.getElementById(
        'file-input'
      ) as HTMLInputElement;
      let changeFired = false;
      fileInput.addEventListener('change', () => {
        changeFired = true;
      });

      const mockFile = new File(['%PDF-1.4 test'], 'sample.pdf', {
        type: 'application/pdf',
      });

      await injectFilesIntoTarget([mockFile], fileInput);

      expect(changeFired).toBe(true);
      expect(fileInput.files?.length).toBe(1);
      expect(fileInput.files?.[0].name).toBe('sample.pdf');
      expect(state.files).toHaveLength(1);
      expect(state.files[0].name).toBe('sample.pdf');
    });
  });

  describe('UI Injection', () => {
    it('injects Google Drive button into dropzone without triggering file input', () => {
      const dropZone = document.createElement('div');
      dropZone.id = 'drop-zone';
      dropZone.innerHTML = `
        <div class="content">
          <p>Drop here</p>
        </div>
        <input id="file-input" type="file" />
      `;
      document.body.appendChild(dropZone);

      scanAndInjectGoogleDriveUI();

      const btn = dropZone.querySelector('.gdrive-btn');
      expect(btn).not.toBeNull();
      expect(btn?.textContent).toContain('Google Drive');
    });

    it('injects Google Drive button into file controls', () => {
      const controls = document.createElement('div');
      controls.id = 'file-controls';
      controls.innerHTML = `
        <button id="add-more-btn">Add More</button>
      `;
      document.body.appendChild(controls);

      scanAndInjectGoogleDriveUI();

      const gdriveBtn = document.getElementById('gdrive-add-more-btn');
      expect(gdriveBtn).not.toBeNull();
      expect(gdriveBtn?.textContent).toContain('Google Drive');
    });

    it('injects Google Drive tab into settings modal', () => {
      const modal = document.createElement('div');
      modal.id = 'shortcuts-modal';
      modal.innerHTML = `
        <div class="flex border-b border-gray-700">
          <button id="shortcuts-tab-btn">Shortcuts</button>
          <button id="preferences-tab-btn">Preferences</button>
        </div>
        <div id="shortcuts-tab-content"></div>
        <div id="preferences-tab-content"></div>
      `;
      document.body.appendChild(modal);

      setupSettingsGoogleDriveTab();

      const gdriveTabBtn = document.getElementById('gdrive-tab-btn');
      expect(gdriveTabBtn).not.toBeNull();
      expect(gdriveTabBtn?.textContent).toContain('Google Drive');

      const gdriveContent = document.getElementById('gdrive-tab-content');
      expect(gdriveContent).not.toBeNull();
    });

    it('injects Google Drive login or status button into navbar', () => {
      saveGoogleCredentials('123-client', 'aiza-key');
      const container = document.createElement('div');
      container.id = 'nav-gdrive-container';
      document.body.appendChild(container);

      updateNavbarGoogleDriveUI();

      const loginBtn = document.getElementById('nav-gdrive-login-btn');
      expect(loginBtn).not.toBeNull();
      expect(loginBtn?.textContent).toContain('Connexion Google Drive');

      // Now simulate active session
      saveCachedToken({
        accessToken: 'mock-token',
        expiresAt: Date.now() + 3600000,
      });

      updateNavbarGoogleDriveUI();

      expect(container.textContent).toContain('Drive connecté');
      const logoutBtn = document.getElementById('nav-gdrive-logout-btn');
      expect(logoutBtn).not.toBeNull();
    });
  });

  describe('Session Persistence', () => {
    it('persists token across sessionStorage and recognizes active connection', () => {
      expect(isGoogleDriveConnected()).toBe(false);
      expect(getCachedToken()).toBeNull();

      const testToken = {
        accessToken: 'ya29.sample_oauth_token',
        expiresAt: Date.now() + 3600 * 1000,
      };

      saveCachedToken(testToken);

      expect(isGoogleDriveConnected()).toBe(true);
      expect(getCachedToken()?.accessToken).toBe('ya29.sample_oauth_token');

      clearCachedToken();
      expect(isGoogleDriveConnected()).toBe(false);
      expect(getCachedToken()).toBeNull();
    });
  });
});
