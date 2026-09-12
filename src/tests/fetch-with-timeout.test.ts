import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  fetchWithTimeout,
  FetchTimeoutError,
  DEFAULT_FETCH_TIMEOUT_MS,
} from '../js/utils/fetch-with-timeout';

describe('fetchWithTimeout', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('passes an abort signal to fetch and returns its response', async () => {
    const response = new Response('ok', { status: 200 });
    const spy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(response as unknown as Response);

    await expect(fetchWithTimeout('https://example.test/file')).resolves.toBe(
      response
    );

    const init = spy.mock.calls[0][1] as RequestInit;
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('aborts and reports a FetchTimeoutError once the deadline passes', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('Aborted', 'AbortError'))
          );
        })
    );

    const promise = fetchWithTimeout('https://example.test/slow', {
      timeoutMs: 20,
    });

    await expect(promise).rejects.toBeInstanceOf(FetchTimeoutError);
    await expect(promise).rejects.toMatchObject({
      url: 'https://example.test/slow',
      timeoutMs: 20,
    });
  });

  it('lets a genuine network error through unchanged', async () => {
    const networkError = new TypeError('Failed to fetch');
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(networkError);

    await expect(fetchWithTimeout('https://example.test/down')).rejects.toBe(
      networkError
    );
  });

  it('defaults to a 30 s deadline', () => {
    expect(DEFAULT_FETCH_TIMEOUT_MS).toBe(30_000);
  });
});
