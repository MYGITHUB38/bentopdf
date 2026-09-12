/**
 * `fetch` with a mandatory, explicit timeout.
 *
 * Every outbound request to a third-party API (Google Drive, OAuth, CDNs) must
 * carry one: without it a stalled connection leaves the UI on a loading spinner
 * with no way back. Rule 01 §9 of the repository ruleset.
 */

export const DEFAULT_FETCH_TIMEOUT_MS = 30_000;

export class FetchTimeoutError extends Error {
  readonly url: string;
  readonly timeoutMs: number;

  constructor(url: string, timeoutMs: number) {
    super(`Request to ${url} timed out after ${timeoutMs} ms`);
    this.name = 'FetchTimeoutError';
    this.url = url;
    this.timeoutMs = timeoutMs;
  }
}

export interface FetchWithTimeoutOptions extends RequestInit {
  /** Milliseconds before the request is aborted. Defaults to 30 s. */
  timeoutMs?: number;
}

/**
 * Aborts the request once `timeoutMs` has elapsed and reports it as a
 * `FetchTimeoutError`, so callers can tell a timeout from a network error.
 *
 * An `AbortSignal` supplied by the caller is honoured as well: whichever fires
 * first wins.
 */
export async function fetchWithTimeout(
  input: RequestInfo | URL,
  options: FetchWithTimeoutOptions = {}
): Promise<Response> {
  const { timeoutMs = DEFAULT_FETCH_TIMEOUT_MS, signal, ...rest } = options;

  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  // AbortSignal.any is not available everywhere yet; fall back to the timeout
  // alone rather than dropping the timeout, which is the guarantee that matters.
  const combined =
    signal && typeof (AbortSignal as { any?: unknown }).any === 'function'
      ? AbortSignal.any([signal, timeoutSignal])
      : timeoutSignal;

  try {
    return await fetch(input, { ...rest, signal: combined });
  } catch (err) {
    if (timeoutSignal.aborted) {
      const url =
        typeof input === 'string'
          ? input
          : String((input as Request).url ?? input);
      throw new FetchTimeoutError(url, timeoutMs);
    }
    throw err;
  }
}
