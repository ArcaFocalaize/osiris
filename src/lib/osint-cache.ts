import { NextResponse } from 'next/server';

// Lightweight server-side helpers shared by the OSINT API routes:
//  - an in-memory TTL cache to short-circuit repeated identical upstream
//    lookups (the same target is often queried several times in a session),
//  - a JSON response helper that attaches sensible Cache-Control headers so
//    browsers / CDNs can reuse deterministic results,
//  - a fetch wrapper with per-attempt timeout and bounded retry/backoff for
//    flaky third-party sources.

interface CacheEntry { value: unknown; expires: number }

const store = new Map<string, CacheEntry>();
const MAX_ENTRIES = 500;

export function getMemo<T>(key: string): T | undefined {
  const hit = store.get(key);
  if (!hit) return undefined;
  if (Date.now() > hit.expires) {
    store.delete(key);
    return undefined;
  }
  // Refresh LRU ordering.
  store.delete(key);
  store.set(key, hit);
  return hit.value as T;
}

export function setMemo(key: string, value: unknown, ttlMs: number): void {
  if (store.size >= MAX_ENTRIES) {
    const oldest = store.keys().next().value;
    if (oldest !== undefined) store.delete(oldest);
  }
  store.set(key, { value, expires: Date.now() + ttlMs });
}

// JSON response with Cache-Control so deterministic lookups can be reused by
// the browser and any CDN in front of the app.
export function cachedJson(data: unknown, ttlSeconds: number, init?: ResponseInit) {
  return NextResponse.json(data, {
    ...init,
    headers: {
      ...(init?.headers as Record<string, string> | undefined),
      'Cache-Control': `public, s-maxage=${ttlSeconds}, stale-while-revalidate=${ttlSeconds * 2}`,
    },
  });
}

interface FetchRetryOptions {
  retries?: number;     // additional attempts after the first (default 1)
  timeoutMs?: number;   // per-attempt timeout (default 8000)
  backoffMs?: number;   // base backoff, doubled each retry (default 400)
}

// fetch with a per-attempt timeout and bounded retry on network errors,
// HTTP 5xx and 429. Client errors (4xx other than 429) are returned as-is and
// not retried. Throws only if every attempt fails to produce a response.
export async function fetchRetry(
  url: string,
  init: RequestInit = {},
  { retries = 1, timeoutMs = 8000, backoffMs = 400 }: FetchRetryOptions = {},
): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        ...init,
        signal: init.signal ?? AbortSignal.timeout(timeoutMs),
      });
      if (res.ok || (res.status < 500 && res.status !== 429)) return res;
      lastError = new Error(`HTTP ${res.status}`);
    } catch (e) {
      lastError = e;
    }
    if (attempt < retries) {
      await new Promise((r) => setTimeout(r, backoffMs * 2 ** attempt));
    }
  }
  throw lastError instanceof Error ? lastError : new Error('fetch failed');
}
