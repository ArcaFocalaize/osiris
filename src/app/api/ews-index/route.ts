import { NextResponse } from 'next/server';

/**
 * OSIRIS — Elite Evacuation Warning System (EWS) Index
 *
 * Proxies the public dashboard.json produced by Kyle McDonald's AEWS project,
 * which monitors global private-jet activity as a proxy for elite evacuation
 * behaviour.  Source: https://ews.kylemcdonald.net
 *
 * Risk-mitigation design decisions:
 *  • Hardcoded CDN URL — not user-controlled, no SSRF risk.
 *  • 10-minute in-memory cache — AEWS only updates ~hourly; prevents CDN abuse.
 *  • 5-second fetch timeout — upstream CDN failures don't block Osiris.
 *  • Stale-cache fallback — if CDN is unreachable, returns last good data
 *    with `stale: true` so the UI can signal degraded accuracy.
 *  • `available: false` sentinel — if no cache exists and fetch fails, the
 *    API returns HTTP 200 with `{ available: false }`.  The UI hides the badge
 *    rather than showing broken data.
 *  • Max 20 aircraft in response — prevents unbounded payload.
 */

const EWS_URL = 'https://pub-49bb6a6f314c47be9b481c25e5f6ca9e.r2.dev/dashboard.json';
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const FETCH_TIMEOUT_MS = 5_000;
const MAX_AIRCRAFT = 20;

interface EWSAircraft {
  hex: string;
  registration: string;
  label: string;
  lat: number;
  lon: number;
  altitudeFt: number;
  groundSpeedKt: number;
}

interface EWSPayload {
  available: true;
  stale: boolean;
  source: 'live' | 'cached';
  emergencyLevel: number;  // 1–5
  alertLevel: string;      // 'normal' | 'watch' | 'elevated' | 'warning' | 'alarm'
  zScore: number;
  baselineMean: number;
  baselineStdDev: number;
  matchedCount: number;
  airborneCount: number;
  liveAircraft: EWSAircraft[];
  fetchedAt: string;
}

interface EWSUnavailable {
  available: false;
}

type EWSResult = EWSPayload | EWSUnavailable;

let cachedData: EWSPayload | null = null;
let lastFetchTime = 0;
let inflight: Promise<EWSPayload | null> | null = null;

function parseUpstream(json: any): EWSPayload {
  return {
    available: true,
    stale: false,
    source: 'live',
    emergencyLevel: Math.min(5, Math.max(1, Number(json.current?.emergencyLevel ?? 1))),
    alertLevel: String(json.current?.alertLevel ?? 'normal'),
    zScore: Number(json.current?.zScore ?? 0),
    baselineMean: Number(json.current?.baselineMean ?? 0),
    baselineStdDev: Number(json.current?.baselineStdDev ?? 0),
    matchedCount: Number(json.liveStatus?.matchedCount ?? 0),
    airborneCount: Number(json.liveStatus?.airborneCount ?? 0),
    liveAircraft: (Array.isArray(json.liveAircraft) ? json.liveAircraft : [])
      .slice(0, MAX_AIRCRAFT)
      .map((a: any) => ({
        hex: String(a.hex ?? ''),
        registration: String(a.registration ?? ''),
        label: String(a.label ?? ''),
        lat: Number(a.lat ?? 0),
        lon: Number(a.lon ?? 0),
        altitudeFt: Number(a.altitudeFt ?? 0),
        groundSpeedKt: Number(a.groundSpeedKt ?? 0),
      })),
    fetchedAt: new Date().toISOString(),
  };
}

async function fetchUpstream(): Promise<EWSPayload | null> {
  try {
    const res = await fetch(EWS_URL, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      cache: 'no-store',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    const data = parseUpstream(json);
    cachedData = data;
    lastFetchTime = Date.now();
    return data;
  } catch (err) {
    console.warn('[OSIRIS/ews-index] upstream fetch failed:', err instanceof Error ? err.message : err);
    if (cachedData) {
      return { ...cachedData, stale: true, source: 'cached' };
    }
    return null;
  }
}

export async function GET() {
  const now = Date.now();
  const cacheHit = cachedData && now - lastFetchTime < CACHE_TTL_MS;

  if (cacheHit) {
    return NextResponse.json(cachedData as EWSResult, {
      headers: { 'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=600' },
    });
  }

  // Coalesce concurrent requests into a single upstream fetch
  if (!inflight) {
    inflight = fetchUpstream().finally(() => { inflight = null; });
  }

  const data = await inflight.catch(() => null);

  if (!data) {
    const unavailable: EWSUnavailable = { available: false };
    return NextResponse.json(unavailable, {
      headers: { 'Cache-Control': 'no-store' },
    });
  }

  return NextResponse.json(data as EWSResult, {
    headers: { 'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=600' },
  });
}
