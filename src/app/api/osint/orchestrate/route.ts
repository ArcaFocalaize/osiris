import { NextResponse } from 'next/server';
import { isRateLimited, getClientIp } from '@/lib/ssrf-guard';
import { getMemo, setMemo, cachedJson } from '@/lib/osint-cache';
import { detectTargetType, orchestrate } from '@/lib/intel/orchestrator';
import type { WebLayer } from '@/lib/intel/types';

// Orchestrated OSINT/HUMINT collection.
// Fans a registry of collection agents across the open / deep / dark web for a
// single target and returns an Admiralty-rated intelligence dossier (BLUF +
// findings + pivots). Free sources only; no API keys; SSRF-guarded fetches.
const DOSSIER_TTL_S = 300;
const VALID_LAYERS: WebLayer[] = ['surface', 'deep', 'dark'];

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const raw = (searchParams.get('target') || '').trim();

  if (!raw) {
    return NextResponse.json({ error: 'Missing target parameter' }, { status: 400 });
  }
  if (raw.length > 120) {
    return NextResponse.json({ error: 'Target too long' }, { status: 400 });
  }

  const type = detectTargetType(raw);
  if (!type) {
    return NextResponse.json({ error: 'Could not classify target (expected email, domain, IPv4, username or name)' }, { status: 400 });
  }

  // Orchestration is expensive (many upstream calls) — rate-limit tightly.
  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 6, 60_000)) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  // Optional layer filter, e.g. ?layers=surface,deep
  const layersParam = (searchParams.get('layers') || '').split(',').map((s) => s.trim()).filter(Boolean);
  const layers = layersParam.filter((l): l is WebLayer => (VALID_LAYERS as string[]).includes(l));

  const cacheKey = `orchestrate:${type}:${raw.toLowerCase()}:${layers.sort().join('|') || 'all'}`;
  const cached = getMemo(cacheKey);
  if (cached) return cachedJson(cached, DOSSIER_TTL_S);

  try {
    const dossier = await orchestrate(raw, type, {
      layers: layers.length ? layers : undefined,
      overallTimeoutMs: 15_000,
    });
    setMemo(cacheKey, dossier, DOSSIER_TTL_S * 1000);
    return cachedJson(dossier, DOSSIER_TTL_S);
  } catch (e) {
    console.warn('[OSIRIS] Orchestration error:', e instanceof Error ? e.message : e);
    return NextResponse.json({ error: 'Orchestration failed' }, { status: 500 });
  }
}
