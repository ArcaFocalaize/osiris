import { NextResponse } from 'next/server';
import { isRateLimited, getClientIp } from '@/lib/ssrf-guard';
import { parseIPv4, isPrivateOrReserved } from '@/lib/osint-utils';
import { getMemo, setMemo, cachedJson } from '@/lib/osint-cache';

// Shodan InternetDB is a passive snapshot — cache for 10 minutes.
const SHODAN_TTL_S = 600;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const ip = searchParams.get('ip');

  if (!ip) {
    return NextResponse.json({ error: 'Missing IP parameter' }, { status: 400 });
  }

  // Validate + block private/reserved ranges (SSRF / noise hygiene).
  const octets = parseIPv4(ip);
  if (!octets) {
    return NextResponse.json({ error: 'Invalid IPv4 address format' }, { status: 400 });
  }
  if (isPrivateOrReserved(octets)) {
    return NextResponse.json({ error: 'Private and reserved IP ranges are not allowed' }, { status: 400 });
  }

  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 20, 60_000)) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  const cacheKey = `shodan:${ip}`;
  const cached = getMemo(cacheKey);
  if (cached) return cachedJson(cached, SHODAN_TTL_S);

  try {
    const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(8000),
      cache: 'no-store'
    });

    if (res.status === 404) {
      const empty = {
        ip,
        status: 'No Shodan InternetDB records found',
        ports: [],
        cpes: [],
        hostnames: [],
        tags: [],
        vulns: []
      };
      setMemo(cacheKey, empty, SHODAN_TTL_S * 1000);
      return cachedJson(empty, SHODAN_TTL_S);
    }

    if (!res.ok) {
      throw new Error(`Shodan HTTP ${res.status}`);
    }

    const data = await res.json();
    setMemo(cacheKey, data, SHODAN_TTL_S * 1000);
    return cachedJson(data, SHODAN_TTL_S);
  } catch (error) {
    return NextResponse.json(
      { error: 'Shodan lookup failed', detail: error instanceof Error ? error.message : 'unknown' },
      { status: 502 }
    );
  }
}
