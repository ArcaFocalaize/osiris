import { NextResponse } from 'next/server';
import { isRateLimited, getClientIp } from '@/lib/ssrf-guard';
import { getMemo, setMemo, cachedJson, fetchRetry } from '@/lib/osint-cache';

// MAC vendor (OUI) prefixes are static — cache for a day.
const MAC_TTL_S = 86400;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const mac = searchParams.get('mac');

  if (!mac) {
    return NextResponse.json({ error: 'Missing MAC parameter' }, { status: 400 });
  }

  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 20, 60_000)) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  // Clean the MAC address format to allow varied inputs
  const cleanMac = mac.trim().toUpperCase().replace(/[^A-F0-9:-]/g, '');

  const cacheKey = `mac:${cleanMac}`;
  const cached = getMemo(cacheKey);
  if (cached) return cachedJson(cached, MAC_TTL_S);

  try {
    const res = await fetchRetry(`https://macvendors.co/api/${encodeURIComponent(cleanMac)}`, {
      headers: { 'Accept': 'application/json' }
    }, { retries: 1, timeoutMs: 8000 });

    if (!res.ok) {
      throw new Error(`MacVendors API HTTP ${res.status}`);
    }

    const data = await res.json();
    if (data && data.result && data.result.company) {
      const payload = {
        mac: cleanMac,
        vendor: data.result.company,
        address: data.result.address,
        prefix: data.result.mac_prefix
      };
      setMemo(cacheKey, payload, MAC_TTL_S * 1000);
      return cachedJson(payload, MAC_TTL_S);
    } else {
      return NextResponse.json({ mac: cleanMac, vendor: 'Not Found' });
    }
  } catch (error: any) {
    return NextResponse.json({ error: 'MAC lookup failed', detail: error.message }, { status: 502 });
  }
}
