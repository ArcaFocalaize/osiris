import { NextResponse } from 'next/server';
import { getMemo, setMemo, cachedJson, fetchRetry } from '@/lib/osint-cache';

// Breach data updates occasionally — cache for 5 minutes.
const LEAKS_TTL_S = 300;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const email = searchParams.get('email');

  if (!email) return NextResponse.json({ error: 'Missing email parameter' }, { status: 400 });

  const cacheKey = `leaks:${email.toLowerCase()}`;
  const cached = getMemo(cacheKey);
  if (cached) return cachedJson(cached, LEAKS_TTL_S);

  try {
    // We will call the breach-analytics endpoint to get deep details on what exactly was leaked.
    const res = await fetchRetry(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`, {
      headers: { 'Accept': 'application/json' }
    }, { retries: 1, timeoutMs: 8000 });
    
    if (res.status === 404) {
      const empty = { email, breached: false, breaches: [], data_exposed: [] };
      setMemo(cacheKey, empty, LEAKS_TTL_S * 1000);
      return cachedJson(empty, LEAKS_TTL_S);
    }

    if (!res.ok) throw new Error(`XposedOrNot API HTTP ${res.status}`);

    const data = await res.json();
    
    // Parse the analytics data
    let breachList = [];
    const dataExposed = new Set<string>();

    if (data.BreachesSummary && data.BreachesSummary.site) {
       breachList = data.BreachesSummary.site.split(';').filter(Boolean);
    }
    
    if (data.ExposedData && Array.isArray(data.ExposedData)) {
       data.ExposedData.forEach((item: any) => {
          if (item.data_classes && Array.isArray(item.data_classes)) {
             item.data_classes.forEach((dc: string) => dataExposed.add(dc));
          }
       });
    }

    const payload = {
      email,
      breached: breachList.length > 0,
      breaches: breachList,
      data_exposed: Array.from(dataExposed).sort()
    };
    setMemo(cacheKey, payload, LEAKS_TTL_S * 1000);
    return cachedJson(payload, LEAKS_TTL_S);
  } catch (error: any) {
    return NextResponse.json({ error: 'Leak lookup failed', detail: error.message }, { status: 502 });
  }
}
