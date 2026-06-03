import { NextResponse } from 'next/server';
import { isRateLimited, getClientIp } from '@/lib/ssrf-guard';

// In-memory cache for the Phishing.army domain blocklist (free, no API key)
let phishingSet: Set<string> | null = null;
let phishingFetchedAt = 0;
const PHISHING_TTL_MS = 60 * 60 * 1000; // 1h

// In-memory cache for the Tor bulk exit-node list (free, no API key). Fetching
// it on every request was wasteful — the list changes slowly.
let torSet: Set<string> | null = null;
let torFetchedAt = 0;
const TOR_TTL_MS = 30 * 60 * 1000; // 30m

async function getPhishingBlocklist(): Promise<Set<string> | null> {
  const now = Date.now();
  if (phishingSet && now - phishingFetchedAt < PHISHING_TTL_MS) return phishingSet;
  try {
    const res = await fetch('https://phishing.army/download/phishing_army_blocklist.txt', {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return phishingSet;
    const text = await res.text();
    const set = new Set<string>();
    for (const line of text.split('\n')) {
      const d = line.trim().toLowerCase();
      if (d && !d.startsWith('#')) set.add(d);
    }
    phishingSet = set;
    phishingFetchedAt = now;
    return set;
  } catch {
    return phishingSet;
  }
}

async function getTorExitSet(): Promise<Set<string> | null> {
  const now = Date.now();
  if (torSet && now - torFetchedAt < TOR_TTL_MS) return torSet;
  try {
    const res = await fetch('https://check.torproject.org/torbulkexitlist', {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return torSet;
    const text = await res.text();
    const set = new Set<string>();
    for (const line of text.split('\n')) {
      const ip = line.trim();
      if (ip && !ip.startsWith('#')) set.add(ip);
    }
    torSet = set;
    torFetchedAt = now;
    return set;
  } catch {
    return torSet;
  }
}

// Threat Intelligence — AlienVault OTX + Tor exit + abuse.ch Feodo
// + GreyNoise Community + Phishing.army. All free, keyless public endpoints.
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const query = searchParams.get('query'); // Optional: IP or domain to check
  
  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 20, 60_000)) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }
  
  try {
    const results: any = { timestamp: new Date().toISOString() };

    // 1. AlienVault OTX — public pulse feed (no key needed for public data)
    try {
      const res = await fetch('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10&page=1', {
        signal: AbortSignal.timeout(8000),
        headers: { 'Accept': 'application/json' },
      });
      // Public endpoint may require auth, fall back to activity feed
      if (!res.ok) {
        const actRes = await fetch('https://otx.alienvault.com/api/v1/pulses/activity?limit=10', {
          signal: AbortSignal.timeout(8000),
        });
        if (actRes.ok) {
          const data = await actRes.json();
          results.pulses = (data.results || []).slice(0, 10).map((p: any) => ({
            name: p.name,
            description: p.description?.slice(0, 200),
            created: p.created,
            modified: p.modified,
            tags: p.tags?.slice(0, 5),
            adversary: p.adversary,
            targeted_countries: p.targeted_countries,
            indicators_count: p.indicator_count,
          }));
        }
      }
    } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }

    // 2. Check specific IP/domain if provided
    if (query) {
      const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(query);
      
      if (isIP) {
        // Check against the cached Tor exit-node list
        try {
          const tor = await getTorExitSet();
          results.tor_exit_node = tor ? tor.has(query) : null;
        } catch {
          results.tor_exit_node = null;
        }

        // abuse.ch Feodo Tracker — botnet C2 IP blocklist (free, no API key)
        try {
          const feodoRes = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json', {
            signal: AbortSignal.timeout(6000),
            headers: { 'Accept': 'application/json' },
          });
          if (feodoRes.ok) {
            const feed = await feodoRes.json();
            const hit = Array.isArray(feed) ? feed.find((e: any) => e.ip_address === query) : null;
            results.feodo_c2 = hit
              ? { listed: true, malware: hit.malware, first_seen: hit.first_seen, last_online: hit.last_online }
              : { listed: false };
          }
        } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }

        // GreyNoise Community API — keyless IP triage (benign / malicious /
        // unknown + whether the IP is mass-scanning the internet). One of the
        // most useful free signals for separating targeted from background noise.
        try {
          const gnRes = await fetch(`https://api.greynoise.io/v3/community/${query}`, {
            signal: AbortSignal.timeout(5000),
            headers: { 'Accept': 'application/json' },
          });
          if (gnRes.ok) {
            const gn = await gnRes.json();
            results.greynoise = {
              noise: gn.noise === true,
              riot: gn.riot === true,
              classification: gn.classification,
              name: gn.name,
              last_seen: gn.last_seen,
              link: gn.link,
            };
          } else if (gnRes.status === 404) {
            results.greynoise = { noise: false, classification: 'unknown', note: 'Not observed by GreyNoise' };
          }
        } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }

        // AlienVault OTX IP reputation (public)
        try {
          const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${query}/general`, {
            signal: AbortSignal.timeout(5000),
          });
          if (res.ok) {
            const data = await res.json();
            results.otx = {
              reputation: data.reputation,
              pulse_count: data.pulse_info?.count || 0,
              country: data.country_name,
              asn: data.asn,
            };
          }
        } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }
      } else {
        // Domain check
        try {
          const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(query)}/general`, {
            signal: AbortSignal.timeout(5000),
          });
          if (res.ok) {
            const data = await res.json();
            results.otx = {
              pulse_count: data.pulse_info?.count || 0,
              whois: data.whois ? {
                registrar: data.whois.registrar,
                creation_date: data.whois.creation_date,
                expiration_date: data.whois.expiration_date,
              } : null,
            };
          }
        } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }

        // Phishing.army — community phishing domain blocklist (free, no API key, cached 1h)
        try {
          const blocklist = await getPhishingBlocklist();
          if (blocklist) {
            results.phishing_army = { listed: blocklist.has(query.toLowerCase()) };
          }
        } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }
      }
    }

    const pulseCount = results.otx?.pulse_count || 0;
    const gnMalicious = results.greynoise?.classification === 'malicious';
    const knownBad =
      results.feodo_c2?.listed ||
      results.phishing_army?.listed ||
      results.tor_exit_node === true ||
      gnMalicious;
    results.threat_level = knownBad || pulseCount > 5 ? 'HIGH' :
                           pulseCount > 0 || results.greynoise?.noise ? 'MEDIUM' : 'LOW';

    return NextResponse.json(results);
  } catch {
    return NextResponse.json({ error: 'Threat lookup failed' }, { status: 500 });
  }
}
