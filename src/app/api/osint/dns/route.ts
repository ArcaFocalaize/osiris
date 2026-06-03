import { NextResponse } from 'next/server';
import { isRateLimited, getClientIp } from '@/lib/ssrf-guard';
import { getMemo, setMemo, cachedJson } from '@/lib/osint-cache';

// DNS records are stable for short windows — cache for 5 minutes.
const DNS_TTL_S = 300;

interface DnsAnswer { name: string; type: number; TTL: number; data: string }

// DoH query against a given resolver. Returns the parsed answer set plus the
// authenticated-data (DNSSEC) flag so the caller can reason about validation.
// `do=1` requests DNSSEC records so the AD bit is meaningful.
async function doh(resolver: string, name: string, type: string): Promise<{ answers: DnsAnswer[]; ad: boolean; status: number }> {
  const res = await fetch(`${resolver}?name=${encodeURIComponent(name)}&type=${type}&do=1`, {
    signal: AbortSignal.timeout(5000),
    headers: { 'Accept': 'application/dns-json' },
  });
  if (!res.ok) return { answers: [], ad: false, status: -1 };
  const data = await res.json();
  return { answers: data.Answer || [], ad: data.AD === true, status: data.Status };
}

// Strip the surrounding quotes DoH returns on TXT records and join the
// character-strings of a single chunked TXT RR.
function cleanTxt(raw: string): string {
  return raw.replace(/^"|"$/g, '').replace(/"\s+"/g, '');
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const domain = searchParams.get('domain');
  if (!domain) return NextResponse.json({ error: 'Missing domain parameter' }, { status: 400 });

  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 20, 60_000)) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  // Basic domain validation
  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
    return NextResponse.json({ error: 'Invalid domain format' }, { status: 400 });
  }

  const cacheKey = `dns:${domain.toLowerCase()}`;
  const cached = getMemo(cacheKey);
  if (cached) return cachedJson(cached, DNS_TTL_S);

  try {
    const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'];
    const GOOGLE = 'https://dns.google/resolve';
    const CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';

    interface DnsResults {
      domain: string;
      records: Record<string, Array<{ name: string; type: number; ttl: number; data: string }>>;
      timestamp: string;
      dnssec?: { authenticated: boolean; resolver: string };
      email_security?: {
        spf: string | null;
        spf_policy: string | null;
        dmarc: string | null;
        dmarc_policy: string | null;
        dkim_hint: boolean;
        posture: 'strong' | 'partial' | 'weak' | 'none';
      };
      reverse_dns?: Record<string, string>;
      resolver_consistency?: { consistent: boolean; google_a: string[]; cloudflare_a: string[] };
      summary?: Record<string, unknown>;
    }

    const results: DnsResults = { domain, records: {}, timestamp: new Date().toISOString() };

    const lookups = await Promise.allSettled(
      types.map(async (type) => {
        const { answers, ad } = await doh(GOOGLE, domain, type);
        return { type, answers, ad };
      })
    );

    let dnssecAuthenticated = false;
    for (const result of lookups) {
      if (result.status === 'fulfilled') {
        const { type, answers, ad } = result.value;
        if (ad) dnssecAuthenticated = true;
        results.records[type] = answers.map((a) => ({
          name: a.name,
          type: a.type,
          ttl: a.TTL,
          data: type === 'TXT' ? cleanTxt(a.data) : a.data,
        }));
      }
    }
    results.dnssec = { authenticated: dnssecAuthenticated, resolver: 'dns.google' };

    // ── Email authentication posture (SPF / DMARC / DKIM) ──
    const txtRecords = (results.records.TXT || []).map((r) => r.data);
    const spf = txtRecords.find((t) => /^v=spf1/i.test(t)) || null;
    const spfPolicy = spf ? (spf.match(/[~\-?+]all/)?.[0] ?? null) : null;

    let dmarc: string | null = null;
    let dmarcPolicy: string | null = null;
    try {
      const { answers } = await doh(GOOGLE, `_dmarc.${domain}`, 'TXT');
      const rec = answers.map((a) => cleanTxt(a.data)).find((t) => /^v=DMARC1/i.test(t));
      if (rec) {
        dmarc = rec;
        dmarcPolicy = rec.match(/p=(none|quarantine|reject)/i)?.[1]?.toLowerCase() ?? null;
      }
    } catch { /* _dmarc lookup is best-effort */ }

    // DKIM uses arbitrary selectors; probe a handful of common ones for a hint.
    let dkimHint = false;
    try {
      const selectors = ['google', 'default', 'selector1', 'k1', 'dkim'];
      const probes = await Promise.allSettled(
        selectors.map((s) => doh(GOOGLE, `${s}._domainkey.${domain}`, 'TXT'))
      );
      dkimHint = probes.some(
        (p) => p.status === 'fulfilled' && p.value.answers.some((a) => /v=DKIM1|p=/i.test(a.data))
      );
    } catch { /* DKIM probing is best-effort */ }

    // Email posture grade: SPF -all/~all + DMARC reject/quarantine = strong.
    let posture: 'strong' | 'partial' | 'weak' | 'none' = 'none';
    if (spf && dmarc) {
      const strictSpf = spfPolicy === '-all' || spfPolicy === '~all';
      const strictDmarc = dmarcPolicy === 'reject' || dmarcPolicy === 'quarantine';
      posture = strictSpf && strictDmarc ? 'strong' : 'partial';
    } else if (spf || dmarc) {
      posture = 'weak';
    }
    results.email_security = {
      spf, spf_policy: spfPolicy, dmarc, dmarc_policy: dmarcPolicy, dkim_hint: dkimHint, posture,
    };

    // ── Reverse DNS (PTR) for the resolved A records ──
    const aRecords = (results.records.A || []).map((r) => r.data);
    const reverse: Record<string, string> = {};
    await Promise.allSettled(
      aRecords.slice(0, 4).map(async (ip) => {
        const arpa = `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
        const { answers } = await doh(GOOGLE, arpa, 'PTR');
        if (answers.length) reverse[ip] = answers[0].data.replace(/\.$/, '');
      })
    );
    if (Object.keys(reverse).length) results.reverse_dns = reverse;

    // ── Cross-resolver consistency check (Google vs Cloudflare) ──
    try {
      const { answers } = await doh(CLOUDFLARE, domain, 'A');
      const cfA = answers.map((a) => a.data).sort();
      const gA = [...aRecords].sort();
      results.resolver_consistency = {
        consistent: JSON.stringify(cfA) === JSON.stringify(gA),
        google_a: gA,
        cloudflare_a: cfA,
      };
    } catch { /* secondary resolver is best-effort */ }

    // Summary
    const mxRecords = results.records.MX || [];
    const nsRecords = results.records.NS || [];
    const caaRecords = results.records.CAA || [];
    results.summary = {
      ip_addresses: aRecords,
      mail_servers: mxRecords.map((r) => r.data),
      nameservers: nsRecords.map((r) => r.data),
      caa: caaRecords.map((r) => r.data),
      dnssec: dnssecAuthenticated,
      email_posture: posture,
      total_records: Object.values(results.records).flat().length,
    };

    setMemo(cacheKey, results, DNS_TTL_S * 1000);
    return cachedJson(results, DNS_TTL_S);
  } catch {
    return NextResponse.json({ error: 'DNS lookup failed' }, { status: 500 });
  }
}
