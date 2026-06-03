import { NextResponse } from 'next/server';
import tls from 'node:tls';
import { isRateLimited, getClientIp } from '@/lib/ssrf-guard';
import { getMemo, setMemo, cachedJson } from '@/lib/osint-cache';

// Certificate Transparency logs are immutable historical records — cache 10m.
const CERTS_TTL_S = 600;

interface LiveCert {
  reachable: boolean;
  subject?: string;
  issuer?: string;
  san?: string[];
  valid_from?: string;
  valid_to?: string;
  days_remaining?: number;
  expired?: boolean;
  self_signed?: boolean;
  wildcard?: boolean;
  key_bits?: number;
  sig_algorithm?: string;
  serial?: string;
  protocol?: string;
  cipher?: string;
  error?: string;
}

// Live TLS handshake to read the leaf certificate actually served on :443.
// crt.sh only shows historical issuance; this captures the current posture.
function inspectLiveCert(host: string): Promise<LiveCert> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v: LiveCert) => { if (!settled) { settled = true; try { socket.destroy(); } catch { /* already closed */ } resolve(v); } };

    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        // We deliberately do NOT reject unauthorised certs: self-signed /
        // expired certs are themselves intelligence, not a failure.
        rejectUnauthorized: false,
        timeout: 6000,
      },
      () => {
        const cert = socket.getPeerCertificate(false);
        if (!cert || Object.keys(cert).length === 0) {
          return done({ reachable: true, error: 'No certificate presented' });
        }
        const now = Date.now();
        const validTo = new Date(cert.valid_to).getTime();
        const san = (cert.subjectaltname || '')
          .split(',')
          .map((s) => s.trim().replace(/^DNS:/, ''))
          .filter(Boolean);
        done({
          reachable: true,
          subject: cert.subject?.CN || host,
          issuer: cert.issuer?.O || cert.issuer?.CN,
          san,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          days_remaining: Math.floor((validTo - now) / 86_400_000),
          expired: now > validTo,
          self_signed: !!cert.issuer?.CN && cert.issuer.CN === cert.subject?.CN,
          wildcard: san.some((s) => s.startsWith('*.')) || (cert.subject?.CN || '').startsWith('*.'),
          key_bits: cert.bits,
          sig_algorithm: (cert as { asn1Curve?: string; sigalg?: string }).sigalg,
          serial: cert.serialNumber,
          protocol: socket.getProtocol() || undefined,
          cipher: socket.getCipher()?.name,
        });
      }
    );
    socket.on('error', (e) => done({ reachable: false, error: e instanceof Error ? e.message : 'handshake failed' }));
    socket.on('timeout', () => done({ reachable: false, error: 'TLS handshake timed out' }));
  });
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const domain = searchParams.get('domain');
  if (!domain) return NextResponse.json({ error: 'Missing domain parameter' }, { status: 400 });

  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 20, 60_000)) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
    return NextResponse.json({ error: 'Invalid domain format' }, { status: 400 });
  }

  const cacheKey = `certs:${domain.toLowerCase()}`;
  const cached = getMemo(cacheKey);
  if (cached) return cachedJson(cached, CERTS_TTL_S);

  try {
    // Run the CT-log history and the live handshake concurrently.
    const [ctRes, live] = await Promise.all([
      fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
        signal: AbortSignal.timeout(10000),
        headers: { 'User-Agent': 'Osiris-OSINT/3.0' },
      }).catch(() => null),
      inspectLiveCert(domain).catch((): LiveCert => ({ reachable: false, error: 'inspection failed' })),
    ]);

    if (!ctRes || !ctRes.ok) {
      const payload = { domain, certificates: [], subdomains: [], live_certificate: live, error: 'crt.sh unavailable' };
      return NextResponse.json(payload);
    }

    const certs = await ctRes.json();
    
    // Deduplicate by common name and extract subdomains
    const seen = new Set<string>();
    const subdomains = new Set<string>();
    const uniqueCerts = [];

    for (const cert of certs.slice(0, 200)) {
      const key = `${cert.common_name}-${cert.serial_number}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Extract subdomains
      const name = cert.name_value || '';
      name.split('\n').forEach((n: string) => {
        const clean = n.trim().replace(/^\*\./, '');
        if (clean.endsWith(domain)) subdomains.add(clean);
      });

      uniqueCerts.push({
        id: cert.id,
        issuer: cert.issuer_name,
        common_name: cert.common_name,
        name_value: cert.name_value,
        not_before: cert.not_before,
        not_after: cert.not_after,
        serial: cert.serial_number,
      });
    }

    const payload = {
      domain,
      live_certificate: live,
      certificates: uniqueCerts.slice(0, 50),
      subdomains: Array.from(subdomains).sort(),
      total_certs: certs.length,
      unique_subdomains: subdomains.size,
      timestamp: new Date().toISOString(),
    };
    setMemo(cacheKey, payload, CERTS_TTL_S * 1000);
    return cachedJson(payload, CERTS_TTL_S);
  } catch {
    return NextResponse.json({ domain, certificates: [], subdomains: [], error: 'Lookup failed' }, { status: 500 });
  }
}
