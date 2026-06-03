// Orchestrated OSINT/HUMINT collection — agent registry.
//
// Each agent wraps ONE free, publicly accessible source and returns normalised
// `Finding`s plus optional `Pivot`s (leads for the next collection pass).
// Agents never throw: on any failure they resolve with an empty result so the
// orchestrator degrades gracefully.

import { safeFetch } from '@/lib/ssrf-guard';
import type {
  CollectionAgent,
  Credibility,
  Finding,
  Pivot,
  Reliability,
  TargetType,
} from './types';

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

function admiralty(rel: Reliability, cred: Credibility): string {
  return `${rel}${cred}`;
}

function makeFinding(
  agent: string,
  discipline: Finding['discipline'],
  layer: Finding['layer'],
  reliability: Reliability,
  credibility: Credibility,
  title: string,
  summary: string,
  data?: Record<string, unknown>,
  citations?: Finding['citations'],
): Finding {
  return {
    agent,
    discipline,
    layer,
    title,
    summary,
    reliability,
    credibility,
    admiralty: admiralty(reliability, credibility),
    data,
    citations,
  };
}

// Fetch JSON with the agent's own abort signal; null on any error.
async function getJson<T = unknown>(url: string, signal: AbortSignal): Promise<T | null> {
  try {
    const res = await safeFetch(url, { signal, headers: { 'User-Agent': UA, Accept: 'application/json' } });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function getText(url: string, signal: AbortSignal): Promise<string | null> {
  try {
    const res = await safeFetch(url, { signal, headers: { 'User-Agent': UA, Accept: 'text/html' } });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TECHINT — DNS / infrastructure (surface)
// ─────────────────────────────────────────────────────────────────────────────
const dnsAgent: CollectionAgent = {
  id: 'dns_infra',
  name: 'DNS Infrastructure',
  discipline: 'TECHINT',
  layer: 'surface',
  reliability: 'B',
  appliesTo: ['domain'],
  async collect(target, _t, signal) {
    const types = ['A', 'AAAA', 'MX', 'NS', 'TXT'];
    const records: Record<string, string[]> = {};
    const pivots: Pivot[] = [];
    await Promise.all(
      types.map(async (rt) => {
        const data = await getJson<{ Answer?: { data: string }[] }>(
          `https://dns.google/resolve?name=${encodeURIComponent(target)}&type=${rt}`,
          signal,
        );
        const ans = data?.Answer?.map((a) => a.data).filter(Boolean) ?? [];
        if (ans.length) records[rt] = ans;
      }),
    );
    if (!Object.keys(records).length) return { findings: [] };
    for (const ip of records.A ?? []) {
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) pivots.push({ type: 'ipv4', value: ip, reason: 'A record of target domain' });
    }
    const summary = Object.entries(records).map(([k, v]) => `${k}: ${v.length}`).join(', ');
    return {
      findings: [
        makeFinding('dns_infra', 'TECHINT', 'surface', 'B', 1,
          `DNS footprint for ${target}`,
          `Resolved records — ${summary}.`,
          records,
          [{ label: 'Google DNS-over-HTTPS', url: 'https://dns.google' }]),
      ],
      pivots,
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// OSINT — Certificate Transparency (surface) → subdomains
// ─────────────────────────────────────────────────────────────────────────────
const certAgent: CollectionAgent = {
  id: 'cert_transparency',
  name: 'Certificate Transparency',
  discipline: 'OSINT',
  layer: 'surface',
  reliability: 'B',
  appliesTo: ['domain'],
  async collect(target, _t, signal) {
    const data = await getJson<{ name_value: string }[]>(
      `https://crt.sh/?q=${encodeURIComponent('%.' + target)}&output=json`,
      signal,
    );
    if (!data || !Array.isArray(data)) return { findings: [] };
    const subs = new Set<string>();
    for (const row of data) {
      for (const name of String(row.name_value || '').split('\n')) {
        const n = name.trim().toLowerCase();
        if (n && !n.startsWith('*') && n.endsWith(target)) subs.add(n);
      }
    }
    const list = Array.from(subs).sort();
    if (!list.length) return { findings: [] };
    const pivots: Pivot[] = list.slice(0, 10).map((d) => ({ type: 'domain', value: d, reason: 'CT-log subdomain' }));
    return {
      findings: [
        makeFinding('cert_transparency', 'OSINT', 'surface', 'B', 2,
          `${list.length} subdomains via CT logs`,
          `Certificate Transparency reveals ${list.length} distinct hostnames under ${target}. Sample: ${list.slice(0, 8).join(', ')}.`,
          { subdomains: list.slice(0, 100), total: list.length },
          [{ label: 'crt.sh', url: `https://crt.sh/?q=%25.${target}` }]),
      ],
      pivots,
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// OSINT — RDAP registration (surface)
// ─────────────────────────────────────────────────────────────────────────────
const rdapAgent: CollectionAgent = {
  id: 'rdap',
  name: 'RDAP Registration',
  discipline: 'OSINT',
  layer: 'surface',
  reliability: 'A',
  appliesTo: ['domain', 'ipv4'],
  async collect(target, type, signal) {
    const url = type === 'ipv4'
      ? `https://rdap.org/ip/${encodeURIComponent(target)}`
      : `https://rdap.org/domain/${encodeURIComponent(target)}`;
    const data = await getJson<Record<string, unknown>>(url, signal);
    if (!data) return { findings: [] };
    const events = (data.events as { eventAction: string; eventDate: string }[] | undefined) ?? [];
    const reg = events.find((e) => e.eventAction === 'registration')?.eventDate;
    const exp = events.find((e) => e.eventAction === 'expiration')?.eventDate;
    const entities = (data.entities as { roles?: string[]; handle?: string }[] | undefined) ?? [];
    const roles = entities.flatMap((e) => e.roles ?? []);
    return {
      findings: [
        makeFinding('rdap', 'OSINT', 'surface', 'A', 1,
          `Registration record for ${target}`,
          `RDAP authoritative record. Registered: ${reg ?? 'n/a'}${exp ? `, expires ${exp}` : ''}. Roles: ${roles.join(', ') || 'n/a'}.`,
          { registration: reg, expiration: exp, roles, name: data.name, handle: data.handle },
          [{ label: 'RDAP', url }]),
      ],
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// OSINT — Wayback / archive presence (deep)
// ─────────────────────────────────────────────────────────────────────────────
const waybackAgent: CollectionAgent = {
  id: 'wayback',
  name: 'Web Archive',
  discipline: 'OSINT',
  layer: 'deep',
  reliability: 'B',
  appliesTo: ['domain'],
  async collect(target, _t, signal) {
    const avail = await getJson<{ archived_snapshots?: { closest?: { timestamp?: string; url?: string } } }>(
      `https://archive.org/wayback/available?url=${encodeURIComponent(target)}`,
      signal,
    );
    const closest = avail?.archived_snapshots?.closest;
    if (!closest?.timestamp) return { findings: [] };
    const ts = closest.timestamp;
    const human = `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
    return {
      findings: [
        makeFinding('wayback', 'OSINT', 'deep', 'B', 2,
          `Historical archive of ${target}`,
          `Wayback Machine holds snapshots of ${target}; latest indexed capture ~${human}.`,
          { latest_snapshot: human, snapshot_url: closest.url },
          [{ label: 'Wayback Machine', url: `https://web.archive.org/web/*/${target}` }]),
      ],
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// SOCMINT — GitHub presence (surface)
// ─────────────────────────────────────────────────────────────────────────────
const githubAgent: CollectionAgent = {
  id: 'github',
  name: 'GitHub Recon',
  discipline: 'SOCMINT',
  layer: 'surface',
  reliability: 'B',
  appliesTo: ['username'],
  async collect(target, _t, signal) {
    const user = await getJson<Record<string, unknown>>(`https://api.github.com/users/${encodeURIComponent(target)}`, signal);
    if (!user || user.message === 'Not Found') return { findings: [] };
    const pivots: Pivot[] = [];
    if (typeof user.blog === 'string' && user.blog) {
      const m = user.blog.match(/[a-z0-9.-]+\.[a-z]{2,}/i);
      if (m) pivots.push({ type: 'domain', value: m[0].toLowerCase(), reason: 'GitHub profile website' });
    }
    return {
      findings: [
        makeFinding('github', 'SOCMINT', 'surface', 'B', 1,
          `GitHub account @${target}`,
          `Public developer profile: ${user.public_repos ?? 0} repos, ${user.followers ?? 0} followers. Name: ${user.name ?? 'n/a'}, company: ${user.company ?? 'n/a'}, location: ${user.location ?? 'n/a'}.`,
          { name: user.name, company: user.company, location: user.location, blog: user.blog, public_repos: user.public_repos, followers: user.followers, created_at: user.created_at },
          [{ label: 'GitHub profile', url: `https://github.com/${target}` }]),
      ],
      pivots,
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// SOCMINT — social account enumeration (surface)
// ─────────────────────────────────────────────────────────────────────────────
const SOCIAL_SITES: { name: string; url: (u: string) => string; absent?: string }[] = [
  { name: 'X / Twitter', url: (u) => `https://twitter.com/${u}` },
  { name: 'Instagram', url: (u) => `https://www.instagram.com/${u}/` },
  { name: 'TikTok', url: (u) => `https://www.tiktok.com/@${u}` },
  { name: 'Reddit', url: (u) => `https://www.reddit.com/user/${u}` },
  { name: 'Telegram', url: (u) => `https://t.me/${u}`, absent: 'If you have Telegram, you can contact' },
  { name: 'Twitch', url: (u) => `https://www.twitch.tv/${u}` },
  { name: 'YouTube', url: (u) => `https://www.youtube.com/@${u}` },
  { name: 'Medium', url: (u) => `https://medium.com/@${u}` },
  { name: 'Keybase', url: (u) => `https://keybase.io/${u}` },
  { name: 'Mastodon', url: (u) => `https://mstdn.social/@${u}` },
];

const socialAgent: CollectionAgent = {
  id: 'social_enum',
  name: 'Social Footprint',
  discipline: 'SOCMINT',
  layer: 'surface',
  reliability: 'C',
  appliesTo: ['username'],
  async collect(target, _t, signal) {
    const hits: { name: string; url: string }[] = [];
    await Promise.all(
      SOCIAL_SITES.map(async (s) => {
        const url = s.url(target);
        try {
          const res = await safeFetch(url, { signal, redirect: 'manual', headers: { 'User-Agent': UA, Accept: 'text/html' } } as RequestInit);
          if (res.status >= 300 && res.status < 400) return;
          if (res.status === 404 || res.status === 410) return;
          if (res.status !== 200) return;
          if (s.absent && (await res.text()).includes(s.absent)) return;
          hits.push({ name: s.name, url });
        } catch { /* unreachable / blocked → skip */ }
      }),
    );
    if (!hits.length) return { findings: [] };
    // More corroborating platforms → higher credibility.
    const cred: Credibility = hits.length >= 4 ? 2 : 3;
    return {
      findings: [
        makeFinding('social_enum', 'SOCMINT', 'surface', 'C', cred,
          `${hits.length} social accounts for "${target}"`,
          `Persona "${target}" appears on: ${hits.map((h) => h.name).join(', ')}. Verify manually — handle collisions are common.`,
          { accounts: hits },
          hits.map((h) => ({ label: h.name, url: h.url }))),
      ],
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// CTI — breach exposure (deep)
// ─────────────────────────────────────────────────────────────────────────────
const breachAgent: CollectionAgent = {
  id: 'breach',
  name: 'Breach Exposure',
  discipline: 'CTI',
  layer: 'deep',
  reliability: 'B',
  appliesTo: ['email'],
  async collect(target, _t, signal) {
    const data = await getJson<{ BreachesSummary?: { site?: string }; ExposedData?: { data_classes?: string[] }[] }>(
      `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(target)}`,
      signal,
    );
    if (!data) return { findings: [] };
    const sites = (data.BreachesSummary?.site || '').split(';').filter(Boolean);
    if (!sites.length) {
      return {
        findings: [
          makeFinding('breach', 'CTI', 'deep', 'B', 2,
            `No known breaches for ${target}`,
            `Address not present in indexed breach corpora at collection time.`,
            { breached: false },
            [{ label: 'XposedOrNot', url: 'https://xposedornot.com' }]),
        ],
      };
    }
    const classes = new Set<string>();
    for (const e of data.ExposedData ?? []) for (const c of e.data_classes ?? []) classes.add(c);
    return {
      findings: [
        makeFinding('breach', 'CTI', 'deep', 'B', 1,
          `Email exposed in ${sites.length} breaches`,
          `${target} appears in ${sites.length} breach datasets (${sites.slice(0, 6).join(', ')}). Exposed data classes: ${Array.from(classes).slice(0, 8).join(', ') || 'n/a'}.`,
          { breached: true, breaches: sites, data_exposed: Array.from(classes).sort() },
          [{ label: 'XposedOrNot', url: 'https://xposedornot.com' }]),
      ],
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// HUMINT/dark — onion search gateway (dark, via Ahmia clearnet mirror)
// ─────────────────────────────────────────────────────────────────────────────
const darkAgent: CollectionAgent = {
  id: 'darkweb_ahmia',
  name: 'Dark Web Mentions',
  discipline: 'HUMINT',
  layer: 'dark',
  reliability: 'D',
  appliesTo: ['email', 'domain', 'username', 'name'],
  async collect(target, _t, signal) {
    // Ahmia indexes .onion services and is reachable over clearnet. We read the
    // public search results page (no auth, no Tor) and count/extract onion hits.
    const html = await getText(`https://ahmia.fi/search/?q=${encodeURIComponent(target)}`, signal);
    if (!html) return { findings: [] };
    const onions = Array.from(new Set((html.match(/[a-z2-7]{16,56}\.onion/gi) || []).map((s) => s.toLowerCase())));
    const titles = Array.from(html.matchAll(/<h4>\s*<a [^>]*>([^<]+)<\/a>/gi)).map((m) => m[1].trim()).slice(0, 8);
    if (!onions.length && !titles.length) {
      return {
        findings: [
          makeFinding('darkweb_ahmia', 'HUMINT', 'dark', 'D', 4,
            `No dark-web index hits for "${target}"`,
            `Ahmia onion index returned no results for "${target}" at collection time. Absence is not proof of absence.`,
            { hits: 0 },
            [{ label: 'Ahmia', url: `https://ahmia.fi/search/?q=${encodeURIComponent(target)}` }]),
        ],
      };
    }
    return {
      findings: [
        makeFinding('darkweb_ahmia', 'HUMINT', 'dark', 'D', 3,
          `Dark-web index references for "${target}"`,
          `Ahmia onion index returned ${onions.length} unique .onion services / ${titles.length} listings mentioning "${target}". UNVERIFIED — treat as raw leads requiring corroboration.`,
          { onion_services: onions.slice(0, 20), listings: titles },
          [{ label: 'Ahmia search', url: `https://ahmia.fi/search/?q=${encodeURIComponent(target)}` }]),
      ],
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// CTI — IP/domain threat reputation (surface/deep)
// ─────────────────────────────────────────────────────────────────────────────
const threatAgent: CollectionAgent = {
  id: 'threat_intel',
  name: 'Threat Reputation',
  discipline: 'CTI',
  layer: 'surface',
  reliability: 'B',
  appliesTo: ['ipv4', 'domain'],
  async collect(target, type, signal) {
    const path = type === 'ipv4' ? 'IPv4' : 'domain';
    const data = await getJson<{ pulse_info?: { count?: number }; reputation?: number }>(
      `https://otx.alienvault.com/api/v1/indicators/${path}/${encodeURIComponent(target)}/general`,
      signal,
    );
    if (!data) return { findings: [] };
    const pulses = data.pulse_info?.count ?? 0;
    const cred: Credibility = pulses > 5 ? 1 : pulses > 0 ? 2 : 3;
    return {
      findings: [
        makeFinding('threat_intel', 'CTI', pulses > 0 ? 'deep' : 'surface', 'B', cred,
          `Threat reputation for ${target}`,
          pulses > 0
            ? `Indicator referenced in ${pulses} OTX threat pulses — potential malicious association.`
            : `No active threat pulses associated with ${target}.`,
          { pulse_count: pulses, reputation: data.reputation },
          [{ label: 'AlienVault OTX', url: `https://otx.alienvault.com/indicator/${path === 'IPv4' ? 'ip' : 'domain'}/${target}` }]),
      ],
    };
  },
};

export const AGENTS: CollectionAgent[] = [
  dnsAgent,
  certAgent,
  rdapAgent,
  waybackAgent,
  githubAgent,
  socialAgent,
  breachAgent,
  darkAgent,
  threatAgent,
];

export function agentsFor(type: TargetType): CollectionAgent[] {
  return AGENTS.filter((a) => a.appliesTo.includes(type));
}
