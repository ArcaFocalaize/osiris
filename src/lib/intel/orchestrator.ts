// Orchestrated OSINT/HUMINT collection — orchestrator.
//
// Fans collection agents out across the open / deep / dark web in parallel,
// each under its own deadline, then fuses the results into a single dossier
// following the doctrine in the operator guides:
//   - target triage → discipline-appropriate tasking,
//   - Admiralty-rated findings,
//   - corroboration-aware confidence,
//   - BLUF summary + caveats + pivots for the next collection pass.

import { search as sanctionsSearch } from '@/lib/sanctions';
import { AGENTS, agentsFor } from './agents';
import type {
  AgentReport,
  Credibility,
  Dossier,
  Finding,
  Pivot,
  TargetType,
  WebLayer,
} from './types';

const PER_AGENT_TIMEOUT_MS = 9_000;

const RE_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RE_IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const RE_DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const RE_USERNAME = /^[A-Za-z0-9_.-]{2,40}$/;

export function detectTargetType(raw: string): TargetType | null {
  const t = raw.trim();
  if (!t) return null;
  if (RE_EMAIL.test(t)) return 'email';
  if (RE_IPV4.test(t)) {
    const oct = t.split('.').map(Number);
    if (oct.every((n) => n >= 0 && n <= 255)) return 'ipv4';
  }
  if (RE_DOMAIN.test(t)) return 'domain';
  if (/\s/.test(t)) return 'name';        // multi-word → person/org name
  if (RE_USERNAME.test(t)) return 'username';
  return 'name';
}

// Sanctions / PEP screening runs against the local OFAC index (not an agent in
// the fetch registry because it uses an in-process data source).
async function sanctionsReport(target: string, type: TargetType): Promise<AgentReport> {
  const start = Date.now();
  const base = {
    agent: 'sanctions_pep',
    discipline: 'OSINT' as const,
    layer: 'surface' as WebLayer,
    reliability: 'A' as const,
  };
  try {
    // Only screen names/emails/domains; an IP is not a sanctioned identity.
    if (type === 'ipv4') {
      return { ...base, ok: true, ms: Date.now() - start, findings: [], pivots: [] };
    }
    const q = type === 'email' ? target.split('@')[0].replace(/[._-]+/g, ' ') : target;
    const hits = await sanctionsSearch(q, { limit: 5 });
    const findings: Finding[] = hits.length
      ? [{
          ...base,
          title: `Sanctions/PEP match for "${q}"`,
          summary: `${hits.length} OFAC/sanctions list candidate(s): ${hits.slice(0, 3).map((h) => h.name).join('; ')}. Verify identity — name collisions are common.`,
          credibility: 3 as Credibility,
          admiralty: 'A3',
          data: { matches: hits.map((h) => ({ name: h.name, schema: h.schema, programs: h.programs, countries: h.countries })) },
          citations: [{ label: 'OFAC SDN (OpenSanctions)', url: 'https://www.opensanctions.org' }],
        }]
      : [];
    return { ...base, ok: true, ms: Date.now() - start, findings, pivots: [] };
  } catch (e) {
    return { ...base, ok: false, ms: Date.now() - start, findings: [], pivots: [], error: e instanceof Error ? e.message : 'error' };
  }
}

function withTimeout<T>(p: Promise<T>, ms: number, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('agent timeout')), ms);
    const onAbort = () => { clearTimeout(timer); reject(new Error('aborted')); };
    signal.addEventListener('abort', onAbort, { once: true });
    p.then((v) => { clearTimeout(timer); signal.removeEventListener('abort', onAbort); resolve(v); },
           (e) => { clearTimeout(timer); signal.removeEventListener('abort', onAbort); reject(e); });
  });
}

interface OrchestrateOptions {
  layers?: WebLayer[];        // restrict collection to these layers
  overallTimeoutMs?: number;
}

export async function orchestrate(
  rawTarget: string,
  type: TargetType,
  opts: OrchestrateOptions = {},
): Promise<Dossier> {
  const started = Date.now();
  const target = rawTarget.trim();
  const allowedLayers = opts.layers && opts.layers.length ? new Set(opts.layers) : null;

  const overall = new AbortController();
  const overallTimer = setTimeout(() => overall.abort(), opts.overallTimeoutMs ?? 15_000);

  // Select agents for this target type, honouring the layer filter.
  const selected = agentsFor(type).filter((a) => !allowedLayers || allowedLayers.has(a.layer));

  // Raise the listener limit to avoid MaxListenersExceededWarning — each agent
  // adds one abort listener to the shared signal.
  if (typeof (overall.signal as EventTarget & { setMaxListeners?: (n: number) => void }).setMaxListeners === 'function') {
    (overall.signal as EventTarget & { setMaxListeners: (n: number) => void }).setMaxListeners(selected.length + 5);
  }

  const agentRuns: Promise<AgentReport>[] = selected.map(async (agent) => {
    const start = Date.now();
    const ac = new AbortController();
    const onAbort = () => ac.abort();
    overall.signal.addEventListener('abort', onAbort, { once: true });
    try {
      const out = await withTimeout(agent.collect(target, type, ac.signal), PER_AGENT_TIMEOUT_MS, overall.signal);
      return {
        agent: agent.id,
        discipline: agent.discipline,
        layer: agent.layer,
        reliability: agent.reliability,
        ok: true,
        ms: Date.now() - start,
        findings: out.findings,
        pivots: out.pivots ?? [],
      };
    } catch (e) {
      ac.abort();
      return {
        agent: agent.id,
        discipline: agent.discipline,
        layer: agent.layer,
        reliability: agent.reliability,
        ok: false,
        ms: Date.now() - start,
        findings: [],
        pivots: [],
        error: e instanceof Error ? e.message : 'error',
      };
    } finally {
      overall.signal.removeEventListener('abort', onAbort);
    }
  });

  // Sanctions screening participates only when surface collection is allowed.
  const reports: AgentReport[] = await Promise.all(
    !allowedLayers || allowedLayers.has('surface')
      ? [...agentRuns, sanctionsReport(target, type)]
      : agentRuns,
  );
  clearTimeout(overallTimer);

  // ── Fuse ──
  const findings: Finding[] = reports.flatMap((r) => r.findings);

  // Corroboration: if the same target value is independently confirmed by ≥2
  // surface/deep agents, promote credibility of the strongest finding.
  const positiveLayers = new Set(findings.filter((f) => f.credibility <= 2).map((f) => f.agent));
  if (positiveLayers.size >= 2) {
    for (const f of findings) {
      if (f.credibility === 2) f.credibility = 1 as Credibility;
      f.admiralty = `${f.reliability}${f.credibility}`;
    }
  }

  const pivots: Pivot[] = dedupePivots(reports.flatMap((r) => r.pivots), target);

  const byDiscipline: Record<string, number> = {};
  for (const f of findings) byDiscipline[f.discipline] = (byDiscipline[f.discipline] ?? 0) + 1;
  const byLayer: Record<WebLayer, number> = { surface: 0, deep: 0, dark: 0 };
  for (const f of findings) byLayer[f.layer] += 1;

  const agentsOk = reports.filter((r) => r.ok).length;
  const confidence = computeConfidence(findings, agentsOk, reports.length);

  return {
    target,
    target_type: type,
    classification: 'OSINT // UNCLASSIFIED',
    bluf: buildBluf(target, type, findings, byLayer),
    collected_at: new Date().toISOString(),
    duration_ms: Date.now() - started,
    confidence,
    coverage: {
      agents_run: reports.length,
      agents_ok: agentsOk,
      findings: findings.length,
      by_discipline: byDiscipline,
      by_layer: byLayer,
    },
    agents: reports.sort((a, b) => a.agent.localeCompare(b.agent)),
    findings: rankFindings(findings),
    pivots,
    caveats: buildCaveats(findings, reports),
  };
}

function dedupePivots(pivots: Pivot[], target: string): Pivot[] {
  const seen = new Set<string>([target.toLowerCase()]);
  const out: Pivot[] = [];
  for (const p of pivots) {
    const key = `${p.type}:${p.value.toLowerCase()}`;
    if (seen.has(key) || seen.has(p.value.toLowerCase())) continue;
    seen.add(key);
    out.push(p);
    if (out.length >= 30) break;
  }
  return out;
}

// Rank: best Admiralty rating first (A1 strongest), then by discipline weight.
function rankFindings(findings: Finding[]): Finding[] {
  const relRank: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, E: 4, F: 5 };
  return [...findings].sort((a, b) => {
    const r = (relRank[a.reliability] ?? 9) - (relRank[b.reliability] ?? 9);
    if (r !== 0) return r;
    return a.credibility - b.credibility;
  });
}

function computeConfidence(findings: Finding[], ok: number, total: number): Dossier['confidence'] {
  if (!findings.length) return 'LOW';
  const strong = findings.filter((f) => f.reliability <= 'B' && f.credibility <= 2).length;
  const coverage = total ? ok / total : 0;
  if (strong >= 3 && coverage >= 0.6) return 'HIGH';
  if (strong >= 1 && coverage >= 0.4) return 'MODERATE';
  return 'LOW';
}

function buildBluf(
  target: string,
  type: TargetType,
  findings: Finding[],
  byLayer: Record<WebLayer, number>,
): string {
  if (!findings.length) {
    return `BLUF: No corroborated open-, deep- or dark-web intelligence recovered for ${type} target "${target}" within the collection window. Recommend manual tasking.`;
  }
  const exposed: string[] = [];
  if (findings.some((f) => f.agent === 'breach' && (f.data?.breached as boolean))) exposed.push('credential breach exposure');
  if (findings.some((f) => f.agent === 'threat_intel' && Number(f.data?.pulse_count) > 0)) exposed.push('active threat-intel associations');
  if (findings.some((f) => f.agent === 'sanctions_pep')) exposed.push('a possible sanctions/PEP match');
  if (byLayer.dark > 0 && findings.some((f) => f.layer === 'dark' && Number(f.data?.hits ?? 1) !== 0 && f.credibility <= 3)) exposed.push('dark-web index references');
  const headline = exposed.length
    ? `Notable: ${exposed.join('; ')}.`
    : 'No high-severity exposure flagged.';
  return `BLUF: ${findings.length} findings on ${type} target "${target}" across surface (${byLayer.surface}), deep (${byLayer.deep}) and dark (${byLayer.dark}) layers. ${headline} All ratings are Admiralty-coded; verify dark/social leads before action.`;
}

function buildCaveats(findings: Finding[], reports: AgentReport[]): string[] {
  const c: string[] = [
    'All collection is from free, publicly accessible sources; absence of a finding is not proof of absence.',
    'Dark-web and social-handle findings are UNVERIFIED leads (Admiralty C–D) — corroborate before acting.',
  ];
  const failed = reports.filter((r) => !r.ok).map((r) => r.agent);
  if (failed.length) c.push(`Degraded collection: ${failed.join(', ')} did not return within the deadline.`);
  if (findings.some((f) => f.agent === 'social_enum')) c.push('Social account hits may be handle collisions, not the same persona.');
  return c;
}

export const REGISTRY_SIZE = AGENTS.length + 1; // +1 for sanctions screening
