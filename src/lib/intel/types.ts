// Orchestrated OSINT/HUMINT collection — shared types.
//
// Doctrine reference (see "Guida Completa Analisi Intelligence Operativa"):
//  - Collection is split across the classic "-INT" disciplines.
//  - Every finding carries an Admiralty Code rating: a source-reliability
//    letter (A–F) and an information-credibility number (1–6).
//  - Findings are tagged by the web layer they were collected from
//    (surface / deep / dark) so the consumer can weigh exposure.
//  - The dossier leads with a BLUF (Bottom Line Up Front) summary.
//
// ETHICS / LEGAL: every agent uses only publicly accessible, free sources
// (clearnet APIs, certificate transparency, breach-notification services,
// onion *search* gateways with clearnet mirrors). No agent bypasses access
// controls, harvests credentials, or crawls authenticated/illegal content.

export type Discipline =
  | 'OSINT'    // open-source
  | 'SOCMINT'  // social media
  | 'TECHINT'  // technical / infrastructure
  | 'GEOINT'   // geospatial
  | 'FININT'   // financial
  | 'CTI'      // cyber threat intelligence
  | 'HUMINT';  // human-source surface (handles, mentions, persona linkage)

export type WebLayer = 'surface' | 'deep' | 'dark';

export type TargetType = 'email' | 'domain' | 'ipv4' | 'username' | 'name';

// Admiralty source reliability (A best … F unjudgeable).
export type Reliability = 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
// Admiralty information credibility (1 confirmed … 6 cannot be judged).
export type Credibility = 1 | 2 | 3 | 4 | 5 | 6;

export interface Citation {
  label: string;
  url?: string;
}

// A single piece of collected intelligence.
export interface Finding {
  agent: string;
  discipline: Discipline;
  layer: WebLayer;
  title: string;
  summary: string;
  reliability: Reliability;
  credibility: Credibility;
  admiralty: string;          // e.g. "B2"
  data?: Record<string, unknown>;
  citations?: Citation[];
}

// A lead the orchestrator surfaces for a follow-up collection pass.
export interface Pivot {
  type: TargetType;
  value: string;
  reason: string;
}

export interface AgentReport {
  agent: string;
  discipline: Discipline;
  layer: WebLayer;
  reliability: Reliability;
  ok: boolean;
  ms: number;
  findings: Finding[];
  pivots: Pivot[];
  error?: string;
}

// Definition of a collection agent in the registry.
export interface CollectionAgent {
  id: string;
  name: string;
  discipline: Discipline;
  layer: WebLayer;
  reliability: Reliability;        // baseline source reliability
  // Which target types this agent can act on.
  appliesTo: TargetType[];
  // Perform collection. MUST resolve (never throw) within `signal`'s deadline;
  // return findings + optional pivots. Returning [] means "nothing found".
  collect: (target: string, type: TargetType, signal: AbortSignal) => Promise<{
    findings: Finding[];
    pivots?: Pivot[];
  }>;
}

export interface Dossier {
  target: string;
  target_type: TargetType;
  classification: string;          // always "OSINT // UNCLASSIFIED" here
  bluf: string;                    // Bottom Line Up Front
  collected_at: string;
  duration_ms: number;
  confidence: 'LOW' | 'MODERATE' | 'HIGH';
  coverage: {
    agents_run: number;
    agents_ok: number;
    findings: number;
    by_discipline: Record<string, number>;
    by_layer: Record<WebLayer, number>;
  };
  agents: AgentReport[];
  findings: Finding[];
  pivots: Pivot[];
  caveats: string[];
}
