import { NextResponse } from 'next/server';

/**
 * OSIRIS — Pentagon Pizza Index (PPI)
 *
 * Tracks anomalous late-night US government / defence activity as a proxy
 * for imminent major decisions.  Inspired by the anecdotal OSINT technique
 * of watching food deliveries spike to the Pentagon/NSC before operations.
 *
 * Algorithm:
 *  1. Fetch the same 3 RSS feeds used by the GDELT fallback route.
 *  2. Count headline + summary hits against two keyword tiers:
 *       • critical  — very specific to crisis decisions (situation room, joint
 *                     chiefs, pentagon, secdef, war powers, norad …)
 *       • elevated  — broader government/military activity (nato, us military,
 *                     national security, defense secretary …)
 *  3. Compute a raw score 1–5 from keyword density.
 *  4. Late-night multiplier: if DC local time is 20:00–04:59, bump score +1.
 *  5. 15-minute in-memory cache — prevents RSS abuse.
 *  6. Stale-cache fallback: if all feeds fail, return last good data with
 *     `stale: true`.  If no cache exists, return `{ available: false }`.
 */

export const dynamic = 'force-dynamic';

const RSS_FEEDS = [
  'https://feeds.bbci.co.uk/news/world/rss.xml',
  'https://www.aljazeera.com/xml/rss/all.xml',
  'https://rss.nytimes.com/services/xml/rss/nyt/World.xml',
];

// Tier 1 – direct crisis/command indicators
const CRITICAL_KEYWORDS = [
  'pentagon',
  'joint chiefs',
  'situation room',
  'secdef',
  'war powers',
  'norad',
  'strategic command',
  'nuclear option',
  'oval office emergency',
  'nsc meeting',
  'national security council',
];

// Tier 2 – elevated government/military activity
const ELEVATED_KEYWORDS = [
  'us military',
  'u.s. military',
  'american forces',
  'us troops',
  'u.s. troops',
  'nato summit',
  'defense secretary',
  'secretary of defense',
  'national security',
  'us air force',
  'us navy',
  'us army',
  'cia director',
  'fbi director',
  'white house briefing',
];

const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const FETCH_TIMEOUT_MS = 5_000;

export const LEVEL_LABELS: Record<number, string> = {
  1: 'QUIET',
  2: 'ACTIVE',
  3: 'ELEVATED',
  4: 'HOT',
  5: 'BURNING',
};

export interface PizzaIndexPayload {
  available: true;
  stale: boolean;
  level: number;
  label: string;
  dcHour: number;
  lateNight: boolean;
  criticalHits: number;
  elevatedHits: number;
  fetchedAt: string;
}

interface PizzaIndexUnavailable {
  available: false;
}

let cache: PizzaIndexPayload | null = null;
let lastFetchTime = 0;

function getDCHour(): number {
  return Number(
    new Intl.DateTimeFormat('en-US', {
      timeZone: 'America/New_York',
      hour: 'numeric',
      hour12: false,
    }).format(new Date()),
  );
}

function countKeywords(text: string, keywords: string[]): number {
  let total = 0;
  for (const kw of keywords) {
    // simple indexOf loop — avoids regex ReDoS risk
    let pos = 0;
    while ((pos = text.indexOf(kw, pos)) !== -1) {
      total++;
      pos += kw.length;
    }
  }
  return total;
}

async function computePPI(): Promise<PizzaIndexPayload | null> {
  const fetches = RSS_FEEDS.map((url) =>
    fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
      .then((r) => (r.ok ? r.text() : ''))
      .catch(() => ''),
  );

  const texts = await Promise.all(fetches);
  const combined = texts.join(' ').toLowerCase();

  const criticalHits = countKeywords(combined, CRITICAL_KEYWORDS);
  const elevatedHits = countKeywords(combined, ELEVATED_KEYWORDS);

  // Raw score from keyword density
  let level = 1;
  if (criticalHits >= 1 || elevatedHits >= 8) level = 2;
  if (criticalHits >= 3 || elevatedHits >= 20) level = 3;
  if (criticalHits >= 7 || elevatedHits >= 40) level = 4;
  if (criticalHits >= 14 || elevatedHits >= 70) level = 5;

  // Late-night (DC 20:00–04:59) multiplier — unusual hours = suspicious
  const dcHour = getDCHour();
  const lateNight = dcHour >= 20 || dcHour < 5;
  if (lateNight && level < 5) level++;

  return {
    available: true,
    stale: false,
    level,
    label: LEVEL_LABELS[level],
    dcHour,
    lateNight,
    criticalHits,
    elevatedHits,
    fetchedAt: new Date().toISOString(),
  };
}

export async function GET() {
  const now = Date.now();

  if (cache && now - lastFetchTime < CACHE_TTL_MS) {
    return NextResponse.json(cache);
  }

  try {
    const data = await computePPI();
    if (data) {
      cache = data;
      lastFetchTime = now;
      return NextResponse.json(data);
    }
  } catch {
    if (cache) {
      return NextResponse.json({ ...cache, stale: true });
    }
  }

  return NextResponse.json({ available: false } satisfies PizzaIndexUnavailable);
}
