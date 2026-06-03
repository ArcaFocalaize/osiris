import { NextResponse } from 'next/server';
import { isRateLimited, getClientIp } from '@/lib/ssrf-guard';
import { getMemo, setMemo, cachedJson } from '@/lib/osint-cache';

// Sherlock / WhatsMyName-style username enumeration across public platforms.
// Free, no API key. We probe a curated set of high-signal sites and infer
// account existence from the HTTP status code (and, where status alone is
// ambiguous, an optional body string match). Results are cached briefly.
const USERNAME_TTL_S = 600;

type Site = {
  name: string;
  category: 'social' | 'dev' | 'creative' | 'gaming' | 'forum' | 'professional';
  url: (u: string) => string;
  // 'exists' detection: status code that indicates the profile is present.
  // Some sites return 200 for missing profiles, so an optional `absentString`
  // (found in the body of a *missing* profile) is used to disambiguate.
  existsCode?: number;
  absentString?: string;
};

const SITES: Site[] = [
  { name: 'GitHub', category: 'dev', url: u => `https://github.com/${u}`, existsCode: 200 },
  { name: 'GitLab', category: 'dev', url: u => `https://gitlab.com/${u}`, existsCode: 200 },
  { name: 'Docker Hub', category: 'dev', url: u => `https://hub.docker.com/u/${u}`, existsCode: 200 },
  { name: 'NPM', category: 'dev', url: u => `https://www.npmjs.com/~${u}`, existsCode: 200 },
  { name: 'PyPI', category: 'dev', url: u => `https://pypi.org/user/${u}/`, existsCode: 200 },
  { name: 'Replit', category: 'dev', url: u => `https://replit.com/@${u}`, existsCode: 200 },
  { name: 'Keybase', category: 'dev', url: u => `https://keybase.io/${u}`, existsCode: 200 },
  { name: 'Reddit', category: 'forum', url: u => `https://www.reddit.com/user/${u}`, existsCode: 200 },
  { name: 'HackerNews', category: 'forum', url: u => `https://news.ycombinator.com/user?id=${u}`, existsCode: 200, absentString: 'No such user.' },
  { name: 'Telegram', category: 'social', url: u => `https://t.me/${u}`, existsCode: 200, absentString: "If you have Telegram, you can contact" },
  { name: 'Instagram', category: 'social', url: u => `https://www.instagram.com/${u}/`, existsCode: 200 },
  { name: 'X / Twitter', category: 'social', url: u => `https://twitter.com/${u}`, existsCode: 200 },
  { name: 'TikTok', category: 'social', url: u => `https://www.tiktok.com/@${u}`, existsCode: 200 },
  { name: 'Pinterest', category: 'social', url: u => `https://www.pinterest.com/${u}/`, existsCode: 200 },
  { name: 'Mastodon (mstdn)', category: 'social', url: u => `https://mstdn.social/@${u}`, existsCode: 200 },
  { name: 'Twitch', category: 'gaming', url: u => `https://www.twitch.tv/${u}`, existsCode: 200 },
  { name: 'Steam', category: 'gaming', url: u => `https://steamcommunity.com/id/${u}`, existsCode: 200, absentString: 'The specified profile could not be found' },
  { name: 'YouTube', category: 'creative', url: u => `https://www.youtube.com/@${u}`, existsCode: 200 },
  { name: 'Vimeo', category: 'creative', url: u => `https://vimeo.com/${u}`, existsCode: 200 },
  { name: 'SoundCloud', category: 'creative', url: u => `https://soundcloud.com/${u}`, existsCode: 200 },
  { name: 'Behance', category: 'creative', url: u => `https://www.behance.net/${u}`, existsCode: 200 },
  { name: 'Dribbble', category: 'creative', url: u => `https://dribbble.com/${u}`, existsCode: 200 },
  { name: 'Flickr', category: 'creative', url: u => `https://www.flickr.com/people/${u}`, existsCode: 200 },
  { name: 'Medium', category: 'creative', url: u => `https://medium.com/@${u}`, existsCode: 200 },
  { name: 'DeviantArt', category: 'creative', url: u => `https://www.deviantart.com/${u}`, existsCode: 200 },
  { name: 'Patreon', category: 'creative', url: u => `https://www.patreon.com/${u}`, existsCode: 200 },
  { name: 'Spotify', category: 'creative', url: u => `https://open.spotify.com/user/${u}`, existsCode: 200 },
  { name: 'About.me', category: 'professional', url: u => `https://about.me/${u}`, existsCode: 200 },
  { name: 'Gravatar', category: 'professional', url: u => `https://gravatar.com/${u}`, existsCode: 200 },
  { name: 'Linktree', category: 'professional', url: u => `https://linktr.ee/${u}`, existsCode: 200 },
  { name: 'Wordpress', category: 'creative', url: u => `https://${u}.wordpress.com/`, existsCode: 200 },
];

// Mimic a real browser; many platforms 403 obvious bots.
const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

async function probe(site: Site, username: string, signal: AbortSignal): Promise<{
  name: string;
  category: string;
  url: string;
  found: boolean | null;
}> {
  const url = site.url(username);
  const base = { name: site.name, category: site.category, url };
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      signal,
      headers: { 'User-Agent': UA, Accept: 'text/html' },
    });

    // Redirects to a login/landing page usually mean "not found".
    if (res.status >= 300 && res.status < 400) return { ...base, found: false };
    if (res.status === 404 || res.status === 410) return { ...base, found: false };
    if (res.status === 403 || res.status === 429) return { ...base, found: null }; // blocked/unknown

    const matchesExists = res.status === (site.existsCode ?? 200);
    if (!matchesExists) return { ...base, found: false };

    if (site.absentString) {
      const body = await res.text();
      if (body.includes(site.absentString)) return { ...base, found: false };
    }
    return { ...base, found: true };
  } catch {
    return { ...base, found: null };
  }
}

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const raw = (searchParams.get('user') || '').trim();

  if (!raw) {
    return NextResponse.json({ error: 'Missing user parameter' }, { status: 400 });
  }
  // Strict allow-list prevents path/SSRF injection into the URL templates.
  if (!/^[A-Za-z0-9_.-]{2,40}$/.test(raw)) {
    return NextResponse.json(
      { error: 'Invalid username (allowed: letters, digits, _ . - ; 2-40 chars)' },
      { status: 400 }
    );
  }

  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 10, 60_000)) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  const username = raw;
  const cacheKey = `username:${username.toLowerCase()}`;
  const cached = getMemo(cacheKey);
  if (cached) return cachedJson(cached, USERNAME_TTL_S);

  // Cap the total wall-clock time so the panel never hangs.
  const controller = new AbortController();
  const overall = setTimeout(() => controller.abort(), 12_000);

  try {
    const checks = await Promise.all(
      SITES.map(s => probe(s, username, controller.signal))
    );
    clearTimeout(overall);

    const found = checks.filter(c => c.found === true);
    const notFound = checks.filter(c => c.found === false);
    const unknown = checks.filter(c => c.found === null);

    const payload = {
      username,
      checked: SITES.length,
      found_count: found.length,
      found: found.sort((a, b) => a.name.localeCompare(b.name)),
      not_found: notFound.map(c => c.name).sort(),
      inconclusive: unknown.map(c => c.name).sort(),
      timestamp: new Date().toISOString(),
      note: 'Heuristic detection (HTTP status + body match). Verify hits manually; some sites rate-limit automated probes.',
    };

    setMemo(cacheKey, payload, USERNAME_TTL_S * 1000);
    return cachedJson(payload, USERNAME_TTL_S);
  } catch {
    clearTimeout(overall);
    return NextResponse.json({ error: 'Username lookup failed' }, { status: 500 });
  }
}
