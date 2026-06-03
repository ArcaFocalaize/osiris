import { NextResponse } from 'next/server';
import { getMemo, setMemo, cachedJson, fetchRetry } from '@/lib/osint-cache';

// GitHub profiles change over time \u2014 cache briefly (2 minutes).
const GH_TTL_S = 120;

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const username = searchParams.get('user');

  if (!username) return NextResponse.json({ error: 'Missing username parameter' }, { status: 400 });

  const cacheKey = `github:${username.toLowerCase()}`;
  const cached = getMemo(cacheKey);
  if (cached) return cachedJson(cached, GH_TTL_S);

  try {
    const [userRes, reposRes] = await Promise.all([
      fetchRetry(`https://api.github.com/users/${encodeURIComponent(username)}`, { headers: { 'User-Agent': 'OSIRIS-Recon' } }, { retries: 1, timeoutMs: 8000 }),
      fetchRetry(`https://api.github.com/users/${encodeURIComponent(username)}/repos?sort=updated&per_page=5`, { headers: { 'User-Agent': 'OSIRIS-Recon' } }, { retries: 1, timeoutMs: 8000 })
    ]);

    if (userRes.status === 404) return NextResponse.json({ error: 'User not found' }, { status: 404 });
    if (!userRes.ok) throw new Error(`GitHub API HTTP ${userRes.status}`);

    const userData = await userRes.json();
    const reposData = reposRes.ok ? await reposRes.json() : [];

    const payload = {
      username: userData.login,
      name: userData.name,
      company: userData.company,
      blog: userData.blog,
      location: userData.location,
      email: userData.email,
      bio: userData.bio,
      twitter: userData.twitter_username,
      public_repos: userData.public_repos,
      followers: userData.followers,
      created_at: userData.created_at,
      avatar_url: userData.avatar_url,
      recent_repos: Array.isArray(reposData) ? reposData.map((r: any) => ({ name: r.name, language: r.language, updated: r.updated_at })) : []
    };
    setMemo(cacheKey, payload, GH_TTL_S * 1000);
    return cachedJson(payload, GH_TTL_S);
  } catch (error: any) {
    return NextResponse.json({ error: 'GitHub lookup failed', detail: error.message }, { status: 502 });
  }
}
