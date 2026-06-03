import { NextResponse } from 'next/server';
import { isRateLimited, getClientIp } from '@/lib/ssrf-guard';
import catalog from './catalog.json';

// Intel Sources Catalog — curated OSINT/CTI tools, supply-chain security tools
// and NIS2-correlated compliance frameworks. Static dataset, no external calls.
const CATALOG_TTL_S = 3600;

type Tool = {
  name: string;
  type: string;
  free_alternatives: string;
  data_provided: string;
  formats: string;
  info_type: string;
  use_case: string;
  cti_value: string;
  smb_relevant: boolean;
};

export async function GET(req: Request) {
  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 30, 60_000)) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  const { searchParams } = new URL(req.url);
  const q = (searchParams.get('q') || '').trim().toLowerCase().slice(0, 80);
  const section = (searchParams.get('section') || '').trim().toLowerCase();
  const smbOnly = searchParams.get('smb') === '1';
  const infoType = (searchParams.get('info_type') || '').trim().toLowerCase().slice(0, 60);

  let tools = catalog.tools as Tool[];

  if (smbOnly) tools = tools.filter((t) => t.smb_relevant);
  if (infoType) tools = tools.filter((t) => t.info_type.toLowerCase().includes(infoType));
  if (q) {
    tools = tools.filter((t) =>
      [t.name, t.data_provided, t.info_type, t.use_case, t.cti_value, t.free_alternatives]
        .join(' ')
        .toLowerCase()
        .includes(q)
    );
  }

  // Distinct info types for client-side faceting
  const infoTypes = Array.from(
    new Set((catalog.tools as Tool[]).map((t) => t.info_type).filter(Boolean))
  ).sort();

  const body =
    section === 'tools'
      ? { tools }
      : section === 'supply_chain'
        ? { supply_chain: catalog.supply_chain }
        : section === 'frameworks'
          ? { frameworks: catalog.frameworks }
          : {
              version: catalog.version,
              description: catalog.description,
              counts: {
                tools: (catalog.tools as Tool[]).length,
                supply_chain_categories: catalog.supply_chain.length,
                frameworks: catalog.frameworks.length,
                smb_relevant: (catalog.tools as Tool[]).filter((t) => t.smb_relevant).length,
              },
              info_types: infoTypes,
              tools,
              supply_chain: catalog.supply_chain,
              frameworks: catalog.frameworks,
            };

  return NextResponse.json(
    { ...body, timestamp: new Date().toISOString() },
    {
      headers: {
        'Cache-Control': `public, s-maxage=${CATALOG_TTL_S}, stale-while-revalidate=${CATALOG_TTL_S * 2}`,
      },
    }
  );
}
