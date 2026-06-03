'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface Exchange { name: string; country: string; open: boolean; }
interface CountryRisk { code: string; risk_score: number; risk_level: string; tags: string[]; }

interface EWSData {
  available: boolean;
  stale?: boolean;
  emergencyLevel?: number;
  alertLevel?: string;
  zScore?: number;
  matchedCount?: number;
  airborneCount?: number;
}

interface CyberData {
  stats?: {
    active_cves?: number;
  };
}

interface PizzaIndexData {
  available: boolean;
  stale?: boolean;
  level?: number;
  label?: string;
  dcHour?: number;
  lateNight?: boolean;
  criticalHits?: number;
  elevatedHits?: number;
}

const RISK_TOOLTIPS: Record<string, string> = {
  CRITICAL: 'Active conflict, sanctions, or major instability detected',
  HIGH: 'Elevated threat level — ongoing tensions or security concerns',
  ELEVATED: 'Moderate risk — political instability or regional disputes',
  LOW: 'Stable — no significant threats detected',
};

const EWS_LABELS: Record<number, string> = {
  1: 'NORMAL',
  2: 'WATCH',
  3: 'ELEVATED',
  4: 'WARNING',
  5: 'ALARM',
};

const PPI_LABELS: Record<number, string> = {
  1: 'QUIET',
  2: 'ACTIVE',
  3: 'ELEVATED',
  4: 'HOT',
  5: 'BURNING',
};

export default function GlobalStatusBar() {
  const [exchanges, setExchanges] = useState<Exchange[]>([]);
  const [risks, setRisks] = useState<CountryRisk[]>([]);
  const [cyber, setCyber] = useState<CyberData | null>(null);
  const [openCount, setOpenCount] = useState(0);
  const [hoveredRisk, setHoveredRisk] = useState<CountryRisk | null>(null);
  const [ewsData, setEwsData] = useState<EWSData | null>(null);
  const [hoveredEWS, setHoveredEWS] = useState(false);
  const [pizzaData, setPizzaData] = useState<PizzaIndexData | null>(null);
  const [hoveredPPI, setHoveredPPI] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [riskRes, cyberRes] = await Promise.allSettled([
          fetch('/api/country-risk'),
          fetch('/api/cyber-threats'),
        ]);
        if (riskRes.status === 'fulfilled' && riskRes.value.ok) {
          const d = await riskRes.value.json();
          setExchanges(d.exchanges || []);
          setRisks(d.countries || []);
          setOpenCount(d.open_exchanges || 0);
        }
        if (cyberRes.status === 'fulfilled' && cyberRes.value.ok) {
          setCyber(await cyberRes.value.json());
        }
      } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }
    };
    fetchData();
    const iv = setInterval(fetchData, 1800000); // 30 min
    return () => clearInterval(iv);
  }, []);

  useEffect(() => {
    const fetchEWS = async () => {
      try {
        const res = await fetch('/api/ews-index');
        if (res.ok) setEwsData(await res.json());
      } catch { /* non-critical — badge stays hidden */ }
    };
    fetchEWS();
    const iv = setInterval(fetchEWS, 10 * 60 * 1000); // 10 min — matches upstream update cadence
    return () => clearInterval(iv);
  }, []);

  useEffect(() => {
    const fetchPPI = async () => {
      try {
        const res = await fetch('/api/pizza-index');
        if (res.ok) setPizzaData(await res.json());
      } catch { /* non-critical — badge stays hidden */ }
    };
    fetchPPI();
    const iv = setInterval(fetchPPI, 15 * 60 * 1000); // 15 min
    return () => clearInterval(iv);
  }, []);

  const topRisks = risks.slice(0, 6);
  const cveCount = cyber?.stats?.active_cves || 0;

  const riskTextClass = (level: string) =>
    level === 'CRITICAL' ? 'text-[#FF3D3D]' : level === 'HIGH' ? 'text-[#FF9500]' : level === 'ELEVATED' ? 'text-[#FFD700]' : 'text-[#00E676]';

  const riskBorderClass = (level: string) =>
    level === 'CRITICAL' ? 'border-[#FF3D3D]/25' : level === 'HIGH' ? 'border-[#FF9500]/25' : level === 'ELEVATED' ? 'border-[#FFD700]/25' : 'border-[#00E676]/25';

  const riskTagClass = (level: string) =>
    level === 'CRITICAL' ? 'bg-[#FF3D3D]/15 text-[#FF3D3D]' : level === 'HIGH' ? 'bg-[#FF9500]/15 text-[#FF9500]' : level === 'ELEVATED' ? 'bg-[#FFD700]/15 text-[#FFD700]' : 'bg-[#00E676]/15 text-[#00E676]';

  const ewsTextClass: Record<number, string> = {
    1: 'text-[#4caf78]',
    2: 'text-[#a8b840]',
    3: 'text-[#d4a017]',
    4: 'text-[#d4621a]',
    5: 'text-[#c0392b]',
  };

  const ewsBgClass: Record<number, string> = {
    1: 'bg-[#4caf78]',
    2: 'bg-[#a8b840]',
    3: 'bg-[#d4a017]',
    4: 'bg-[#d4621a]',
    5: 'bg-[#c0392b]',
  };

  const ewsBorderClass: Record<number, string> = {
    1: 'border-[#4caf78]/25',
    2: 'border-[#a8b840]/25',
    3: 'border-[#d4a017]/25',
    4: 'border-[#d4621a]/25',
    5: 'border-[#c0392b]/25',
  };

  const ppiTextClass: Record<number, string> = {
    1: 'text-[#4caf78]',
    2: 'text-[#a8b840]',
    3: 'text-[#d4a017]',
    4: 'text-[#d4621a]',
    5: 'text-[#c0392b]',
  };

  const ppiBgClass: Record<number, string> = {
    1: 'bg-[#4caf78]',
    2: 'bg-[#a8b840]',
    3: 'bg-[#d4a017]',
    4: 'bg-[#d4621a]',
    5: 'bg-[#c0392b]',
  };

  const ppiBorderClass: Record<number, string> = {
    1: 'border-[#4caf78]/25',
    2: 'border-[#a8b840]/25',
    3: 'border-[#d4a017]/25',
    4: 'border-[#d4621a]/25',
    5: 'border-[#c0392b]/25',
  };

  const countryFlag = (code: string) => {
    try {
      return String.fromCodePoint(...code.toUpperCase().split('').map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
    } catch { return code; }
  };

  if (exchanges.length === 0 && risks.length === 0) return null;

  const tickerContent = (
    <>
      {exchanges.map(ex => (
        <span key={ex.name} className="inline-flex items-center gap-1 mx-2.5">
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${ex.open ? 'bg-[var(--alert-green)]' : 'bg-[var(--text-muted)]/30'}`} />
          <span className={`${ex.open ? 'text-[var(--text-primary)]' : 'text-[var(--text-muted)]/40'}`}>{ex.name}</span>
        </span>
      ))}
      <span className="text-[var(--border-primary)] mx-1.5">|</span>
      {topRisks.map(r => (
        <span
          key={r.code}
          className="inline-flex items-center gap-1 mx-2 relative cursor-help pointer-events-auto"
          onMouseEnter={() => setHoveredRisk(r)}
          onMouseLeave={() => setHoveredRisk(null)}
        >
          <span className="text-[13px]">{countryFlag(r.code)}</span>
          <span className={`font-bold ${riskTextClass(r.risk_level)}`}>{r.risk_score}</span>
        </span>
      ))}
      <span className="text-[var(--border-primary)] mx-1.5">|</span>
      <span className="inline-flex items-center gap-1.5 mx-2.5">
        <span className="text-[#E040FB]">CYBER</span>
        <span className="text-[var(--text-primary)]">{cveCount} CVEs</span>
      </span>
    </>
  );

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 4, duration: 0.8 }}
      className="hidden md:block absolute bottom-0 left-0 right-0 z-[198] pointer-events-none"
    >
      <div className="h-[30px] overflow-hidden bg-black/90 border-t border-[var(--cyan-primary)]/40 flex items-center text-[11px] font-mono tracking-wider backdrop-blur-md relative shadow-[0_-4px_20px_rgba(0,229,255,0.1)]">
        {/* Animated glitch line overlay */}
        <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-[var(--cyan-primary)] to-transparent opacity-50 animate-[hud-scanline_3s_linear_infinite]" />
        
        {/* Static label */}
        <div className="flex-shrink-0 px-4 h-full flex items-center gap-1.5 border-r border-[var(--cyan-primary)]/30 bg-black pointer-events-auto relative z-10 shadow-[4px_0_10px_rgba(0,0,0,0.5)]">
          <span className="text-[var(--cyan-primary)]/50">MKT</span>
          <span className="text-[var(--cyan-primary)] font-bold">{openCount}/{exchanges.length}</span>
        </div>

        {/* CSS-animated ticker */}
        <div className="flex-1 overflow-hidden relative [mask-image:linear-gradient(to_right,transparent,black_5%,black_95%,transparent)]">
          <div className="flex items-center animate-ticker whitespace-nowrap">
            {tickerContent}
            {tickerContent}
          </div>
        </div>

        {/* PPI badge — hidden when unavailable; never throws */}
        {pizzaData?.available && (
          <div
            className="flex-shrink-0 px-3 h-full flex items-center gap-1.5 border-l border-[var(--cyan-primary)]/30 bg-black pointer-events-auto relative z-10 cursor-help"
            onMouseEnter={() => setHoveredPPI(true)}
            onMouseLeave={() => setHoveredPPI(false)}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${ppiBgClass[pizzaData.level ?? 1]}`}
            />
            <span className="text-[var(--cyan-primary)]/50">PPI</span>
            <span className={`font-bold ${ppiTextClass[pizzaData.level ?? 1]}`}>
              {pizzaData.level}
            </span>
            {pizzaData.stale && (
              <span className="text-[var(--text-muted)]/40 text-[7px]">~</span>
            )}
          </div>
        )}

        {/* EWS badge — hidden when unavailable; never throws */}
        {ewsData?.available && (
          <div
            className="flex-shrink-0 px-3 h-full flex items-center gap-1.5 border-l border-[var(--cyan-primary)]/30 bg-black pointer-events-auto relative z-10 cursor-help"
            onMouseEnter={() => setHoveredEWS(true)}
            onMouseLeave={() => setHoveredEWS(false)}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${ewsBgClass[ewsData.emergencyLevel ?? 1]}`}
            />
            <span className="text-[var(--cyan-primary)]/50">EWS</span>
            <span className={`font-bold ${ewsTextClass[ewsData.emergencyLevel ?? 1]}`}>
              {ewsData.emergencyLevel}
            </span>
            {ewsData.stale && (
              <span className="text-[var(--text-muted)]/40 text-[7px]">~</span>
            )}
          </div>
        )}
      </div>

      {/* PPI hover tooltip */}
      {pizzaData?.available && hoveredPPI && (
        <div className="absolute bottom-[28px] right-0 z-[300] pointer-events-none">
          <div
            className={`glass-panel px-3 py-2 text-[10px] font-mono whitespace-nowrap ${ppiBorderClass[pizzaData.level ?? 1]}`}
          >
            <div className="flex items-center gap-2 mb-1">
              <span className={`font-bold ${ppiTextClass[pizzaData.level ?? 1]}`}>
                🍕 PPI {pizzaData.level} — {PPI_LABELS[pizzaData.level ?? 1]}
              </span>
            </div>
            <div className="text-[9px] text-[var(--text-secondary)] mb-1">
              Pentagon Pizza Index — late-night DC activity proxy
            </div>
            <div className="flex flex-col gap-0.5 text-[9px]">
              <span className="text-[var(--text-muted)]">
                DC time: <span className="text-[var(--text-primary)]">{pizzaData.dcHour}:00{pizzaData.lateNight ? ' 🌙' : ''}</span>
              </span>
              <span className="text-[var(--text-muted)]">
                Critical signals: <span className="text-[var(--text-primary)]">{pizzaData.criticalHits ?? '–'}</span>
              </span>
              <span className="text-[var(--text-muted)]">
                Gov activity: <span className="text-[var(--text-primary)]">{pizzaData.elevatedHits ?? '–'}</span>
              </span>
              {pizzaData.stale && (
                <span className="text-[var(--text-muted)]/60 italic">Cached data — upstream unavailable</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* EWS hover tooltip */}
      {ewsData?.available && hoveredEWS && (
        <div className="absolute bottom-[28px] right-0 z-[300] pointer-events-none">
          <div
            className={`glass-panel px-3 py-2 text-[10px] font-mono whitespace-nowrap ${ewsBorderClass[ewsData.emergencyLevel ?? 1]}`}
          >
            <div className="flex items-center gap-2 mb-1">
              <span className={`font-bold ${ewsTextClass[ewsData.emergencyLevel ?? 1]}`}>
                EWS {ewsData.emergencyLevel} — {EWS_LABELS[ewsData.emergencyLevel ?? 1]}
              </span>
            </div>
            <div className="text-[9px] text-[var(--text-secondary)] mb-1">
              Elite private-jet evacuation index
            </div>
            <div className="flex flex-col gap-0.5 text-[9px]">
              <span className="text-[var(--text-muted)]">
                Z-score: <span className="text-[var(--text-primary)]">{ewsData.zScore?.toFixed(2) ?? '–'}</span>
              </span>
              <span className="text-[var(--text-muted)]">
                Matched jets: <span className="text-[var(--text-primary)]">{ewsData.matchedCount ?? '–'}</span>
              </span>
              <span className="text-[var(--text-muted)]">
                Total airborne: <span className="text-[var(--text-primary)]">{ewsData.airborneCount?.toLocaleString() ?? '–'}</span>
              </span>
              {ewsData.stale && (
                <span className="text-[var(--text-muted)]/60 italic">Cached data — upstream unavailable</span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Hover tooltip for risk scores */}
      {hoveredRisk && (
        <div
          className="absolute bottom-[28px] left-1/2 -translate-x-1/2 z-[300] pointer-events-none"
        >
          <div className={`glass-panel px-3 py-2 text-[10px] font-mono text-center whitespace-nowrap ${riskBorderClass(hoveredRisk.risk_level)}`}>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[12px]">{countryFlag(hoveredRisk.code)}</span>
              <span className={`font-bold ${riskTextClass(hoveredRisk.risk_level)}`}>
                {hoveredRisk.risk_level}
              </span>
              <span className="text-[var(--text-muted)]">Score: {hoveredRisk.risk_score}/100</span>
            </div>
            <div className="text-[9px] text-[var(--text-secondary)]">
              {RISK_TOOLTIPS[hoveredRisk.risk_level] || 'Risk assessment based on global threat data'}
            </div>
            {hoveredRisk.tags?.length > 0 && (
              <div className="flex gap-1 mt-1 justify-center flex-wrap">
                {hoveredRisk.tags.slice(0, 3).map(t => (
                  <span key={t} className={`px-1.5 py-0.5 rounded text-[8px] ${riskTagClass(hoveredRisk.risk_level)}`}>
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </motion.div>
  );
}
