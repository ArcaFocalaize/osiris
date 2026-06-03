'use client';

import { memo } from 'react';
import {
  Plane, Satellite, Activity, Sun, AlertTriangle, Camera, Flame, Target,
  CloudLightning, Radiation, Tv, Anchor, Ship, Newspaper,
  Network, Share2, Radio
} from 'lucide-react';

interface LayerPanelProps {
  data: any;
  activeLayers: any;
  setActiveLayers: React.Dispatch<React.SetStateAction<any>>;
  isMobile?: boolean;
}

const LAYER_GROUPS = [
  {
    label: 'SDK',
    fullLabel: 'OSIRIS SDK',
    color: '#1565C0',
    layers: [
      { key: 'sdk_sea', label: 'Maritime Lines', icon: Anchor, color: '#4FC3F7', dataKey: 'sdk_entities' },
      { key: 'sdk_ransomware', label: 'Ransomware Feed', icon: AlertTriangle, color: '#FF3D3D', dataKey: 'sdk_entities' },
    ],
  },
  {
    label: 'AVIATION',
    fullLabel: 'AVIATION',
    color: '#00E5FF',
    layers: [
      { key: 'flights', label: 'Commercial', icon: Plane, color: '#00E5FF', dataKey: 'commercial_flights' },
      { key: 'private', label: 'Private', icon: Plane, color: '#00E676', dataKey: 'private_flights' },
      { key: 'jets', label: 'Private Jets', icon: Plane, color: '#FF69B4', dataKey: 'private_jets' },
      { key: 'military', label: 'Military', icon: Shield, color: '#FF3D3D', dataKey: 'military_flights' },
    ],
  },
  {
    label: 'MARITIME',
    fullLabel: 'MARITIME & SPACE',
    color: '#00BCD4',
    layers: [
      { key: 'maritime', label: 'Maritime / Naval', icon: Ship, color: '#00BCD4', dataKey: 'maritime_ships,maritime_ports,maritime_chokepoints' },
      { key: 'cables', label: 'Submarine Cables', icon: Share2, color: '#4FC3F7', dataKey: 'submarine_cables' },
      { key: 'satellites', label: 'Satellites', icon: Satellite, color: '#D4AF37', dataKey: 'satellites' },
    ],
  },
  {
    label: 'SURVEIL',
    fullLabel: 'SURVEILLANCE',
    color: '#39FF14',
    layers: [
      { key: 'cctv', label: 'CCTV Cameras', icon: Camera, color: '#39FF14', dataKey: 'cameras' },
      { key: 'live_news', label: 'Live News Feeds', icon: Tv, color: '#FF4081', dataKey: 'live_feeds' },
    ],
  },
  {
    label: 'HAZARD',
    fullLabel: 'NATURAL HAZARDS',
    color: '#FF9500',
    layers: [
      { key: 'earthquakes', label: 'Earthquakes (24h)', icon: Activity, color: '#FF9500', dataKey: 'earthquakes' },
      { key: 'fires', label: 'Active Fires', icon: Flame, color: '#FF6B00', dataKey: 'fires' },
      { key: 'weather', label: 'Severe Weather', icon: CloudLightning, color: '#E040FB', dataKey: 'weather_events' },
    ],
  },
  {
    label: 'THREAT',
    fullLabel: 'THREATS & INFRA',
    color: '#FF3D3D',
    layers: [
      { key: 'infrastructure', label: 'Nuclear Facilities', icon: Radiation, color: '#76FF03', dataKey: 'infrastructure' },
      { key: 'global_incidents', label: 'Global Incidents', icon: AlertTriangle, color: '#FF3D3D', dataKey: 'gdelt' },
      { key: 'gps_jamming', label: 'GPS Jamming', icon: Radio, color: '#FF4444', dataKey: 'gps_jamming' },
    ],
  },
  {
    label: 'DISPLAY',
    fullLabel: 'DISPLAY',
    color: '#448AFF',
    layers: [
      { key: 'day_night', label: 'Day / Night Cycle', icon: Sun, color: '#448AFF', dataKey: '' },
    ],
  },
];

const ALL_LAYERS = LAYER_GROUPS.flatMap(g => g.layers);

// SVG component for Shield which was missing in the imports above
function Shield(props: any) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  );
}

function LayerPanel({ data, activeLayers, setActiveLayers, isMobile }: LayerPanelProps) {
  const toggle = (key: string) => setActiveLayers((prev: any) => ({ ...prev, [key]: !prev[key] }));
  
  const getCount = (dk: string): number | null => {
    if (!dk) return null;
    let total = 0;
    let found = false;
    for (const k of dk.split(',')) {
      if (data[k] && Array.isArray(data[k])) {
        total += data[k].length;
        found = true;
      }
    }
    return found ? total : null;
  };

  if (isMobile) {
    return (
      <div className="flex flex-col gap-4 py-2">
        {LAYER_GROUPS.map((group) => (
          <div key={group.label} className="flex flex-col gap-2">
            <div 
              className="text-[10px] font-bold font-mono tracking-widest border-b border-white/10 pb-1"
              style={{ color: group.color }}
            >
              {group.fullLabel}
            </div>
            <div className="grid grid-cols-2 gap-2">
              {group.layers.map((layer) => {
                const isLayerActive = activeLayers[layer.key];
                const count = getCount(layer.dataKey);
                
                return (
                  <button
                    key={layer.key}
                    onClick={() => {
                      if (layer.key === 'sdk_ransomware') {
                        alert('Ransomware Feed - Coming Soon');
                      } else {
                        toggle(layer.key);
                      }
                    }}
                    className={`flex items-center gap-2 px-2 py-2 rounded border transition-colors ${
                      isLayerActive 
                        ? 'bg-white/10 border-white/20' 
                        : 'bg-transparent border-white/5 hover:border-white/10'
                    }`}
                  >
                    <div 
                      className={`w-2 h-2 rounded-full border flex-shrink-0 transition-all ${
                        isLayerActive ? 'bg-current border-current scale-100' : 'bg-transparent border-white/30 scale-75'
                      }`}
                      style={{ color: isLayerActive ? layer.color : 'inherit', boxShadow: isLayerActive ? `0 0 8px ${layer.color}` : 'none' }}
                    />
                    <span className={`text-[9px] font-mono uppercase tracking-wider flex-1 text-left ${isLayerActive ? 'text-white' : 'text-white/60'}`}>
                      {layer.label}
                    </span>
                    {count !== null && (
                      <span className="text-[8px] font-mono tabular-nums opacity-60">
                        {count.toLocaleString()}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="absolute top-0 left-0 h-full w-[218px] border-r border-[var(--border-secondary)] flex flex-col pt-28 pb-10 z-50 pointer-events-auto bg-black/45 backdrop-blur-md styled-scrollbar overflow-y-auto">

      <div className="px-6 mb-4">
        <div className="text-[10px] font-mono font-bold tracking-[0.28em] text-[var(--text-muted)] uppercase">Layers</div>
        <div className="mt-1 h-px w-full bg-gradient-to-r from-[var(--border-primary)] to-transparent" />
      </div>

      <div className="flex-1 flex flex-col gap-5 px-3">
        {LAYER_GROUPS.map((group) => {
          const groupActiveCount = group.layers.filter(l => activeLayers[l.key]).length;
          const isActive = groupActiveCount > 0;

          return (
            <div key={group.label} className="flex flex-col gap-1.5">
              {/* Group header */}
              <div className="flex items-center gap-2.5 pl-3 pr-1">
                <span
                  className="w-2 h-2 rounded-full flex-shrink-0 transition-all"
                  style={{
                    backgroundColor: isActive ? group.color : 'rgba(255,255,255,0.18)',
                    boxShadow: isActive ? `0 0 10px ${group.color}` : 'none',
                  }}
                />
                <span
                  className="text-[12px] font-mono font-bold tracking-[0.1em] uppercase transition-colors"
                  style={{ color: isActive ? group.color : 'rgba(255,255,255,0.58)' }}
                >
                  {group.fullLabel}
                </span>
                {groupActiveCount > 0 && (
                  <span className="ml-auto text-[10px] font-mono tabular-nums text-[var(--text-muted)]">
                    {groupActiveCount}
                  </span>
                )}
              </div>

              {/* Layer rows — always visible */}
              <div className="flex flex-col gap-0.5 pl-2">
                {group.layers.map((layer) => {
                  const isLayerActive = activeLayers[layer.key];
                  const count = getCount(layer.dataKey);
                  const Icon = layer.icon || Shield;

                  return (
                    <button
                      key={layer.key}
                      onClick={() => {
                        if (layer.key === 'sdk_ransomware') {
                          alert('Ransomware Feed - Coming Soon');
                        } else {
                          toggle(layer.key);
                        }
                      }}
                      className={`group w-full flex items-center gap-2.5 pl-4 pr-2.5 py-2 rounded-md border transition-colors ${
                        isLayerActive
                          ? 'bg-white/[0.07] border-white/10'
                          : 'bg-transparent border-transparent hover:bg-white/[0.04]'
                      }`}
                    >
                      <Icon
                        className="w-4 h-4 flex-shrink-0 transition-colors"
                        style={{ color: isLayerActive ? layer.color : 'rgba(255,255,255,0.35)' }}
                        strokeWidth={2}
                      />
                      <span
                        className={`text-[12px] font-medium tracking-wide flex-1 text-left transition-colors ${
                          isLayerActive
                            ? 'text-[var(--text-primary)]'
                            : 'text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]'
                        }`}
                      >
                        {layer.label}
                      </span>
                      {count !== null && (
                        <span className="text-[10px] font-mono tabular-nums text-[var(--text-muted)] group-hover:text-[var(--text-secondary)]">
                          {count.toLocaleString()}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default memo(LayerPanel);
