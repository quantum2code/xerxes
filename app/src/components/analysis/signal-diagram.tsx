'use client';

import { useId, useState, type CSSProperties } from 'react';
import { Button } from '@base-ui/react/button';
import { motion } from 'motion/react';
import { Tilt } from '@/components/motion-primitives/tilt';
import { TransitionPanel } from '@/components/motion-primitives/transition-panel';
import { useMotionPreference } from '@/components/motion-primitives/use-motion-preference';
import { detectors, type AnalysisResult, type ModuleKey } from '@/lib/analysis';
import { getSignalState } from '@/lib/signal-state';

export function SignalDiagram({ active, onSelect, loading = false, result = null }: {
  active: ModuleKey;
  onSelect: (key: ModuleKey) => void;
  loading?: boolean;
  result?: AnalysisResult | null;
}) {
  const id = useId().replaceAll(':', '');
  const reducedMotion = useMotionPreference();
  const [engaged, setEngaged] = useState(false);
  const selectedIndex = detectors.findIndex(({ key }) => key === active);
  const layers = detectors.map((detector, index) => ({ ...detector, index, state: getSignalState(detector.key, result, loading) }));
  const selected = layers[selectedIndex];
  const transition = reducedMotion ? { duration: 0 } : { type: 'spring' as const, stiffness: 260, damping: 28 };

  return <figure className="signal-diagram" data-report={Boolean(result) || undefined} data-selected-tone={selected.state.tone} aria-label="Explore the five URL analysis checks">
    <Tilt className="signal-tilt">
      <div
        className="signal-stage"
        data-engaged={engaged || undefined}
        data-loading={loading || undefined}
        onPointerEnter={() => setEngaged(true)}
        onPointerLeave={() => setEngaged(false)}
        onFocus={() => setEngaged(true)}
        onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setEngaged(false); }}
      >
        <svg className="signal-svg" viewBox="0 0 360 300" fill="none" aria-hidden="true">
          <defs>
            <radialGradient id={`${id}-base`}><stop stopColor="#c6a364" stopOpacity=".2" /><stop offset="1" stopColor="#c6a364" stopOpacity="0" /></radialGradient>
          </defs>
          <ellipse cx="150" cy="253" rx="116" ry="36" fill={`url(#${id}-base)`} />
          <ellipse cx="150" cy="253" rx="104" ry="29" stroke="#ad9563" strokeOpacity=".3" />
          <ellipse cx="150" cy="253" rx="85" ry="23" stroke="#ad9563" strokeOpacity=".12" />
          <path d="M150 15V251" stroke="#8c815f" strokeOpacity=".38" strokeDasharray="2 6" />
          <path d="M30 24h8m-4-4v8M312 260h8m-4-4v8" stroke="#8b846e" strokeWidth=".8" />
          {/* SVG uses painter's order: lower plates must be painted first so
              their opaque surfaces cannot erase the upper plates' edges. */}
          {[...layers].reverse().map(({ key, index, state }) => {
            const isActive = key === active;
            const y = 37 + index * 40;
            const lift = reducedMotion ? 0 : (engaged ? (index - 2) * 3 : 0) - (isActive && engaged ? 5 : 0);
            const showWire = isActive || state.tone === 'alert' || state.tone === 'warning' || state.tone === 'notice';
            const symbolY = y + 18;
            return <motion.g key={key} data-signal={key} data-layer-index={index} data-tone={state.tone} data-active={isActive || undefined} animate={{ y: lift }} transition={transition}>
              <path className="signal-wire" d={`M235 ${y + 7}H277L300 ${y + 18}H321`} />
              <motion.path
                className="signal-wire-lit"
                d={`M235 ${y + 7}H277L300 ${y + 18}H321`}
                initial={false}
                animate={{ pathLength: showWire ? 1 : 0, opacity: showWire ? 1 : 0 }}
                transition={{ duration: reducedMotion ? 0 : 0.28, ease: [0.16, 1, 0.3, 1] }}
              />
              <circle className="signal-terminal" cx="324" cy={symbolY} r={result ? 6 : 2.5} />
              {result && <>
                <text className="signal-readout" x="257" y={y - 3}>{state.metric}</text>
                <path className="signal-status-mark" d={state.tone === 'alert' || state.tone === 'warning'
                  ? `M324 ${symbolY - 3}v3m0 3h.01`
                  : state.tone === 'unknown' ? `M321 ${symbolY}h6`
                  : state.tone === 'notice' ? `M324 ${symbolY}v3m0-6h.01`
                  : `M321 ${symbolY}l2 2 4-4`} />
              </>}
              <g className="signal-plate">
                <path d={`M66 ${y}v13c0 11 38 21 84 21s84-10 84-21V${y}`} fill="#1d211b" />
                <ellipse className="signal-bottom-rim" cx="150" cy={y + 13} rx="84" ry="21" />
                <ellipse className="signal-surface" cx="150" cy={y} rx="84" ry="21" fill="#1b1e19" />
                <ellipse cx="150" cy={y} rx="57" ry="14" className="signal-inner-ring" />
                <path d={`M66 ${y}v13m168-13v13M150 ${y - 21}v42`} className="signal-inner-ring" />
              </g>
              <circle className="signal-center" cx="150" cy={y} r="3" />
            </motion.g>;
          })}
        </svg>
        <div className="signal-hitareas" role="group" aria-label="Highlight an analysis check">
          {layers.map(({ key, name, index, state }) => <Button
            key={key}
            className="signal-hitarea"
            style={{ '--layer-y': `${((37 + index * 40 - 15) / 300) * 100}%` } as CSSProperties}
            aria-label={`Highlight ${name}`}
            aria-pressed={key === active}
            aria-describedby={result ? `${id}-state-${key}` : undefined}
            onPointerEnter={() => onSelect(key)}
            onFocus={() => onSelect(key)}
            onClick={() => onSelect(key)}
          ><span className="sr-only">{name}</span>{result && <span className="sr-only" id={`${id}-state-${key}`}>{state.metric}. {state.label}. {state.detail}</span>}</Button>)}
        </div>
      </div>
    </Tilt>
    <figcaption className="signal-caption">
      <TransitionPanel className="signal-caption-text" activeIndex={selectedIndex} size="largest">{layers.map(({ key, name, state }) => <div className="signal-info" key={key}>
        <div className="signal-info-heading"><span>{name}</span>{result && <span className="signal-state-label">{state.label}</span>}</div>
        {result && <p className="signal-detail">{state.detail}</p>}
      </div>)}</TransitionPanel>
    </figcaption>
  </figure>;
}
