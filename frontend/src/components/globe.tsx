'use client';

import { motion } from 'framer-motion';
import { useMemo } from 'react';

/**
 * Pure-SVG animated globe. No three.js dependency.
 * Renders meridians + parallels with subtle rotation + scattered "telemetry"
 * pings to evoke an intelligence dashboard.
 */
export function Globe({ className = '' }: { className?: string }) {
  // Stable randomized ping positions per mount.
  const pings = useMemo(
    () =>
      Array.from({ length: 16 }, (_, i) => ({
        cx: 50 + Math.cos((i / 16) * Math.PI * 2) * (15 + Math.random() * 25),
        cy: 50 + Math.sin((i / 16) * Math.PI * 2) * (15 + Math.random() * 25),
        delay: Math.random() * 4,
        size: 1 + Math.random() * 1.5,
      })),
    [],
  );

  return (
    <div className={className}>
      <motion.svg
        viewBox="0 0 100 100"
        className="h-full w-full"
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.8, ease: 'easeOut' }}
      >
        <defs>
          <radialGradient id="globeFill" cx="50%" cy="40%">
            <stop offset="0%" stopColor="rgba(34,211,238,0.15)" />
            <stop offset="60%" stopColor="rgba(34,211,238,0.04)" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>
          <radialGradient id="globeStroke" cx="50%" cy="40%">
            <stop offset="0%" stopColor="rgba(34,211,238,0.7)" />
            <stop offset="100%" stopColor="rgba(34,211,238,0.15)" />
          </radialGradient>
        </defs>

        {/* glow */}
        <circle cx="50" cy="50" r="44" fill="url(#globeFill)" />

        {/* parallels (rotating sphere) */}
        <motion.g
          animate={{ rotate: 360 }}
          transition={{ duration: 60, repeat: Infinity, ease: 'linear' }}
          style={{ transformOrigin: '50px 50px' }}
        >
          {[10, 18, 25, 32, 38, 42].map((ry) => (
            <ellipse
              key={ry}
              cx="50"
              cy="50"
              rx="40"
              ry={ry}
              fill="none"
              stroke="url(#globeStroke)"
              strokeWidth="0.15"
              opacity="0.65"
            />
          ))}
          {/* meridians */}
          {[10, 18, 25, 32, 38].map((rx) => (
            <ellipse
              key={`m${rx}`}
              cx="50"
              cy="50"
              rx={rx}
              ry="40"
              fill="none"
              stroke="url(#globeStroke)"
              strokeWidth="0.15"
              opacity="0.5"
            />
          ))}
          <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(34,211,238,0.5)" strokeWidth="0.3" />
        </motion.g>

        {/* telemetry pings */}
        {pings.map((p, i) => (
          <g key={i}>
            <motion.circle
              cx={p.cx}
              cy={p.cy}
              r={p.size}
              fill="#22d3ee"
              initial={{ opacity: 0 }}
              animate={{ opacity: [0, 1, 0] }}
              transition={{
                duration: 2.4,
                delay: p.delay,
                repeat: Infinity,
                repeatDelay: 3,
              }}
            />
            <motion.circle
              cx={p.cx}
              cy={p.cy}
              r={p.size}
              fill="none"
              stroke="#22d3ee"
              strokeWidth="0.3"
              initial={{ scale: 1, opacity: 0 }}
              animate={{ scale: [1, 4], opacity: [0.6, 0] }}
              transition={{
                duration: 2.4,
                delay: p.delay,
                repeat: Infinity,
                repeatDelay: 3,
              }}
              style={{ transformOrigin: `${p.cx}px ${p.cy}px` }}
            />
          </g>
        ))}

        {/* crosshair frame */}
        <g stroke="rgba(34,211,238,0.4)" strokeWidth="0.3" fill="none">
          <path d="M 5 10 L 5 5 L 10 5" />
          <path d="M 95 10 L 95 5 L 90 5" />
          <path d="M 5 90 L 5 95 L 10 95" />
          <path d="M 95 90 L 95 95 L 90 95" />
        </g>
      </motion.svg>
    </div>
  );
}
