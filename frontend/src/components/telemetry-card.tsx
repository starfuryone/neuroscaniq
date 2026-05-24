'use client';

import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface TelemetryCardProps {
  label: string;
  value: string | number;
  delta?: string;
  trend?: 'up' | 'down' | 'flat';
  className?: string;
  unit?: string;
}

export function TelemetryCard({ label, value, delta, trend, className, unit }: TelemetryCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className={cn(
        'relative overflow-hidden rounded-md border border-ink-700/60 bg-ink-850/60 p-4 backdrop-blur-sm',
        className,
      )}
    >
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-bone-400">{label}</span>
        <div className="pulse-dot" />
      </div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className="font-mono text-2xl font-semibold text-bone-100">{value}</span>
        {unit && <span className="font-mono text-xs text-bone-400">{unit}</span>}
      </div>
      {delta && (
        <div
          className={cn(
            'mt-1 font-mono text-[11px]',
            trend === 'up' && 'text-ok',
            trend === 'down' && 'text-danger',
            trend === 'flat' && 'text-bone-400',
          )}
        >
          {trend === 'up' && '▲ '}
          {trend === 'down' && '▼ '}
          {delta}
        </div>
      )}
      {/* subtle scan beam */}
      <div className="pointer-events-none absolute -bottom-px left-0 right-0 h-px bg-gradient-to-r from-transparent via-signal-400/30 to-transparent" />
    </motion.div>
  );
}
