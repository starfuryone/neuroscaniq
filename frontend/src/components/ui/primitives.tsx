'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

/* ----------------------- Card --------------------------------------- */
export const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        'rounded-lg border border-ink-700/60 bg-ink-850/40 backdrop-blur-sm',
        'shadow-[inset_0_1px_0_rgba(255,255,255,0.02)]',
        className,
      )}
      {...props}
    />
  ),
);
Card.displayName = 'Card';

export const CardHeader = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('flex flex-col gap-1 border-b border-ink-700/40 px-5 py-4', className)} {...props} />
);

export const CardTitle = ({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) => (
  <h3 className={cn('font-mono text-xs uppercase tracking-[0.18em] text-bone-300', className)} {...props} />
);

export const CardBody = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('px-5 py-4', className)} {...props} />
);

/* ----------------------- Badge -------------------------------------- */
export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'signal' | 'warn' | 'danger' | 'critical' | 'ok' | 'outline';
}

export const Badge = ({ className, variant = 'default', ...props }: BadgeProps) => {
  const styles = {
    default: 'bg-ink-700 text-bone-200',
    signal: 'bg-signal-400/15 text-signal-400 border border-signal-400/30',
    warn: 'bg-warn/10 text-warn border border-warn/30',
    danger: 'bg-danger/10 text-danger border border-danger/30',
    critical: 'bg-critical/15 text-critical border border-critical/40',
    ok: 'bg-ok/10 text-ok border border-ok/30',
    outline: 'border border-ink-600 text-bone-300',
  }[variant];
  return (
    <span
      className={cn(
        'inline-flex items-center rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider',
        styles,
        className,
      )}
      {...props}
    />
  );
};

/* ----------------------- Label -------------------------------------- */
export const Label = ({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) => (
  <label
    className={cn('font-mono text-[11px] uppercase tracking-[0.14em] text-bone-300', className)}
    {...props}
  />
);
