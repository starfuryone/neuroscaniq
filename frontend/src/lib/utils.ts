import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/** tailwind-merge wrapper for conditional class composition. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Format an integer with thousands separators. */
export function fmtInt(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '—';
  return n.toLocaleString();
}

/** Format a risk score 0–100 with one decimal when fractional. */
export function fmtRisk(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '0';
  return Number.isInteger(n) ? String(n) : n.toFixed(1);
}

/** ISO date → relative ("3m ago", "2d ago"). */
export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  const diff = Date.now() - then;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export const RISK_LEVELS = ['low', 'medium', 'high', 'critical'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export function riskClass(level: string | undefined): string {
  switch (level) {
    case 'critical':
      return 'risk-critical';
    case 'high':
      return 'risk-high';
    case 'medium':
      return 'risk-medium';
    default:
      return 'risk-low';
  }
}
