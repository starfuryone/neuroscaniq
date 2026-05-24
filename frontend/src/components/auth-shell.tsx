'use client';

import Link from 'next/link';

export function AuthShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div className="relative grid min-h-screen lg:grid-cols-2">
      {/* left: branded panel */}
      <div className="relative hidden flex-col justify-between border-r border-ink-700/40 bg-ink-900 p-10 lg:flex">
        <Link href="/" className="flex items-center gap-2 font-mono text-sm">
          <div className="relative h-5 w-5">
            <div className="absolute inset-0 rounded-sm border border-signal-400/60" />
            <div className="absolute inset-1 rounded-[2px] bg-signal-400/60" />
          </div>
          <span>Neuro<span className="text-signal-400">Scan</span>IQ</span>
        </Link>
        <div>
          <h2 className="font-display text-3xl font-semibold tracking-tight">
            See your infrastructure
            <br /> from the outside in.
          </h2>
          <p className="mt-3 max-w-md text-sm text-bone-400">
            Continuous exposure intelligence for security teams. Strictly defensive use.
          </p>
        </div>
        <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-bone-500">
          · Authorized · Auditable · Defensive ·
        </div>
        <div
          className="pointer-events-none absolute inset-0 bg-grid-faint bg-grid-32 opacity-30"
          aria-hidden
        />
      </div>

      {/* right: form */}
      <div className="flex flex-col items-center justify-center p-8">
        <div className="w-full max-w-sm">
          <h1 className="font-display text-3xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-1 text-sm text-bone-400">{subtitle}</p>
          <div className="mt-8">{children}</div>
        </div>
      </div>
    </div>
  );
}
