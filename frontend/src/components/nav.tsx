'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuthStore } from '@/store/auth';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

const NAV = [
  { href: '/search', label: 'Search' },
  { href: '/maps', label: 'Maps' },
  { href: '/screenshots', label: 'Images' },
  { href: '/monitor', label: 'Monitor' },
  { href: '/developer', label: 'Developer' },
];

export function Nav() {
  const path = usePathname();
  const user = useAuthStore((s) => s.user);
  const clear = useAuthStore((s) => s.clear);

  return (
    <header className="sticky top-0 z-40 border-b border-ink-700/40 bg-ink-950/80 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-6 px-4">
        <Link href="/" className="flex items-center gap-2 font-mono text-sm font-semibold tracking-tight">
          <div className="relative h-5 w-5">
            <div className="absolute inset-0 rounded-sm border border-signal-400/60" />
            <div className="absolute inset-1 rounded-[2px] bg-signal-400/60" />
            <div className="pulse-dot absolute -right-0.5 -top-0.5" />
          </div>
          <span className="text-bone-100">
            Neuro<span className="text-signal-400">Scan</span>IQ
          </span>
        </Link>

        <nav className="hidden items-center gap-1 md:flex">
          {NAV.map((item) => {
            const active = path?.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  'rounded-md px-3 py-1.5 font-mono text-xs uppercase tracking-[0.12em] transition-colors',
                  active
                    ? 'bg-ink-800 text-signal-400'
                    : 'text-bone-300 hover:bg-ink-800/60 hover:text-bone-100',
                )}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto flex items-center gap-2">
          {user ? (
            <>
              {user.role === 'admin' && (
                <Link href="/admin">
                  <Button variant="ghost" size="sm">Admin</Button>
                </Link>
              )}
              <Link href="/dashboard">
                <Button variant="outline" size="sm">{user.email}</Button>
              </Link>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  clear();
                  window.location.href = '/';
                }}
              >
                Sign out
              </Button>
            </>
          ) : (
            <>
              <Link href="/login">
                <Button variant="ghost" size="sm">Sign in</Button>
              </Link>
              <Link href="/register">
                <Button variant="primary" size="sm">Get access</Button>
              </Link>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
