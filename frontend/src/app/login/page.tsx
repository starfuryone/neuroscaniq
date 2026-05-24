'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/primitives';
import { api, APIError } from '@/lib/api';
import { useAuthStore } from '@/store/auth';

export default function LoginPage() {
  const router = useRouter();
  const setTokens = useAuthStore((s) => s.setTokens);
  const setUser = useAuthStore((s) => s.setUser);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const tokens = await api.post<{ access_token: string; refresh_token: string }>(
        '/auth/login',
        { email, password },
      );
      setTokens(tokens.access_token, tokens.refresh_token);
      const me = await api.get<any>('/users/me');
      setUser(me);
      toast.success('Signed in');
      router.push('/dashboard');
    } catch (err) {
      const msg = err instanceof APIError ? err.message : 'Login failed';
      toast.error(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Sign in" subtitle="Access your monitoring console.">
      <form onSubmit={onSubmit} className="space-y-5">
        <div className="space-y-1.5">
          <Label htmlFor="email">Email</Label>
          <Input
            id="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </Button>
        <div className="flex items-center justify-between font-mono text-[11px] text-bone-400">
          <Link href="/register" className="hover:text-signal-400">Create account</Link>
          <Link href="/auth/reset" className="hover:text-signal-400">Forgot password?</Link>
        </div>
      </form>
    </AuthShell>
  );
}

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
