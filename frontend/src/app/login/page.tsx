'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/primitives';
import { AuthShell } from '@/components/auth-shell';
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

