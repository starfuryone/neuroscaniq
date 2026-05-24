'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/primitives';
import { api, APIError } from '@/lib/api';
import { AuthShell } from '@/app/login/page';

export default function RegisterPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post('/auth/register', { email, password, full_name: fullName });
      toast.success('Account created. Check your email to verify.');
      router.push('/login');
    } catch (err) {
      const msg = err instanceof APIError ? err.message : 'Registration failed';
      toast.error(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Create account" subtitle="Free tier: 100 searches / month.">
      <form onSubmit={onSubmit} className="space-y-5">
        <div className="space-y-1.5">
          <Label htmlFor="full_name">Full name</Label>
          <Input id="full_name" required value={fullName} onChange={(e) => setFullName(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="email">Work email</Label>
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
            autoComplete="new-password"
            required
            minLength={10}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <p className="font-mono text-[10px] text-bone-500">
            Min 10 chars · upper · lower · digit
          </p>
        </div>
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? 'Creating…' : 'Create account'}
        </Button>
        <div className="font-mono text-[11px] text-bone-400">
          Have an account?{' '}
          <Link href="/login" className="hover:text-signal-400">
            Sign in
          </Link>
        </div>
      </form>
    </AuthShell>
  );
}
