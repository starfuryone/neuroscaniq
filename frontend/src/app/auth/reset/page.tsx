'use client';

import { useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/primitives';
import { api, APIError } from '@/lib/api';
import { AuthShell } from '@/app/login/page';

function ResetInner() {
  const params = useSearchParams();
  const router = useRouter();
  const token = params.get('token');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  async function requestReset(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post('/auth/password-reset/request', { email });
      toast.success('If that account exists, a reset email is on the way.');
    } catch (err) {
      // Intentionally show the same response either way to avoid user enumeration.
      toast.success('If that account exists, a reset email is on the way.');
    } finally {
      setBusy(false);
    }
  }

  async function confirmReset(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post('/auth/password-reset/confirm', { token, new_password: password });
      toast.success('Password updated. Please sign in.');
      router.push('/login');
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Reset failed');
    } finally {
      setBusy(false);
    }
  }

  if (token) {
    return (
      <AuthShell title="Set new password" subtitle="Choose a strong replacement.">
        <form onSubmit={confirmReset} className="space-y-5">
          <div className="space-y-1.5">
            <Label htmlFor="new_password">New password</Label>
            <Input
              id="new_password"
              type="password"
              required
              minLength={10}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <Button type="submit" className="w-full" disabled={busy}>
            {busy ? 'Updating…' : 'Update password'}
          </Button>
        </form>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Reset password" subtitle="Enter the email tied to your account.">
      <form onSubmit={requestReset} className="space-y-5">
        <div className="space-y-1.5">
          <Label htmlFor="email">Email</Label>
          <Input
            id="email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? 'Sending…' : 'Send reset link'}
        </Button>
        <div className="font-mono text-[11px] text-bone-400">
          <Link href="/login" className="hover:text-signal-400">Back to sign in</Link>
        </div>
      </form>
    </AuthShell>
  );
}

export default function ResetPage() {
  return (
    <Suspense fallback={<div className="p-8 font-mono text-bone-400">Loading…</div>}>
      <ResetInner />
    </Suspense>
  );
}
