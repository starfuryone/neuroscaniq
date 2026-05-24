'use client';

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { CheckCircle2, XCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api, APIError } from '@/lib/api';
import { AuthShell } from '@/components/auth-shell';

function VerifyInner() {
  const params = useSearchParams();
  const router = useRouter();
  const token = params.get('token');
  const [status, setStatus] = useState<'pending' | 'success' | 'error'>('pending');
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (!token) {
      setStatus('error');
      setMessage('Missing verification token.');
      return;
    }
    api
      .post('/auth/verify-email', { token })
      .then(() => {
        setStatus('success');
        setMessage('Email verified.');
        setTimeout(() => router.push('/login'), 2000);
      })
      .catch((err) => {
        setStatus('error');
        setMessage(err instanceof APIError ? err.message : 'Verification failed');
      });
  }, [token, router]);

  return (
    <AuthShell title="Verify email" subtitle="Confirming your address.">
      <div className="space-y-4">
        {status === 'pending' && (
          <div className="rounded border border-ink-700 bg-ink-850/40 p-6 text-center font-mono text-sm text-bone-300">
            Verifying token…
          </div>
        )}
        {status === 'success' && (
          <div className="rounded border border-ok/30 bg-ok/5 p-6 text-center">
            <CheckCircle2 className="mx-auto h-10 w-10 text-ok" />
            <div className="mt-3 text-sm text-bone-100">{message}</div>
            <div className="mt-1 text-xs text-bone-400">Redirecting to sign in…</div>
          </div>
        )}
        {status === 'error' && (
          <div className="rounded border border-danger/30 bg-danger/5 p-6 text-center">
            <XCircle className="mx-auto h-10 w-10 text-danger" />
            <div className="mt-3 text-sm text-bone-100">{message}</div>
            <Link href="/login" className="mt-4 inline-block">
              <Button variant="outline" size="sm">Back to sign in</Button>
            </Link>
          </div>
        )}
      </div>
    </AuthShell>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={<div className="p-8 font-mono text-bone-400">Loading…</div>}>
      <VerifyInner />
    </Suspense>
  );
}
