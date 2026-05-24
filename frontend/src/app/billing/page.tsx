'use client';

import { useState } from 'react';
import useSWR from 'swr';
import { toast } from 'sonner';
import { Check, ExternalLink } from 'lucide-react';
import { Nav } from '@/components/nav';
import { Card, CardBody, CardHeader, CardTitle, Badge } from '@/components/ui/primitives';
import { Button } from '@/components/ui/button';
import { api, APIError } from '@/lib/api';
import type { Subscription } from '@/types';
import { cn, relativeTime } from '@/lib/utils';

const fetcher = (key: string) => api.get<any>(key);

const PLANS = [
  {
    id: 'free',
    name: 'Free',
    price: '$0',
    blurb: 'For evaluation and personal research.',
    features: ['100 searches / month', '1,000 API calls / month', '1 monitor', 'Community support'],
  },
  {
    id: 'pro',
    name: 'Pro',
    price: '$99',
    blurb: 'For security teams and consultants.',
    features: [
      '10,000 searches / month',
      '100,000 API calls / month',
      '25 monitors',
      'Screenshot history',
      'Webhook alerts',
      'Email support',
    ],
    featured: true,
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 'Custom',
    blurb: 'For SOCs, MSSPs, and large surfaces.',
    features: [
      'Unlimited searches',
      'High-throughput API',
      '1,000+ monitors',
      'Org accounts & SSO',
      'Dedicated support',
      'Custom data exports',
    ],
  },
];

export default function BillingPage() {
  const { data: sub } = useSWR<Subscription>('/billing/subscription', fetcher);
  const [busy, setBusy] = useState<string | null>(null);

  async function checkout(plan: 'pro' | 'enterprise') {
    setBusy(plan);
    try {
      const r = await api.post<{ checkout_url: string }>('/billing/checkout', { plan });
      window.location.href = r.checkout_url;
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Checkout failed');
      setBusy(null);
    }
  }

  async function portal() {
    setBusy('portal');
    try {
      const r = await api.post<{ portal_url: string }>('/billing/portal');
      window.location.href = r.portal_url;
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Could not open portal');
      setBusy(null);
    }
  }

  return (
    <>
      <Nav />
      <div className="mx-auto max-w-[1400px] px-4 py-6">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Billing & Plan</h1>
        <p className="mt-1 text-sm text-bone-400">
          Subscribe, upgrade, or manage billing. Paid plans are processed by Stripe.
        </p>

        {sub && (
          <Card className="mt-6">
            <CardHeader>
              <CardTitle>Current Subscription</CardTitle>
            </CardHeader>
            <CardBody className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-display text-3xl font-semibold uppercase text-signal-400">
                  {sub.plan}
                </span>
                <Badge variant="outline">{sub.status}</Badge>
                {sub.current_period_end && (
                  <span className="font-mono text-[11px] text-bone-400">
                    renews {relativeTime(sub.current_period_end)}
                  </span>
                )}
              </div>
              {sub.plan !== 'free' && (
                <Button variant="outline" onClick={portal} disabled={busy === 'portal'}>
                  Open Stripe portal <ExternalLink className="h-3.5 w-3.5" />
                </Button>
              )}
            </CardBody>
          </Card>
        )}

        <div className="mt-6 grid gap-4 lg:grid-cols-3">
          {PLANS.map((p) => {
            const isCurrent = sub?.plan === p.id;
            return (
              <Card
                key={p.id}
                className={cn(
                  'relative',
                  p.featured && 'border-signal-400/40 shadow-[0_0_32px_-12px_rgba(34,211,238,0.4)]',
                )}
              >
                {p.featured && (
                  <div className="absolute -top-2 right-4">
                    <Badge variant="signal">Recommended</Badge>
                  </div>
                )}
                <CardHeader>
                  <CardTitle>{p.name}</CardTitle>
                  <div className="mt-2 flex items-baseline gap-1">
                    <span className="font-display text-3xl font-semibold text-bone-50">{p.price}</span>
                    {p.price !== 'Custom' && (
                      <span className="font-mono text-xs text-bone-400">/ month</span>
                    )}
                  </div>
                  <p className="text-xs text-bone-400">{p.blurb}</p>
                </CardHeader>
                <CardBody className="space-y-4">
                  <ul className="space-y-1.5 text-sm">
                    {p.features.map((f) => (
                      <li key={f} className="flex items-start gap-2 text-bone-200">
                        <Check className="mt-0.5 h-3.5 w-3.5 flex-none text-signal-400" />
                        {f}
                      </li>
                    ))}
                  </ul>
                  <div className="pt-2">
                    {isCurrent ? (
                      <Button variant="outline" className="w-full" disabled>
                        Current plan
                      </Button>
                    ) : p.id === 'free' ? (
                      <Button variant="ghost" className="w-full" disabled>
                        Default
                      </Button>
                    ) : (
                      <Button
                        className="w-full"
                        variant={p.featured ? 'primary' : 'outline'}
                        onClick={() => checkout(p.id as 'pro' | 'enterprise')}
                        disabled={busy === p.id}
                      >
                        {busy === p.id ? 'Redirecting…' : `Upgrade to ${p.name}`}
                      </Button>
                    )}
                  </div>
                </CardBody>
              </Card>
            );
          })}
        </div>
      </div>
    </>
  );
}
