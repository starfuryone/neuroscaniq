'use client';

import useSWR, { mutate } from 'swr';
import Link from 'next/link';
import { Bell, CheckCircle2 } from 'lucide-react';
import { Nav } from '@/components/nav';
import { Card, CardBody, CardHeader, CardTitle, Badge } from '@/components/ui/primitives';
import { TelemetryCard } from '@/components/telemetry-card';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import type { Alert, Monitor, Asset, Subscription } from '@/types';
import { relativeTime } from '@/lib/utils';

const fetcher = (key: string) => api.get<any>(key);

export default function Dashboard() {
  const { data: alerts = [] } = useSWR<Alert[]>('/alerts?unread_only=false&limit=50', fetcher);
  const { data: monitors = [] } = useSWR<Monitor[]>('/monitor/monitors', fetcher);
  const { data: assets = [] } = useSWR<Asset[]>('/monitor/assets', fetcher);
  const { data: subscription } = useSWR<Subscription>('/billing/subscription', fetcher);

  const open = alerts.filter((a) => !a.is_resolved);
  const critical = open.filter((a) => a.severity === 'critical' || a.severity === 'high');
  const verifiedAssets = assets.filter((a) => a.status === 'verified');

  async function markRead(id: string) {
    await api.post(`/alerts/${id}/read`);
    await mutate('/alerts?unread_only=false&limit=50');
  }

  async function resolve(id: string) {
    await api.post(`/alerts/${id}/resolve`);
    await mutate('/alerts?unread_only=false&limit=50');
  }

  return (
    <>
      <Nav />
      <div className="mx-auto max-w-[1400px] px-4 py-6">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Operations Dashboard</h1>

        <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <TelemetryCard label="Open Alerts" value={open.length} />
          <TelemetryCard
            label="High / Critical"
            value={critical.length}
            trend={critical.length > 0 ? 'down' : 'flat'}
          />
          <TelemetryCard label="Active Monitors" value={monitors.length} />
          <TelemetryCard label="Verified Assets" value={verifiedAssets.length} />
        </div>

        {/* Subscription banner */}
        {subscription && (
          <Card className="mt-4">
            <CardBody className="flex items-center justify-between">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-bone-400">
                  Current plan
                </div>
                <div className="mt-1 flex items-center gap-2">
                  <span className="font-display text-xl font-semibold uppercase text-signal-400">
                    {subscription.plan}
                  </span>
                  <Badge variant="outline">{subscription.status}</Badge>
                </div>
                <div className="mt-2 font-mono text-[11px] text-bone-400">
                  {subscription.monthly_search_quota.toLocaleString()} searches ·{' '}
                  {subscription.monthly_api_quota.toLocaleString()} API calls ·{' '}
                  {subscription.monitor_quota} monitors
                </div>
              </div>
              <Link href="/billing">
                <Button variant="outline" size="sm">Manage plan</Button>
              </Link>
            </CardBody>
          </Card>
        )}

        <Card className="mt-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bell className="h-3 w-3" /> Recent Alerts
            </CardTitle>
          </CardHeader>
          <CardBody className="p-0">
            {alerts.length === 0 ? (
              <div className="p-10 text-center text-sm text-bone-400">
                No alerts yet. Verified monitors will surface exposure changes here.
              </div>
            ) : (
              <ul className="divide-y divide-ink-700/40">
                {alerts.map((a) => (
                  <li key={a.id} className="flex items-start justify-between gap-4 p-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge
                          variant={
                            a.severity === 'critical'
                              ? 'critical'
                              : a.severity === 'high'
                                ? 'danger'
                                : a.severity === 'medium'
                                  ? 'warn'
                                  : 'outline'
                          }
                        >
                          {a.severity}
                        </Badge>
                        <span className="font-mono text-xs text-bone-400">{a.kind}</span>
                        <span className="ml-auto font-mono text-xs text-bone-500">
                          {relativeTime(a.created_at)}
                        </span>
                      </div>
                      <div className="mt-1.5 text-sm text-bone-100">{a.title}</div>
                      <div className="mt-0.5 text-xs text-bone-400">{a.message}</div>
                    </div>
                    <div className="flex flex-col gap-1">
                      {!a.is_read && (
                        <Button variant="ghost" size="sm" onClick={() => markRead(a.id)}>
                          Mark read
                        </Button>
                      )}
                      {!a.is_resolved && (
                        <Button variant="outline" size="sm" onClick={() => resolve(a.id)}>
                          <CheckCircle2 className="h-3.5 w-3.5" /> Resolve
                        </Button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>
    </>
  );
}
