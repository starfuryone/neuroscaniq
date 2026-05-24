'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import useSWR, { mutate } from 'swr';
import { toast } from 'sonner';
import { Users, Database, AlertOctagon, Server } from 'lucide-react';
import { Nav } from '@/components/nav';
import { Card, CardBody, CardHeader, CardTitle, Badge } from '@/components/ui/primitives';
import { TelemetryCard } from '@/components/telemetry-card';
import { Button } from '@/components/ui/button';
import { api, APIError } from '@/lib/api';
import { useAuthStore } from '@/store/auth';
import type { AdminStats } from '@/types';
import { relativeTime } from '@/lib/utils';

const fetcher = (key: string) => api.get<any>(key);

export default function AdminPage() {
  const router = useRouter();
  const user = useAuthStore((s) => s.user);

  useEffect(() => {
    if (user && user.role !== 'admin') router.replace('/dashboard');
  }, [user, router]);

  const { data: stats } = useSWR<AdminStats>('/admin/stats', fetcher);
  const { data: users = [] } = useSWR<any[]>('/admin/users?limit=100', fetcher);
  const { data: audit = [] } = useSWR<any[]>('/admin/audit-log?limit=50', fetcher);

  async function toggleActive(id: string, current: boolean) {
    try {
      await api.patch(`/admin/users/${id}`, { is_active: !current });
      toast.success(current ? 'User deactivated' : 'User reactivated');
      await mutate('/admin/users?limit=100');
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Update failed');
    }
  }

  if (!user) {
    return (
      <>
        <Nav />
        <div className="p-10 text-center font-mono text-bone-400">Loading…</div>
      </>
    );
  }

  return (
    <>
      <Nav />
      <div className="mx-auto max-w-[1400px] px-4 py-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-signal-400">
              · Operator Console
            </div>
            <h1 className="mt-1 font-display text-3xl font-semibold tracking-tight">
              Admin
            </h1>
          </div>
          <Badge variant="signal">{user.email}</Badge>
        </div>

        <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <TelemetryCard
            label="Users"
            value={stats?.users ?? '—'}
          />
          <TelemetryCard
            label="Indexed Hosts"
            value={stats?.hosts.toLocaleString() ?? '—'}
          />
          <TelemetryCard
            label="Open Alerts"
            value={stats?.open_alerts ?? '—'}
            trend={(stats?.open_alerts ?? 0) > 10 ? 'down' : 'flat'}
          />
          <TelemetryCard
            label="Scan Queue"
            value={stats?.scan_queue_depth ?? '—'}
          />
        </div>

        <div className="mt-6 grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-3 w-3" /> Users · {users.length}
              </CardTitle>
            </CardHeader>
            <CardBody className="p-0">
              <div className="max-h-[480px] overflow-y-auto">
                <table className="w-full font-mono text-xs">
                  <thead className="sticky top-0 bg-ink-850/95 backdrop-blur">
                    <tr className="border-b border-ink-700/40 text-left text-bone-400">
                      <th className="py-2 pl-4">Email</th>
                      <th className="py-2">Role</th>
                      <th className="py-2">Last login</th>
                      <th className="py-2 pr-4 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u) => (
                      <tr key={u.id} className="border-b border-ink-700/20">
                        <td className="py-2 pl-4 text-bone-100">{u.email}</td>
                        <td className="py-2">
                          <Badge variant={u.role === 'admin' ? 'signal' : 'outline'}>
                            {u.role}
                          </Badge>
                        </td>
                        <td className="py-2 text-bone-400">{relativeTime(u.last_login_at)}</td>
                        <td className="py-2 pr-4 text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toggleActive(u.id, u.is_active)}
                          >
                            {u.is_active ? 'Deactivate' : 'Activate'}
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertOctagon className="h-3 w-3" /> Audit Log · {audit.length}
              </CardTitle>
            </CardHeader>
            <CardBody className="p-0">
              <div className="max-h-[480px] divide-y divide-ink-700/30 overflow-y-auto">
                {audit.map((entry) => (
                  <div key={entry.id} className="px-4 py-2.5 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-signal-400">{entry.action}</span>
                      <span className="text-bone-500">{relativeTime(entry.created_at)}</span>
                    </div>
                    <div className="mt-0.5 text-bone-400">
                      {entry.resource_type && (
                        <span>
                          {entry.resource_type}:{entry.resource_id ?? '—'}
                        </span>
                      )}
                      {entry.actor_user_id && (
                        <span className="ml-2 text-bone-500">by {entry.actor_user_id.slice(0, 8)}…</span>
                      )}
                    </div>
                    {entry.error && (
                      <div className="mt-1 text-danger">{entry.error}</div>
                    )}
                  </div>
                ))}
                {audit.length === 0 && (
                  <div className="p-6 text-center text-sm text-bone-500">No audit entries.</div>
                )}
              </div>
            </CardBody>
          </Card>
        </div>

        <Card className="mt-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-3 w-3" /> Worker Queues
            </CardTitle>
          </CardHeader>
          <CardBody>
            <div className="grid gap-3 sm:grid-cols-3">
              <Stat label="Jobs queued" value={stats?.jobs_queued ?? 0} />
              <Stat label="Jobs running" value={stats?.jobs_running ?? 0} />
              <Stat label="Alert queue" value={stats?.alert_queue_depth ?? 0} />
            </div>
          </CardBody>
        </Card>
      </div>
    </>
  );
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-md border border-ink-700/60 bg-ink-900/40 px-4 py-3">
      <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-bone-400">{label}</div>
      <div className="mt-1 font-mono text-xl text-bone-100">{value}</div>
    </div>
  );
}
