'use client';

import { useState } from 'react';
import useSWR, { mutate } from 'swr';
import { toast } from 'sonner';
import { Plus, ShieldCheck, ShieldAlert, Trash2, Activity } from 'lucide-react';
import { Nav } from '@/components/nav';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardBody, CardHeader, CardTitle, Badge, Label } from '@/components/ui/primitives';
import { api, APIError } from '@/lib/api';
import type { Asset, OwnershipProof, Monitor } from '@/types';
import { relativeTime } from '@/lib/utils';

const fetcher = (key: string) => api.get<any>(key);

export default function MonitorPage() {
  const { data: assets = [] } = useSWR<Asset[]>('/monitor/assets', fetcher);
  const { data: monitors = [] } = useSWR<Monitor[]>('/monitor/monitors', fetcher);
  const [showAdd, setShowAdd] = useState(false);

  return (
    <>
      <Nav />
      <div className="mx-auto max-w-[1400px] px-4 py-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-display text-3xl font-semibold tracking-tight">
              Attack Surface Monitor
            </h1>
            <p className="mt-1 text-sm text-bone-400">
              Track exposure changes for assets you own. Ownership must be verified before scanning.
            </p>
          </div>
          <Button onClick={() => setShowAdd((v) => !v)}>
            <Plus className="h-4 w-4" /> Add Asset
          </Button>
        </div>

        {showAdd && <AddAssetForm onDone={() => setShowAdd(false)} />}

        {/* Assets */}
        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Registered Assets · {assets.length}</CardTitle>
          </CardHeader>
          <CardBody className="p-0">
            {assets.length === 0 ? (
              <div className="p-10 text-center text-sm text-bone-400">
                No assets yet. Add an IP, CIDR, domain, or ASN you control.
              </div>
            ) : (
              <ul className="divide-y divide-ink-700/40">
                {assets.map((a) => (
                  <AssetRow key={a.id} asset={a} />
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        {/* Monitors */}
        <Card className="mt-4">
          <CardHeader>
            <CardTitle>Active Monitors · {monitors.length}</CardTitle>
          </CardHeader>
          <CardBody>
            {monitors.length === 0 ? (
              <div className="py-6 text-center text-sm text-bone-400">
                No active monitors. Verify an asset to start monitoring it.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full font-mono text-xs">
                  <thead>
                    <tr className="border-b border-ink-700/40 text-left text-bone-400">
                      <th className="py-2 pr-4">Asset</th>
                      <th className="py-2 pr-4">Cadence</th>
                      <th className="py-2 pr-4">Last Run</th>
                      <th className="py-2">Next Run</th>
                    </tr>
                  </thead>
                  <tbody>
                    {monitors.map((m) => {
                      const asset = assets.find((a) => a.id === m.asset_id);
                      return (
                        <tr key={m.id} className="border-b border-ink-700/20">
                          <td className="py-2 pr-4 text-bone-100">{asset?.value ?? m.asset_id}</td>
                          <td className="py-2 pr-4 text-signal-400">{m.cadence}</td>
                          <td className="py-2 pr-4">{relativeTime(m.last_run_at)}</td>
                          <td className="py-2">{relativeTime(m.next_run_at)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </>
  );
}

function AddAssetForm({ onDone }: { onDone: () => void }) {
  const [kind, setKind] = useState<'ip' | 'domain' | 'cidr' | 'asn'>('domain');
  const [value, setValue] = useState('');
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post('/monitor/assets', { kind, value, label });
      await mutate('/monitor/assets');
      toast.success('Asset registered. Verify ownership to enable monitoring.');
      onDone();
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Failed to add asset');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mt-4">
      <CardBody>
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-[120px,2fr,1fr,auto]">
          <div className="space-y-1">
            <Label>Kind</Label>
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as any)}
              className="h-10 w-full rounded-md border border-ink-700 bg-ink-900 px-3 font-mono text-sm text-bone-100"
            >
              <option value="domain">Domain</option>
              <option value="ip">IP</option>
              <option value="cidr">CIDR</option>
              <option value="asn">ASN</option>
            </select>
          </div>
          <div className="space-y-1">
            <Label>Value</Label>
            <Input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="example.com or 198.51.100.0/24"
              required
            />
          </div>
          <div className="space-y-1">
            <Label>Label (optional)</Label>
            <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Marketing site" />
          </div>
          <div className="flex items-end">
            <Button type="submit" disabled={busy}>
              {busy ? 'Saving…' : 'Register'}
            </Button>
          </div>
        </form>
      </CardBody>
    </Card>
  );
}

function AssetRow({ asset }: { asset: Asset }) {
  const { data: proofs = [] } = useSWR<OwnershipProof[]>(
    asset.status === 'pending' ? `/monitor/assets/${asset.id}/proofs` : null,
    () => Promise.resolve([] as OwnershipProof[]),
  );
  const [verifying, setVerifying] = useState(false);

  async function startProof(method: 'dns_txt' | 'email' | 'file_upload') {
    try {
      const proof = await api.post<OwnershipProof>(`/monitor/assets/${asset.id}/proofs`, { method });
      toast.info(proof.instructions ?? `Follow the ${method} instructions, then verify.`);
      await mutate(`/monitor/assets/${asset.id}/proofs`);
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Failed to begin verification');
    }
  }

  async function startMonitor() {
    setVerifying(true);
    try {
      await api.post('/monitor/monitors', { asset_id: asset.id, cadence: 'daily' });
      await mutate('/monitor/monitors');
      toast.success('Monitor started. First scan queued.');
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Failed to start monitor');
    } finally {
      setVerifying(false);
    }
  }

  async function remove() {
    if (!confirm(`Revoke ${asset.value}?`)) return;
    try {
      await api.delete(`/monitor/assets/${asset.id}`);
      await mutate('/monitor/assets');
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Failed to revoke');
    }
  }

  return (
    <li className="flex flex-col gap-3 p-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-base text-bone-100">{asset.value}</span>
          <Badge variant="outline">{asset.kind}</Badge>
          {asset.status === 'verified' ? (
            <Badge variant="ok">
              <ShieldCheck className="mr-1 h-3 w-3" /> verified
            </Badge>
          ) : asset.status === 'revoked' ? (
            <Badge variant="danger">revoked</Badge>
          ) : (
            <Badge variant="warn">
              <ShieldAlert className="mr-1 h-3 w-3" /> awaiting verification
            </Badge>
          )}
        </div>
        {asset.label && <div className="mt-1 text-xs text-bone-400">{asset.label}</div>}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {asset.status === 'pending' && (
          <>
            <Button variant="outline" size="sm" onClick={() => startProof('dns_txt')}>
              DNS TXT
            </Button>
            <Button variant="outline" size="sm" onClick={() => startProof('file_upload')}>
              File upload
            </Button>
            <Button variant="outline" size="sm" onClick={() => startProof('email')}>
              Email
            </Button>
          </>
        )}
        {asset.status === 'verified' && (
          <Button size="sm" onClick={startMonitor} disabled={verifying}>
            <Activity className="h-3.5 w-3.5" />
            Start monitor
          </Button>
        )}
        <Button variant="ghost" size="icon" onClick={remove} aria-label="Revoke">
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </li>
  );
}
