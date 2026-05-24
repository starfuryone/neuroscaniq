'use client';

import { useState } from 'react';
import useSWR, { mutate } from 'swr';
import { toast } from 'sonner';
import { Copy, Key, Trash2, Plus, AlertTriangle } from 'lucide-react';
import { Nav } from '@/components/nav';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardBody, CardHeader, CardTitle, Badge, Label } from '@/components/ui/primitives';
import { api, APIError } from '@/lib/api';
import type { APIKey, APIKeyCreated } from '@/types';
import { fmtInt, relativeTime } from '@/lib/utils';

const fetcher = (key: string) => api.get<any>(key);

export default function DeveloperPage() {
  const { data: keys = [] } = useSWR<APIKey[]>('/api-keys', fetcher);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [justCreated, setJustCreated] = useState<APIKeyCreated | null>(null);

  async function createKey(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const created = await api.post<APIKeyCreated>('/api-keys', { name });
      setJustCreated(created);
      setName('');
      await mutate('/api-keys');
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Failed to create key');
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (!confirm('Revoke this key? Any callers using it will start receiving 401 errors.')) return;
    try {
      await api.delete(`/api-keys/${id}`);
      await mutate('/api-keys');
      toast.success('Key revoked');
    } catch (err) {
      toast.error(err instanceof APIError ? err.message : 'Failed to revoke');
    }
  }

  return (
    <>
      <Nav />
      <div className="mx-auto max-w-[1400px] px-4 py-6">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Developer</h1>
        <p className="mt-1 text-sm text-bone-400">
          API keys authenticate REST requests. Treat them like passwords — they grant the same access
          your account has.
        </p>

        {/* Just-created banner with plaintext copy */}
        {justCreated && (
          <Card className="mt-6 border-warn/40">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-warn">
                <AlertTriangle className="h-3 w-3" /> Copy this key now
              </CardTitle>
            </CardHeader>
            <CardBody className="space-y-3">
              <p className="text-sm text-bone-300">
                The plaintext secret is shown <strong>once</strong> and cannot be recovered. Store it in
                your secret manager before closing this notice.
              </p>
              <div className="flex items-center gap-2 rounded border border-ink-700 bg-ink-900 p-2.5">
                <code className="flex-1 break-all font-mono text-sm text-signal-400">
                  {justCreated.plaintext_key}
                </code>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => {
                    navigator.clipboard.writeText(justCreated.plaintext_key);
                    toast.success('Copied to clipboard');
                  }}
                  aria-label="Copy"
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
              <Button variant="outline" size="sm" onClick={() => setJustCreated(null)}>
                I've saved it
              </Button>
            </CardBody>
          </Card>
        )}

        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Create new key</CardTitle>
          </CardHeader>
          <CardBody>
            <form onSubmit={createKey} className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <div className="flex-1 space-y-1.5">
                <Label htmlFor="key_name">Key label</Label>
                <Input
                  id="key_name"
                  required
                  placeholder="prod-monitoring"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <Button type="submit" disabled={busy}>
                <Plus className="h-3.5 w-3.5" /> {busy ? 'Generating…' : 'Generate key'}
              </Button>
            </form>
          </CardBody>
        </Card>

        <Card className="mt-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-3 w-3" /> Active keys · {keys.filter((k) => k.is_active).length}
            </CardTitle>
          </CardHeader>
          <CardBody className="p-0">
            {keys.length === 0 ? (
              <div className="p-10 text-center text-sm text-bone-400">No keys yet.</div>
            ) : (
              <ul className="divide-y divide-ink-700/40">
                {keys.map((k) => (
                  <li key={k.id} className="flex items-center justify-between p-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-bone-100">{k.name}</span>
                        {k.is_active ? (
                          <Badge variant="ok">active</Badge>
                        ) : (
                          <Badge variant="danger">revoked</Badge>
                        )}
                      </div>
                      <div className="mt-1 font-mono text-xs text-bone-400">
                        {k.prefix}…{' '}
                        <span className="text-bone-500">
                          · created {relativeTime(k.created_at)} ·{' '}
                          {fmtInt(k.usage_count)} calls
                          {k.last_used_at && ` · last used ${relativeTime(k.last_used_at)}`}
                        </span>
                      </div>
                    </div>
                    {k.is_active && (
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => revoke(k.id)}
                        aria-label="Revoke"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        <Card className="mt-4">
          <CardHeader>
            <CardTitle>Quick start</CardTitle>
          </CardHeader>
          <CardBody>
            <pre className="overflow-x-auto rounded border border-ink-700 bg-ink-900 p-4 font-mono text-xs text-bone-200">
{`curl https://api.neuroscaniq.local/api/v1/search?q=port:443 \\
  -H "Authorization: Bearer nsiq_xxxxxxxx_yyyyyyyyyyyyyyyy"`}
            </pre>
            <p className="mt-3 text-sm text-bone-400">
              Full reference: see <code className="rounded bg-ink-800 px-1 font-mono text-xs">docs/API.md</code> in the source distribution.
            </p>
          </CardBody>
        </Card>
      </div>
    </>
  );
}
