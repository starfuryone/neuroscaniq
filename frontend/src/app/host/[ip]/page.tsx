'use client';

import { use } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { ArrowLeft, Sparkles, AlertTriangle, Shield, Server, Globe2, Lock } from 'lucide-react';
import { Nav } from '@/components/nav';
import { Badge, Card, CardBody, CardHeader, CardTitle } from '@/components/ui/primitives';
import { api } from '@/lib/api';
import type { HostDetail, Screenshot } from '@/types';
import { riskClass, relativeTime, fmtRisk } from '@/lib/utils';

const fetcher = (key: string) => api.get<any>(key);

export default function HostPage({ params }: { params: Promise<{ ip: string }> }) {
  const { ip } = use(params);
  const { data: host, error } = useSWR<HostDetail>(`/hosts/${ip}`, fetcher);
  const { data: shots } = useSWR<Screenshot[]>(`/hosts/${ip}/screenshots`, fetcher);

  return (
    <>
      <Nav />
      <div className="mx-auto max-w-[1400px] px-4 py-6">
        <Link
          href="/search"
          className="inline-flex items-center gap-1 font-mono text-[11px] uppercase tracking-[0.14em] text-bone-400 hover:text-signal-400"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to search
        </Link>

        {error && (
          <div className="mt-6 rounded border border-danger/30 bg-danger/5 p-6 text-sm text-danger">
            {(error as Error).message}
          </div>
        )}

        {!host && !error && (
          <div className="mt-8 font-mono text-bone-400">Resolving host…</div>
        )}

        {host && (
          <>
            {/* Header */}
            <div className="mt-4 flex flex-col gap-3 border-b border-ink-700/40 pb-6 lg:flex-row lg:items-end lg:justify-between">
              <div>
                <h1 className="font-display text-4xl font-semibold tracking-tight text-bone-50">
                  {host.ip}
                </h1>
                {host.hostname && (
                  <div className="mt-1 font-mono text-sm text-bone-300">{host.hostname}</div>
                )}
                <div className="mt-3 flex flex-wrap items-center gap-4 font-mono text-[11px] text-bone-400">
                  {host.asn_org && (
                    <span>
                      <span className="text-bone-500">AS</span>
                      {host.asn} · {host.asn_org}
                    </span>
                  )}
                  {(host.country || host.city) && (
                    <span className="flex items-center gap-1">
                      <Globe2 className="h-3 w-3" />
                      {[host.city, host.region, host.country].filter(Boolean).join(', ')}
                    </span>
                  )}
                  <span>Last seen {relativeTime(host.last_seen)}</span>
                </div>
              </div>

              <div className="flex flex-col items-end gap-2">
                <div
                  className={`rounded border px-4 py-2 text-right font-mono ${riskClass(host.risk_level)}`}
                >
                  <div className="text-[10px] uppercase tracking-[0.18em]">Risk Score</div>
                  <div className="text-3xl font-semibold">{fmtRisk(host.risk_score)}</div>
                  <div className="text-xs uppercase">{host.risk_level}</div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {host.tags.map((t) => (
                    <Badge key={t} variant="signal">
                      {t}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>

            {/* AI summary */}
            {host.ai_summary && (
              <Card className="mt-6 border-signal-400/30">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-signal-400">
                    <Sparkles className="h-3 w-3" /> AI EXPOSURE SUMMARY
                  </CardTitle>
                </CardHeader>
                <CardBody className="text-sm leading-relaxed text-bone-200">
                  {host.ai_summary}
                </CardBody>
              </Card>
            )}

            {/* Three column grid */}
            <div className="mt-6 grid gap-4 lg:grid-cols-3">
              {/* Open ports */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Server className="h-3 w-3" /> Open Ports · {host.ports.length}
                  </CardTitle>
                </CardHeader>
                <CardBody>
                  <div className="flex flex-wrap gap-2">
                    {host.ports.map((p) => (
                      <Badge key={p} variant="outline" className="text-sm">
                        {p}
                      </Badge>
                    ))}
                    {host.ports.length === 0 && (
                      <span className="text-sm text-bone-500">No open ports observed.</span>
                    )}
                  </div>
                </CardBody>
              </Card>

              {/* TLS */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Lock className="h-3 w-3" /> TLS Certificate
                  </CardTitle>
                </CardHeader>
                <CardBody className="space-y-2 font-mono text-xs text-bone-300">
                  {host.tls ? (
                    <>
                      <Row k="Subject CN" v={(host.tls as any).subject_cn} />
                      <Row k="Issuer" v={(host.tls as any).issuer_cn} />
                      <Row k="Not After" v={(host.tls as any).not_after} />
                      <Row k="Protocol" v={(host.tls as any).protocol} />
                      <Row k="Fingerprint" v={(host.tls as any).fingerprint_sha256?.slice(0, 32) + '…'} />
                    </>
                  ) : (
                    <span className="text-bone-500">No TLS observed on default secure ports.</span>
                  )}
                </CardBody>
              </Card>

              {/* HTTP */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Globe2 className="h-3 w-3" /> HTTP
                  </CardTitle>
                </CardHeader>
                <CardBody className="space-y-2 font-mono text-xs text-bone-300">
                  {host.http ? (
                    <>
                      <Row k="URL" v={(host.http as any).url} />
                      <Row k="Status" v={(host.http as any).status} />
                      <Row k="Server" v={(host.http as any).server} />
                      <Row k="Title" v={(host.http as any).title} />
                    </>
                  ) : (
                    <span className="text-bone-500">No HTTP service detected.</span>
                  )}
                </CardBody>
              </Card>
            </div>

            {/* Services list */}
            <Card className="mt-4">
              <CardHeader>
                <CardTitle>Services</CardTitle>
              </CardHeader>
              <CardBody>
                <div className="overflow-x-auto">
                  <table className="min-w-full font-mono text-xs">
                    <thead>
                      <tr className="border-b border-ink-700/40 text-left text-bone-400">
                        <th className="py-2 pr-4">Port</th>
                        <th className="py-2 pr-4">Server</th>
                        <th className="py-2 pr-4">Title</th>
                        <th className="py-2">Banner</th>
                      </tr>
                    </thead>
                    <tbody>
                      {host.services.map((s: any, i: number) => (
                        <tr key={i} className="border-b border-ink-700/20 align-top">
                          <td className="py-2 pr-4 text-signal-400">{s.port}</td>
                          <td className="py-2 pr-4 text-bone-200">{s.server || '—'}</td>
                          <td className="py-2 pr-4 text-bone-200">{s.title || '—'}</td>
                          <td className="py-2 text-bone-400">
                            <span className="line-clamp-2">{s.banner || '—'}</span>
                          </td>
                        </tr>
                      ))}
                      {host.services.length === 0 && (
                        <tr>
                          <td colSpan={4} className="py-4 text-center text-bone-500">
                            No services indexed.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </CardBody>
            </Card>

            {/* Risk factors */}
            <Card className="mt-4">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-3 w-3" /> Risk Factors
                </CardTitle>
              </CardHeader>
              <CardBody>
                {Object.keys(host.risk_factors).length === 0 ? (
                  <span className="text-sm text-bone-500">No notable risk factors.</span>
                ) : (
                  <ul className="space-y-1 font-mono text-xs">
                    {Object.entries(host.risk_factors).map(([k, v]) => (
                      <li
                        key={k}
                        className="flex items-start justify-between gap-4 border-b border-ink-700/30 py-1"
                      >
                        <span className="text-bone-200">{k}</span>
                        <span className="text-warn">+{String(v)}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </CardBody>
            </Card>

            {/* Screenshots */}
            {shots && shots.length > 0 && (
              <Card className="mt-4">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-3 w-3" /> Captured Screenshots
                  </CardTitle>
                </CardHeader>
                <CardBody>
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                    {shots.map((s) => (
                      <div
                        key={s.id}
                        className="overflow-hidden rounded border border-ink-700/60 bg-ink-900"
                      >
                        {s.thumbnail_url ? (
                          <img
                            src={s.thumbnail_url}
                            alt={s.title ?? `Screenshot of ${s.ip}:${s.port}`}
                            className="aspect-[16/10] w-full object-cover"
                          />
                        ) : (
                          <div className="flex aspect-[16/10] items-center justify-center text-xs text-bone-500">
                            no preview
                          </div>
                        )}
                        <div className="p-2 font-mono text-[11px] text-bone-300">
                          <div className="truncate">{s.title ?? s.url}</div>
                          <div className="mt-1 text-bone-500">
                            :{s.port} · {relativeTime(s.captured_at)}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardBody>
              </Card>
            )}
          </>
        )}
      </div>
    </>
  );
}

function Row({ k, v }: { k: string; v: any }) {
  return (
    <div className="flex justify-between gap-4">
      <span className="text-bone-500">{k}</span>
      <span className="truncate text-bone-100">{v ?? '—'}</span>
    </div>
  );
}
