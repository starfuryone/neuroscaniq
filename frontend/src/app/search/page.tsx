'use client';

import { useEffect, useState, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import useSWR from 'swr';
import { Search, ChevronLeft, ChevronRight, MapPin } from 'lucide-react';
import { Nav } from '@/components/nav';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/primitives';
import { api } from '@/lib/api';
import type { SearchResponse } from '@/types';
import { fmtInt, riskClass, relativeTime } from '@/lib/utils';

const fetcher = (key: string) => api.get<SearchResponse>(key);

function SearchPageInner() {
  const router = useRouter();
  const params = useSearchParams();
  const q = params.get('q') ?? '';
  const page = Number(params.get('page') ?? '1');
  const sort = params.get('sort') ?? 'risk';
  const [draft, setDraft] = useState(q);

  useEffect(() => setDraft(q), [q]);

  const key = `/search?q=${encodeURIComponent(q)}&page=${page}&page_size=25&sort=${sort}`;
  const { data, error, isLoading } = useSWR<SearchResponse>(key, fetcher, {
    keepPreviousData: true,
  });

  function submit(newQuery: string) {
    const usp = new URLSearchParams({ q: newQuery, page: '1', sort });
    router.push(`/search?${usp.toString()}`);
  }

  function setPage(p: number) {
    const usp = new URLSearchParams({ q, page: String(p), sort });
    router.push(`/search?${usp.toString()}`);
  }

  function applyFacet(name: string, value: string) {
    const term = name === 'risk_level'
      ? `risk:${value}`
      : name === 'country'
        ? `country:${value}`
        : name === 'port'
          ? `port:${value}`
          : name === 'asn_org'
            ? `org:"${value}"`
            : name === 'tags'
              ? `tag:${value}`
              : `${name}:${value}`;
    submit((q ? `${q} ` : '') + term);
  }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <>
      <Nav />
      <div className="mx-auto max-w-[1400px] px-4 py-6">
        {/* Search bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit(draft);
          }}
          className="flex items-center gap-2 rounded-md border border-ink-700 bg-ink-850/80 p-1.5 focus-within:border-signal-400/50 focus-within:shadow-signal-glow"
        >
          <Search className="ml-2 h-4 w-4 text-bone-400" />
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="port:443 country:US product:nginx"
            className="flex-1 bg-transparent px-2 py-2 font-mono text-sm text-bone-100 placeholder:text-bone-500 focus:outline-none"
          />
          <select
            value={sort}
            onChange={(e) => {
              const usp = new URLSearchParams({ q, page: '1', sort: e.target.value });
              router.push(`/search?${usp.toString()}`);
            }}
            className="rounded border border-ink-700 bg-ink-900 px-2 py-1.5 font-mono text-xs text-bone-200"
          >
            <option value="risk">Sort: Risk</option>
            <option value="recent">Sort: Most recent</option>
            <option value="relevance">Sort: Relevance</option>
          </select>
          <Button type="submit" size="sm">Search</Button>
        </form>

        {/* Result stats */}
        <div className="mt-4 flex items-center justify-between font-mono text-[11px] uppercase tracking-[0.14em] text-bone-400">
          <span>
            {isLoading && !data ? (
              'Searching…'
            ) : data ? (
              <>
                <span className="text-bone-100">{fmtInt(data.total)}</span> hosts ·{' '}
                <span className="text-signal-400">{data.took_ms}ms</span>
              </>
            ) : null}
          </span>
          {data && (
            <span>
              page {data.page} / {totalPages}
            </span>
          )}
        </div>

        {error && (
          <div className="mt-6 rounded border border-danger/30 bg-danger/5 p-4 text-sm text-danger">
            Failed to load results: {(error as Error).message}
          </div>
        )}

        <div className="mt-4 grid gap-4 lg:grid-cols-[280px,1fr]">
          {/* Facets */}
          <aside className="space-y-3">
            {data?.facets.map((facet) => (
              <div key={facet.name} className="rounded-md border border-ink-700/60 bg-ink-850/40">
                <div className="border-b border-ink-700/40 px-4 py-2 font-mono text-[10px] uppercase tracking-[0.16em] text-bone-400">
                  {facet.name.replace('_', ' ')}
                </div>
                <ul className="px-2 py-2 text-sm">
                  {facet.buckets.slice(0, 10).map((b) => (
                    <li key={b.key}>
                      <button
                        onClick={() => applyFacet(facet.name, b.key)}
                        className="flex w-full items-center justify-between rounded px-2 py-1 text-left text-bone-200 transition-colors hover:bg-ink-800/80 hover:text-signal-400"
                      >
                        <span className="truncate font-mono text-xs">{b.key || '∅'}</span>
                        <span className="font-mono text-[10px] text-bone-500">{fmtInt(b.count)}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </aside>

          {/* Hits */}
          <div className="space-y-3">
            {data?.hits.length === 0 && !isLoading && (
              <div className="rounded border border-ink-700/60 bg-ink-850/40 p-10 text-center text-bone-400">
                No hosts match this query.
              </div>
            )}
            {data?.hits.map((h) => (
              <Link
                key={h.ip}
                href={`/host/${h.ip}`}
                className="group block rounded-md border border-ink-700/60 bg-ink-850/40 p-4 transition-colors hover:border-signal-400/30"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-lg text-bone-100 group-hover:text-signal-400">
                        {h.ip}
                      </span>
                      {h.hostname && (
                        <span className="truncate font-mono text-xs text-bone-400">{h.hostname}</span>
                      )}
                      <span
                        className={`ml-auto rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${riskClass(h.risk_level)}`}
                      >
                        {h.risk_level} · {Math.round(h.risk_score)}
                      </span>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-bone-400">
                      {h.asn_org && (
                        <span>
                          AS{h.asn} <span className="text-bone-300">{h.asn_org}</span>
                        </span>
                      )}
                      {(h.country || h.city) && (
                        <span className="flex items-center gap-1">
                          <MapPin className="h-3 w-3" />
                          {[h.city, h.country].filter(Boolean).join(', ')}
                        </span>
                      )}
                      <span>last seen {relativeTime(h.last_seen)}</span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {h.ports.slice(0, 16).map((p) => (
                        <Badge key={p} variant="outline">
                          {p}
                        </Badge>
                      ))}
                      {h.ports.length > 16 && (
                        <Badge variant="outline">+{h.ports.length - 16}</Badge>
                      )}
                    </div>
                    {h.tags.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {h.tags.slice(0, 6).map((t) => (
                          <Badge key={t} variant="signal">
                            {t}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </Link>
            ))}

            {/* Pagination */}
            {data && data.total > data.page_size && (
              <div className="flex items-center justify-between pt-2 font-mono text-xs text-bone-400">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage(page - 1)}
                >
                  <ChevronLeft className="h-3.5 w-3.5" /> Prev
                </Button>
                <span>
                  {page} / {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage(page + 1)}
                >
                  Next <ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

export default function SearchPage() {
  return (
    <Suspense fallback={<div className="p-8 font-mono text-bone-400">Loading…</div>}>
      <SearchPageInner />
    </Suspense>
  );
}
