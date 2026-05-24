'use client';

import { useState, Suspense } from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import useSWR from 'swr';
import { Search, Image as ImageIcon } from 'lucide-react';
import { Nav } from '@/components/nav';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/primitives';
import { api } from '@/lib/api';
import type { Screenshot } from '@/types';
import { relativeTime } from '@/lib/utils';

const fetcher = (key: string) => api.get<any>(key);

function ScreenshotsInner() {
  const router = useRouter();
  const params = useSearchParams();
  const q = params.get('q') ?? '';
  const tech = params.get('tech') ?? '';
  const [draft, setDraft] = useState(q);
  const [techDraft, setTechDraft] = useState(tech);

  const usp = new URLSearchParams();
  if (q) usp.set('q', q);
  if (tech) usp.set('technology', tech);
  usp.set('limit', '40');

  const { data: shots = [], isLoading } = useSWR<Screenshot[]>(
    `/screenshots?${usp.toString()}`,
    fetcher,
  );

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const next = new URLSearchParams();
    if (draft) next.set('q', draft);
    if (techDraft) next.set('tech', techDraft);
    router.push(`/screenshots?${next.toString()}`);
  }

  return (
    <>
      <Nav />
      <div className="mx-auto max-w-[1400px] px-4 py-6">
        <h1 className="font-display text-3xl font-semibold tracking-tight">Image Search</h1>
        <p className="mt-1 text-sm text-bone-400">
          Browse captured HTTP login pages and service banners. Click through to host detail.
        </p>

        <form onSubmit={submit} className="mt-6 flex flex-wrap items-end gap-3">
          <div className="flex flex-1 items-center gap-2 rounded-md border border-ink-700 bg-ink-850/80 p-1.5">
            <Search className="ml-2 h-4 w-4 text-bone-400" />
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="title or url contains…"
              className="flex-1 bg-transparent px-2 py-2 font-mono text-sm text-bone-100 placeholder:text-bone-500 focus:outline-none"
            />
          </div>
          <Input
            value={techDraft}
            onChange={(e) => setTechDraft(e.target.value)}
            placeholder="technology (e.g. nginx)"
            className="w-[220px]"
          />
          <Button type="submit">Render</Button>
        </form>

        {isLoading && (
          <div className="mt-10 text-center font-mono text-sm text-bone-400">Loading…</div>
        )}

        {!isLoading && shots.length === 0 && (
          <div className="mt-10 rounded border border-ink-700/60 bg-ink-850/40 p-12 text-center">
            <ImageIcon className="mx-auto h-8 w-8 text-bone-500" />
            <div className="mt-3 text-sm text-bone-400">No captured images match this filter.</div>
          </div>
        )}

        <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {shots.map((s) => (
            <Link
              key={s.id}
              href={`/host/${s.ip}`}
              className="group overflow-hidden rounded-md border border-ink-700/60 bg-ink-900 transition-colors hover:border-signal-400/40"
            >
              {s.thumbnail_url ? (
                <img
                  src={s.thumbnail_url}
                  alt={s.title ?? `${s.ip}:${s.port}`}
                  className="aspect-[16/10] w-full object-cover transition-transform group-hover:scale-[1.02]"
                />
              ) : (
                <div className="flex aspect-[16/10] items-center justify-center font-mono text-xs text-bone-500">
                  no preview
                </div>
              )}
              <div className="p-3 font-mono text-xs">
                <div className="truncate text-bone-100">{s.title || s.url}</div>
                <div className="mt-1 flex items-center justify-between text-bone-500">
                  <span>
                    {s.ip}:{s.port}
                  </span>
                  <span>{relativeTime(s.captured_at)}</span>
                </div>
                {s.technology_stack && s.technology_stack.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {s.technology_stack.slice(0, 4).map((t) => (
                      <Badge key={t} variant="outline">
                        {t}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            </Link>
          ))}
        </div>
      </div>
    </>
  );
}

export default function ScreenshotsPage() {
  return (
    <Suspense fallback={<div className="p-8 font-mono text-bone-400">Loading…</div>}>
      <ScreenshotsInner />
    </Suspense>
  );
}
