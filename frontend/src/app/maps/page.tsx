'use client';

import dynamic from 'next/dynamic';
import { Nav } from '@/components/nav';

const MapView = dynamic(() => import('@/components/map-view').then((m) => m.MapView), {
  ssr: false,
  loading: () => (
    <div className="flex h-[calc(100vh-3.5rem)] items-center justify-center font-mono text-sm text-bone-400">
      Loading map…
    </div>
  ),
});

export default function MapsPage() {
  return (
    <>
      <Nav />
      <MapView />
    </>
  );
}
