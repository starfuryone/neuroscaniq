'use client';

import { useEffect, useRef, useState } from 'react';
import L, { type LatLngExpression } from 'leaflet';
import 'leaflet/dist/leaflet.css';
import 'leaflet.markercluster/dist/MarkerCluster.css';
import 'leaflet.markercluster/dist/MarkerCluster.Default.css';
import 'leaflet.markercluster';
import useSWR from 'swr';
import { Search } from 'lucide-react';
import { api } from '@/lib/api';
import type { SearchResponse } from '@/types';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { riskClass } from '@/lib/utils';

/**
 * Dark-tile global map with clustered host markers, colored by risk.
 * Driven by the search API so all existing query filters apply.
 */
export function MapView() {
  const mapRef = useRef<HTMLDivElement | null>(null);
  const mapInstance = useRef<L.Map | null>(null);
  const layerRef = useRef<any>(null);

  const [query, setQuery] = useState('');
  const [submitted, setSubmitted] = useState('');

  const { data } = useSWR<SearchResponse>(
    `/search?q=${encodeURIComponent(submitted)}&page=1&page_size=500&sort=recent`,
    (k: string) => api.get<SearchResponse>(k),
  );

  // Initialize map once.
  useEffect(() => {
    if (!mapRef.current || mapInstance.current) return;
    const map = L.map(mapRef.current, {
      worldCopyJump: true,
      attributionControl: true,
      preferCanvas: true,
      zoomControl: false,
    }).setView([20, 0], 2);

    // Dark tile layer (CartoDB Voyager Dark).
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      subdomains: 'abcd',
      maxZoom: 18,
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> · &copy; CARTO',
    }).addTo(map);

    L.control.zoom({ position: 'bottomright' }).addTo(map);
    mapInstance.current = map;
  }, []);

  // Refresh markers when data changes.
  useEffect(() => {
    const map = mapInstance.current;
    if (!map || !data) return;

    if (layerRef.current) {
      map.removeLayer(layerRef.current);
    }

    // @ts-expect-error -- L.markerClusterGroup is added by the plugin
    const cluster = L.markerClusterGroup({
      chunkedLoading: true,
      iconCreateFunction: (c: any) => {
        const count = c.getChildCount();
        const size = count > 100 ? 56 : count > 25 ? 44 : 32;
        return L.divIcon({
          html: `<div style="
            width:${size}px;height:${size}px;
            display:flex;align-items:center;justify-content:center;
            background:rgba(34,211,238,0.15);
            color:#22d3ee;border:1px solid rgba(34,211,238,0.5);
            border-radius:999px;font-family:JetBrains Mono;font-size:12px;font-weight:600;
            box-shadow:0 0 16px rgba(34,211,238,0.2);">${count}</div>`,
          className: '',
          iconSize: [size, size],
        });
      },
    });

    for (const h of data.hits) {
      if (h.lat == null || h.lon == null) continue;
      const color =
        h.risk_level === 'critical'
          ? '#ef4444'
          : h.risk_level === 'high'
            ? '#f87171'
            : h.risk_level === 'medium'
              ? '#fbbf24'
              : '#22d3ee';

      const marker = L.circleMarker([h.lat, h.lon] as LatLngExpression, {
        radius: 5,
        color,
        fillColor: color,
        fillOpacity: 0.7,
        weight: 1,
      });
      marker.bindPopup(
        `<div style="font-family:JetBrains Mono;font-size:12px;color:#e8ecf0;background:#0d1219;padding:8px;border:1px solid #1d242f;border-radius:4px;">
          <div style="font-weight:600;color:#22d3ee;"><a href="/host/${h.ip}" style="color:#22d3ee;">${h.ip}</a></div>
          <div style="color:#9aa5b3;margin-top:4px;">${h.asn_org ?? ''}</div>
          <div style="color:#9aa5b3;">${[h.city, h.country].filter(Boolean).join(', ')}</div>
          <div style="margin-top:4px;">Risk: <span style="color:${color}">${h.risk_level}</span> · ${h.ports.length} ports</div>
        </div>`,
        { closeButton: false, className: 'dark-popup' },
      );
      cluster.addLayer(marker);
    }
    map.addLayer(cluster);
    layerRef.current = cluster;
  }, [data]);

  return (
    <div className="relative">
      <div ref={mapRef} className="h-[calc(100vh-3.5rem)] w-full" />
      <div className="absolute left-4 top-4 z-[400] w-[min(420px,calc(100vw-32px))] rounded-md border border-ink-700/60 bg-ink-900/95 p-2 backdrop-blur-md">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setSubmitted(query);
          }}
          className="flex items-center gap-2"
        >
          <Search className="ml-1 h-4 w-4 text-bone-400" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter map: port:443 country:US"
            className="border-0 bg-transparent focus-visible:ring-0"
          />
          <Button type="submit" size="sm">
            Render
          </Button>
        </form>
        {data && (
          <div className="mt-2 flex items-center justify-between px-1 font-mono text-[10px] uppercase tracking-[0.16em] text-bone-400">
            <span>{data.hits.length} markers</span>
            <span className="text-signal-400">{data.took_ms}ms</span>
          </div>
        )}
      </div>
    </div>
  );
}
