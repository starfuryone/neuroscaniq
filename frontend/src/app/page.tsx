'use client';

import Link from 'next/link';
import { motion } from 'framer-motion';
import { Search, Shield, Activity, Globe2, Bell, Code2, ArrowRight } from 'lucide-react';
import { Nav } from '@/components/nav';
import { Globe } from '@/components/globe';
import { TelemetryCard } from '@/components/telemetry-card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/primitives';

export default function Home() {
  return (
    <div className="relative min-h-screen overflow-hidden">
      {/* atmospheric backdrop */}
      <div
        className="pointer-events-none absolute inset-0 -z-10 bg-grid-faint bg-grid-64 opacity-[0.4]"
        aria-hidden
      />
      <div
        className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[640px] bg-scan-glow"
        aria-hidden
      />

      <Nav />

      {/* ---------------- HERO ---------------- */}
      <section className="scanlines relative">
        <div className="mx-auto grid max-w-[1400px] gap-8 px-4 py-16 lg:grid-cols-[1.1fr,1fr] lg:py-24">
          <div>
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="mb-6 inline-flex items-center gap-2"
            >
              <Badge variant="signal">
                <span className="pulse-dot mr-2" />
                Live · Indexing 4,128 ASNs
              </Badge>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
              className="font-display text-5xl font-semibold leading-[1.02] tracking-tight text-bone-50 lg:text-7xl"
            >
              Search and Monitor
              <br />
              <span className="text-signal-400">Internet-Connected</span>
              <br />
              Infrastructure.
            </motion.h1>

            <motion.p
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.15 }}
              className="mt-6 max-w-xl text-lg leading-relaxed text-bone-300"
            >
              AI-powered internet exposure intelligence for security teams, researchers,
              and infrastructure operators. NeuroScanIQ continuously indexes publicly
              accessible assets, fingerprints services, and surfaces meaningful exposure
              changes — strictly for defensive use.
            </motion.p>

            {/* hero search */}
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.3 }}
              className="mt-8"
            >
              <form
                action="/search"
                method="GET"
                className="group flex items-center gap-2 rounded-md border border-ink-600 bg-ink-850/80 p-1.5 backdrop-blur-sm focus-within:border-signal-400/50 focus-within:shadow-signal-glow"
              >
                <Search className="ml-2 h-4 w-4 text-bone-400" />
                <input
                  name="q"
                  type="text"
                  placeholder="port:443 country:US product:nginx"
                  className="flex-1 bg-transparent px-2 py-2 font-mono text-sm text-bone-100 placeholder:text-bone-500 focus:outline-none"
                />
                <Button type="submit" size="sm">
                  Search <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </form>
              <div className="mt-3 flex flex-wrap gap-2 font-mono text-[11px] text-bone-500">
                <span>Try:</span>
                {['port:6379', 'product:openssh', 'tls.subject_cn:example.com', 'asn:AS13335'].map(
                  (q) => (
                    <Link
                      key={q}
                      href={`/search?q=${encodeURIComponent(q)}`}
                      className="rounded border border-ink-700 bg-ink-800/60 px-2 py-0.5 transition-colors hover:border-signal-400/40 hover:text-signal-400"
                    >
                      {q}
                    </Link>
                  ),
                )}
              </div>
            </motion.div>
          </div>

          {/* right column: globe */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="relative flex items-center justify-center"
          >
            <Globe className="aspect-square w-full max-w-[520px]" />
          </motion.div>
        </div>

        {/* live telemetry strip */}
        <div className="mx-auto max-w-[1400px] px-4 pb-16">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <TelemetryCard label="Indexed Hosts" value="1.24B" delta="+2.4M today" trend="up" />
            <TelemetryCard label="Services Tracked" value="4.7B" delta="+8.2M today" trend="up" />
            <TelemetryCard label="ASNs Mapped" value="89,412" delta="stable" trend="flat" />
            <TelemetryCard label="Avg Search Latency" value="148" unit="ms" delta="-12ms wk/wk" trend="up" />
          </div>
        </div>
      </section>

      {/* ---------------- FEATURE GRID ---------------- */}
      <section className="border-t border-ink-700/40 bg-ink-900/40">
        <div className="mx-auto max-w-[1400px] px-4 py-20">
          <div className="mb-10 flex items-end justify-between">
            <div>
              <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-signal-400">
                · 02 · Platform
              </div>
              <h2 className="mt-2 font-display text-4xl font-semibold tracking-tight text-bone-50">
                Built for defensive operations.
              </h2>
            </div>
            <p className="hidden max-w-md text-sm text-bone-400 lg:block">
              No exploitation tooling. No brute-force. No credential attacks. Monitoring
              requires proof of ownership.
            </p>
          </div>

          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {[
              {
                icon: Search,
                title: 'Internet Asset Search',
                body: 'Shodan-style query language across ports, services, TLS certs, ASN, geography, software, and HTTP titles.',
              },
              {
                icon: Activity,
                title: 'Attack Surface Monitoring',
                body: 'Track changes in exposure for authorized assets. Differential alerts on new ports, TLS rotation, or risk drift.',
              },
              {
                icon: Shield,
                title: 'AI Exposure Categorization',
                body: 'Behavioral classification of services. Anomaly detection. Risk prioritization with explainable factors.',
              },
              {
                icon: Globe2,
                title: 'Global Infrastructure Maps',
                body: 'Clustered geolocation, real-time service heatmaps, and ASN topology overlays.',
              },
              {
                icon: Bell,
                title: 'Alert Routing',
                body: 'Email, webhooks, and dashboard inbox with severity grading and resolution workflows.',
              },
              {
                icon: Code2,
                title: 'Developer APIs',
                body: 'REST endpoints for search, host detail, monitoring, alerts, and screenshot retrieval.',
              },
            ].map((f, i) => (
              <motion.div
                key={f.title}
                initial={{ opacity: 0, y: 8 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: i * 0.05 }}
                className="group relative overflow-hidden rounded-lg border border-ink-700/60 bg-ink-850/40 p-6 transition-colors hover:border-signal-400/30"
              >
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-signal-400/30 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
                <f.icon className="h-5 w-5 text-signal-400" />
                <h3 className="mt-4 font-display text-lg font-semibold text-bone-100">{f.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-bone-400">{f.body}</p>
                <div className="mt-4 font-mono text-[10px] uppercase tracking-[0.18em] text-bone-500">
                  · 0{i + 1}
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ---------------- DEFENSIVE POSTURE BANNER ---------------- */}
      <section className="border-t border-ink-700/40">
        <div className="mx-auto max-w-[1400px] px-4 py-20">
          <div className="grid items-start gap-10 lg:grid-cols-[1fr,1.4fr]">
            <div>
              <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-signal-400">
                · 03 · Trust Posture
              </div>
              <h2 className="mt-2 font-display text-4xl font-semibold tracking-tight text-bone-50">
                What NeuroScanIQ <span className="text-danger">will not</span> do.
              </h2>
              <p className="mt-4 text-sm leading-relaxed text-bone-400">
                The platform is purpose-built for defensive cybersecurity. The engineering
                surface area itself is constrained — there is no exploit module to disable.
              </p>
            </div>
            <div className="space-y-2 font-mono text-sm">
              {[
                'No exploitation modules',
                'No credential attack tooling',
                'No malware-adjacent functionality',
                'No scanning of private RFC1918 / loopback ranges',
                'Monitoring requires verified ownership (DNS TXT, email, file upload, or ASN attestation)',
                'All scan workers enforce a central allow-list before any probe',
              ].map((claim) => (
                <div
                  key={claim}
                  className="flex items-start gap-3 rounded border border-ink-700/60 bg-ink-850/40 px-4 py-2.5 text-bone-200"
                >
                  <span className="mt-1.5 h-1.5 w-1.5 flex-none rounded-full bg-signal-400" />
                  {claim}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- CTA ---------------- */}
      <section className="relative border-t border-ink-700/40">
        <div className="mx-auto max-w-[1400px] px-4 py-24 text-center">
          <h2 className="font-display text-4xl font-semibold tracking-tight text-bone-50 lg:text-5xl">
            See your infrastructure
            <br /> the way attackers do.
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-sm text-bone-400">
            Free tier includes 100 searches per month. Paid plans unlock continuous
            monitoring, exports, and elevated API throughput.
          </p>
          <div className="mt-8 flex items-center justify-center gap-3">
            <Link href="/register">
              <Button size="lg">Create free account</Button>
            </Link>
            <Link href="/developer">
              <Button variant="outline" size="lg">
                API documentation
              </Button>
            </Link>
          </div>
        </div>
      </section>

      <footer className="border-t border-ink-700/40 py-8">
        <div className="mx-auto flex max-w-[1400px] flex-col items-center justify-between gap-4 px-4 font-mono text-[11px] uppercase tracking-[0.14em] text-bone-500 md:flex-row">
          <span>© 2026 NeuroScanIQ · AI-Powered Internet Exposure Intelligence</span>
          <span>For authorized defensive use only.</span>
        </div>
      </footer>
    </div>
  );
}
