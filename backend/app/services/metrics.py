"""Prometheus metrics for the NeuroScanIQ platform.

Exposes counters and histograms for scan operations, Nmap enrichment,
and worker health. Metrics are served via GET /metrics in the API
process, and optionally via a standalone HTTP listener in workers.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram, Info

APP_INFO = Info("neuroscaniq", "NeuroScanIQ platform metadata")
APP_INFO.info({"version": "0.1.0", "component": "api"})

# ---------- Scanner metrics ----------

SCAN_STARTED = Counter(
    "neuroscaniq_scans_started_total",
    "Total scans initiated",
    ["scan_type"],
)

SCAN_COMPLETED = Counter(
    "neuroscaniq_scans_completed_total",
    "Total scans completed successfully",
    ["scan_type"],
)

SCAN_FAILED = Counter(
    "neuroscaniq_scans_failed_total",
    "Total scans that failed",
    ["scan_type", "reason"],
)

SCAN_REJECTED = Counter(
    "neuroscaniq_scans_rejected_total",
    "Total scans rejected by authorization",
    ["scan_type", "reason"],
)

SCAN_TIMEOUT = Counter(
    "neuroscaniq_scans_timeout_total",
    "Total scans that timed out",
    ["scan_type"],
)

SCAN_DURATION = Histogram(
    "neuroscaniq_scan_duration_seconds",
    "Scan execution duration in seconds",
    ["scan_type"],
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 90, 120, 180),
)

PORTS_DISCOVERED = Histogram(
    "neuroscaniq_ports_discovered",
    "Number of open ports discovered per scan",
    ["scan_type"],
    buckets=(0, 1, 2, 5, 10, 20, 50, 100),
)

# ---------- Nmap-specific metrics ----------

NMAP_CACHE_HIT = Counter(
    "neuroscaniq_nmap_cache_hits_total",
    "Nmap results served from cache",
)

NMAP_CACHE_MISS = Counter(
    "neuroscaniq_nmap_cache_misses_total",
    "Nmap results not in cache (fresh scan required)",
)

NMAP_COOLDOWN_REJECTED = Counter(
    "neuroscaniq_nmap_cooldown_rejected_total",
    "Nmap scans rejected due to cooldown period",
)

NMAP_CONCURRENCY_WAITING = Histogram(
    "neuroscaniq_nmap_semaphore_wait_seconds",
    "Time spent waiting to acquire the Nmap concurrency semaphore",
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30),
)
