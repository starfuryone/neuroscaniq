/** Type definitions mirroring backend Pydantic schemas. */

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface SearchHit {
  ip: string;
  hostname?: string | null;
  country?: string | null;
  city?: string | null;
  asn?: number | null;
  asn_org?: string | null;
  ports: number[];
  services: Array<Record<string, unknown>>;
  risk_score: number;
  risk_level: RiskLevel;
  tags: string[];
  last_seen?: string | null;
  lat?: number | null;
  lon?: number | null;
}

export interface SearchFacet {
  name: string;
  buckets: Array<{ key: string; count: number }>;
}

export interface SearchResponse {
  total: number;
  page: number;
  page_size: number;
  took_ms: number;
  hits: SearchHit[];
  facets: SearchFacet[];
  query: string;
}

export interface HostDetail {
  ip: string;
  hostname?: string | null;
  country?: string | null;
  city?: string | null;
  region?: string | null;
  asn?: number | null;
  asn_org?: string | null;
  organization?: string | null;
  ports: number[];
  services: Array<Record<string, unknown>>;
  tls?: Record<string, unknown> | null;
  http?: Record<string, unknown> | null;
  risk_score: number;
  risk_level: RiskLevel;
  risk_factors: Record<string, unknown>;
  tags: string[];
  last_seen?: string | null;
  ai_summary?: string | null;
}

export interface APIKey {
  id: string;
  name: string;
  prefix: string;
  is_active: boolean;
  created_at: string;
  last_used_at?: string | null;
  usage_count: number;
}

export interface APIKeyCreated extends APIKey {
  plaintext_key: string;
}

export type AssetKind = 'ip' | 'cidr' | 'domain' | 'asn';
export type AssetStatus = 'pending' | 'verified' | 'rejected' | 'revoked';

export interface Asset {
  id: string;
  kind: AssetKind;
  value: string;
  label?: string | null;
  status: AssetStatus;
  verified_at?: string | null;
  created_at: string;
}

export type ProofMethod = 'dns_txt' | 'email' | 'file_upload' | 'asn_attestation';
export type ProofStatus = 'pending' | 'verified' | 'rejected' | 'expired';

export interface OwnershipProof {
  id: string;
  asset_id: string;
  method: ProofMethod;
  status: ProofStatus;
  challenge: string;
  expected_value: string;
  attempts: number;
  verified_at?: string | null;
  created_at: string;
  instructions?: string | null;
  last_check_detail?: string | null;
}

export type MonitorCadence = 'hourly' | 'daily' | 'weekly';

export interface Monitor {
  id: string;
  asset_id: string;
  cadence: MonitorCadence;
  is_active: boolean;
  last_run_at?: string | null;
  next_run_at?: string | null;
  config?: Record<string, unknown> | null;
  created_at: string;
}

export type AlertSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Alert {
  id: string;
  asset_id?: string | null;
  monitor_id?: string | null;
  host_id?: string | null;
  severity: AlertSeverity;
  kind: string;
  title: string;
  message: string;
  is_read: boolean;
  is_resolved: boolean;
  created_at: string;
}

export interface Subscription {
  plan: 'free' | 'pro' | 'enterprise';
  status: string;
  current_period_end?: string | null;
  cancel_at?: string | null;
  monthly_search_quota: number;
  monthly_api_quota: number;
  monitor_quota: number;
}

export interface AdminStats {
  users: number;
  hosts: number;
  open_alerts: number;
  jobs_queued: number;
  jobs_running: number;
  scan_queue_depth: number;
  alert_queue_depth: number;
}

export interface Screenshot {
  id: string;
  ip: string;
  port: number;
  url: string;
  title?: string | null;
  captured_at: string;
  technology_stack: string[];
  image_url?: string | null;
  thumbnail_url?: string | null;
}
