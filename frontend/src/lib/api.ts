/**
 * Thin typed fetch wrapper.
 *
 * Reads/writes tokens from the Zustand auth store. On 401 it makes ONE
 * attempt to refresh the access token using the stored refresh token,
 * then retries the original request once. If refresh fails the store is
 * cleared and a "session-expired" event is dispatched so the UI can react.
 */

import { useAuthStore } from '@/store/auth';

const API_BASE = (process.env.NEXT_PUBLIC_API_URL || '') + '/api/v1';

export class APIError extends Error {
  status: number;
  code?: string;
  details?: Record<string, unknown>;
  requestId?: string;

  constructor(status: number, payload: any, fallback: string) {
    const err = payload?.error ?? {};
    super(err.message || fallback);
    this.status = status;
    this.code = err.code;
    this.details = err.details;
    this.requestId = err.request_id;
  }
}

type Json = Record<string, unknown> | unknown[] | null;

async function rawFetch<T>(
  method: string,
  path: string,
  body?: Json,
  init?: RequestInit,
): Promise<T> {
  const token = useAuthStore.getState().accessToken;
  const headers: Record<string, string> = {
    'Accept': 'application/json',
    ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(init?.headers as Record<string, string> | undefined),
  };

  const resp = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    cache: 'no-store',
    ...init,
  });

  if (resp.status === 204) return undefined as unknown as T;

  let payload: any = null;
  try {
    payload = await resp.json();
  } catch {
    /* body may be empty */
  }

  if (!resp.ok) {
    throw new APIError(resp.status, payload, `${method} ${path} failed`);
  }
  return payload as T;
}

async function refreshAccess(): Promise<boolean> {
  const { refreshToken, setTokens, clear } = useAuthStore.getState();
  if (!refreshToken) return false;
  try {
    const resp = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!resp.ok) {
      clear();
      return false;
    }
    const data = await resp.json();
    setTokens(data.access_token, data.refresh_token);
    return true;
  } catch {
    clear();
    return false;
  }
}

async function withRefresh<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof APIError && err.status === 401) {
      const ok = await refreshAccess();
      if (ok) return fn();
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('auth:session-expired'));
      }
    }
    throw err;
  }
}

export const api = {
  get: <T,>(path: string, init?: RequestInit) => withRefresh(() => rawFetch<T>('GET', path, undefined, init)),
  post: <T,>(path: string, body?: Json, init?: RequestInit) =>
    withRefresh(() => rawFetch<T>('POST', path, body, init)),
  patch: <T,>(path: string, body?: Json, init?: RequestInit) =>
    withRefresh(() => rawFetch<T>('PATCH', path, body, init)),
  put: <T,>(path: string, body?: Json, init?: RequestInit) =>
    withRefresh(() => rawFetch<T>('PUT', path, body, init)),
  delete: <T,>(path: string, init?: RequestInit) =>
    withRefresh(() => rawFetch<T>('DELETE', path, undefined, init)),
};

export { API_BASE };
