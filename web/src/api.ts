export interface ApiEnvelope<T = unknown> {
  ok: boolean;
  data?: T;
  total?: number;
  limit?: number;
  offset?: number;
  error?: { message?: string };
}

export async function api<T = unknown>(path: string, opts?: RequestInit): Promise<ApiEnvelope<T>> {
  const r = await fetch(path, opts);
  const j = (await r.json()) as ApiEnvelope<T>;
  if (!j.ok) throw new Error((j.error && j.error.message) || ('HTTP ' + r.status));
  return j;
}

export interface Page<T = unknown> {
  rows: T[];
  total: number;
  limit: number;
  offset: number;
}

export function unwrapPage<T = unknown>(j: Partial<ApiEnvelope<T[]>> & { data?: T[] }): Page<T> {
  return { rows: j.data || [], total: j.total || 0, limit: j.limit || 0, offset: j.offset || 0 };
}
