export function esc(s: unknown): string {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function fmtBytes(n: number | string): string {
  let v: number = +n || 0;
  if (v < 1024) return v + ' B';
  if (v < 1048576) return (v / 1024).toFixed(1) + ' KB';
  if (v < 1073741824) return (v / 1048576).toFixed(1) + ' MB';
  return (v / 1073741824).toFixed(2) + ' GB';
}

export function sparkline(vals: number[]): string {
  if (!vals.length) return '';
  const max = Math.max(...vals, 1);
  return vals.map((v, i) => `${(i * 120 / Math.max(vals.length - 1, 1)).toFixed(1)},${(36 - (v / max) * 30).toFixed(1)}`).join(' ');
}

export function cnText(v: boolean | null | undefined): string {
  return (v === null || v === undefined) ? '未知（库未加载）' : (v ? 'CN' : '非CN');
}

export interface UpstreamLike {
  id: number;
  name: string;
}

export function upName(upstreams: UpstreamLike[], id: number): string {
  const u = upstreams.find(x => x.id === id);
  return u ? u.name : `id(${id})`;
}

export interface RuleLike {
  geo_ip?: string;
  geo_site?: string;
}

export function geoLabel(r: RuleLike): string {
  const p: string[] = [];
  if (r.geo_ip) p.push('geoip:' + r.geo_ip);
  if (r.geo_site) p.push('geosite:' + r.geo_site);
  return p.length ? esc(p.join('+')) : '—';
}
