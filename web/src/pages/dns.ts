import { esc } from '../format.js';

export interface DnsStatus { proxy: string; cache_count: number; log_count: number; fallback: string[] }
export interface DnsNs { type: number; url: string; host: string; proxy: string }
export interface DnsCacheEntry { domain: string; class: number; resolver_id: string; ip: string; ttl_left: number; hits: number; negative: boolean }
export interface DnsLogEntry { ts: number; domain: string; class: number; resolver_id: string; via_proxy: boolean; duration_ms: number; status: string; ip_count: number; from_cache: boolean }

export function dnsStatusHtml(d: DnsStatus): string {
  return `<div class="form-row"><span>代理</span><span class="pill ${d.proxy === 'none' ? 'off' : 'on'}">${esc(d.proxy)}</span>`
    + `<span>缓存 ${d.cache_count}</span><span>日志 ${d.log_count}</span>`
    + `<span>兜底 ${(d.fallback || []).map(esc).join(' / ')}</span></div>`;
}

export function nsTableHtml(rows: DnsNs[]): string {
  if (!rows.length) return '<div class="empty">未配置上游 DNS</div>';
  return rows.map(n => `<tr><td class="num">${n.type}</td><td>${esc(n.url)}</td>`
    + `<td class="num">${esc(n.host)}</td><td>${esc(n.proxy) || '—'}</td></tr>`).join('');
}

export function cacheTableHtml(rows: DnsCacheEntry[]): string {
  if (!rows.length) return '<tr><td colspan="6"><div class="empty">缓存为空</div></td></tr>';
  return rows.map(e => `<tr><td>${esc(e.domain)}</td><td class="num">${e.class}</td>`
    + `<td class="num">${esc(e.ip) || (e.negative ? 'NX' : '—')}</td>`
    + `<td class="num">${e.ttl_left}s</td><td class="num">${e.hits}</td>`
    + `<td>${esc(e.resolver_id)}</td></tr>`).join('');
}

export function logsTableHtml(rows: DnsLogEntry[]): string {
  if (!rows.length) return '<tr><td colspan="6"><div class="empty">暂无解析日志</div></td></tr>';
  return rows.map(l => `<tr><td>${esc(l.domain)}</td><td class="num">${l.class}</td>`
    + `<td><span class="pill ${l.status === 'ok' ? 'on' : 'off'}">${esc(l.status)}</span></td>`
    + `<td class="num">${l.duration_ms}ms</td><td class="num">${l.ip_count}</td>`
    + `<td>${l.from_cache ? '缓存' : esc(l.resolver_id)}${l.via_proxy ? '·代理' : ''}</td></tr>`).join('');
}
