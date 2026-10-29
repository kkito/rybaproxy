import { esc, upName, geoLabel, type UpstreamLike } from './format.js';

export interface Rule { id: number; priority: number; domain_pattern: string; ip_cidr: string; geo_ip: string; geo_site: string; port: number; protocol: string; upstream_id: number }

export function ruleRowHtml(r: Rule, upstreams: UpstreamLike[]): string {
  return `<td class="num">${r.priority}</td>`
    + `<td>${esc(r.domain_pattern) || '—'}</td>`
    + `<td class="num">${esc(r.ip_cidr) || '—'}</td>`
    + `<td class="num">${r.port || '*'}</td>`
    + `<td><span class="pill proto">${esc(r.protocol)}</span></td>`
    + `<td>${esc(upName(upstreams, r.upstream_id))}</td>`
    + `<td class="num">${geoLabel(r)}</td>`
    + `<td class="row-actions">`
    + `<button data-edit="${r.id}">编辑</button>`
    + `<button class="danger" data-del="${r.id}">删除</button>`
    + `</td>`;
}
