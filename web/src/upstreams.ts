import { esc } from './format.js';

export interface Upstream { id: number; name: string; type: string; host: string; port: number; enabled: boolean; username?: string }

export function upstreamAddr(u: Upstream): string {
  return u.host ? `${esc(u.host)}${u.port ? ':' + u.port : ''}` : '—';
}

export function upstreamOptionsHtml(upstreams: Upstream[]): string {
  const opts = upstreams.map(u => `<option value="${u.id}">${esc(u.name)} (${u.id})</option>`).join('');
  return opts || '<option value="0">direct</option>';
}

export function upstreamRowHtml(u: Upstream): string {
  return `<td>${esc(u.name)}</td>`
    + `<td><span class="pill proto">${esc(u.type)}</span></td>`
    + `<td class="num">${upstreamAddr(u)}</td>`
    + `<td><span class="pill ${u.enabled ? 'on' : 'off'}">${u.enabled ? '启用' : '停用'}</span></td>`
    + `<td class="row-actions">`
    + `<button data-test="${u.id}">测试</button>`
    + `<button data-toggle="${u.id}">${u.enabled ? '停用' : '启用'}</button>`
    + `<button data-edit="${u.id}">编辑</button>`
    + `<button class="danger" data-del="${u.id}">删除</button>`
    + `</td>`;
}
