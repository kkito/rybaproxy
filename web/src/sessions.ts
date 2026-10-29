import { esc, fmtBytes } from './format.js';
import type { Page } from './api.js';

export interface Session { protocol: string; client_ip: string; target_host: string; target_port: number; status: number | string; bytes_up: number; bytes_down: number }

export function isActive(s: Session): boolean {
  return s.status === 0 || s.status === '0';
}

export function emptyRowHtml(cols: number, text: string): string {
  return `<tr><td colspan="${cols}"><div class="empty">${esc(text)}</div></td></tr>`;
}

export function sessionRowHtml(s: Session): string {
  return `<td><span class="pill proto">${esc(s.protocol)}</span></td>`
    + `<td class="num">${esc(s.client_ip)}</td>`
    + `<td>${esc(s.target_host)}:${s.target_port}</td>`
    + `<td><span class="pill ${isActive(s) ? 'on' : 'off'}">${isActive(s) ? '活跃' : '已关闭'}</span></td>`
    + `<td class="num">${fmtBytes(s.bytes_up)}</td>`
    + `<td class="num">${fmtBytes(s.bytes_down)}</td>`;
}

export function pagerHtml(sessPage: Page<Session>): string {
  const pages = Math.max(1, Math.ceil(sessPage.total / sessPage.limit));
  const cur = Math.floor(sessPage.offset / sessPage.limit) + 1;
  return `<button class="btn ghost sm" id="pgPrev" ${sessPage.offset <= 0 ? 'disabled' : ''}>上一页</button>`
    + `<span class="num">${cur} / ${pages} · 共 ${sessPage.total} 条</span>`
    + `<button class="btn ghost sm" id="pgNext" ${sessPage.offset + sessPage.limit >= sessPage.total ? 'disabled' : ''}>下一页</button>`;
}
