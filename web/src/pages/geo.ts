import { cnText } from '../format.js';

export interface GeoDbInfo { exists?: boolean; size?: number; cn_count?: number; url?: string }
export interface GeoStatus { dir?: string; proxy?: string; geoip?: GeoDbInfo; geosite?: GeoDbInfo }

export function geoDbText(x: GeoDbInfo | undefined, n: string): string {
  if (!x || !x.exists) return `${n}: 未下载`;
  return `${n}: ${((x.size || 0) / 1048576).toFixed(1)}MB / ${x.cn_count} 条`;
}

export function geoStatusText(d: GeoStatus): string {
  return `${geoDbText(d.geoip, 'geoip')}　${geoDbText(d.geosite, 'geosite')}`;
}

export function geoSrcText(d: GeoStatus): string {
  return `目录: ${d.dir || '?'}${d.proxy ? ' 代理: ' + d.proxy : '（直连下载）'}\n源: ${((d.geoip || {}).url || '').replace('https://', '')}`;
}

export interface GeoCheck { ips?: string[]; geoip_cn?: boolean | null; geosite_cn?: boolean | null; db_loaded?: boolean; matched_rule?: string; upstream?: { name?: string; id?: number } }

export function geoCheckText(d: GeoCheck): string {
  const up = d.upstream || {};
  return `解析 IP: ${(d.ips || []).join(', ') || '—'}\n`
    + `IP 归属: ${cnText(d.geoip_cn)}　域名归属: ${cnText(d.geosite_cn)}${d.db_loaded === false ? '\n⚠ IP 库未加载：请先点 下载/更新' : ''}\n`
    + `命中规则: ${d.matched_rule}　出口: ${up.name || ('id(' + up.id + ')')}`;
}
