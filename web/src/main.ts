// 测试用 barrel：只做 re-export，不碰 DOM、不发请求（单测零网络，见 AGENTS.md §4）。
// 浏览器入口是 app.ts（DOM 胶水 + 副作用），esbuild 打的是它；
// 不要把 app.ts import 进来，否则任何 import main.ts 的单测都会跑起整页初始化。
import './ryba-card.js';
import './ryba-stat.js';
import './ryba-modal.js';
export { RybaCard } from './ryba-card.js';
export { RybaStat } from './ryba-stat.js';
export { RybaModal } from './ryba-modal.js';
export { api, unwrapPage, type ApiEnvelope, type Page } from './api.js';
export { esc, fmtBytes, sparkline, cnText, upName, geoLabel } from './format.js';
export { dnsStatusHtml, nsTableHtml, cacheTableHtml, logsTableHtml } from './pages/dns.js';
export { geoDbText, geoStatusText, geoSrcText, geoCheckText } from './pages/geo.js';
export { upstreamRowHtml, upstreamAddr } from './upstreams.js';
export { ruleRowHtml } from './rules.js';
export { sessionRowHtml, emptyRowHtml, pagerHtml, isActive } from './sessions.js';
export { heatLevel, heroValues } from './dashboard.js';
