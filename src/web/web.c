#include "rybaproxy/web.h"
#include "rybaproxy/stats.h"
#include "rybaproxy/db.h"
#include "rybaproxy/router.h"
#include "rybaproxy/upstream.h"

#include <civetweb.h>
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char INDEX_HTML[] =
"<!DOCTYPE html>\n"
"<html lang=\"zh-CN\">\n"
"<head>\n"
"<meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
"<title>rybaproxy · 管理面板（设计稿 C · 花园午后）</title>\n"
"<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n"
"<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n"
"<link href=\"https://fonts.googleapis.com/css2?family=Playfair+Display:wght@500;700&family=Source+Sans+3:wght@400;500;600&family=Space+Grotesk:wght@500;600&display=swap\" rel=\"stylesheet\">\n"
"<style>\n"
"  :root {\n"
"    --bg: #F5F1E8; --ink: #2E3A33; --ink-soft: #5A665E;\n"
"    --accent: #C67B5C; --accent-soft: #E8CFC2;\n"
"    --mint: #8FA888; --mint-soft: #DCE6D9; --mint-deep: #5F7E5A;\n"
"    --stone: #E3DCCF; --stone-deep: #D6CEBF;\n"
"    --card: #FBF8F1; --line: #D9D2C3; --danger: #B85454;\n"
"    --shadow: 0 1px 2px rgba(46,58,51,.06), 0 8px 24px rgba(46,58,51,.08);\n"
"    --radius: 14px; --radius-sm: 8px;\n"
"  }\n"
"  * { box-sizing: border-box; }\n"
"  html, body { margin: 0; padding: 0; }\n"
"  body { font-family: \"Source Sans 3\", system-ui, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.5; -webkit-font-smoothing: antialiased; }\n"
"  h1, h2, h3 { font-family: \"Playfair Display\", Georgia, serif; font-weight: 700; margin: 0; }\n"
"  .num { font-family: \"Space Grotesk\", ui-monospace, monospace; font-variant-numeric: tabular-nums; }\n"
"  button:focus-visible, input:focus-visible, select:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }\n"
"  .shell { max-width: 1280px; margin: 0 auto; padding: 32px 28px 64px; }\n"
"  .hero { display: grid; grid-template-columns: 1fr; gap: 20px; margin-bottom: 24px; }\n"
"  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }\n"
"  @media (max-width: 1024px) { .grid { grid-template-columns: repeat(2, 1fr); } }\n"
"  @media (max-width: 680px) { .grid { grid-template-columns: 1fr; } }\n"
"  .span-2 { grid-column: span 2; }\n"
"  .span-3 { grid-column: span 3; }\n"
"  @media (max-width: 680px) { .row-34 { grid-template-columns: 1fr !important; } }\n"
"  @media (max-width: 1024px) { .span-3 { grid-column: span 2; } }\n"
"  @media (max-width: 680px) { .span-2, .span-3 { grid-column: span 1; } }\n"
"\n"
"  ryba-card { display: block; background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); padding: 24px 26px; box-shadow: var(--shadow); position: relative; overflow: hidden; min-width: 0; }\n"
"  ryba-card::before { content: \"\"; position: absolute; inset: 0; pointer-events: none; background-image: url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120' viewBox='0 0 120 120'><g fill='none' stroke='%238FA888' stroke-width='0.6' opacity='0.25'><path d='M60 10 C30 30 30 90 60 110 C90 90 90 30 60 10 Z'/><path d='M60 10 L60 110'/><path d='M60 40 L40 55 M60 40 L80 55 M60 70 L42 82 M60 70 L78 82'/></g></svg>\"); background-size: 120px 120px; background-repeat: repeat; opacity: .45; transition: opacity .4s ease; }\n"
"  ryba-card:hover::before { opacity: .75; }\n"
"  @media (prefers-reduced-motion: reduce) { ryba-card::before { transition: none; } }\n"
"\n"
"  ryba-card[data-p=\"1\"]::before { background-image: url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'><g fill='none' stroke='%23C67B5C' stroke-width='0.7' opacity='0.22'><circle cx='50' cy='50' r='8'/><circle cx='50' cy='50' r='20'/><circle cx='50' cy='50' r='34'/><path d='M50 16 L50 84 M16 50 L84 50'/></g></svg>\"); }\n"
"  ryba-card[data-p=\"2\"]::before { background-image: url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='80' height='80' viewBox='0 0 80 80'><g fill='%238FA888' opacity='0.18'><circle cx='10' cy='10' r='2'/><circle cx='30' cy='20' r='1.5'/><circle cx='55' cy='12' r='2.2'/><circle cx='70' cy='35' r='1.8'/><circle cx='20' cy='50' r='2'/><circle cx='45' cy='55' r='1.6'/><circle cx='65' cy='65' r='2.4'/><circle cx='35' cy='72' r='1.9'/></g></svg>\"); }\n"
"  ryba-card[data-p=\"3\"]::before { background-image: url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='90' height='90' viewBox='0 0 90 90'><g fill='none' stroke='%235F7E5A' stroke-width='0.8' opacity='0.2'><path d='M0 45 Q22 20 45 45 T90 45'/><path d='M0 60 Q22 35 45 60 T90 60'/><path d='M0 30 Q22 5 45 30 T90 30'/></g></svg>\"); }\n"
"  ryba-card .card-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }\n"
"  ryba-card .card-title { font-family: \"Playfair Display\", serif; font-size: 1.25rem; }\n"
"  ryba-card .card-eyebrow { font-size: .72rem; letter-spacing: .12em; text-transform: uppercase; color: var(--ink-soft); }\n"
"\n"
"  ryba-stat { display: block; }\n"
"  ryba-stat .stat-value { font-size: 2.4rem; line-height: 1; color: var(--ink); }\n"
"  ryba-stat .stat-label { font-size: .85rem; color: var(--ink-soft); margin-top: 6px; }\n"
"  ryba-stat .stat-trend { display: inline-flex; align-items: center; gap: 4px; font-size: .78rem; color: var(--mint); margin-top: 8px; }\n"
"  ryba-stat .spark { width: 100%; height: 34px; margin-top: 10px; }\n"
"\n"
"  .table { width: 100%; border-collapse: collapse; font-size: .9rem; table-layout: fixed; }\n"
"  .table th { text-align: left; font-weight: 600; color: var(--ink-soft); font-size: .72rem; letter-spacing: .08em; text-transform: uppercase; padding: 8px 6px; border-bottom: 1px solid var(--line); }\n"
"  .table td { padding: 10px 8px; border-bottom: 1px solid var(--stone-deep); vertical-align: middle; }\n"
"  .table tr:last-child td { border-bottom: none; }\n"
"  .pill { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: .72rem; font-weight: 600; }\n"
"  .pill.on { background: var(--mint-soft); color: #3F5A4A; }\n"
"  .pill.off { background: #ECE4E0; color: #7A5A50; }\n"
"  .pill.proto { background: var(--accent-soft); color: #7A4A36; }\n"
"  .row-actions { display: flex; gap: 6px; }\n"
"  .row-actions button { background: transparent; border: 1px solid var(--line); color: var(--ink-soft); padding: 4px 12px; border-radius: 6px; cursor: pointer; font-size: .78rem; transition: all .15s ease; margin-right: 4px; }\n"
"  .row-actions button:hover { border-color: var(--accent); color: var(--accent); }\n"
"  .row-actions button.danger:hover { border-color: var(--danger); color: var(--danger); }\n"
"\n"
"  .form-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }\n"
"  .form-row input, .form-row select { padding: 8px 10px; border: 1px solid var(--line); border-radius: 8px; background: #fff; font: inherit; color: var(--ink); min-width: 0; flex: 1 1 140px; }\n"
"  .btn { padding: 9px 16px; border: none; border-radius: 8px; cursor: pointer; font: inherit; font-weight: 600; background: var(--accent); color: #fff; transition: transform .1s ease, box-shadow .15s ease; }\n"
"  .btn:hover { box-shadow: 0 4px 12px rgba(198,123,92,.35); }\n"
"  .btn:active { transform: translateY(1px); }\n"
"  .btn.ghost { background: transparent; color: var(--ink); border: 1px solid var(--line); }\n"
"  .btn.sm { padding: 6px 12px; font-size: .82rem; }\n"
"\n"
"  .empty { text-align: center; padding: 28px 12px; color: var(--ink-soft); }\n"
"  .empty svg { margin-bottom: 8px; opacity: .6; }\n"
"\n"
"  .skel { background: linear-gradient(90deg, var(--stone) 0%, var(--stone-deep) 50%, var(--stone) 100%); background-size: 200% 100%; animation: shimmer 1.4s infinite; border-radius: 6px; height: 14px; }\n"
"  @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }\n"
"  @media (prefers-reduced-motion: reduce) { .skel { animation: none; } }\n"
"\n"
"  .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); background: var(--ink); color: #fff; padding: 10px 18px; border-radius: 10px; font-size: .88rem; opacity: 0; transition: opacity .2s, transform .2s; pointer-events: none; z-index: 50; }\n"
"  .toast.show { opacity: 1; transform: translateX(-50%) translateY(-4px); }\n"
"\n"
"  /* modal */\n"
"  ryba-modal { position: fixed; inset: 0; display: none; align-items: center; justify-content: center; background: rgba(46,58,51,.35); z-index: 40; padding: 20px; }\n"
"  ryba-modal.open { display: flex; }\n"
"  ryba-modal .modal-card { background: var(--card); border-radius: var(--radius); padding: 26px; width: min(520px, 100%); box-shadow: var(--shadow); border: 1px solid var(--line); }\n"
"  ryba-modal .modal-title { font-family: \"Playfair Display\", serif; font-size: 1.3rem; margin-bottom: 14px; }\n"
"  ryba-modal .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }\n"
"\n"
"  /* heatmap tooltip */\n"
"  #heatmap { display: grid; grid-template-columns: repeat(15, 1fr); gap: 5px; }\n"
"  #heatmap .cell { aspect-ratio: 1/1; border-radius: 3px; cursor: pointer; transition: transform .12s; position: relative; }\n"
"  #heatmap .cell:hover { transform: scale(1.2); z-index: 2; }\n"
"  #hmTip { position: fixed; pointer-events: none; background: var(--ink); color: #fff; padding: 6px 10px; border-radius: 6px; font-size: .75rem; opacity: 0; transition: opacity .15s; z-index: 60; white-space: nowrap; }\n"
"\n"
"  header.top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }\n"
"  header.top .brand { display: flex; align-items: center; gap: 12px; }\n"
"  header.top .brand-mark { width: 38px; height: 38px; border-radius: 10px; background: var(--accent); display: grid; place-items: center; color: #fff; font-family: \"Playfair Display\", serif; font-size: 1.15rem; }\n"
"  header.top h1 { font-size: 1.6rem; }\n"
"  header.top .meta { font-size: .8rem; color: var(--ink-soft); }\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div class=\"shell\">\n"
"  <header class=\"top\">\n"
"    <div class=\"brand\">\n"
"      <div class=\"brand-mark\">R</div>\n"
"      <div>\n"
"        <h1>rybaproxy</h1>\n"
"        <div class=\"meta\">家庭代理 · 管理面板</div>\n"
"      </div>\n"
"    </div>\n"
"    <div class=\"meta num\" id=\"clock\">--:--</div>\n"
"  </header>\n"
"\n"
"  <section class=\"hero\">\n"
"    <ryba-card id=\"heroCard\">\n"
"      <div class=\"card-head\">\n"
"        <div>\n"
"          <div class=\"card-eyebrow\">实时 · 活跃会话</div>\n"
"          <div class=\"card-title\">家中流量总览</div>\n"
"        </div>\n"
"        <span class=\"pill on\">运行中</span>\n"
"      </div>\n"
"      <div class=\"grid\" style=\"grid-template-columns: repeat(4,1fr); gap:16px;\">\n"
"        <ryba-stat value=\"42\" label=\"当前活跃会话\" trend=\"+3 较昨日\"></ryba-stat>\n"
"        <ryba-stat value=\"1.2 GB\" label=\"今日上行\" trend=\"\"></ryba-stat>\n"
"        <ryba-stat value=\"8.7 GB\" label=\"今日下行\" trend=\"\"></ryba-stat>\n"
"        <ryba-stat value=\"3\" label=\"错误 / 丢弃\" trend=\"0 丢弃\"></ryba-stat>\n"
"      </div>\n"
"    </ryba-card>\n"
"  </section>\n"
"\n"
"  <div class=\"row-34\" style=\"display:grid; grid-template-columns: minmax(0,4fr) minmax(0,6fr); gap:20px; margin-bottom:20px;\">\n"
"    <ryba-card>\n"
"      <div class=\"card-head\">\n"
"        <div>\n"
"          <div class=\"card-eyebrow\">上游</div>\n"
"          <div class=\"card-title\">出口节点</div>\n"
"        </div>\n"
"        <button class=\"btn sm\" id=\"openUpstream\">+ 新建</button>\n"
"      </div>\n"
"      <table class=\"table\" id=\"upstreamTable\">\n"
"        <colgroup><col style=\"width:100px\"><col style=\"width:64px\"><col style=\"width:120px\"><col style=\"width:56px\"><col style=\"width:60px\"></colgroup>\n"
"        <thead><tr><th>名称</th><th>类型</th><th>地址</th><th>状态</th><th></th></tr></thead>\n"
"        <tbody></tbody>\n"
"      </table>\n"
"    </ryba-card>\n"
"\n"
"    <ryba-card>\n"
"      <div class=\"card-head\">\n"
"        <div>\n"
"          <div class=\"card-eyebrow\">路由</div>\n"
"          <div class=\"card-title\">规则列表</div>\n"
"        </div>\n"
"        <button class=\"btn ghost\" id=\"openRule\">+ 添加规则</button>\n"
"      </div>\n"
"      <table class=\"table\" id=\"ruleTable\">\n"
"        <colgroup><col style=\"width:64px\"><col style=\"width:150px\"><col style=\"width:130px\"><col style=\"width:60px\"><col style=\"width:70px\"><col style=\"width:60px\"><col style=\"width:110px\"></colgroup>\n"
"        <thead><tr><th>优先级</th><th>域名</th><th>IP/CIDR</th><th>端口</th><th>协议</th><th>上游</th><th></th></tr></thead>\n"
"        <tbody></tbody>\n"
"      </table>\n"
"      <div class=\"empty\" id=\"ruleEmpty\" style=\"display:none;\">\n"
"        <svg width=\"48\" height=\"48\" viewBox=\"0 0 48 48\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\"><path d=\"M8 14h32M8 24h24M8 34h28\"/></svg>\n"
"        <div>还没有路由规则</div>\n"
"        <div style=\"font-size:.8rem; margin-top:4px;\">点击「添加规则」开始分流</div>\n"
"      </div>\n"
"    </ryba-card>\n"
"  </div>\n"
"\n"
"  <div class=\"grid\">\n"
"    <ryba-card class=\"span-3\">\n"
"      <div class=\"card-head\">\n"
"        <div>\n"
"          <div class=\"card-eyebrow\">会话</div>\n"
"          <div class=\"card-title\">最近连接</div>\n"
"        </div>\n"
"      </div>\n"
"      <table class=\"table\" id=\"sessionTable\">\n"
"        <colgroup><col style=\"width:70px\"><col style=\"width:130px\"><col style=\"width:200px\"><col style=\"width:70px\"><col style=\"width:80px\"><col style=\"width:80px\"></colgroup>\n"
"        <thead><tr><th>协议</th><th>客户端</th><th>目标</th><th>状态</th><th>上行</th><th>下行</th></tr></thead>\n"
"        <tbody></tbody>\n"
"      </table>\n"
"    </ryba-card>\n"
"\n"
"    <ryba-card class=\"span-3\">\n"
"      <div class=\"card-head\">\n"
"        <div>\n"
"          <div class=\"card-eyebrow\">流量</div>\n"
"          <div class=\"card-title\">最近 30 天</div>\n"
"        </div>\n"
"        <div style=\"font-size:.8rem;color:var(--ink-soft);\">方块颜色 = 当日流量</div>\n"
"      </div>\n"
"      <div id=\"heatmap\"></div>\n"
"      <div style=\"display:flex; align-items:center; gap:6px; margin-top:12px; font-size:.72rem; color:var(--ink-soft);\">\n"
"        <span>少</span>\n"
"        <span style=\"width:12px;height:12px;background:#E8E2D4;border-radius:2px;\"></span>\n"
"        <span style=\"width:12px;height:12px;background:#C9D6C2;border-radius:2px;\"></span>\n"
"        <span style=\"width:12px;height:12px;background:#8FA888;border-radius:2px;\"></span>\n"
"        <span style=\"width:12px;height:12px;background:#5F7E5A;border-radius:2px;\"></span>\n"
"        <span>多</span>\n"
"      </div>\n"
"    </ryba-card>\n"
"  </div>\n"
"</div>\n"
"\n"
"<!-- modals -->\n"
"<ryba-modal id=\"mUpstream\">\n"
"  <div class=\"modal-card\">\n"
"    <div class=\"modal-title\">新建出口节点</div>\n"
"    <div style=\"display:grid; gap:12px;\">\n"
"      <div><label style=\"font-size:.8rem;color:var(--ink-soft);\">名称</label><input name=\"name\" placeholder=\"如 office-vpn\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;\"></div>\n"
"      <div><label style=\"font-size:.8rem;color:var(--ink-soft);\">类型</label><select name=\"type\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;background:#fff;\"><option value=\"direct\">direct（直连）</option><option value=\"http\">http</option><option value=\"socks5\">socks5</option></select></div>\n"
"      <div style=\"display:grid; grid-template-columns:2fr 1fr; gap:10px;\">\n"
"        <div><label style=\"font-size:.8rem;color:var(--ink-soft);\">主机</label><input name=\"host\" placeholder=\"10.0.0.5\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;\"></div>\n"
"        <div><label style=\"font-size:.8rem;color:var(--ink-soft);\">端口</label><input name=\"port\" type=\"number\" placeholder=\"8080\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;\"></div>\n"
"      </div>\n"
"    </div>\n"
"    <div class=\"modal-actions\">\n"
"      <button class=\"btn ghost\" data-close>取消</button>\n"
"      <button class=\"btn\" id=\"saveUpstream\">保存</button>\n"
"    </div>\n"
"  </div>\n"
"</ryba-modal>\n"
"\n"
"<ryba-modal id=\"mRule\">\n"
"  <div class=\"modal-card\">\n"
"    <div class=\"modal-title\" id=\"ruleModalTitle\">添加路由规则</div>\n"
"    <div style=\"display:grid; gap:12px;\">\n"
"      <div>\n"
"        <label style=\"font-size:.8rem;color:var(--ink-soft);\">域名模式</label>\n"
"        <input name=\"domain_pattern\" placeholder=\"如 *.example.com（留空则不匹配域名）\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;\">\n"
"      </div>\n"
"      <div>\n"
"        <label style=\"font-size:.8rem;color:var(--ink-soft);\">IP / CIDR</label>\n"
"        <input name=\"ip_cidr\" placeholder=\"如 192.168.0.0/16（留空则不匹配 IP）\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;\">\n"
"      </div>\n"
"      <div style=\"display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px;\">\n"
"        <div><label style=\"font-size:.8rem;color:var(--ink-soft);\">端口</label><input name=\"port\" type=\"number\" placeholder=\"0 = 任意\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;\"></div>\n"
"        <div><label style=\"font-size:.8rem;color:var(--ink-soft);\">优先级</label><input name=\"priority\" type=\"number\" value=\"100\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;\"></div>\n"
"        <div><label style=\"font-size:.8rem;color:var(--ink-soft);\">上游 ID</label><input name=\"upstream_id\" type=\"number\" value=\"0\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;\"></div>\n"
"      </div>\n"
"      <div>\n"
"        <label style=\"font-size:.8rem;color:var(--ink-soft);\">协议</label>\n"
"        <select name=\"protocol\" style=\"width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;font:inherit;background:#fff;\">\n"
"          <option value=\"any\">any（全部）</option><option value=\"http\">http</option><option value=\"socks5\">socks5</option>\n"
"        </select>\n"
"      </div>\n"
"      <p style=\"font-size:.75rem;color:var(--ink-soft);margin:0;\">域名与 IP 至少填一项；优先级越小越先匹配。</p>\n"
"    </div>\n"
"    <div class=\"modal-actions\">\n"
"      <button class=\"btn ghost\" data-close>取消</button>\n"
"      <button class=\"btn\" id=\"saveRule\">保存</button>\n"
"    </div>\n"
"  </div>\n"
"</ryba-modal>\n"
"\n"
"<ryba-modal id=\"mConfirm\">\n"
"  <div class=\"modal-card\">\n"
"    <div class=\"modal-title\" id=\"confirmTitle\">确认删除？</div>\n"
"    <p style=\"color:var(--ink-soft); margin:0 0 8px;\">此操作不可撤销。</p>\n"
"    <div class=\"modal-actions\">\n"
"      <button class=\"btn ghost\" data-close>取消</button>\n"
"      <button class=\"btn\" id=\"confirmOk\" style=\"background:var(--danger);\">删除</button>\n"
"    </div>\n"
"  </div>\n"
"</ryba-modal>\n"
"<div id=\"hmTip\"></div>\n"
"<div class=\"toast\" id=\"toast\"></div>\n"
"\n"
"<script>\n"
"/* ---------- Web Components ---------- */\n"
"class RybaCard extends HTMLElement { constructor(){ super(); } }\n"
"customElements.define('ryba-card', RybaCard);\n"
"\n"
"class RybaStat extends HTMLElement {\n"
"  static get observedAttributes(){ return ['value','label','trend']; }\n"
"  constructor(){ super(); this._rendered=false; }\n"
"  connectedCallback(){ if(!this._rendered){ this._rendered=true; this.render(); } }\n"
"  attributeChangedCallback(){ if(this._rendered) this.render(); }\n"
"  render(){\n"
"    const value = this.getAttribute('value') ?? '';\n"
"    const label = this.getAttribute('label') ?? '';\n"
"    const trend = this.getAttribute('trend') ?? '';\n"
"    this.innerHTML = `\n"
"      <div class=\"stat-value num\">${value}</div>\n"
"      <div class=\"stat-label\">${label}</div>\n"
"      ${trend ? `<div class=\"stat-trend\">↗ ${trend}</div>` : ''}\n"
"      <svg class=\"spark\" viewBox=\"0 0 120 36\" preserveAspectRatio=\"none\">\n"
"        <polyline fill=\"none\" stroke=\"#8FA888\" stroke-width=\"1.6\" points=\"${this._spark()}\"/>\n"
"      </svg>`;\n"
"  }\n"
"  _spark(){ const pts=[]; let v=18; for(let i=0;i<12;i++){ v += (Math.random()-0.5)*6; v=Math.max(6,Math.min(30,v)); pts.push(`${i*11},${36-v}`); } return pts.join(' '); }\n"
"}\n"
"customElements.define('ryba-stat', RybaStat);\n"
"\n"
"class RybaModal extends HTMLElement {\n"
"  constructor(){ super(); }\n"
"  connectedCallback(){\n"
"    this.addEventListener('click', e => { if(e.target === this || e.target.hasAttribute('data-close')) this.close(); });\n"
"  }\n"
"  open(){ this.classList.add('open'); }\n"
"  close(){ this.classList.remove('open'); }\n"
"}\n"
"customElements.define('ryba-modal', RybaModal);\n"
"\n"
"/* ---------- Data ---------- */\n"
"let upstreams = [\n"
"  { name: 'home-direct', type: 'direct', host: '-', port: '-', enabled: true },\n"
"  { name: 'office-vpn', type: 'http', host: '10.0.0.5', port: 8080, enabled: true },\n"
"  { name: 'backup-socks', type: 'socks5', host: '192.168.1.9', port: 1080, enabled: false },\n"
"];\n"
"let rules = [\n"
"  { priority: 10, domain: '*.google.com', ip: '', port: 0, proto: 'any', upstream: 1 },\n"
"  { priority: 50, domain: '', ip: '192.168.0.0/16', port: 0, proto: 'http', upstream: 0 },\n"
"  { priority: 100, domain: '*.internal.lan', ip: '', port: 0, proto: 'any', upstream: 2 },\n"
"];\n"
"const sessions = [\n"
"  { proto: 'http', client: '192.168.1.23', target: 'api.example.com:443', status: 'active', up: '12 KB', down: '1.4 MB' },\n"
"  { proto: 'socks5', client: '192.168.1.41', target: 'cdn.fastly.net:443', status: 'active', up: '3 KB', down: '8.2 MB' },\n"
"  { proto: 'http', client: '192.168.1.7', target: 'updates.apple.com:443', status: 'closed', up: '0', down: '240 KB' },\n"
"  { proto: 'socks5', client: '192.168.1.23', target: 'github.com:443', status: 'active', up: '8 KB', down: '3.1 MB' },\n"
"];\n"
"\n"
"/* ---------- Render ---------- */\n"
"function renderUpstreams() {\n"
"  const tb = document.querySelector('#upstreamTable tbody');\n"
"  tb.innerHTML = '';\n"
"  upstreams.forEach((u,i) => {\n"
"    const tr = document.createElement('tr');\n"
"    tr.innerHTML = `\n"
"      <td>${u.name}</td>\n"
"      <td><span class=\"pill proto\">${u.type}</span></td>\n"
"      <td class=\"num\">${u.host}${u.port!=='-'?':'+u.port:''}</td>\n"
"      <td><span class=\"pill ${u.enabled?'on':'off'}\">${u.enabled?'启用':'停用'}</span></td>\n"
"      <td class=\"row-actions\">\n"
"        <button class=\"danger\" data-del=\"${i}\">删除</button>\n"
"      </td>`;\n"
"    tr.querySelector('[data-del]').addEventListener('click', () => confirmDelete(() => { upstreams.splice(i,1); renderUpstreams(); toast('已删除节点'); }));\n"
"    tb.appendChild(tr);\n"
"  });\n"
"}\n"
"\n"
"function renderRules() {\n"
"  const tb = document.querySelector('#ruleTable tbody');\n"
"  const empty = document.getElementById('ruleEmpty');\n"
"  const table = document.querySelector('#ruleTable');\n"
"  tb.innerHTML = '';\n"
"  if (!rules.length) { empty.style.display='block'; table.style.display='none'; return; }\n"
"  empty.style.display='none'; table.style.display='';\n"
"  rules.forEach((r,i) => {\n"
"    const tr = document.createElement('tr');\n"
"    tr.innerHTML = `\n"
"      <td class=\"num\">${r.priority}</td>\n"
"      <td>${r.domain || '—'}</td>\n"
"      <td class=\"num\">${r.ip || '—'}</td>\n"
"      <td class=\"num\">${r.port || '*'}</td>\n"
"      <td><span class=\"pill proto\">${r.proto}</span></td>\n"
"      <td class=\"num\">${r.upstream}</td>\n"
"      <td class=\"row-actions\">\n"
"        <button data-edit=\"${i}\">编辑</button>\n"
"        <button class=\"danger\" data-del=\"${i}\">删除</button>\n"
"      </td>`;\n"
"    tr.querySelector('[data-edit]').addEventListener('click', () => openRuleEditor(i));\n"
"    tr.querySelector('[data-del]').addEventListener('click', () => confirmDelete(() => { rules.splice(i,1); renderRules(); toast('已删除规则'); }));\n"
"    tb.appendChild(tr);\n"
"  });\n"
"}\n"
"\n"
"function renderSessions() {\n"
"  const tb = document.querySelector('#sessionTable tbody');\n"
"  tb.innerHTML = '';\n"
"  sessions.forEach(s => {\n"
"    const tr = document.createElement('tr');\n"
"    tr.innerHTML = `\n"
"      <td><span class=\"pill proto\">${s.proto}</span></td>\n"
"      <td class=\"num\">${s.client}</td>\n"
"      <td>${s.target}</td>\n"
"      <td><span class=\"pill ${s.status==='active'?'on':'off'}\">${s.status==='active'?'活跃':'已关闭'}</span></td>\n"
"      <td class=\"num\">${s.up}</td>\n"
"      <td class=\"num\">${s.down}</td>`;\n"
"    tb.appendChild(tr);\n"
"  });\n"
"}\n"
"\n"
"function renderHeatmap() {\n"
"  const box = document.getElementById('heatmap');\n"
"  const tip = document.getElementById('hmTip');\n"
"  box.innerHTML = '';\n"
"  const levels = ['#E8E2D4','#C9D6C2','#8FA888','#5F7E5A'];\n"
"  const labels = ['0–50 MB','50–200 MB','200–800 MB','800 MB+'];\n"
"  for (let i = 0; i < 30; i++) {\n"
"    const cell = document.createElement('div');\n"
"    cell.className = 'cell';\n"
"    const v = Math.random();\n"
"    const lvl = v < 0.35 ? 0 : v < 0.6 ? 1 : v < 0.85 ? 2 : 3;\n"
"    const mb = (lvl===0? Math.round(Math.random()*50) : lvl===1? 50+Math.round(Math.random()*150) : lvl===2? 200+Math.round(Math.random()*600) : 800+Math.round(Math.random()*1200));\n"
"    cell.style.background = levels[lvl];\n"
"    cell.addEventListener('mouseenter', e => {\n"
"      tip.textContent = `第 ${i+1} 天 · ${mb} MB`;\n"
"      tip.style.opacity = '1';\n"
"      const r = cell.getBoundingClientRect();\n"
"      tip.style.left = (r.left + r.width/2 - tip.offsetWidth/2) + 'px';\n"
"      tip.style.top = (r.top - 30) + 'px';\n"
"    });\n"
"    cell.addEventListener('mouseleave', () => { tip.style.opacity = '0'; });\n"
"    box.appendChild(cell);\n"
"  }\n"
"}\n"
"\n"
"/* ---------- Modals ---------- */\n"
"const mUp = document.getElementById('mUpstream');\n"
"const mRule = document.getElementById('mRule');\n"
"document.getElementById('openUpstream').addEventListener('click', () => mUp.open());\n"
"document.getElementById('openRule').addEventListener('click', () => openRuleEditor(-1));\n"
"\n"
"function openRuleEditor(i) {\n"
"  editingRule = i;\n"
"  const m = mRule;\n"
"  const set = (n,v) => { const el = m.querySelector(`[name=\"${n}\"]`); if(el) el.value = v; };\n"
"  document.getElementById('ruleModalTitle').textContent = i < 0 ? '添加路由规则' : '编辑路由规则';\n"
"  if (i < 0) {\n"
"    set('domain_pattern',''); set('ip_cidr',''); set('port',''); set('priority',100); set('upstream_id',0); set('protocol','any');\n"
"  } else {\n"
"    const r = rules[i];\n"
"    set('domain_pattern', r.domain); set('ip_cidr', r.ip); set('port', r.port); set('priority', r.priority); set('upstream_id', r.upstream); set('protocol', r.proto);\n"
"  }\n"
"  m.open();\n"
"}\n"
"\n"
"document.getElementById('saveUpstream').addEventListener('click', () => {\n"
"  const m = mUp; const get = n => m.querySelector(`[name=\"${n}\"]`).value;\n"
"  upstreams.push({ name: get('name')||'new-node', type: get('type'), host: get('host')||'-', port: parseInt(get('port')||0)||'-', enabled: true });\n"
"  renderUpstreams(); m.close(); toast('已创建节点');\n"
"});\n"
"\n"
"let editingRule = -1;\n"
"function openRuleEditor(i) {\n"
"  editingRule = i;\n"
"  const m = mRule;\n"
"  const set = (n,v) => { const el = m.querySelector(`[name=\"${n}\"]`); if(el) el.value = v; };\n"
"  document.getElementById('ruleModalTitle').textContent = i < 0 ? '添加路由规则' : '编辑路由规则';\n"
"  if (i < 0) {\n"
"    set('domain_pattern',''); set('ip_cidr',''); set('port',''); set('priority',100); set('upstream_id',0); set('protocol','any');\n"
"  } else {\n"
"    const r = rules[i];\n"
"    set('domain_pattern', r.domain); set('ip_cidr', r.ip); set('port', r.port); set('priority', r.priority); set('upstream_id', r.upstream); set('protocol', r.proto);\n"
"  }\n"
"  m.open();\n"
"}\n"
"document.getElementById('saveRule').addEventListener('click', () => {\n"
"  const m = mRule; const get = n => m.querySelector(`[name=\"${n}\"]`).value;\n"
"  const nr = { priority: parseInt(get('priority')||100), domain: get('domain_pattern'), ip: get('ip_cidr'), port: parseInt(get('port')||0), proto: get('protocol'), upstream: parseInt(get('upstream_id')||0) };\n"
"  if (editingRule < 0) {\n"
"    rules.push(nr); toast('已添加规则');\n"
"  } else {\n"
"    rules[editingRule] = nr; toast('已更新规则');\n"
"  }\n"
"  renderRules(); m.close(); editingRule = -1;\n"
"});\n"
"\n"
"let _confirmCb = null;\n"
"const mConfirm = document.getElementById('mConfirm');\n"
"function confirmDelete(cb){ _confirmCb = cb; mConfirm.open(); }\n"
"document.getElementById('confirmOk').addEventListener('click', () => { if(_confirmCb){ _confirmCb(); _confirmCb=null; } mConfirm.close(); });\n"
"\n"
"function toast(msg) { const t = document.getElementById('toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove('show'), 2200); }\n"
"function tick(){ const d=new Date(); document.getElementById('clock').textContent = d.toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'}); }\n"
"setInterval(tick,1000); tick();\n"
"\n"
"document.querySelectorAll(\"ryba-card\").forEach((c,i)=>c.setAttribute(\"data-p\", i%4));\n"
"renderUpstreams(); renderRules(); renderSessions(); renderHeatmap();\n"
"</script>\n"
"</body>\n"
"</html>\n"

;

static void send_json(struct mg_connection *conn, int status, const char *body) {
    mg_printf(conn, "HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
              status, (int)strlen(body));
    mg_write(conn, body, strlen(body));
}

static void handle_stats(struct mg_connection *conn, server_ctx_t *srv) {
    (void)srv;
    stats_snapshot_t snap = stats_get();
    char buf[512];
    snprintf(buf, sizeof buf,
        "{\"total_sessions\":%llu,\"bytes_up\":%llu,\"bytes_down\":%llu,\"errors\":%llu,\"bad_requests\":%llu,\"dropped\":%llu}",
        (unsigned long long)snap.total_sessions,
        (unsigned long long)snap.total_bytes_up,
        (unsigned long long)snap.total_bytes_down,
        (unsigned long long)snap.total_errors,
        (unsigned long long)snap.bad_requests,
        (unsigned long long)snap.dropped_events);
    send_json(conn, 200, buf);
}

static void handle_upstreams(struct mg_connection *conn, server_ctx_t *srv) {
    pthread_mutex_lock(&srv->lock);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < srv->upstream_count; i++) {
        upstream_profile_t *u = &srv->upstreams[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", u->id);
        cJSON_AddStringToObject(o, "name", u->name);
        cJSON_AddNumberToObject(o, "type", (double)u->type);
        cJSON_AddStringToObject(o, "host", u->host);
        cJSON_AddNumberToObject(o, "port", u->port);
        cJSON_AddBoolToObject(o, "enabled", u->enabled);
        cJSON_AddItemToArray(arr, o);
    }
    pthread_mutex_unlock(&srv->lock);
    char *s = cJSON_PrintUnformatted(arr);
    send_json(conn, 200, s ? s : "[]");
    if (s) free(s);
    cJSON_Delete(arr);
}

static void handle_rules_list(struct mg_connection *conn, server_ctx_t *srv) {
    pthread_mutex_lock(&srv->lock);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < srv->router.count; i++) {
        rule_t *r = &srv->router.rules[i];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", r->id);
        cJSON_AddNumberToObject(o, "priority", r->priority);
        cJSON_AddBoolToObject(o, "enabled", r->enabled);
        cJSON_AddStringToObject(o, "domain_pattern", r->domain_pattern);
        cJSON_AddStringToObject(o, "ip_cidr", r->ip_cidr);
        cJSON_AddNumberToObject(o, "port", r->port);
        const char *ps = "any";
        if (r->protocol == PROTO_HTTP) ps = "http";
        else if (r->protocol == PROTO_SOCKS5) ps = "socks5";
        cJSON_AddStringToObject(o, "protocol", ps);
        cJSON_AddNumberToObject(o, "upstream_id", r->upstream_id);
        cJSON_AddItemToArray(arr, o);
    }
    pthread_mutex_unlock(&srv->lock);
    char *s = cJSON_PrintUnformatted(arr);
    send_json(conn, 200, s ? s : "[]");
    if (s) free(s);
    cJSON_Delete(arr);
}

static void handle_rules_add(struct mg_connection *conn, server_ctx_t *srv) {
    char buf[4096];
    int n = mg_read(conn, buf, sizeof buf - 1);
    if (n < 0) n = 0;
    buf[n] = '\0';
    cJSON *j = cJSON_Parse(buf);
    if (!j) { send_json(conn, 400, "{\"error\":\"bad json\"}"); return; }
    rule_t r; memset(&r, 0, sizeof r);
    r.enabled = 1;
    r.priority = 100;
    r.port = 0;
    r.protocol = 0;
    cJSON *v;
    if ((v = cJSON_GetObjectItem(j, "domain_pattern")) && cJSON_IsString(v)) snprintf(r.domain_pattern, sizeof r.domain_pattern, "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(j, "ip_cidr")) && cJSON_IsString(v)) snprintf(r.ip_cidr, sizeof r.ip_cidr, "%s", v->valuestring);
    if ((v = cJSON_GetObjectItem(j, "port"))) r.port = v->valueint;
    if ((v = cJSON_GetObjectItem(j, "priority"))) r.priority = v->valueint;
    if ((v = cJSON_GetObjectItem(j, "upstream_id"))) r.upstream_id = v->valueint;
    if ((v = cJSON_GetObjectItem(j, "protocol")) && cJSON_IsString(v)) {
        if (strcmp(v->valuestring, "http") == 0) r.protocol = PROTO_HTTP;
        else if (strcmp(v->valuestring, "socks5") == 0 || strcmp(v->valuestring, "socks") == 0) r.protocol = PROTO_SOCKS5;
        else r.protocol = 0;
    }
    if ((v = cJSON_GetObjectItem(j, "name")) && cJSON_IsString(v)) snprintf(r.name, sizeof r.name, "%s", v->valuestring);
    cJSON_Delete(j);

    pthread_mutex_lock(&srv->lock);
    r.id = srv->router.next_rule_id++;
    router_add_rule(&srv->router, &r);
    pthread_mutex_unlock(&srv->lock);

    char out[128];
    snprintf(out, sizeof out, "{\"id\":%d}", r.id);
    send_json(conn, 201, out);
}

static void handle_rules_delete(struct mg_connection *conn, server_ctx_t *srv) {
    const struct mg_request_info *ri = mg_get_request_info(conn);
    const char *qs = ri->query_string ? ri->query_string : "";
    char val[32]; val[0] = '\0';
    mg_get_var(qs, strlen(qs), "id", val, sizeof val);
    int id = atoi(val);
    pthread_mutex_lock(&srv->lock);
    int rc = router_remove_rule(&srv->router, id);
    pthread_mutex_unlock(&srv->lock);
    if (rc != 0) send_json(conn, 404, "{\"error\":\"not found\"}");
    else send_json(conn, 200, "{\"ok\":true}");
}

static void handle_sessions(struct mg_connection *conn, server_ctx_t *srv) {
    (void)srv;
    char buf[65536];
    /* default limit 100 */
    const struct mg_request_info *ri = mg_get_request_info(conn);
    int limit = 100;
    if (ri->query_string) {
        char v[32]; v[0]='\0';
        mg_get_var(ri->query_string, strlen(ri->query_string), "limit", v, sizeof v);
        if (v[0]) limit = atoi(v);
    }
    if (db_get_recent_sessions(limit, buf, sizeof buf) != 0) {
        send_json(conn, 500, "{\"error\":\"db\"}");
        return;
    }
    send_json(conn, 200, buf);
}

static int begin_request(struct mg_connection *conn) {
    const struct mg_request_info *ri = mg_get_request_info(conn);
    server_ctx_t *srv = (server_ctx_t *)mg_get_user_context_data(conn);
    const char *uri = ri->request_uri ? ri->request_uri : "/";
    const char *method = ri->request_method ? ri->request_method : "GET";

    if (strcmp(uri, "/api/stats") == 0) {
        handle_stats(conn, srv);
    } else if (strcmp(uri, "/api/upstreams") == 0) {
        handle_upstreams(conn, srv);
    } else if (strcmp(uri, "/api/rules") == 0) {
        if (strcmp(method, "POST") == 0) handle_rules_add(conn, srv);
        else if (strcmp(method, "DELETE") == 0) handle_rules_delete(conn, srv);
        else handle_rules_list(conn, srv);
    } else if (strncmp(uri, "/api/sessions", 13) == 0) {
        handle_sessions(conn, srv);
    } else {
        mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
                  (int)strlen(INDEX_HTML));
        mg_write(conn, INDEX_HTML, strlen(INDEX_HTML));
    }
    return 1;
}

struct mg_context *web_start(server_ctx_t *srv, int port) {
    char portstr[32];
    snprintf(portstr, sizeof portstr, "%d", port);
    const char *options[] = { "listening_ports", portstr, "num_threads", "4", NULL };
    struct mg_callbacks cbs;
    memset(&cbs, 0, sizeof cbs);
    cbs.begin_request = begin_request;
    return mg_start(&cbs, srv, options);
}

void web_stop(struct mg_context *ctx) {
    if (ctx) mg_stop(ctx);
}
