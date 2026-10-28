// @ts-nocheck
import { api, unwrapPage, type Page } from './api.js';
import { esc, fmtBytes, sparkline, cnText, upName, geoLabel } from './format.js';
import './ryba-card.js';
import './ryba-stat.js';
import './ryba-modal.js';

/* ---------- API ---------- */


interface Upstream { id: number; name: string; type: string; host: string; port: number; enabled: boolean; username?: string }
interface Rule { id: number; priority: number; domain_pattern: string; ip_cidr: string; geo_ip: string; geo_site: string; port: number; protocol: string; upstream_id: number }
interface DayStat { day: string; bytes_up: number; bytes_down: number; sessions: number }
interface Metrics { total_sessions?: number; errors?: number; dropped?: number }
interface Session { protocol: string; client_ip: string; target_host: string; target_port: number; status: number | string; bytes_up: number; bytes_down: number }

let upstreams: Upstream[] = [], rules: Rule[] = [], daily: DayStat[] = [];
let sessPage: Page<Session> = { rows: [], total: 0, limit: 20, offset: 0 };
let sessFilter = { client: '', target: '' };

async function loadAll(){
  try { await reloadGeoStatus(); } catch(e){}
  const [mu, mr, ms, mm, md] = await Promise.all([
    api<Upstream[]>('/api/upstreams'), api<Rule[]>('/api/rules'),
    api<Session[]>(`/api/sessions?limit=20&offset=0`),
    api<Metrics>('/api/metrics'), api<DayStat[]>('/api/stats/daily?days=30'),
  ]);
  upstreams = mu.data || []; rules = mr.data || [];
  renderUpstreams(); renderRules();
  sessPage = unwrapPage(ms); sessFilter.client=''; sessFilter.target='';
  const m = mm.data || {};
  daily = (md.data || []).slice().sort((a,b) => a.day < b.day ? -1 : 1);
  const today = daily[daily.length-1] || { bytes_up: 0, bytes_down: 0 };
  const hero = document.querySelectorAll('#heroCard ryba-stat');
  const bw = daily.map(d => (+d.bytes_up) + (+d.bytes_down));
  if (hero[0]) { hero[0].setAttribute('value', String(m.total_sessions ?? 0)); hero[0].setAttribute('trend', '累计会话'); }
  if (hero[1]) { hero[1].setAttribute('value', fmtBytes(today.bytes_up)); hero[1].setAttribute('spark', sparkline(daily.map(d => +d.bytes_up))); }
  if (hero[2]) { hero[2].setAttribute('value', fmtBytes(today.bytes_down)); hero[2].setAttribute('spark', sparkline(bw)); }
  if (hero[3]) { hero[3].setAttribute('value', String((+m.errors||0) + (+m.dropped||0))); hero[3].setAttribute('trend', (+m.dropped||0) + ' 丢弃'); }
  renderUpstreams(); renderRules(); renderSessions(); renderHeatmap();
}

async function refreshLive(){
  try {
    const [mm, ms, md] = await Promise.all([
      api<Metrics>('/api/metrics'),
      api<Session[]>(`/api/sessions?limit=${sessPage.limit}&offset=${sessPage.offset}&client=${encodeURIComponent(sessFilter.client)}&target=${encodeURIComponent(sessFilter.target)}`),
      api<DayStat[]>('/api/stats/daily?days=30'),
    ]);
    const m = mm.data || {};
    daily = (md.data || []).slice().sort((a,b) => a.day < b.day ? -1 : 1);
    sessPage = unwrapPage(ms);
    const hero = document.querySelectorAll('#heroCard ryba-stat');
    const today = daily[daily.length-1] || { bytes_up: 0, bytes_down: 0 };
    if (hero[0]) hero[0].setAttribute('value', String(m.total_sessions ?? 0));
    if (hero[1]) hero[1].setAttribute('value', fmtBytes(today.bytes_up));
    if (hero[2]) hero[2].setAttribute('value', fmtBytes(today.bytes_down));
    if (hero[3]) hero[3].setAttribute('value', String((+m.errors||0) + (+m.dropped||0)));
    renderSessions(); renderHeatmap();
  } catch(e){ /* keep old data on poll failure */ }
}

/* ---------- Render ---------- */
function renderUpstreams() {
  const tb = document.querySelector('#upstreamTable tbody');
  tb.innerHTML = '';
  upstreams.forEach((u) => {
    const tr = document.createElement('tr');
    const addr = u.host ? `${esc(u.host)}${u.port ? ':'+u.port : ''}` : '—';
    tr.innerHTML = `
      <td>${esc(u.name)}</td>
      <td><span class="pill proto">${esc(u.type)}</span></td>
      <td class="num">${addr}</td>
      <td><span class="pill ${u.enabled?'on':'off'}">${u.enabled?'启用':'停用'}</span></td>
      <td class="row-actions">
        <button data-test="${u.id}">测试</button>
        <button data-toggle="${u.id}">${u.enabled?'停用':'启用'}</button>
        <button data-edit="${u.id}">编辑</button>
        <button class="danger" data-del="${u.id}">删除</button>
      </td>`;
    tr.querySelector('[data-test]').addEventListener('click', async (e) => {
      const btn = e.target; btn.disabled = true; btn.textContent = '测试中…';
      try {
        const j = await api(`/api/upstreams/${u.id}/test`, { method: 'POST' });
        toast(j.data.reachable ? `可达 · ${j.data.latency_ms} ms` : '不可达');
      } catch(err){ toast('测试失败：' + err.message); }
      btn.disabled = false; btn.textContent = '测试';
    });
    tr.querySelector('[data-toggle]').addEventListener('click', async () => {
      try { await api(`/api/upstreams/${u.id}`, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ enabled: !u.enabled }) }); await reloadUpstreams(); toast(u.enabled ? '已停用' : '已启用'); }
      catch(err){ toast('更新失败：' + err.message); }
    });
    tr.querySelector('[data-edit]').addEventListener('click', () => openUpstreamEditor(u.id));
    tr.querySelector('[data-del]').addEventListener('click', () => confirmDelete(async () => {
      try { await api(`/api/upstreams/${u.id}`, { method: 'DELETE' }); await reloadUpstreams(); toast('已删除节点'); }
      catch(err){ toast('删除失败：' + err.message); }
    }));
    tb.appendChild(tr);
  });
}

function renderSessions() {
  const tb = document.querySelector('#sessionTable tbody');
  tb.innerHTML = '';
  if (!sessPage.rows.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="6"><div class="empty">暂无会话数据</div></td>`;
    tb.appendChild(tr);
  }
  sessPage.rows.forEach(s => {
    const tr = document.createElement('tr');
    const active = s.status === 0 || s.status === '0';
    tr.innerHTML = `
      <td><span class="pill proto">${esc(s.protocol)}</span></td>
      <td class="num">${esc(s.client_ip)}</td>
      <td>${esc(s.target_host)}:${s.target_port}</td>
      <td><span class="pill ${active?'on':'off'}">${active?'活跃':'已关闭'}</span></td>
      <td class="num">${fmtBytes(s.bytes_up)}</td>
      <td class="num">${fmtBytes(s.bytes_down)}</td>`;
    tb.appendChild(tr);
  });
  let pager = document.getElementById('sessPager');
  if (!pager) {
    pager = document.createElement('div');
    pager.id = 'sessPager';
    pager.style.cssText = 'display:flex;gap:8px;align-items:center;margin-top:10px;font-size:.8rem;color:var(--ink-soft);';
    document.querySelector('#sessionTable').after(pager);
  }
  const pages = Math.max(1, Math.ceil(sessPage.total / sessPage.limit));
  const cur = Math.floor(sessPage.offset / sessPage.limit) + 1;
  pager.innerHTML = `<button class="btn ghost sm" id="pgPrev" ${sessPage.offset<=0?'disabled':''}>上一页</button>
    <span class="num">${cur} / ${pages} · 共 ${sessPage.total} 条</span>
    <button class="btn ghost sm" id="pgNext" ${sessPage.offset+sessPage.limit>=sessPage.total?'disabled':''}>下一页</button>`;
  document.getElementById('pgPrev').addEventListener('click', () => { sessPage.offset = Math.max(0, sessPage.offset - sessPage.limit); refreshLive(); });
  document.getElementById('pgNext').addEventListener('click', () => { sessPage.offset += sessPage.limit; refreshLive(); });
}

async function reloadUpstreams(){ const j = await api('/api/upstreams'); upstreams = j.data || []; renderUpstreams(); }

function renderRules() {
  const tb = document.querySelector('#ruleTable tbody');
  const empty = document.getElementById('ruleEmpty');
  const table = document.querySelector('#ruleTable');
  tb.innerHTML = '';
  if (!rules.length) { empty.style.display='block'; table.style.display='none'; return; }
  empty.style.display='none'; table.style.display='';
  rules.forEach((r) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="num">${r.priority}</td>
      <td>${esc(r.domain_pattern) || '—'}</td>
      <td class="num">${esc(r.ip_cidr) || '—'}</td>
      <td class="num">${r.port || '*'}</td>
      <td><span class="pill proto">${esc(r.protocol)}</span></td>
      <td>${esc(upName(upstreams, r.upstream_id))}</td>
      <td class="num">${geoLabel(r)}</td>
      <td class="row-actions">
        <button data-edit="${r.id}">编辑</button>
        <button class="danger" data-del="${r.id}">删除</button>
      </td>`;
    tr.querySelector('[data-edit]').addEventListener('click', () => openRuleEditor(r.id));
    tr.querySelector('[data-del]').addEventListener('click', () => confirmDelete(async () => {
      try { await api(`/api/rules/${r.id}`, { method: 'DELETE' }); await reloadRules(); toast('已删除规则'); }
      catch(err){ toast('删除失败：' + err.message); }
    }));
    tb.appendChild(tr);
  });
}
async function reloadRules(){ const j = await api('/api/rules'); rules = j.data || []; renderRules(); }
async function reloadGeoStatus(){
  try { const j = await api('/api/geo/status'); const d = j.data || {};
    const g = d.geoip || {}, s = d.geosite || {};
    const fmt = (x, n) => (x.exists ? `${n}: ${(x.size/1048576).toFixed(1)}MB / ${x.cn_count} 条` : `${n}: 未下载`);
    document.getElementById('geoStatus').textContent = `${fmt(g, 'geoip')}　${fmt(s, 'geosite')}`;
    document.getElementById('geoSrc').textContent = `目录: ${d.dir || '?'}${d.proxy ? ' 代理: ' + d.proxy : '（直连下载）'}\
源: ${(g.url||'').replace('https://','')}`;
  } catch(err){ document.getElementById('geoStatus').textContent = 'IP 库状态获取失败'; }
}
document.getElementById('geoDownload').addEventListener('click', async () => {
  const b = document.getElementById('geoDownload'); b.disabled = true; b.textContent = '下载中…';
  try { await api('/api/geo/download', { method: 'POST' }); toast('IP 库已更新'); await reloadGeoStatus(); }
  catch(err){ toast('下载失败：' + err.message); }
  b.disabled = false; b.textContent = '下载/更新';
});
document.getElementById('geoCheck').addEventListener('click', async () => {
  const h = document.getElementById('geoHost').value.trim(); if (!h) { toast('请输入域名或 IP'); return; }
  try { const j = await api('/api/geo/check?host=' + encodeURIComponent(h)); const d = j.data;
    document.getElementById('geoResult').textContent =
      `解析 IP: ${(d.ips||[]).join(', ')||'—'}
IP 归属: ${cnText(d.geoip_cn)}　域名归属: ${cnText(d.geosite_cn)}${d.db_loaded === false ? '\
⚠ IP 库未加载：请先点 下载/更新' : ''}
命中规则: ${d.matched_rule}　出口: ${d.upstream.name||('id('+d.upstream.id+')')}`;
  } catch(err){ toast('检测失败：' + err.message); }
});

function renderHeatmap() {
  const box = document.getElementById('heatmap');
  const tip = document.getElementById('hmTip');
  box.innerHTML = '';
  const levels = ['#E8E2D4','#C9D6C2','#8FA888','#5F7E5A'];
  const days = daily.slice(-30);
  if (!days.length) { box.innerHTML = '<div class="empty">暂无流量数据</div>'; return; }
  const max = Math.max(...days.map(d => (+d.bytes_up) + (+d.bytes_down)), 1);
  days.forEach((d) => {
    const cell = document.createElement('div');
    cell.className = 'cell';
    const frac = ((+d.bytes_up) + (+d.bytes_down)) / max;
    const lvl = frac < 0.25 ? 0 : frac < 0.5 ? 1 : frac < 0.8 ? 2 : 3;
    cell.style.background = levels[lvl];
    const mb = (((+d.bytes_up) + (+d.bytes_down)) / 1048576).toFixed(1);
    cell.addEventListener('mouseenter', () => {
      tip.textContent = `${d.day} · ${mb} MB · ${d.sessions} 会话`;
      tip.style.opacity = '1';
      const r = cell.getBoundingClientRect();
      tip.style.left = (r.left + r.width/2 - tip.offsetWidth/2) + 'px';
      tip.style.top = (r.top - 30) + 'px';
    });
    cell.addEventListener('mouseleave', () => { tip.style.opacity = '0'; });
    box.appendChild(cell);
  });
}

/* ---------- Modals ---------- */
const mUp = document.getElementById('mUpstream');
const mRule = document.getElementById('mRule');
document.getElementById('openUpstream').addEventListener('click', () => openUpstreamEditor(-1));
document.getElementById('openRule').addEventListener('click', () => openRuleEditor(-1));

let editingUpstream = -1;
function openUpstreamEditor(id) {
  editingUpstream = id;
  const m = mUp;
  const set = (n,v) => { const el = m.querySelector(`[name="${n}"]`); if(el) el.value = v; };
  document.querySelector('#mUpstream .modal-title').textContent = id < 0 ? '新建出口节点' : '编辑出口节点';
  if (id < 0) { set('name',''); set('type','direct'); set('host',''); set('port',''); set('username',''); set('password',''); }
  else { const u = upstreams.find(x => x.id === id); if(!u) return; set('name',u.name); set('type',u.type); set('host',u.host); set('port',u.port); set('username',u.username||''); set('password',''); }
  m.open();
}
document.getElementById('saveUpstream').addEventListener('click', async () => {
  const m = mUp; const get = n => m.querySelector(`[name="${n}"]`).value.trim();
  const payload = { name: get('name'), type: get('type'), host: get('host'), port: parseInt(get('port')||0), username: get('username') };
  const pw = get('password'); if (pw) payload.password = pw;
  if (!payload.name) { toast('名称必填'); return; }
  if (payload.type !== 'direct' && (!payload.host || !payload.port)) { toast('非直连节点需填写主机与端口'); return; }
  try {
    if (editingUpstream < 0) await api('/api/upstreams', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    else await api(`/api/upstreams/${editingUpstream}`, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    await reloadUpstreams(); m.close(); editingUpstream = -1; toast('已保存节点');
  } catch(err){ toast('保存失败：' + err.message); }
});

let editingRule = -1;
function openRuleEditor(id) {
  editingRule = id;
  const m = mRule;
  const set = (n,v) => { const el = m.querySelector(`[name="${n}"]`); if(el) el.value = v; };
  document.getElementById('ruleModalTitle').textContent = id < 0 ? '添加路由规则' : '编辑路由规则';
  const usel = m.querySelector('[name="upstream_id"]');
  usel.innerHTML = upstreams.map(u => `<option value="${u.id}">${esc(u.name)} (${u.id})</option>`).join('') || '<option value="0">direct</option>';
  usel.value = id < 0 ? (upstreams.length ? upstreams[0].id : 0) : ((rules.find(x => x.id === id) || {}).upstream_id || 0);
  if (id < 0) { set('domain_pattern',''); set('ip_cidr',''); set('port',''); set('priority',100); set('protocol','any'); set('geo_ip',''); set('geo_site',''); }
  else {
    const r = rules.find(x => x.id === id); if(!r) return;
    set('domain_pattern', r.domain_pattern); set('ip_cidr', r.ip_cidr); set('port', r.port); set('priority', r.priority); set('protocol', r.protocol); set('geo_ip', r.geo_ip||''); set('geo_site', r.geo_site||'');
  }
  m.open();
}
document.getElementById('saveRule').addEventListener('click', async () => {
  const m = mRule; const get = n => m.querySelector(`[name="${n}"]`).value.trim();
  const nr = { priority: parseInt(get('priority')||100), domain_pattern: get('domain_pattern'), ip_cidr: get('ip_cidr'), geo_ip: get('geo_ip'), geo_site: get('geo_site'), port: parseInt(get('port')||0), protocol: get('protocol'), upstream_id: parseInt(get('upstream_id')||0) };
  if (!nr.domain_pattern && !nr.ip_cidr && !nr.geo_ip && !nr.geo_site) { toast('域名 / IP / 地理条件至少填一项'); return; }
  if (!Number.isFinite(nr.priority)) { toast('优先级必须是数字'); return; }
  try {
    if (editingRule < 0) await api('/api/rules', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(nr) });
    else await api(`/api/rules/${editingRule}`, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(nr) });
    await reloadRules(); m.close(); editingRule = -1; toast('已保存规则');
  } catch(err){ toast('保存失败：' + err.message); }
});

let _confirmCb = null;
const mConfirm = document.getElementById('mConfirm');
function confirmDelete(cb){ _confirmCb = cb; mConfirm.open(); }
document.getElementById('confirmOk').addEventListener('click', async () => { if(_confirmCb){ const cb = _confirmCb; _confirmCb=null; await cb(); } mConfirm.close(); });

function toast(msg) { const t = document.getElementById('toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove('show'), 2200); }
function tick(){ const d=new Date(); document.getElementById('clock').textContent = d.toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'}); }
setInterval(tick,1000); tick();

document.querySelectorAll("ryba-card").forEach((c,i)=>c.setAttribute("data-p", i%4));
let _fltT = null;
function bindFilter(id, key){
  document.getElementById(id).addEventListener('input', (e) => {
    sessFilter[key] = e.target.value.trim();
    sessPage.offset = 0;
    clearTimeout(_fltT); _fltT = setTimeout(refreshLive, 400);
  });
}
bindFilter('fltClient','client'); bindFilter('fltTarget','target');
loadAll().catch(e => toast('加载失败：' + e.message));
setInterval(refreshLive, 5000);
