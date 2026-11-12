const invoke = window.__TAURI_INTERNALS__.invoke;
const $ = id => document.getElementById(id);
const countryNames = new Intl.DisplayNames(['ru'], {type:'region'});
function flag(code) { return code && /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map(c => 127397 + c.charCodeAt(0))) : ''; }
const canConnect = p => !!p && (p.imported || p.enabled && p.inbound_enabled && ['vless', 'hysteria'].includes(p.protocol) && p.has_local_config);
let profiles = [], selectedProfileKey = localStorage.getItem('vpn.selectedProfile') || null;
let mode = 'off', busy = false;
let groups = [];
let lastStats = null;
const fmtRate = b => b >= 1048576 ? `${(b / 1048576).toFixed(1)} МБ/с` : b >= 1024 ? `${Math.round(b / 1024)} КБ/с` : `${Math.round(b)} Б/с`;
const fmtTotal = b => b >= 1073741824 ? `${(b / 1073741824).toFixed(2)} ГБ` : b >= 1048576 ? `${(b / 1048576).toFixed(1)} МБ` : `${Math.round(b / 1024)} КБ`;
async function pollStats() {
  const el = $('traffic-stats');
  if (mode !== 'tun') { lastStats = null; el.hidden = true; return; }
  try {
    const now = await invoke('vpn_stats');
    const dt = lastStats ? (now.ts_ms - lastStats.ts_ms) / 1000 : 0;
    const row = (route, label) => {
      const rate = dir => dt > 0 ? Math.max(0, now[route][dir] - lastStats[route][dir]) / dt : 0;
      return `${label}: ↓ ${fmtRate(rate('down'))} ↑ ${fmtRate(rate('up'))} · всего ↓ ${fmtTotal(now[route].down)} ↑ ${fmtTotal(now[route].up)}`;
    };
    el.textContent = `${row('vpn', 'Через VPN')}\n${row('direct', 'Напрямую')}`;
    el.hidden = false; lastStats = now;
  } catch { el.hidden = true; lastStats = null; }
}
setInterval(pollStats, 1500);
function key(p) { return p.imported ? `imported:${p.imported_id}` : `${p.server_id}:${p.inbound_id}:${p.email}`; }
const importedRow = i => ({imported:true, imported_id:i.id, server_id:'imported', inbound_id:0, email:i.name, host:i.host, transport:i.transport, insecure:i.insecure, server_name:'Импорт', country:null, protocol:'vless', enabled:true, inbound_enabled:true, has_local_config:true});
async function syncMcpSelection() { const p=profiles.find(p=>key(p)===selectedProfileKey); await invoke('select_mcp_profile',{profile:p && !p.imported ? {server_id:p.server_id,inbound_id:p.inbound_id,email:p.email} : null}); }
function connectionState(value) {
  mode = value; const connected = mode !== 'off';
  $('connection-state').dataset.state = connected ? 'on' : 'off';
  $('connection-label').textContent = mode === 'tun' ? 'Подключено' : mode === 'proxy' ? 'Прокси активен' : 'Отключено';
  $('connection-heading').textContent = mode === 'tun' ? 'TUN подключён' : mode === 'proxy' ? 'Прокси подключён' : 'Готовы к работе';
  $('vpn-toggle').dataset.connected = String(connected); $('vpn-toggle').setAttribute('aria-pressed', String(connected));
  $('toggle-label').textContent = connected ? 'Отключить' : 'Подключить';
  $('vpn-toggle').disabled = busy || (!connected && !canConnect(profiles.find(p => key(p) === selectedProfileKey)));
  $('proxy-indicator').textContent = mode === 'tun' ? 'Глобальный TUN активен' : mode === 'proxy' ? 'Прокси активен' : 'Глобальный TUN выключен';
  document.querySelector('footer').dataset.connected = String(mode === 'tun'); renderProfiles();
}
let probes = {};
// Server liveness (TCP handshake to the server, made outside the tunnel): a coloured mark plus the time.
function probeBadge(p) {
  const badge = document.createElement('span'); badge.className = 'probe';
  const r = probes[key(p)];
  let state = 'none', text = '—', title = 'Ещё не проверялось';
  if (r) {
    const when = new Date(r.ts * 1000).toLocaleTimeString('ru-RU');
    if (r.udp) { text = 'UDP'; title = 'Hysteria 2 работает по UDP: проверка недоступна'; }
    else if (r.ms != null) { state = r.ms < 150 ? 'ok' : r.ms < 400 ? 'mid' : 'slow'; text = `${r.ms} мс`; title = `Сервер отвечает, проверено в ${when}`; }
    else { state = 'bad'; text = 'нет ответа'; title = `${r.error || 'нет ответа'} · проверено в ${when}`; }
  }
  badge.dataset.state = state; badge.textContent = text; badge.title = title;
  return badge;
}
async function pollProbes() {
  try {
    const next = await invoke('get_probe_results');
    if (JSON.stringify(next) !== JSON.stringify(probes)) { probes = next; renderProfiles(); }
  } catch { /* older backend: no probes */ }
}
setInterval(pollProbes, 5000);
// User-defined groups of connection configs: a config is in one group or in none ("Без группы").
// Which sections are collapsed is remembered per viewer; if storage is unavailable it lasts until the window reloads.
const collapsedKey = 'vpn.collapsedGroups';
function collapsedGroups() { try { return new Set(JSON.parse(localStorage.getItem(collapsedKey) || '[]')); } catch { return new Set(); } }
function setGroupCollapsed(id, collapsed) {
  const ids = collapsedGroups(); if (collapsed) ids.add(id); else ids.delete(id);
  try { localStorage.setItem(collapsedKey, JSON.stringify([...ids])); } catch { /* no storage: nothing to keep */ }
}
let armedGroup = null;
function showError(text) { $('connection-error').textContent = text; $('connection-error').hidden = false; }
function groupHead(section, items, collapsed) {
  const head = document.createElement('div'); head.className = 'group-head';
  const toggle = document.createElement('button'); toggle.type = 'button'; toggle.className = 'group-toggle'; toggle.setAttribute('aria-expanded', String(!collapsed));
  const chevron = document.createElement('span'); chevron.className = 'group-chevron'; chevron.setAttribute('aria-hidden', 'true'); chevron.textContent = '▾';
  const title = document.createElement('span'); title.className = 'group-title'; title.textContent = section.name;
  const count = document.createElement('span'); count.className = 'group-count'; count.textContent = String(items.length);
  toggle.append(chevron, title, count);
  if (collapsed && items.some(p => mode === 'tun' && key(p) === connectedKey)) {
    const live = document.createElement('span'); live.className = 'group-live'; live.textContent = 'подключено'; live.title = 'В свёрнутой группе есть активное подключение';
    toggle.append(live);
  }
  toggle.addEventListener('click', () => { setGroupCollapsed(section.id, !collapsed); renderProfiles(); });
  head.append(toggle);
  if (section.group) head.append(groupActions(section.group, head));
  return head;
}
function groupActions(group, head) {
  const actions = document.createElement('span'); actions.className = 'group-actions';
  const rename = document.createElement('button'); rename.type = 'button'; rename.textContent = 'Имя'; rename.title = 'Переименовать группу';
  rename.addEventListener('click', () => renameGroup(head, group));
  const del = document.createElement('button'); del.type = 'button';
  const armed = armedGroup === group.id; del.textContent = armed ? 'Точно?' : 'Удалить'; del.dataset.armed = String(armed);
  del.title = 'Удалить группу. Её конфигурации останутся в списке без группы';
  del.addEventListener('click', async () => {
    if (armedGroup !== group.id) { armedGroup = group.id; renderProfiles(); setTimeout(() => { if (armedGroup === group.id) { armedGroup = null; renderProfiles(); } }, 4000); return; }
    armedGroup = null;
    try { await invoke('delete_profile_group', { id: group.id }); } catch (e) { showError(`Не удалось удалить группу: ${e}`); }
    await loadProfiles();
  });
  actions.append(rename, del); return actions;
}
function renameGroup(head, group) {
  const input = document.createElement('input'); input.className = 'profile-rename'; input.value = group.name; input.maxLength = 40;
  head.replaceChildren(input); input.focus(); input.select();
  let done = false;
  const finish = async save => {
    if (done) return; done = true; const name = input.value.trim();
    if (save && name && name !== group.name) { try { await invoke('rename_profile_group', { id: group.id, name }); } catch (e) { showError(`Не удалось переименовать группу: ${e}`); } }
    await loadProfiles();
  };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') finish(true); if (e.key === 'Escape') finish(false); });
  input.addEventListener('blur', () => finish(true));
}
// Creating a group: the name field sits outside #profiles, so refreshes of the list do not wipe it.
function startNewGroup() {
  const slot = $('new-group-slot'); if (slot.childElementCount) { slot.querySelector('input').focus(); return; }
  const input = document.createElement('input'); input.className = 'profile-rename'; input.placeholder = 'Название группы'; input.maxLength = 40;
  slot.append(input); input.focus();
  let done = false;
  const finish = async save => {
    if (done) return; done = true; const name = input.value.trim(); input.remove();
    if (save && name) { try { await invoke('create_profile_group', { name }); } catch (e) { showError(`Не удалось создать группу: ${e}`); } await loadProfiles(); }
  };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') finish(true); if (e.key === 'Escape') finish(false); });
  input.addEventListener('blur', () => finish(true));
}
// The group selector of a config row; shown only once at least one group exists.
function moveControl(p) {
  const select = document.createElement('select'); select.className = 'group-select'; select.title = 'Группа'; select.setAttribute('aria-label', 'Группа конфигурации');
  select.add(new Option('Без группы', ''));
  for (const g of groups) select.add(new Option(g.name, g.id));
  select.value = groups.find(g => g.members.includes(key(p)))?.id ?? '';
  select.addEventListener('change', async () => {
    select.disabled = true;
    try { await invoke('move_profile_to_group', { member: key(p), group: select.value || null }); } catch (e) { showError(`Не удалось переместить конфигурацию: ${e}`); }
    await loadProfiles();
  });
  return select;
}
function withMove(p, row) {
  const item = document.createElement('div'); item.className = 'profile-item';
  const actions = document.createElement('div'); actions.className = 'profile-actions'; actions.append(moveControl(p));
  item.append(row, actions); return item;
}
function renderSection(list, section, items, collapsed) {
  const isCollapsed = collapsed.has(section.id);
  const wrap = document.createElement('section'); wrap.className = 'profile-group';
  wrap.append(groupHead(section, items, isCollapsed));
  if (!isCollapsed) {
    const body = document.createElement('div'); body.className = 'profile-group-items';
    if (items.length) body.append(...items.map(p => profileRow(p)));
    else { const hint = document.createElement('p'); hint.className = 'group-empty'; hint.textContent = 'Пусто. Чтобы добавить сюда конфигурацию, выберите группу в её строке.'; body.append(hint); }
    wrap.append(body);
  }
  list.append(wrap);
}
function profileRow(p) {
    const row = document.createElement('button'); row.type='button'; row.className='profile-row'; row.setAttribute('aria-pressed', String(key(p) === selectedProfileKey)); row.disabled = busy || mode === 'proxy'; row.dataset.active = String(mode === 'tun' && key(p) === connectedKey);
    const country = document.createElement('span'); country.className='profile-flag'; country.textContent=flag(p.country) || '🌐';
    const copy = document.createElement('span'); copy.className='profile-copy';
    const server = document.createElement('strong'); server.className='profile-server'; server.textContent=p.server_name || 'Сервер'; if (p.imported) { const tag=document.createElement('span'); tag.className='profile-tag'; tag.textContent=p.transport==='hysteria2'?'импорт · hy2':p.transport==='awg'?'импорт · awg':'импорт'; server.textContent=p.host || 'Импорт'; server.append(tag); }
    if (p.insecure) { const warning=document.createElement('span'); warning.className='profile-tag profile-tag-warning'; warning.textContent='без проверки TLS'; server.append(warning); }
    const client = document.createElement('span'); client.className='profile-client'; client.textContent=p.email;
    copy.append(server,client); row.append(country,copy,probeBadge(p)); row.addEventListener('click',()=>{ selectedProfileKey=key(p); localStorage.setItem('vpn.selectedProfile', selectedProfileKey); syncMcpSelection().catch(e=>{ $('connection-error').textContent=`Не удалось сохранить выбор для MCP: ${e}`; $('connection-error').hidden=false; }); renderProfiles(); connectionState(mode); if(mode==='tun' && key(p)!==connectedKey) switchProfile(); }); if (p.imported) return importedItem(p, row, client);
    return groups.length ? withMove(p, row) : row;
}
function renderProfiles() {
  const list = $('profiles'); list.replaceChildren();
  if (!profiles.length) { const empty = document.createElement('p'); empty.className='empty-state'; empty.textContent='Отметьте конфигурации в Администрировании или импортируйте ссылку (кнопка «Импорт»).'; list.append(empty); }
  if (!groups.length) { for (const p of profiles) list.append(profileRow(p)); }
  else {
    const collapsed = collapsedGroups(), home = new Map();
    for (const g of groups) for (const m of g.members) home.set(m, g.id);
    for (const g of groups) renderSection(list, { id: g.id, name: g.name, group: g }, profiles.filter(p => home.get(key(p)) === g.id), collapsed);
    const loose = profiles.filter(p => !home.has(key(p)));
    if (loose.length) renderSection(list, { id: 'ungrouped', name: 'Без группы' }, loose, collapsed);
  }
  const chosen = profiles.find(p=>key(p)===selectedProfileKey);
  $('active-profile-label').textContent = chosen ? `${chosen.imported ? '⬇' : flag(chosen.country)} ${chosen.imported ? (chosen.host || 'Импорт') : chosen.server_name} · ${chosen.email}` : 'Выберите конфигурацию';
  $('vpn-toggle').disabled = busy || (mode === 'off' && !canConnect(chosen));
}
let armedDelete=null;
function importedItem(p, row, client) {
  const item=document.createElement('div'); item.className='profile-item';
  const actions=document.createElement('div'); actions.className='profile-actions';
  const edit=document.createElement('button'); edit.type='button'; edit.textContent='Имя'; edit.disabled=mode!=='off'; edit.title='Переименовать';
  const del=document.createElement('button'); del.type='button'; del.disabled=mode!=='off';
  const armed=armedDelete===p.imported_id; del.textContent=armed?'Точно?':'Удалить'; del.dataset.armed=String(armed);
  edit.addEventListener('click',()=>{ const input=document.createElement('input'); input.className='profile-rename'; input.value=p.email; input.maxLength=128; client.replaceChildren(input); input.focus(); input.select();
    let done=false; const finish=async save=>{ if(done)return; done=true; if(save && input.value.trim() && input.value.trim()!==p.email){ try{ await invoke('rename_imported_profile',{id:p.imported_id,name:input.value.trim()}); }catch(e){ $('connection-error').textContent=`Не удалось переименовать: ${e}`; $('connection-error').hidden=false; } } await loadProfiles(); };
    input.addEventListener('keydown',e=>{ if(e.key==='Enter')finish(true); if(e.key==='Escape')finish(false); }); input.addEventListener('blur',()=>finish(true)); });
  del.addEventListener('click',async()=>{ if(armedDelete!==p.imported_id){ armedDelete=p.imported_id; renderProfiles(); setTimeout(()=>{ if(armedDelete===p.imported_id){ armedDelete=null; renderProfiles(); } },4000); return; } armedDelete=null;
    try{ await invoke('delete_imported_profile',{id:p.imported_id}); }catch(e){ $('connection-error').textContent=`Не удалось удалить: ${e}`; $('connection-error').hidden=false; } await loadProfiles(); });
  if (groups.length) actions.append(moveControl(p));
  actions.append(edit,del); item.append(row,actions); return item;
}
async function loadProfiles() {
  $('refresh').disabled=true;
  try { const [servers,imported,userGroups]=await Promise.all([invoke('list_connectable_profiles'),invoke('list_imported_profiles'),invoke('list_profile_groups')]); groups=userGroups; profiles=[...servers,...imported.map(importedRow)]; if (!profiles.some(p=>key(p)===selectedProfileKey)) selectedProfileKey=profiles[0] ? key(profiles[0]) : null; if (selectedProfileKey) localStorage.setItem('vpn.selectedProfile',selectedProfileKey); else localStorage.removeItem('vpn.selectedProfile'); await syncMcpSelection(); renderProfiles(); }
  catch(e) { $('profiles').innerHTML=''; const err=document.createElement('p'); err.className='empty-state'; err.textContent=`Не удалось загрузить конфигурации: ${e}`; $('profiles').append(err); }
  finally { $('refresh').disabled=false; }
}
// "Замерить пинги": starts a probe round now and waits (at most 60 s) until every configuration has a result newer than the click.
let measuring = false;
async function measurePings() {
  if (measuring) return;
  const button = $('measure-pings');
  if (!profiles.length) { button.textContent = 'Нет конфигураций'; setTimeout(() => { button.textContent = 'Замерить пинги'; }, 2000); return; }
  measuring = true; button.disabled = true; button.textContent = 'Замеряем…';
  const from = Math.floor(Date.now() / 1000);
  const missing = () => profiles.filter(p => !(probes[key(p)] && probes[key(p)].ts >= from)).length;
  let pending = profiles.length, label = 'Готово';
  try {
    await invoke('probe_now');
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 1000));
      probes = await invoke('get_probe_results'); renderProfiles();
      pending = missing();
      button.textContent = pending ? `Замеряем… ${profiles.length - pending}/${profiles.length}` : 'Замеряем…';
      if (!pending) break;
    }
    if (pending) label = 'Не все замерены';
  } catch (e) { label = 'Ошибка'; showError(`Не удалось замерить пинги: ${e}`); }
  button.textContent = label;
  setTimeout(() => { button.textContent = 'Замерить пинги'; button.disabled = false; measuring = false; }, 2500);
}
$('measure-pings').addEventListener('click', measurePings);
$('new-group').addEventListener('click', startNewGroup);
$('refresh').addEventListener('click',()=>{ loadProfiles(); invoke('probe_now').then(()=>setTimeout(pollProbes,4000)).catch(()=>{}); });
if (/Windows/.test(navigator.userAgent)) $('open-admin').hidden = true; // administration is macOS-only
$('open-admin').addEventListener('click',async()=>{ try { await invoke('open_admin'); } catch(e) { $('connection-error').textContent=`Не удалось открыть администрирование: ${e}`; $('connection-error').hidden=false; } });
let connectedKey=null;
async function connectSelected(p) {
  $('connection-message').textContent = mode==='tun' ? 'Переключаем профиль…' : 'Подключаем TUN…';
  const result=p.imported ? await invoke('connect_imported_profile',{id:p.imported_id}) : await invoke('connect_profile',{serverId:p.server_id,inboundId:p.inbound_id,email:p.email});
  mode='tun'; connectedKey=key(p); $('connection-error').hidden=true; $('connection-message').textContent=result;
  showExitIp();
}
async function showExitIp() {
  const el=$('exit-ip'); el.hidden=false; el.textContent='Внешний IP: проверяем…';
  for (let i=0;i<3;i++) {
    try { const ip=await invoke('get_exit_ip'); if(mode==='tun') el.textContent=`Внешний IP (ipify): ${ip}`; return; } catch(e) { if(mode!=='tun') break; await new Promise(r=>setTimeout(r,1500)); }
  }
  el.textContent='Внешний IP: не удалось получить';
}
async function switchProfile() {
  const p=profiles.find(item=>key(item)===selectedProfileKey);
  if(busy || !canConnect(p)) return;
  busy=true; connectionState(mode); $('connection-error').hidden=true;
  try { await connectSelected(p); }
  catch(e) { mode=await invoke('get_vpn_mode').catch(()=>'off'); if(mode==='off') connectedKey=null; $('connection-error').textContent=`Не удалось переключить профиль: ${e}`; $('connection-error').hidden=false; }
  finally { busy=false; connectionState(mode); }
}
$('vpn-toggle').addEventListener('click',async()=>{
  if(busy)return; busy=true; connectionState(mode); $('connection-error').hidden=true;
  try { if(mode!=='off') { await invoke('xray_stop'); mode='off'; connectedKey=null; $('exit-ip').hidden=true; $('connection-error').hidden=true; $('connection-message').textContent='VPN отключён.'; } else { const p=profiles.find(item=>key(item)===selectedProfileKey); if(!canConnect(p)) return; await connectSelected(p); } }
  catch(e) { mode=await invoke('get_vpn_mode').catch(()=>'off'); if(mode==='off') connectedKey=null; $('connection-error').textContent=`Не удалось выполнить действие: ${e}`; $('connection-error').hidden=false; }
  finally { busy=false; connectionState(mode); }
});
invoke('build_info').then(value=>$('build-info').textContent=value).catch(()=>$('build-info').textContent='Версия неизвестна');
invoke('get_vpn_mode').then(m=>{connectionState(m); if(m==='tun') showExitIp();}).catch(()=>connectionState('off'));
loadProfiles();
pollProbes();

window.addEventListener('focus', loadProfiles);

setInterval(async()=>{ if(busy)return; try { const [current,selected]=await Promise.all([invoke('get_vpn_mode'),invoke('get_mcp_profile')]); if(selected){const selectedKey=key(selected);if(selectedKey!==selectedProfileKey && profiles.some(p=>key(p)===selectedKey)){selectedProfileKey=selectedKey;localStorage.setItem('vpn.selectedProfile',selectedKey);renderProfiles();}} if(!busy && current!==mode) connectionState(current); } catch {} },2000);

const importModal=$('import-modal'), importStatus=$('import-status');
function importMessage(text, ok=false){ importStatus.textContent=text; importStatus.dataset.ok=String(ok); }
function closeImport(){ importModal.hidden=true; $('import-text').value=''; $('import-name').value=''; importMessage(''); }
$('open-import').addEventListener('click',()=>{ importModal.hidden=false; importMessage(''); $('import-text').focus(); });
$('import-cancel').addEventListener('click',closeImport);
const bypassModal=$('bypass-modal'), bypassMessage=(t,ok=false)=>{ const el=$('bypass-status'); el.textContent=t; el.classList.toggle('ok',ok); };
let bypassSnapshot='';
let logSnapshot=false;
const bypassForm=()=>({ bittorrent:$('bypass-bittorrent').checked, entries:$('bypass-entries').value.split(/\n/).map(x=>x.trim()).filter(Boolean) });
const bypassKey=f=>JSON.stringify([f.bittorrent,f.entries]);
const plural=n=>n%10===1&&n%100!==11?'запись':[2,3,4].includes(n%10)&&![12,13,14].includes(n%100)?'записи':'записей';
async function saveBypass(){
  try{
    const b=await invoke('set_bypass_settings',bypassForm());
    if(!$('log-verbose').disabled && $('log-verbose').checked!==logSnapshot){ await invoke('set_log_level',{verbose:$('log-verbose').checked}); logSnapshot=$('log-verbose').checked; }
    $('bypass-entries').value=b.entries.join('\n'); bypassSnapshot=bypassKey(bypassForm());
    const n=b.entries.length; const when=mode==='off' ? 'Применится при подключении.' : 'Переподключитесь, чтобы изменения вступили в силу.';
    bypassMessage(`Сохранено: ${n} ${plural(n)}${b.bittorrent?' + BitTorrent':''}. ${when}`,true); return true;
  }catch(e){ bypassMessage(String(e)); return false; }
}
let geoLists=null;
const geoEntries=()=>new Set($('bypass-entries').value.split(/\n/).map(x=>x.trim().toLowerCase()).filter(Boolean));
function renderGeo(){
  const root=$('geo-results'), note=$('geo-note'); root.replaceChildren();
  if(!geoLists){ note.textContent=''; return; }
  const kind=$('geo-kind').value, all=geoLists[kind]||[], q=$('geo-search').value.trim().toLowerCase();
  if(!all.length){ note.textContent='Базы списков в этой сборке нет, их можно вписать вручную.'; return; }
  const found=q?all.filter(n=>n.includes(q)):all, shown=found.slice(0,40), have=geoEntries();
  shown.forEach(n=>{ const entry=`${kind}:${n}`, b=document.createElement('button'); b.type='button'; b.className='geo-chip'; b.textContent=entry; b.setAttribute('role','option');
    if(have.has(entry)){ b.classList.add('added'); b.disabled=true; b.title='Уже добавлено'; }
    else b.addEventListener('click',()=>{ const area=$('bypass-entries'); area.value=(area.value.trim()?area.value.replace(/\s+$/,'')+'\n':'')+entry+'\n'; bypassMessage(''); renderGeo(); });
    root.append(b); });
  note.textContent=found.length>shown.length?`Показано ${shown.length} из ${found.length}; уточните поиск.`:`Найдено: ${found.length}. Нажмите на список, чтобы добавить.`;
}
$('geo-kind').addEventListener('change',renderGeo);
$('geo-search').addEventListener('input',renderGeo);
$('bypass-entries').addEventListener('input',renderGeo);
async function loadGeoLists(){ if(geoLists) { renderGeo(); return; } try{ geoLists=await invoke('list_geo_lists'); }catch{ geoLists={geoip:[],geosite:[]}; } renderGeo(); }
$('open-bypass').addEventListener('click',async()=>{ bypassModal.hidden=false; bypassMessage(''); $('geo-search').value=''; loadGeoLists(); try{ const b=await invoke('get_bypass_settings'); $('bypass-bittorrent').checked=b.bittorrent; $('bypass-entries').value=b.entries.join('\n'); bypassSnapshot=bypassKey(bypassForm()); }catch(e){ bypassMessage(`Не удалось загрузить настройки: ${e}`); }
  try{ logSnapshot=(await invoke('get_log_level'))==='info'; $('log-verbose').checked=logSnapshot; $('log-verbose').disabled=false; }catch{ $('log-verbose').disabled=true; $('log-verbose').checked=false; } });
$('bypass-cancel').addEventListener('click',async()=>{ if((bypassKey(bypassForm())!==bypassSnapshot || (!$('log-verbose').disabled && $('log-verbose').checked!==logSnapshot)) && !(await saveBypass())) return; bypassModal.hidden=true; });
$('bypass-save').addEventListener('click',saveBypass);
importModal.addEventListener('click',e=>{ if(e.target===importModal && !$('import-submit').disabled) closeImport(); });
document.addEventListener('keydown',e=>{ if(e.key==='Escape' && !importModal.hidden && !$('import-submit').disabled) closeImport(); });
$('import-paste').addEventListener('click',async()=>{ try{ const text=await navigator.clipboard.readText(); if(!text.trim()){ importMessage('Буфер обмена пуст.'); return; } $('import-text').value=text; importMessage(''); }catch{ importMessage('Нет доступа к буферу. Вставьте ссылку в поле вручную (⌘V).'); $('import-text').focus(); } });
$('import-submit').addEventListener('click',async()=>{
  const text=$('import-text').value, name=$('import-name').value.trim();
  if(!text.trim()){ importMessage('Вставьте ссылку vless://, hysteria2://, vpn:// или конфиг AmneziaWG'); return; }
  $('import-submit').disabled=true; importMessage('Проверяем…',true);
  try{ const added=await invoke('import_profiles',{text,name:name||null}); await loadProfiles(); const first=profiles.find(p=>p.imported && p.imported_id===added[0].id); if(first && mode==='off'){ selectedProfileKey=key(first); localStorage.setItem('vpn.selectedProfile',selectedProfileKey); await syncMcpSelection(); renderProfiles(); connectionState(mode); } closeImport(); $('connection-message').textContent=added.length>1 ? `Импортировано конфигураций: ${added.length}.` : `Импортирована конфигурация «${added[0].name}».`; if(added.some(p=>p.insecure)) $('connection-message').textContent+=' Внимание: проверка сертификата TLS отключена.'; }
  catch(e){ importMessage(String(e)); }
  finally{ $('import-submit').disabled=false; }
});

// Esc closes the topmost open dialog through its own close/cancel button (so running operations stay protected).
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape' || e.defaultPrevented) return;
  const open = [...document.querySelectorAll('.import-modal')].filter(m => !m.hidden);
  const top = open[open.length - 1]; if (!top) return;
  const button = top.querySelector('[id$="-cancel"]'); if (!button || button.disabled) return;
  e.preventDefault(); button.click();
});
