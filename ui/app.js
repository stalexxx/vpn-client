const invoke = window.__TAURI_INTERNALS__.invoke;
const $ = id => document.getElementById(id);
const countryNames = new Intl.DisplayNames(['ru'], {type:'region'});
function flag(code) { return code && /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map(c => 127397 + c.charCodeAt(0))) : ''; }
const canConnect = p => !!p && (p.imported || p.enabled && p.inbound_enabled && ['vless', 'hysteria'].includes(p.protocol) && p.has_local_config);
let profiles = [], selectedProfileKey = localStorage.getItem('vpn.selectedProfile') || null;
let mode = 'off', busy = false;
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
const importedRow = i => ({imported:true, imported_id:i.id, server_id:'imported', inbound_id:0, email:i.name, host:i.host, transport:i.transport, server_name:'Импорт', country:null, protocol:'vless', enabled:true, inbound_enabled:true, has_local_config:true});
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
function renderProfiles() {
  const list = $('profiles'); list.replaceChildren();
  if (!profiles.length) { const empty = document.createElement('p'); empty.className='empty-state'; empty.textContent='Отметьте конфигурации в Администрировании или импортируйте ссылку (кнопка «Импорт»).'; list.append(empty); }
  for (const p of profiles) {
    const row = document.createElement('button'); row.type='button'; row.className='profile-row'; row.setAttribute('aria-pressed', String(key(p) === selectedProfileKey)); row.disabled = mode !== 'off';
    const country = document.createElement('span'); country.className='profile-flag'; country.textContent=flag(p.country) || '🌐';
    const copy = document.createElement('span'); copy.className='profile-copy';
    const server = document.createElement('strong'); server.className='profile-server'; server.textContent=p.server_name || 'Сервер'; if (p.imported) { const tag=document.createElement('span'); tag.className='profile-tag'; tag.textContent=p.transport==='hysteria2'?'импорт · hy2':'импорт'; server.textContent=p.host || 'Импорт'; server.append(tag); }
    const client = document.createElement('span'); client.className='profile-client'; client.textContent=p.email;
    copy.append(server,client); row.append(country,copy); row.addEventListener('click',()=>{ selectedProfileKey=key(p); localStorage.setItem('vpn.selectedProfile', selectedProfileKey); syncMcpSelection().catch(e=>{ $('connection-error').textContent=`Не удалось сохранить выбор для MCP: ${e}`; $('connection-error').hidden=false; }); renderProfiles(); connectionState(mode); }); list.append(p.imported ? importedItem(p, row, client) : row);
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
  actions.append(edit,del); item.append(row,actions); return item;
}
async function loadProfiles() {
  $('refresh').disabled=true;
  try { const [servers,imported]=await Promise.all([invoke('list_connectable_profiles'),invoke('list_imported_profiles')]); profiles=[...servers,...imported.map(importedRow)]; if (!profiles.some(p=>key(p)===selectedProfileKey)) selectedProfileKey=profiles[0] ? key(profiles[0]) : null; if (selectedProfileKey) localStorage.setItem('vpn.selectedProfile',selectedProfileKey); else localStorage.removeItem('vpn.selectedProfile'); await syncMcpSelection(); renderProfiles(); }
  catch(e) { $('profiles').innerHTML=''; const err=document.createElement('p'); err.className='empty-state'; err.textContent=`Не удалось загрузить конфигурации: ${e}`; $('profiles').append(err); }
  finally { $('refresh').disabled=false; }
}
$('refresh').addEventListener('click',loadProfiles);
$('open-admin').addEventListener('click',async()=>{ try { await invoke('open_admin'); } catch(e) { $('connection-error').textContent=`Не удалось открыть администрирование: ${e}`; $('connection-error').hidden=false; } });
$('vpn-toggle').addEventListener('click',async()=>{
  if(busy)return; busy=true; connectionState(mode); $('connection-error').hidden=true;
  try { if(mode!=='off') { await invoke('xray_stop'); mode='off'; $('connection-message').textContent='VPN отключён.'; } else { const p=profiles.find(item=>key(item)===selectedProfileKey); if(!canConnect(p)) return; $('connection-message').textContent='Подключаем TUN…'; const result=p.imported ? await invoke('connect_imported_profile',{id:p.imported_id}) : await invoke('connect_profile',{serverId:p.server_id,inboundId:p.inbound_id,email:p.email}); mode='tun'; $('connection-message').textContent=result; } }
  catch(e) { mode=await invoke('get_vpn_mode').catch(()=>'off'); $('connection-error').textContent=`Не удалось выполнить действие: ${e}`; $('connection-error').hidden=false; }
  finally { busy=false; connectionState(mode); }
});
invoke('build_info').then(value=>$('build-info').textContent=value).catch(()=>$('build-info').textContent='Версия неизвестна');
invoke('get_vpn_mode').then(connectionState).catch(()=>connectionState('off'));
loadProfiles();

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
$('open-bypass').addEventListener('click',async()=>{ bypassModal.hidden=false; bypassMessage(''); try{ const b=await invoke('get_bypass_settings'); $('bypass-bittorrent').checked=b.bittorrent; $('bypass-entries').value=b.entries.join('\n'); bypassSnapshot=bypassKey(bypassForm()); }catch(e){ bypassMessage(`Не удалось загрузить настройки: ${e}`); }
  try{ logSnapshot=(await invoke('get_log_level'))==='info'; $('log-verbose').checked=logSnapshot; $('log-verbose').disabled=false; }catch{ $('log-verbose').disabled=true; $('log-verbose').checked=false; } });
$('bypass-cancel').addEventListener('click',async()=>{ if((bypassKey(bypassForm())!==bypassSnapshot || (!$('log-verbose').disabled && $('log-verbose').checked!==logSnapshot)) && !(await saveBypass())) return; bypassModal.hidden=true; });
$('bypass-save').addEventListener('click',saveBypass);
importModal.addEventListener('click',e=>{ if(e.target===importModal && !$('import-submit').disabled) closeImport(); });
document.addEventListener('keydown',e=>{ if(e.key==='Escape' && !importModal.hidden && !$('import-submit').disabled) closeImport(); });
$('import-paste').addEventListener('click',async()=>{ try{ const text=await navigator.clipboard.readText(); if(!text.trim()){ importMessage('Буфер обмена пуст.'); return; } $('import-text').value=text; importMessage(''); }catch{ importMessage('Нет доступа к буферу. Вставьте ссылку в поле вручную (⌘V).'); $('import-text').focus(); } });
$('import-submit').addEventListener('click',async()=>{
  const text=$('import-text').value, name=$('import-name').value.trim();
  if(!text.trim()){ importMessage('Вставьте ссылку vless:// или hysteria2://'); return; }
  $('import-submit').disabled=true; importMessage('Проверяем…',true);
  try{ const added=await invoke('import_profiles',{text,name:name||null}); await loadProfiles(); const first=profiles.find(p=>p.imported && p.imported_id===added[0].id); if(first && mode==='off'){ selectedProfileKey=key(first); localStorage.setItem('vpn.selectedProfile',selectedProfileKey); await syncMcpSelection(); renderProfiles(); connectionState(mode); } closeImport(); $('connection-message').textContent=added.length>1 ? `Импортировано конфигураций: ${added.length}.` : `Импортирована конфигурация «${added[0].name}».`; }
  catch(e){ importMessage(String(e)); }
  finally{ $('import-submit').disabled=false; }
});
