const invoke = window.__TAURI_INTERNALS__.invoke;
const $ = id => document.getElementById(id);
const countryNames = new Intl.DisplayNames(['ru'], {type:'region'});
function flag(code) { return code && /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map(c => 127397 + c.charCodeAt(0))) : ''; }
const canConnect = p => !!p && p.enabled && p.inbound_enabled && p.protocol === 'vless' && p.transport === 'xhttp' && p.has_local_config;
let profiles = [], selectedProfileKey = localStorage.getItem('vpn.selectedProfile') || null;
let mode = 'off', busy = false;
function key(p) { return `${p.server_id}:${p.inbound_id}:${p.email}`; }
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
  if (!profiles.length) { const empty = document.createElement('p'); empty.className='empty-state'; empty.textContent='Отметьте конфигурации в Администрировании.'; list.append(empty); }
  for (const p of profiles) {
    const row = document.createElement('button'); row.type='button'; row.className='profile-row'; row.setAttribute('aria-pressed', String(key(p) === selectedProfileKey)); row.disabled = mode !== 'off';
    const country = document.createElement('span'); country.className='profile-flag'; country.textContent=flag(p.country) || '🌐';
    const copy = document.createElement('span'); copy.className='profile-copy';
    const server = document.createElement('strong'); server.className='profile-server'; server.textContent=p.server_name || 'Сервер';
    const client = document.createElement('span'); client.className='profile-client'; client.textContent=p.email;
    copy.append(server,client); row.append(country,copy); row.addEventListener('click',()=>{ selectedProfileKey=key(p); localStorage.setItem('vpn.selectedProfile', selectedProfileKey); renderProfiles(); connectionState(mode); }); list.append(row);
  }
  const chosen = profiles.find(p=>key(p)===selectedProfileKey);
  $('active-profile-label').textContent = chosen ? `${flag(chosen.country)} ${chosen.server_name} · ${chosen.email}` : 'Выберите конфигурацию';
  $('vpn-toggle').disabled = busy || (mode === 'off' && !canConnect(chosen));
}
async function loadProfiles() {
  $('refresh').disabled=true;
  try { profiles=await invoke('list_connectable_profiles'); if (!profiles.some(p=>key(p)===selectedProfileKey)) selectedProfileKey=profiles[0] ? key(profiles[0]) : null; if (selectedProfileKey) localStorage.setItem('vpn.selectedProfile',selectedProfileKey); else localStorage.removeItem('vpn.selectedProfile'); renderProfiles(); }
  catch(e) { $('profiles').innerHTML=''; const err=document.createElement('p'); err.className='empty-state'; err.textContent=`Не удалось загрузить конфигурации: ${e}`; $('profiles').append(err); }
  finally { $('refresh').disabled=false; }
}
$('refresh').addEventListener('click',loadProfiles);
$('open-admin').addEventListener('click',async()=>{ try { await invoke('open_admin'); } catch(e) { $('connection-error').textContent=`Не удалось открыть администрирование: ${e}`; $('connection-error').hidden=false; } });
$('vpn-toggle').addEventListener('click',async()=>{
  if(busy)return; busy=true; connectionState(mode); $('connection-error').hidden=true;
  try { if(mode!=='off') { await invoke('xray_stop'); mode='off'; $('connection-message').textContent='VPN отключён.'; } else { const p=profiles.find(item=>key(item)===selectedProfileKey); if(!canConnect(p)) return; $('connection-message').textContent='Подключаем TUN…'; const result=await invoke('connect_profile',{serverId:p.server_id,inboundId:p.inbound_id,email:p.email}); mode='tun'; $('connection-message').textContent=result; } }
  catch(e) { mode=await invoke('get_vpn_mode').catch(()=>'off'); $('connection-error').textContent=`Не удалось выполнить действие: ${e}`; $('connection-error').hidden=false; }
  finally { busy=false; connectionState(mode); }
});
invoke('build_info').then(value=>$('build-info').textContent=value).catch(()=>$('build-info').textContent='Версия неизвестна');
invoke('get_vpn_mode').then(connectionState).catch(()=>connectionState('off'));
loadProfiles();

window.addEventListener('focus', loadProfiles);
