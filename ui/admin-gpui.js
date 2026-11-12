const invoke = window.__TAURI_INTERNALS__.invoke;
const $ = id => document.getElementById(id);
const countryCodes = 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BH BI BJ BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FO FR GA GB GD GE GH GI GL GM GN GP GQ GR GT GU GW GY HK HN HR HT HU ID IE IL IN IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KZ LA LB LC LI LK LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SC SD SE SG SI SK SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' ');
const countryNames = new Intl.DisplayNames(['ru'], {type:'region'});
function flag(code) { return code && /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(...[...code].map(c=>127397+c.charCodeAt(0))) : ''; }
function fillCountries(select) { const blank=document.createElement('option');blank.value='';blank.textContent='Не указана';select.append(blank); countryCodes.map(code=>({code,name:countryNames.of(code)})).sort((a,b)=>a.name.localeCompare(b.name,'ru')).forEach(({code,name})=>{const o=document.createElement('option');o.value=code;o.textContent=`${code} — ${name}`;select.append(o);}); }
fillCountries($('country'));fillCountries($('host-country'));fillCountries($('wizard-country'));fillCountries($('quick-country'));
let hosts=[],awgServers=[],entries=[],selectedEntry=null;
let servers=[],selectedServer=null,profiles=[],inbounds=[],editing=null,pinnedProfiles=null;
const usableProfile = p => p.enabled && p.inbound_enabled && ['vless', 'hysteria'].includes(p.protocol) && p.has_local_config;
function isPinned(p) { return pinnedProfiles===null || pinnedProfiles.some(k=>k.server_id===selectedServer?.id && k.inbound_id===p.inbound_id && k.email===p.email); }
let wizardIndex=0,installationSucceeded=false,wizardRunning=false,installedTarget=null,installedKey=null,wizardId=null,wizardInboundId=null,wizardClientCreated=false,wizardInbounds=[];
const wizardSteps=[
  {title:'Установка 3x-ui и токен',element:'wizard-step-install',validate:validateInstallStep,next:advanceFromInstall},
  {title:'Inbound',element:'wizard-step-inbound',validate:validateInboundStep,next:advanceFromInbound},
  {title:'Клиент',element:'wizard-step-client',validate:validateClientStep,next:finishWizard}
];
function countryLabel(code) { return code ? [flag(code),countryNames.of(code)].filter(Boolean).join(' ') : ''; }
function hostOf(url) { try{return new URL(url).hostname;}catch{return 'Некорректный адрес';} }
function serverHost(server) { const sshHost=server.ssh_target?.split('@').pop().replace(/:\d+$/,'');return server.panel_host||sshHost||hostOf(server.url); }
const sshHostOf=t=>t?t.split('@').pop().replace(/:\d+$/,'').toLowerCase():'';
// A server = a host record (name, country, SSH) plus whatever is deployed on it: a 3x-ui panel and/or AmneziaWG, matched by SSH host.
function buildEntries(){
  entries=hosts.map(h=>({key:h.id,host:h,name:h.name,country:h.country,hostname:sshHostOf(h.ssh_target),panel:servers.find(s=>sshHostOf(s.ssh_target)===sshHostOf(h.ssh_target))||null,awg:awgServers.find(s=>sshHostOf(s.ssh_target)===sshHostOf(h.ssh_target))||null}));
  servers.filter(s=>!entries.some(e=>e.panel===s)).forEach(s=>entries.push({key:s.id,host:null,name:s.name,country:s.country,hostname:serverHost(s),panel:s,awg:null}));
}
function selected(id) { return selectedServer?.id===id; }
function renderServers() {
  const list=$('servers');list.replaceChildren();
  if(!entries.length){const p=document.createElement('p');p.className='workspace-empty';p.textContent='Серверов пока нет.';list.append(p);}
  entries.forEach(entry=>{const button=document.createElement('button');button.className='server-card';button.type='button';button.setAttribute('aria-pressed',String(selectedEntry?.key===entry.key));const f=document.createElement('span');f.className='server-flag';f.textContent=flag(entry.country)||'🌐';const c=document.createElement('span');c.className='server-copy';const n=document.createElement('strong');n.textContent=entry.hostname||entry.name;const country=document.createElement('span');country.textContent=countryLabel(entry.country)||entry.name;const kinds=document.createElement('span');kinds.className='server-kinds';if(entry.panel){const i=document.createElement('i');i.textContent='3x-ui';kinds.append(i);}if(entry.awg){const i=document.createElement('i');i.textContent='AmneziaWG';kinds.append(i);}c.append(n,country,kinds);button.append(f,c);button.addEventListener('click',()=>selectEntry(entry));list.append(button);});
  $('add-server').disabled=wizardRunning;
}
function renderServerHeader() {
  const e=selectedEntry;
  $('quick-edit').disabled=!e; $('header-delete-server').disabled=!e;
  $('server-title').textContent=e?.name||'Выберите сервер';
  $('server-subtitle').textContent=e ? `${e.hostname}${e.country ? ` · ${countryLabel(e.country)}`:''}` : 'Управление клиентами и подключениями';
  // What can still be deployed here; a server with nothing deployed is a plain host.
  const missing=[];if(e&&!e.panel)missing.push('3x-ui');if(e&&!e.awg)missing.push('AmneziaWG');
  $('deploy-box').hidden=!e||!e.host||!missing.length;
  $('deploy-3xui').hidden=!!e?.panel;$('deploy-awg').hidden=!!e?.awg;
  $('deploy-text').textContent=e&&!e.panel&&!e.awg?'На сервере пока ничего не развёрнуто. Выберите, что установить:':'Добавить на этот сервер:';
  $('create-client-form').hidden=!(e?.panel||e?.awg);$('open-inbound-template').hidden=!e?.panel;
  $('edit-form').hidden=!e?.panel;$('panel-settings-note').hidden=!!e?.panel;
}
function renderInboundOptions() { const select=$('client-inbound');select.replaceChildren();inbounds.filter(i=>i.enable&&i.protocol==='vless').forEach(i=>{const o=document.createElement('option');o.value=i.id;o.textContent=`${i.remark||'Подключение'} · порт ${i.port}`;select.append(o);});if(selectedEntry?.awg){const o=document.createElement('option');o.value='awg';o.textContent=`AmneziaWG + WARP · UDP ${selectedEntry.awg.port}`;select.append(o);}$('create-client-form').querySelector('button').disabled=!select.options.length; }
function renderProfiles() {
  const root=$('profiles');root.replaceChildren();
  if(!selectedServer){if(selectedEntry&&selectedEntry.awg)return;const e=document.createElement('p');e.className='empty-state';e.textContent=selectedEntry?'3x-ui на этом сервере не установлен.':'Выберите сервер слева.';root.append(e);return;}
  const groups=new Map(inbounds.map(i=>[i.id,{name:i.remark||'Подключение',port:i.port,clients:[]} ]));profiles.forEach(p=>{if(!groups.has(p.inbound_id))groups.set(p.inbound_id,{name:p.inbound_name||'Подключение',port:p.port,clients:[]});groups.get(p.inbound_id).clients.push(p);});
  if(!groups.size){const e=document.createElement('p');e.className='empty-state';e.textContent='Inbound-ов нет в кэше. Нажмите «Обновить».';root.append(e);}
  for(const group of groups.values()){const section=document.createElement('section');section.className='inbound-group';const head=document.createElement('header');head.className='group-head';const title=document.createElement('h3');title.textContent=group.name;const port=document.createElement('span');port.textContent=`Порт ${group.port} · ${group.clients.length} клиентов`;head.append(title,port);section.append(head);
    if(!group.clients.length){const none=document.createElement('p');none.className='empty-state';none.textContent='Нет клиентов в этом inbound-е.';none.style.margin='12px';section.append(none);}
    group.clients.forEach(p=>{const row=document.createElement('div');row.className='client-row';const identity=document.createElement('span');identity.className='client-identity';identity.textContent=p.email;identity.title=p.email;const type=document.createElement('span');type.className='client-type';type.textContent=p.has_local_config?(p.transport==='tcp'?'VLESS · TCP · Reality':'VLESS · TLS · XHTTP'):'Нет локальной конфигурации';const pinLabel=document.createElement('label');pinLabel.className='client-pin';const pin=document.createElement('input');pin.type='checkbox';pin.checked=usableProfile(p)&&isPinned(p);pin.disabled=!usableProfile(p);pin.title=pin.disabled?'Доступна только локальная конфигурация активного клиента':'';pin.addEventListener('change',async()=>{const serverId=selectedServer.id;pin.disabled=true;try{await invoke('set_profile_pinned',{serverId,inboundId:p.inbound_id,email:p.email,pinned:pin.checked});pinnedProfiles=await invoke('list_pinned_profiles');if(selected(serverId))renderProfiles();}catch(e){pin.checked=!pin.checked;$('client-status').textContent=`Не удалось изменить отметку: ${e}`;}finally{pin.disabled=false;}});pinLabel.append(pin,document.createTextNode('На главном экране'));if(pin.disabled)pinLabel.title=pin.title;const actions=document.createElement('span');actions.className='client-actions';const qr=document.createElement('button');qr.type='button';qr.textContent='QR и ссылка';qr.disabled=!p.has_local_config;qr.addEventListener('click',()=>showQr(p));actions.append(qr,clientDeleteButton(p));row.append(identity,type,pinLabel,actions);section.append(row);});root.append(section);
  }
}
function renderInbounds() { const root=$('inbounds');root.replaceChildren();if(!selectedServer){if(selectedEntry){if(!selectedEntry.awg)root.innerHTML='<p class="empty-state">3x-ui на этом сервере не установлен.</p>';return;}root.innerHTML='<p class="empty-state">Выберите сервер слева.</p>';return;}if(!inbounds.length){root.innerHTML='<p class="empty-state">Inbound-ы не загружены. Нажмите «Обновить».</p>';return;}inbounds.forEach(i=>{const row=document.createElement('div');row.className='inbound-item';const port=document.createElement('span');port.className='inbound-port';port.textContent=i.port;const copy=document.createElement('span');copy.className='inbound-copy';const name=document.createElement('strong');name.textContent=i.remark||`Inbound ${i.id}`;const info=document.createElement('span');info.textContent=`${i.protocol?.toUpperCase()||'—'} · ${i.transport||'транспорт не указан'} · ID ${i.id}`;copy.append(name,info);const badge=document.createElement('span');badge.className=`badge${i.enable?'':' off'}`;badge.textContent=i.enable?'Включён':'Выключен';const del=document.createElement('button');del.type='button';del.className='danger';del.textContent='Удалить';del.addEventListener('click',()=>deleteInbound(i,del));row.append(port,copy,badge,del);root.append(row);}); }
// Two-step delete, like inbounds. The panel keys clients by email, so the client disappears from every inbound that has this email.
let clientDeleteArmed=null,clientDeleteTimer=null;
function clientDeleteButton(p){
  const b=document.createElement('button');b.type='button';b.className='danger';b.textContent='Удалить';
  const key=`${p.inbound_id}:${p.email}`;
  b.addEventListener('click',async()=>{
    if(!selectedServer)return;
    if(clientDeleteArmed!==key){
      clientDeleteArmed=key;clearTimeout(clientDeleteTimer);
      document.querySelectorAll('#profiles .client-actions .danger').forEach(x=>{x.textContent='Удалить';});
      b.textContent='Точно удалить?';
      $('client-status').textContent=`Клиент «${p.email}» будет удалён с сервера (из всех inbound-ов, где есть такой email). Нажмите ещё раз для подтверждения.`;
      clientDeleteTimer=setTimeout(()=>{clientDeleteArmed=null;b.textContent='Удалить';$('client-status').textContent='';},5000);
      return;
    }
    clearTimeout(clientDeleteTimer);clientDeleteArmed=null;b.disabled=true;
    const id=selectedServer.id;
    try{await invoke('delete_client',{serverId:id,email:p.email});if(!selected(id))return;$('client-share').hidden=true;await refresh();$('client-status').textContent=`Клиент ${p.email} удалён.`;}
    catch(e){if(selected(id))$('client-status').textContent=`Не удалось удалить клиента: ${e}`;b.disabled=false;}
  });
  return b;
}
let inboundDeleteArmed=null;
async function deleteInbound(i,button){
  if(!selectedServer)return;
  if(inboundDeleteArmed!==i.id){
    inboundDeleteArmed=i.id;clearTimeout(inboundDeleteTimer);
    document.querySelectorAll('#inbounds .danger').forEach(b=>{b.textContent='Удалить';});
    button.textContent='Точно удалить?';
    $('client-status').textContent=`Inbound «${i.remark||i.id}» будет удалён с сервера вместе со всеми его клиентами. Нажмите ещё раз для подтверждения.`;
    inboundDeleteTimer=setTimeout(()=>{inboundDeleteArmed=null;button.textContent='Удалить';$('client-status').textContent='';},5000);
    return;
  }
  clearTimeout(inboundDeleteTimer);inboundDeleteArmed=null;button.disabled=true;
  const id=selectedServer.id;
  try{
    const message=await invoke('delete_inbound',{serverId:id,inboundId:i.id});
    if(!selected(id))return;
    const [p,list]=await Promise.all([invoke('list_client_profiles',{serverId:id}),invoke('list_inbounds',{serverId:id})]);
    if(!selected(id))return;
    profiles=p;inbounds=list;renderInboundOptions();renderProfiles();renderInbounds();$('client-status').textContent=message;
  }catch(e){if(selected(id))$('client-status').textContent=`Не удалось удалить inbound: ${e}`;button.disabled=false;}
}
let inboundDeleteTimer=null;
async function loadAll(){
  [hosts,servers,awgServers]=await Promise.all([invoke('list_hosts').catch(()=>[]),invoke('list_servers'),invoke('awg_list_servers').catch(()=>[])]);
  buildEntries();
}
async function selectEntry(entry){
  selectedEntry=entry||null;
  renderServers();renderServerHeader();
  window.awgUi?.show(selectedEntry);
  await selectServer(selectedEntry?.panel||null);
  renderInboundOptions();populateSettings();
}
// Reloads every store and keeps (or moves) the selection; used after deploying, removing, renaming.
window.reloadEntries=async function(key){
  await loadAll();
  const next=entries.find(e=>e.key===(key||selectedEntry?.key))||null;
  await selectEntry(next);
};
async function selectServer(server) { $('quick-edit-form').hidden=true; selectedServer=server;profiles=[];inbounds=[];$('client-share').hidden=true;renderServers();renderServerHeader();renderProfiles();renderInbounds();if(!server)return;const id=server.id;try{const [p,i,pins]=await Promise.all([invoke('list_client_profiles',{serverId:id}),invoke('cached_server_inbounds',{serverId:id}),invoke('list_pinned_profiles')]);if(!selected(id))return;profiles=p;inbounds=i;pinnedProfiles=pins;renderInboundOptions();renderProfiles();renderInbounds();}catch(e){if(selected(id))$('client-status').textContent=`Не удалось загрузить локальный кэш: ${e}`;}}
async function refresh() { if(!selectedServer)return;const id=selectedServer.id;$('refresh-profiles').disabled=true;$('client-status').textContent='Обновляем выбранную панель…';try{const [p,i,pins]=await Promise.all([invoke('refresh_client_profiles',{serverId:id}),invoke('list_inbounds',{serverId:id}),invoke('list_pinned_profiles')]);if(!selected(id))return;profiles=p;inbounds=i;pinnedProfiles=pins;renderInboundOptions();renderProfiles();renderInbounds();$('client-status').textContent='Клиенты и inbound-ы обновлены.';}catch(e){if(selected(id))$('client-status').textContent=`Не удалось обновить панель: ${e}`;}finally{$('refresh-profiles').disabled=false;}}
$('refresh-profiles').addEventListener('click',refresh);
document.querySelectorAll('.tab').forEach(tab=>tab.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t===tab));document.querySelectorAll('.tab-panel').forEach(p=>p.hidden=p.id!==`tab-${tab.dataset.tab}`);}));
$('edit-form').addEventListener('submit',async e=>{e.preventDefault();if(!selectedServer)return;try{const server=await invoke('save_server',{id:selectedServer.id,name:$('name').value,url:$('url').value,token:$('token').value,sshTarget:$('ssh-target').value.trim()||null,panelHost:$('panel-host').value.trim()||null,country:$('country').value||null,sshKey:$('ssh-keyfile').value||null});$('token').value='';const host=selectedEntry?.host,target=$('ssh-target').value.trim();if(host&&target)await invoke('save_host',{id:host.id,name:$('name').value,sshTarget:target,sshKey:$('ssh-keyfile').value||null,country:$('country').value||null});await window.reloadEntries(host?.id||server.id);$('server-status').textContent='Настройки сохранены.';}catch(e){$('server-status').textContent=`Не удалось сохранить настройки: ${e}`;}});
function populateSettings(){const s=selectedServer;refreshWarp();fillSshKeySelect($('ssh-keyfile'),s?.ssh_key||null,false);loadSshKeys().then(()=>{if(selectedServer===s){fillSshKeySelect($('ssh-keyfile'),s?.ssh_key||null,false);showSshOrphans($('ssh-orphan'));}});$('name').value=s?.name||'';$('country').value=s?.country||'';$('url').value=s?.url||'';$('ssh-target').value=s?.ssh_target||'';$('panel-host').value=s?.panel_host||'';$('token').value='';}
document.querySelector('[data-tab="settings"]').addEventListener('click',populateSettings);
let deleteArmed=null;
const deleteButtons=()=>[$('delete-server'),$('header-delete-server')];
function disarmDelete(){clearTimeout(deleteArmed);deleteArmed=null;deleteButtons().forEach(b=>{b.textContent=b.dataset.label||b.textContent;});}
async function deleteSelectedServer(){
  const entry=selectedEntry;if(!entry)return;
  if(!deleteArmed){
    deleteButtons().forEach(b=>{b.dataset.label=b.textContent;b.textContent='Точно удалить?';});
    $('server-status').textContent='Удаляется только запись в приложении (панель, AmneziaWG и клиенты); сам сервер не затрагивается. Нажмите ещё раз для подтверждения.';
    deleteArmed=setTimeout(()=>{disarmDelete();$('server-status').textContent='';},5000);
    return;
  }
  disarmDelete();
  try { if(entry.host)await invoke('delete_host',{id:entry.host.id}); else await invoke('delete_server',{serverId:entry.panel.id}); $('server-status').textContent='Сервер удалён из приложения.'; await loadAll(); await selectEntry(entries[0]||null); renderInboundOptions(); }
  catch(e){$('server-status').textContent=`Не удалось удалить сервер: ${e}`;}
}
$('delete-server').addEventListener('click',deleteSelectedServer);
$('header-delete-server').addEventListener('click',deleteSelectedServer);
$('quick-edit').addEventListener('click',()=>{if(!selectedEntry)return;$('quick-name').value=selectedEntry.name;$('quick-country').value=selectedEntry.country||'';$('quick-edit-form').hidden=false;$('quick-name').focus();});
$('quick-cancel').addEventListener('click',()=>{$('quick-edit-form').hidden=true;});
$('quick-edit-form').addEventListener('submit',async e=>{e.preventDefault();const entry=selectedEntry;if(!entry)return;const button=e.currentTarget.querySelector('button[type="submit"]');button.disabled=true;
  const name=$('quick-name').value.trim(),country=$('quick-country').value||null;
  try{
    if(entry.host)await invoke('save_host',{id:entry.host.id,name,sshTarget:entry.host.ssh_target,sshKey:entry.host.ssh_key||null,country});
    if(entry.panel){const current=entry.panel;await invoke('save_server',{id:current.id,name,country,url:current.url,sshTarget:current.ssh_target||null,panelHost:current.panel_host||null,sshKey:current.ssh_key||null,token:''});}
    $('quick-edit-form').hidden=true;await window.reloadEntries(entry.key);$('server-status').textContent='Название и страна сохранены.';
  }catch(err){$('server-status').textContent=`Не удалось сохранить сервер: ${err}`;}finally{button.disabled=false;}});

function drawQr(canvas,result){const quiet=4,scale=4;canvas.width=canvas.height=(result.size+quiet*2)*scale;const ctx=canvas.getContext('2d');ctx.fillStyle='#fff';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle='#000';result.pixels.forEach((dark,i)=>{if(dark)ctx.fillRect((i%result.size+quiet)*scale,(Math.floor(i/result.size)+quiet)*scale,scale,scale);});}
async function showQr(p){if(!selectedServer)return;const id=selectedServer.id;$('client-share').hidden=true;$('client-qr').hidden=false;$('client-qr-svg').hidden=true;$('copy-conf').hidden=true;$('reveal-conf').hidden=true;try{const result=await invoke('client_qr',{serverId:id,inboundId:p.inbound_id,email:p.email});if(!selected(id))return;drawQr($('client-qr'),result);$('client-link').value=result.link;$('client-share').hidden=false;}catch(e){$('client-status').textContent=`Не удалось показать ссылку: ${e}`;}}
$('create-client-form').addEventListener('submit',async e=>{e.preventDefault();if($('client-inbound').value==='awg'){await window.awgUi.addClient($('client-name').value.trim());$('client-name').value='';return;}if(!selectedServer)return;const id=selectedServer.id,inboundId=Number($('client-inbound').value),email=$('client-name').value.trim();try{await invoke('create_client',{serverId:id,inboundId,email});if(!selected(id))return;$('client-name').value='';await refresh();const p=profiles.find(p=>p.inbound_id===inboundId&&p.email===email);if(p?.has_local_config)await showQr(p);else $('client-status').textContent='Клиент создан. Локальная ссылка пока недоступна.';}catch(e){$('client-status').textContent=`Не удалось создать клиента: ${e}`;}});
$('copy-link').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('client-link').value);$('client-status').textContent='Ссылка скопирована.';}catch{$('client-status').textContent='Не удалось скопировать ссылку.';}});$('close-share').addEventListener('click',()=>$('client-share').hidden=true);
let sshKeys=null;
let sshOrphans=[];
let defaultSshKey=null; // app-wide default key name (null = automatic)
async function loadSshKeys(){[sshKeys,sshOrphans,defaultSshKey]=await Promise.all([invoke('list_ssh_keys').catch(()=>[]),invoke('list_orphan_ssh_pubs').catch(()=>[]),invoke('get_default_ssh_key').then(k=>k||null).catch(()=>null)]);return sshKeys;}
// A .pub without its private half is a common leftover (only the public key was copied): explain why it is not in the list.
function showSshOrphans(el){el.textContent=sshOrphans.map(n=>`Найден ${n}.pub без приватного ключа, он не может использоваться для входа.`).join(' ');el.hidden=!sshOrphans.length;}
// The last key chosen in the wizard ('auto' = the automatic option) is offered again next time, if it still exists.
const LAST_SSH_KEY='vpn.admin.lastSshKey';
const LAST_WARP='vpn.admin.wizardWarp';
function rememberWarp(on){try{localStorage.setItem(LAST_WARP,on?'1':'0');}catch{}}
function recallWarp(){try{return localStorage.getItem(LAST_WARP)!=='0';}catch{return true;}}
function rememberSshKey(value){try{localStorage.setItem(LAST_SSH_KEY,value||'auto');}catch{}}
function recallSshKey(){try{return localStorage.getItem(LAST_SSH_KEY);}catch{return null;}}
function applyRememberedSshKey(select){const last=recallSshKey();if(last==='auto')select.value='';else if(last&&(sshKeys||[]).some(k=>k.name===last))select.value=last;}
// Options: automatic (the app key if present, else ssh defaults) + every ~/.ssh key that has a .pub. A saved key that vanished stays visible.
function fillSshKeySelect(select,current,preferApp){const keys=sshKeys||[];select.replaceChildren(new Option(defaultSshKey?`Ключ по умолчанию (${defaultSshKey})`:'Автоматически (ключ приложения или системный по умолчанию)',''));select.append(new Option('Системный ssh (как в терминале: agent и ключи по умолчанию)','@system'));for(const k of keys)select.append(new Option(`${k.name} · ${k.kind}${k.comment?' · '+k.comment:''}`,k.name));if(current&&!keys.some(k=>k.name===current))select.append(new Option(`${current} (не найден в ~/.ssh)`,current));select.value=current||(preferApp&&!defaultSshKey&&keys.some(k=>k.app_key)?keys.find(k=>k.app_key).name:'');}
// App settings: the default key used for servers that have no key of their own.
$('open-app-settings').addEventListener('click',async()=>{$('app-settings-status').textContent='';await loadSshKeys();fillDefaultKeySelect();showSshOrphans($('default-ssh-orphan'));$('app-settings-modal').hidden=false;});
function fillDefaultKeySelect(){const select=$('default-ssh-key'),keys=sshKeys||[];select.replaceChildren(new Option('Автоматически (ключ приложения или системный по умолчанию)',''));for(const k of keys)select.append(new Option(`${k.name} · ${k.kind}${k.comment?' · '+k.comment:''}`,k.name));if(defaultSshKey&&!keys.some(k=>k.name===defaultSshKey))select.append(new Option(`${defaultSshKey} (не найден в ~/.ssh)`,defaultSshKey));select.value=defaultSshKey||'';}
function closeAppSettings(){$('app-settings-modal').hidden=true;}
$('app-settings-close').addEventListener('click',closeAppSettings);
$('app-settings-modal').addEventListener('click',e=>{if(e.target===$('app-settings-modal'))closeAppSettings();});
$('app-settings-save').addEventListener('click',async()=>{const button=$('app-settings-save');button.disabled=true;try{const value=$('default-ssh-key').value||null;await invoke('set_default_ssh_key',{key:value});defaultSshKey=value;$('app-settings-status').textContent=value?`Ключ по умолчанию: ${value}`:'Выбран автоматический режим.';}catch(e){$('app-settings-status').textContent=`Не удалось сохранить: ${e}`;}finally{button.disabled=false;}});
function wizardPanel(){const url=$('wizard-url').value.trim(),sshTarget=installedTarget||null;return{name:$('wizard-name').value.trim(),url,ssh_target:sshTarget,panel_host:null,ssh_key:installedKey||null};}
function randomPath(){const bytes=crypto.getRandomValues(new Uint8Array(10));return'/'+Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');}
function defaultSni(target){const host=target.split('@').pop().replace(/:\d+$/,'');const match=host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);return match&&match.slice(1).every(n=>Number(n)<=255)?`${match.slice(1).join('-')}.sslip.io`:'';}
function renderWizard(){wizardSteps.forEach((step,i)=>$(step.element).hidden=i!==wizardIndex);$('wizard-indicator').textContent=`ШАГ ${wizardIndex+1} ИЗ 3`;$('wizard-title').textContent=wizardSteps[wizardIndex].title;$('wizard-back').disabled=wizardIndex===0||wizardRunning;$('wizard-next').textContent=wizardIndex===2?'Готово':'Далее';$('wizard-next').disabled=wizardRunning||(wizardIndex===0&&!installationSucceeded)||(wizardIndex===2&&!wizardClientCreated);$('wizard-cancel').disabled=wizardRunning;$('wizard-close').disabled=wizardRunning;$('wizard-install').disabled=wizardRunning||installationSucceeded;$('wizard-create-client').disabled=wizardRunning||wizardClientCreated;$('add-server').disabled=wizardRunning;$('wizard-modal').classList.toggle('busy',wizardRunning);}
function syncSshAuth(){const pw=$('wizard-ssh-auth').value==='password';$('wizard-ssh-password-box').hidden=!pw;$('wizard-ssh-key-hint').hidden=pw;}
$('wizard-ssh-auth').addEventListener('change',syncSshAuth);
$('wizard-ssh-keyfile').addEventListener('change',()=>rememberSshKey($('wizard-ssh-keyfile').value));
$('wizard-warp').addEventListener('change',()=>rememberWarp($('wizard-warp').checked));
async function openWizard(host){await loadSshKeys();fillSshKeySelect($('wizard-ssh-keyfile'),null,true);applyRememberedSshKey($('wizard-ssh-keyfile'));showSshOrphans($('wizard-ssh-orphan'));$('wizard-ssh-keyfile').disabled=false;installedKey=null;$('wizard-ssh-auth').value='key';$('wizard-ssh-password').value='';$('wizard-install-key').checked=true;$('wizard-warp').checked=recallWarp();syncSshAuth(); if(!inboundTemplates.length) await loadTemplates(); $('wizard-modal').hidden=false;wizardIndex=0;installationSucceeded=false;installedTarget=null;wizardInboundId=null;wizardClientCreated=false;wizardInbounds=[];wizardId=await invoke('new_wizard_id');for(const id of ['wizard-name','wizard-ssh','wizard-url','wizard-login','wizard-password','wizard-token','wizard-client-link'])$(id).value='';$('wizard-ssh').disabled=false;$('wizard-password').type='password';$('wizard-show-password').textContent='Показать пароль';$('wizard-country').value='';$('wizard-result').hidden=true;$('wizard-token-auto').hidden=true;$('wizard-token-label').hidden=false;$('wizard-client-result').hidden=true;$('wizard-log').textContent='';$('wizard-status').textContent='';$('wizard-inbound-choice').replaceChildren(new Option('Создать новый inbound','new'));applyTemplate('wizard');$('wizard-inbound-sni').value='';$('wizard-inbound-path').value='/';$('wizard-client-email').value='client-1';await invoke('clear_install').catch(()=>{});
  if(host){$('wizard-name').value=host.name;$('wizard-country').value=host.country||'';$('wizard-ssh').value=host.ssh_target;$('wizard-ssh').disabled=true;fillSshKeySelect($('wizard-ssh-keyfile'),host.ssh_key||null,false);$('wizard-ssh-keyfile').disabled=true;$('wizard-inbound-sni').value=defaultSni(host.ssh_target);}
  renderWizard(); }
function validateInstallStep(){if(!installationSucceeded||!installedTarget)throw new Error('Сначала успешно установите панель.');if(!$('wizard-name').value.trim()||!$('wizard-url').value.trim()||!$('wizard-token').value.trim())throw new Error('Укажите название, адрес панели и API-токен.');}
function validateInboundStep(){if($('wizard-inbound-choice').value==='new'){const port=Number($('wizard-inbound-port').value);if(!$('wizard-inbound-remark').value.trim())throw new Error('Укажите название inbound-а.');if(!Number.isInteger(port)||port<1||port>65535)throw new Error('Порт должен быть от 1 до 65535.');if(!$('wizard-inbound-sni').value.trim())throw new Error('Укажите SNI / домен для сертификата.');if(!$('wizard-inbound-path').value.startsWith('/'))throw new Error('Путь XHTTP должен начинаться с /.');}else if(!$('wizard-inbound-choice').value)throw new Error('Выберите inbound.');}
function validateClientStep(){if(!wizardClientCreated)throw new Error('Сначала создайте клиента и проверьте QR-код.');}
async function advanceFromInstall(){validateInstallStep();wizardRunning=true;renderWizard();try{await invoke('stage_wizard_token',{wizardId,token:$('wizard-token').value});wizardInbounds=await invoke('list_wizard_inbounds',{wizardId,panel:wizardPanel()});const select=$('wizard-inbound-choice');select.replaceChildren(new Option('Создать новый inbound','new'));for(const inbound of wizardInbounds){const opt=new Option(`${inbound.remark||'Inbound'} · ${inbound.protocol} · порт ${inbound.port}`,String(inbound.id));select.append(opt);}if(wizardInbounds.length){select.value=String(wizardInbounds[0].id);$('wizard-new-inbound').hidden=true;$('wizard-status').textContent='На панели уже есть inbound-ы. Выберите один из списка или создайте новый.';}else{$('wizard-new-inbound').hidden=false;$('wizard-status').textContent='Inbound-ов пока нет. Будет создан VLESS + XHTTP + TLS.';}wizardIndex=1;}finally{wizardRunning=false;renderWizard();}}
async function advanceFromInbound(){validateInboundStep();wizardRunning=true;wizardClientCreated=false;$('wizard-client-result').hidden=true;$('wizard-status').textContent=$('wizard-inbound-choice').value==='new'?'Получаем TLS-сертификат и создаём inbound…':'Выбираем существующий inbound…';renderWizard();try{if($('wizard-inbound-choice').value==='new'){const params={remark:$('wizard-inbound-remark').value.trim(),port:Number($('wizard-inbound-port').value),server_name:$('wizard-inbound-sni').value.trim(),path:$('wizard-inbound-path').value};wizardInboundId=await invoke('create_wizard_inbound',{wizardId,panel:wizardPanel(),target:installedTarget,templateId:$('wizard-template').value,params});$('wizard-status').textContent='Inbound создан.';}else wizardInboundId=Number($('wizard-inbound-choice').value);if(!wizardInboundId)throw new Error('Не удалось определить ID inbound-а.');wizardIndex=2;}finally{wizardRunning=false;renderWizard();}}
async function finishWizard(){validateClientStep();wizardRunning=true;$('wizard-status').textContent='Сохраняем сервер и обновляем список клиентов…';renderWizard();try{const server=await invoke('save_wizard_server',{wizardId,panel:wizardPanel(),country:$('wizard-country').value||null});wizardId=null;let warpNote='';if($('wizard-warp').checked){$('wizard-status').textContent='Включаем WARP на сервере (до минуты)…';try{await invoke('enable_server_warp',{serverId:server.id});warpNote=' ✓ WARP включён: трафик выходит через Cloudflare.';}catch(e){warpNote=` WARP не включён: ${e}. Сервер при этом сохранён; включить WARP можно позже в настройках сервера.`;}}$('wizard-modal').hidden=true;$('wizard-token').value='';$('wizard-password').value='';$('wizard-login').value='';await invoke('clear_install').catch(()=>{});await loadAll();await selectEntry(entries.find(e=>e.panel?.id===server.id)||null);$('server-status').textContent='Сервер, inbound и клиент сохранены.'+warpNote;await refresh();}catch(e){$('wizard-status').textContent=`Не удалось завершить мастер: ${e}`;}finally{wizardRunning=false;renderWizard();}}
$('add-server').addEventListener('click',()=>openHostDialog().catch(e=>{$('server-status').textContent=`Не удалось открыть окно: ${e}`;}));
$('deploy-3xui').addEventListener('click',()=>{const e=selectedEntry;if(e?.host)openWizard(e.host).catch(err=>{$('server-status').textContent=`Не удалось открыть мастер: ${err}`;});});
$('deploy-awg').addEventListener('click',()=>{const e=selectedEntry;if(e?.host)window.awgUi.openInstall(e);});
// Adding a server only records how to reach it; 3x-ui or AmneziaWG is deployed afterwards.
async function openHostDialog(){
  await loadSshKeys();fillSshKeySelect($('host-key'),null,true);applyRememberedSshKey($('host-key'));
  $('host-name').value='';$('host-ssh').value='';$('host-country').value='';$('host-status').textContent='';$('host-modal').hidden=false;$('host-name').focus();
}
function closeHostDialog(){$('host-modal').hidden=true;}
$('host-close').addEventListener('click',closeHostDialog);$('host-cancel').addEventListener('click',closeHostDialog);
$('host-form').addEventListener('submit',async e=>{
  e.preventDefault();const button=e.currentTarget.querySelector('button[type="submit"]');button.disabled=true;$('host-status').textContent='';
  try{
    rememberSshKey($('host-key').value);
    const host=await invoke('save_host',{id:null,name:$('host-name').value,sshTarget:$('host-ssh').value.trim(),sshKey:$('host-key').value||null,country:$('host-country').value||null});
    closeHostDialog();await window.reloadEntries(host.id);$('server-status').textContent='Сервер добавлен. Теперь выберите, что на него установить.';
  }catch(err){$('host-status').textContent=`${err}`;}finally{button.disabled=false;}
});
$('wizard-install').addEventListener('click',async()=>{const target=$('wizard-ssh').value.trim();if(!$('wizard-name').value.trim()||!/^root@[A-Za-z0-9._-]+(:\d+)?$/.test(target)){$('wizard-status').textContent='Укажите название и SSH-цель в формате root@хост или root@хост:порт.';return;}const sshPort=target.match(/:(\d+)$/);if(sshPort&&(+sshPort[1]<1||+sshPort[1]>65535)){$('wizard-status').textContent='SSH-порт должен быть от 1 до 65535.';return;}wizardRunning=true;installationSucceeded=false;$('wizard-result').hidden=true;$('wizard-status').textContent='';$('wizard-log').textContent='Подготавливаем установку…';renderWizard();let poll;const update=async()=>{const state=await invoke('install_progress');$('wizard-log').textContent=state.log.join('\n');$('wizard-log').scrollTop=$('wizard-log').scrollHeight;return state;};try{const usePassword=$('wizard-ssh-auth').value==='password';const sshPassword=usePassword?$('wizard-ssh-password').value:'';if(usePassword&&!sshPassword){$('wizard-status').textContent='Введите SSH-пароль.';wizardRunning=false;renderWizard();return;}const selectedKey=$('wizard-ssh-keyfile').value;rememberSshKey(selectedKey);const operation=invoke('install_panel',{target,password:usePassword?sshPassword:null,installKey:usePassword&&$('wizard-install-key').checked,sshKey:selectedKey||null});if(usePassword)$('wizard-ssh-password').value='';poll=setInterval(()=>update().catch(()=>{}),500);await operation;const state=await update();if(!state.finished||!state.success)throw new Error('Установка не завершилась успешно. Подробности приведены в журнале.');installationSucceeded=true;installedTarget=target;installedKey=state.ssh_key||selectedKey||null;$('wizard-ssh').disabled=true;$('wizard-ssh-keyfile').disabled=true;let panelUrl=state.url||'';if(panelUrl){const parsed=new URL(panelUrl);if(parsed.protocol==='http:'){parsed.hostname='127.0.0.1';panelUrl=parsed.toString();$('wizard-url-hint').textContent=state.token?(state.local_only?'Панель закрыта от интернета: приложение управляет ею через SSH-туннель.':''):`Для входа в панель создайте SSH-туннель: ssh -L ${parsed.port}:127.0.0.1:${parsed.port} ${target} -N, затем откройте адрес панели.`;}else $('wizard-url-hint').textContent='';}else $('wizard-url-hint').textContent='Установщик не сообщил адрес. Укажите адрес панели вручную.';$('wizard-url').value=panelUrl;$('wizard-login').value=state.username||'';$('wizard-password').value=state.password||'';$('wizard-token').value=state.token||'';$('wizard-token-auto').hidden=!state.token;$('wizard-token-label').hidden=!!state.token;const sni=defaultSni(target);$('wizard-inbound-sni').value=sni;if(sni){$('wizard-log').textContent+=`\n✓ Домен для сертификата: ${sni} (sslip.io, из IP сервера)`;}if(installedKey){$('wizard-log').textContent+=`\n✓ SSH-ключ сервера: ${installedKey} (запомнен для управления панелью)`;}$('wizard-log').scrollTop=$('wizard-log').scrollHeight;$('wizard-result').hidden=false;$('wizard-status').textContent=state.token?'Установка завершена. Нажмите «Далее».':'Установка завершена. Вставьте API-токен и нажмите «Далее».';}catch(e){try{await update();}catch{}$('wizard-status').textContent=`Установка не выполнена: ${e}`;}finally{clearInterval(poll);wizardRunning=false;renderWizard();}});
$('wizard-create-client').addEventListener('click',async()=>{const email=$('wizard-client-email').value.trim();if(!/^[A-Za-z0-9@._+-]{1,128}$/.test(email)){$('wizard-status').textContent='Введите корректное имя клиента.';return;}if(!wizardInboundId){$('wizard-status').textContent='Сначала выберите или создайте inbound.';return;}wizardRunning=true;$('wizard-status').textContent='Создаём клиента и формируем QR…';renderWizard();try{await invoke('create_wizard_client',{wizardId,panel:wizardPanel(),inboundId:wizardInboundId,email});const result=await invoke('wizard_client_qr',{wizardId,panel:wizardPanel(),inboundId:wizardInboundId,email});drawQr($('wizard-client-qr'),result);$('wizard-client-link').value=result.link;$('wizard-client-result').hidden=false;wizardClientCreated=true;$('wizard-status').textContent='Клиент создан. Проверьте QR-код и нажмите «Готово».';}catch(e){$('wizard-status').textContent=`Не удалось создать клиента: ${e}`;}finally{wizardRunning=false;renderWizard();}});
$('wizard-inbound-choice').addEventListener('change',()=>{$('wizard-new-inbound').hidden=$('wizard-inbound-choice').value!=='new';$('wizard-status').textContent='';});
$('wizard-back').addEventListener('click',()=>{if(wizardIndex>0&&!wizardRunning){wizardIndex--;wizardClientCreated=false;$('wizard-client-result').hidden=true;$('wizard-status').textContent='';renderWizard();}});
$('wizard-next').addEventListener('click',async()=>{try{await wizardSteps[wizardIndex].next();}catch(e){$('wizard-status').textContent=`Не удалось продолжить: ${e}`;wizardRunning=false;renderWizard();}});
async function closeWizard(){if(wizardRunning)return;$('wizard-ssh-password').value='';const id=wizardId;wizardId=null;$('wizard-modal').hidden=true;$('wizard-token').value='';$('wizard-password').value='';$('wizard-login').value='';if(id)await invoke('clear_wizard_token',{wizardId:id}).catch(()=>{});await invoke('clear_install').catch(()=>{});}
$('wizard-cancel').addEventListener('click',closeWizard);$('wizard-close').addEventListener('click',closeWizard);$('wizard-show-password').addEventListener('click',()=>{const f=$('wizard-password');f.type=f.type==='password'?'text':'password';$('wizard-show-password').textContent=f.type==='text'?'Скрыть пароль':'Показать пароль';});

let inboundTemplates=[];
function applyTemplate(prefix) { const t=inboundTemplates.find(t=>t.id===$(prefix==='wizard'?'wizard-template':'admin-template').value); if(!t)return; $(prefix+'-inbound-remark').value=t.remark; $(prefix+'-inbound-port').value=t.port; $(prefix+'-inbound-path').value=t.path; }
async function loadTemplates(){ inboundTemplates=await invoke('list_inbound_templates'); for(const id of ['wizard-template','admin-template']) { const select=$(id); select.replaceChildren(...inboundTemplates.map(t=>new Option(t.name,t.id))); } applyTemplate('wizard');applyTemplate('admin'); }
$('wizard-template').addEventListener('change',()=>applyTemplate('wizard'));
$('admin-template').addEventListener('change',()=>applyTemplate('admin'));
$('wizard-random-path').addEventListener('click',()=>$('wizard-inbound-path').value=randomPath());
$('admin-random-path').addEventListener('click',()=>$('admin-inbound-path').value=randomPath());
$('open-inbound-template').addEventListener('click',()=>{ if(!selectedServer){$('inbound-template-status').textContent='Выберите сервер.';return;} $('inbound-template-form').hidden=false; applyTemplate('admin'); $('admin-inbound-sni').value=defaultSni(selectedServer.ssh_target||'')||''; });
$('inbound-template-form').addEventListener('submit',async e=>{e.preventDefault();if(!selectedServer)return;const id=selectedServer.id, button=e.currentTarget.querySelector('button[type="submit"]');button.disabled=true;$('inbound-template-status').textContent='Получаем сертификат и создаём inbound…';try{await invoke('create_server_inbound',{serverId:id,templateId:$('admin-template').value,params:{remark:$('admin-inbound-remark').value.trim(),port:Number($('admin-inbound-port').value),server_name:$('admin-inbound-sni').value.trim(),path:$('admin-inbound-path').value}});$('inbound-template-status').textContent='Inbound создан.';if(selected(id))await refresh();}catch(err){$('inbound-template-status').textContent=`Не удалось создать inbound: ${err}`;}finally{button.disabled=false;}});
loadTemplates().catch(e=>{$('server-status').textContent=`Не удалось загрузить шаблоны: ${e}`;});
loadAll().then(()=>{renderServers();renderServerHeader();renderInboundOptions();renderProfiles();renderInbounds();if(entries.length)selectEntry(entries[0]);}).catch(e=>{$('server-status').textContent=`Не удалось загрузить серверы: ${e}`;});
let syncingServers=false;
async function syncServers(){
  if(syncingServers||document.hidden||!$('host-modal').hidden||!$('awg-install-modal').hidden||wizardRunning)return;
  syncingServers=true;
  try{
    const before=JSON.stringify([hosts,servers,awgServers]);
    const [h,sv,aw]=await Promise.all([invoke('list_hosts').catch(()=>hosts),invoke('list_servers'),invoke('awg_list_servers').catch(()=>awgServers)]);
    if(JSON.stringify([h,sv,aw])===before)return;
    await window.reloadEntries(selectedEntry?.key);
  }catch(e){$('server-status').textContent=`Не удалось обновить серверы: ${e}`;}finally{syncingServers=false;}
}
window.addEventListener('focus',syncServers);
setInterval(syncServers,5000);

// Server exit: Cloudflare WARP on/off (two-step confirmation, like inbound deletion).
let warpArmed=false,warpTimer=null;
function warpUi(state,text,label){const box=$('warp-box');box.hidden=!selectedServer;$('warp-state').textContent=text;const b=$('warp-toggle');b.textContent=label;b.dataset.state=state;b.disabled=state==='unknown'||state==='busy';}
async function refreshWarp(){
  clearTimeout(warpTimer);warpArmed=false;
  if(!selectedServer){$('warp-box').hidden=true;return;}
  const id=selectedServer.id;warpUi('unknown','Проверяем…','…');
  try{const on=await invoke('server_warp_status',{serverId:id});if(!selected(id))return;warpUi(on?'on':'off',on?'Через Cloudflare WARP: сайты видят адрес Cloudflare, а не сервера.':'С адреса сервера: сайты (например, ipify) видят IP входа.',on?'Отключить WARP':'Включить WARP');}
  catch(e){if(selected(id))warpUi('unknown',`Не удалось определить: ${e}`,'…');}
}
$('warp-toggle').addEventListener('click',async()=>{
  const button=$('warp-toggle');if(!selectedServer||button.disabled)return;
  const id=selectedServer.id,enable=button.dataset.state==='off';
  if(!warpArmed){
    warpArmed=true;button.textContent=enable?'Точно включить?':'Точно отключить?';
    $('warp-state').textContent=enable?'Панель зарегистрирует WARP и перезапустит Xray: активные подключения через этот сервер оборвутся на несколько секунд. Нажмите ещё раз для подтверждения.':'Панель уберёт WARP и перезапустит Xray: подключения оборвутся на несколько секунд, сайты снова будут видеть адрес сервера. Нажмите ещё раз.';
    warpTimer=setTimeout(()=>{if(selected(id))refreshWarp();},5000);return;
  }
  clearTimeout(warpTimer);warpArmed=false;warpUi('busy','Применяем настройки панели (до минуты)…',button.textContent);
  try{const message=await invoke(enable?'enable_server_warp':'disable_server_warp',{serverId:id});if(selected(id))$('server-status').textContent=message;}
  catch(e){if(selected(id))$('server-status').textContent=`WARP: ${e}`;}
  if(selected(id))await refreshWarp();
});

// Esc closes the topmost open dialog through its own close/cancel button (so running operations stay protected).
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape' || e.defaultPrevented) return;
  const open = [...document.querySelectorAll('.modal')].filter(m => !m.hidden);
  const top = open[open.length - 1]; if (!top) return;
  const button = top.querySelector('.close-button'); if (!button || button.disabled) return;
  e.preventDefault(); button.click();
});

$('open-import').addEventListener('click', () => { $('import-status').textContent=''; $('import-modal').hidden=false; });
$('import-close').addEventListener('click', () => { $('import-modal').hidden=true; });
$('import-form').addEventListener('submit', async event => { event.preventDefault(); const button=event.submitter; button.disabled=true; $('import-status').textContent=''; try { const added=await invoke('import_profiles',{text:$('import-text').value,name:$('import-name').value.trim() || null}); $('import-text').value=''; $('import-name').value=''; $('import-status').textContent=`Импортировано: ${added.length}`; } catch (error) { $('import-status').textContent=String(error); } finally { button.disabled=false; } });
