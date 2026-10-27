const invoke = window.__TAURI_INTERNALS__.invoke;
const panelStatus = document.getElementById('panel-status');
const pendingStatus = document.getElementById('pending-status');
const nameField = document.getElementById('name');
const urlField = document.getElementById('url');
const tokenField = document.getElementById('token');
const sshField = document.getElementById('ssh-target');
const hostField = document.getElementById('panel-host');
const profileList = document.getElementById('profiles');
const toggle = document.getElementById('vpn-toggle');
const connectionError = document.getElementById('connection-error');
let profiles = [], selectedProfile = null, connected = false, connectionMode = 'off', pendingClient = null, operationInProgress = false;
function canConnect(profile) { return !!profile && profile.enabled && profile.inbound_enabled && profile.protocol === 'vless' && profile.transport === 'xhttp' && profile.has_local_config; }
function setConnectionState(mode) {
  connectionMode = typeof mode === 'boolean' ? (mode ? 'proxy' : 'off') : mode;
  connected = connectionMode !== 'off';
  const pill = document.getElementById('connection-state'); pill.dataset.state = connected ? 'on' : 'off';
  document.getElementById('connection-label').textContent = connectionMode === 'tun' ? 'TUN подключён' : connectionMode === 'proxy' ? 'Прокси подключён' : 'Отключено';
  document.getElementById('connection-heading').textContent = connectionMode === 'tun' ? 'Глобальный TUN включён' : connectionMode === 'proxy' ? 'Старый режим прокси' : 'Готовы к работе';
  toggle.dataset.connected = String(connected); toggle.setAttribute('aria-pressed', String(connected));
  document.getElementById('toggle-label').textContent = connectionMode === 'tun' ? 'Отключить' : connectionMode === 'proxy' ? 'Переключить на TUN' : 'Подключить';
  document.querySelector('.toggle-symbol').textContent = connectionMode === 'tun' ? '×' : connectionMode === 'proxy' ? '↗' : '↗';
  toggle.disabled = operationInProgress || (!connected && !canConnect(selectedProfile));
  document.querySelectorAll('.profile-row').forEach(row => { row.disabled = connected || row.dataset.usable !== 'true'; });
  document.querySelector('footer').dataset.connected = String(connectionMode === 'tun');
  document.getElementById('proxy-indicator').textContent = connectionMode === 'tun' ? 'Глобальный TUN активен' : connectionMode === 'proxy' ? 'Старый локальный SOCKS-прокси активен' : 'Глобальный TUN выключен';
  if (selectedProfile) document.getElementById('active-profile-label').textContent = `${selectedProfile.email} · ${selectedProfile.inbound_name}`;
}

function renderProfiles() {
  profileList.replaceChildren();
  if (!profiles.length) {
    const empty = document.createElement('p'); empty.className = 'empty-state'; empty.textContent = 'Профили не найдены. Проверьте панель в разделе «Настройки панели и управление».';
    profileList.appendChild(empty); selectedProfile = null; document.getElementById('active-profile-label').textContent = 'Нет доступных конфигураций'; toggle.disabled = true; return;
  }
  if (!selectedProfile || !profiles.some(p => p.inbound_id === selectedProfile.inbound_id && p.email === selectedProfile.email)) selectedProfile = profiles.find(p => p.email === 'vpn-client-test' && p.inbound_id === 6) || profiles[0];
  profiles.forEach(profile => {
    const usable = canConnect(profile); const row = document.createElement('button'); row.type = 'button'; row.className = 'profile-row'; row.dataset.usable = String(usable); row.disabled = connected || !usable; row.setAttribute('aria-pressed', String(selectedProfile === profile));
    const radio = document.createElement('span'); radio.className = 'profile-radio'; const main = document.createElement('span'); main.className = 'profile-main';
    const name = document.createElement('span'); name.className = 'profile-name'; name.textContent = profile.email;
    const meta = document.createElement('span'); meta.className = 'profile-meta'; meta.textContent = `${profile.inbound_name} · порт ${profile.port}`; main.append(name, meta);
    const tag = document.createElement('span'); tag.className = 'profile-tag'; tag.textContent = usable ? 'VLESS · XHTTP' : 'Недоступно'; row.append(radio, main, tag);
    row.addEventListener('click', () => { if (!connected && usable) { selectedProfile = profile; renderProfiles(); setConnectionState(false); } }); profileList.appendChild(row);
  });
  document.getElementById('active-profile-label').textContent = `${selectedProfile.email} · ${selectedProfile.inbound_name}`; toggle.disabled = operationInProgress || (!connected && !canConnect(selectedProfile));
}
async function loadCachedProfiles() {
  profileList.innerHTML = '<p class="empty-state">Загружаем локальные конфигурации…</p>';
  try { profiles = await invoke('list_client_profiles'); renderProfiles(); }
  catch (error) { profiles = []; renderProfiles(); panelStatus.textContent = String(error).includes('No panel configured') ? 'Сначала сохраните панель 3x-ui.' : String(error); }
}
invoke('get_panel').then(panel => { if (panel) { nameField.value = panel.name; urlField.value = panel.url; sshField.value = panel.ssh_target || ''; hostField.value = panel.panel_host || ''; } }).catch(error => { panelStatus.textContent = String(error); });
invoke('build_info').then(text => { document.getElementById('build-info').textContent = text; }).catch(() => { document.getElementById('build-info').textContent = 'сборка неизвестна'; });
invoke('get_vpn_mode').then(mode => { if (!operationInProgress) setConnectionState(mode); }).catch(() => { if (!operationInProgress) setConnectionState('off'); }); loadCachedProfiles();
async function refreshProfiles() {
  const button = document.getElementById('refresh-profiles'); button.disabled = true;
  document.getElementById('connection-message').textContent = 'Обновляем профили из 3x-ui…';
  try { profiles = await invoke('refresh_client_profiles'); renderProfiles(); document.getElementById('connection-message').textContent = 'Профили сохранены локально. Для подключения Keychain больше не нужен.'; }
  catch (error) { document.getElementById('connection-message').textContent = `Не удалось обновить профили: ${String(error)}`; }
  finally { button.disabled = false; }
}
document.getElementById('refresh-profiles').addEventListener('click', refreshProfiles);
document.getElementById('form').addEventListener('submit', async event => {
  event.preventDefault(); panelStatus.textContent = 'Сохраняем…';
  try { await invoke('save_panel', {name:nameField.value,url:urlField.value,token:tokenField.value,sshTarget:sshField.value.trim()||null,panelHost:hostField.value.trim()||null}); tokenField.value=''; panelStatus.textContent='Панель сохранена. Чтобы загрузить профили, нажмите ↻.'; }
  catch (error) { panelStatus.textContent = String(error); }
});
document.getElementById('refresh').addEventListener('click', async () => { panelStatus.textContent='Проверяем панель…'; try { profiles = await invoke('refresh_client_profiles'); renderProfiles(); panelStatus.textContent='Панель доступна, профили сохранены локально.'; } catch(error) { panelStatus.textContent=String(error); } });
toggle.addEventListener('click', async () => {
  if (operationInProgress) return;
  operationInProgress=true; toggle.disabled=true; toggle.setAttribute('aria-busy', 'true');
  connectionError.hidden=true; connectionError.textContent='';
  const message=document.getElementById('connection-message'); let connecting=false;
  if (connectionMode !== 'tun') document.getElementById('toggle-label').textContent='Подключаем…';
  try {
    if (connectionMode === 'tun') {
      message.textContent='Отключаем TUN и восстанавливаем исходный DNS…';
      await invoke('xray_stop'); setConnectionState('off'); message.textContent='VPN отключён. Исходные настройки DNS восстановлены.';
    } else {
      if (connectionMode === 'proxy') {
        message.textContent='Останавливаем старый SOCKS-прокси…';
        await invoke('xray_stop'); setConnectionState('off');
      }
      if (selectedProfile) {
        connecting=true;
        document.getElementById('toggle-label').textContent='Подключаем…';
        message.textContent='Подключаем TUN. Для установки или обновления системного компонента может потребоваться пароль администратора.';
        const result=await invoke('connect_profile',{inboundId:selectedProfile.inbound_id,email:selectedProfile.email});
        setConnectionState('tun'); message.textContent=result;
      }
    }
  } catch(error) {
    setConnectionState(connecting ? 'off' : await invoke('get_vpn_mode').catch(() => 'off'));
    message.textContent=connecting ? 'VPN не подключён.' : 'Не удалось отключить VPN.';
    connectionError.textContent=`Не удалось выполнить действие: ${String(error)}`;
    connectionError.hidden=false;
  }
  finally { operationInProgress=false; toggle.removeAttribute('aria-busy'); setConnectionState(connectionMode); }
});

async function refreshPendingClient() {
  try { pendingClient=await invoke('pending_client'); document.getElementById('pending-client').textContent=pendingClient?`Панель: ${pendingClient.panel_name} · подключение: ${pendingClient.inbound_name} (#${pendingClient.inbound_id}) · клиент: ${pendingClient.email}`:'Нет запросов на подтверждение.'; document.getElementById('approve-client').disabled=!pendingClient; document.getElementById('cancel-client').disabled=!pendingClient; }
  catch(error) { pendingStatus.textContent=String(error); }
}
refreshPendingClient();
document.getElementById('prepare-test-client').addEventListener('click',async()=>{try{await invoke('prepare_test_client');await refreshPendingClient();pendingStatus.textContent='Запрос подготовлен. Создание клиента требует подтверждения.';}catch(error){pendingStatus.textContent=String(error);}});
document.getElementById('approve-client').addEventListener('click',async()=>{if(!pendingClient)return;const button=document.getElementById('approve-client');button.disabled=true;pendingStatus.textContent=`Создаём ${pendingClient.email}…`;try{pendingStatus.textContent=await invoke('approve_pending_client',{inboundId:pendingClient.inbound_id,email:pendingClient.email});await refreshPendingClient();}catch(error){pendingStatus.textContent=`Не удалось создать клиента: ${String(error)}`;}finally{button.disabled=!pendingClient;}});
document.getElementById('cancel-client').addEventListener('click',async()=>{try{await invoke('cancel_pending_client');pendingStatus.textContent='Запрос отклонён.';await refreshPendingClient();}catch(error){pendingStatus.textContent=String(error);}});
