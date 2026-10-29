// Browser-only stand-in for the Tauri backend. Never shipped: only scripts/dev-ui.py injects it.
// Commands that are not mocked reject loudly so gaps are visible while developing the UI.
(() => {
  const delay = (ms = 250) => new Promise(r => setTimeout(r, ms));
  const params = new URLSearchParams(location.search);
  const fail = name => params.get('fail') === name; // e.g. ?fail=connect_profile to test error states

  const servers = [
    {id: 'a'.repeat(32), name: 'Амстердам', country: 'NL', url: 'https://panel.nl.example.net:2053/secret/', ssh_target: 'root@nl.example.net', panel_host: null},
    {id: 'b'.repeat(32), name: 'Хельсинки', country: 'FI', url: 'http://127.0.0.1:28004/path/', ssh_target: 'root@fi.example.net', panel_host: 'fi.example.net'},
    {id: 'c'.repeat(32), name: 'Без страны', country: null, url: 'https://203.0.113.7:54321/x/', ssh_target: null, panel_host: null},
  ];
  const wizardTokens = new Map(), wizardInboundMap = new Map(), wizardProfileMap = new Map();
  const savedInboundMap = new Map(), savedProfileMap = new Map();
  let wizardSequence = 1, inboundSequence = 10;
  const defaultInbounds = id => [
    {id: 1, remark: 'xhttp-443', port: 443, protocol: 'vless', enable: true, transport: 'xhttp'},
    {id: 2, remark: 'tcp-reality', port: 8443, protocol: 'vless', enable: true, transport: 'tcp'},
  ].map(i => ({...i, server_id: id}));
  const inbounds = id => savedInboundMap.get(id) || defaultInbounds(id);
  const profile = (email, inbound, usable = true) => ({
    inbound_id: inbound.id, inbound_name: inbound.remark, port: inbound.port, protocol: inbound.protocol,
    transport: inbound.transport, inbound_enabled: inbound.enable, email, enabled: true,
    share_link: usable ? `vless://00000000-0000-0000-0000-000000000000@example.net:${inbound.port}?type=xhttp&security=tls#${email}` : null,
    has_local_config: usable,
  });
  const profilesFor = id => {
    if (savedProfileMap.has(id)) return savedProfileMap.get(id);
    const [x, t] = inbounds(id);
    return [profile('alice', x), profile('bob', x), profile('laptop', t, false)];
  };

  let pinnedProfiles = JSON.parse(localStorage.getItem('vpn.dev.pinnedProfiles') || 'null');
  const readPins = () => { pinnedProfiles = JSON.parse(localStorage.getItem('vpn.dev.pinnedProfiles') || 'null'); return pinnedProfiles; };
  const savePins = () => localStorage.setItem('vpn.dev.pinnedProfiles', JSON.stringify(pinnedProfiles));
  const usable = p => p.enabled && p.inbound_enabled && p.protocol === 'vless' && p.transport === 'xhttp' && p.has_local_config;
  const allKeys = () => servers.flatMap(s => profilesFor(s.id).filter(usable).map(p => ({server_id:s.id,inbound_id:p.inbound_id,email:p.email})));
  const sameKey = (a,b) => a.server_id===b.server_id && a.inbound_id===b.inbound_id && a.email===b.email;
  let mode = 'off';
  let install = {running: false, finished: false, success: false, log: [], url: null, username: null, password: null, token: null};
  const installScript = [
    'Подключаюсь по SSH…', 'Скачиваю установщик 3x-ui…', 'Устанавливаю зависимости…',
    'Генерирую учётные данные панели…', 'Запускаю x-ui.service…', 'Установка завершена.',
  ];

  const handlers = {
    build_info: () => 'v0.0.0-dev · mock',
    get_vpn_mode: () => mode,
    list_servers: () => servers,
    list_connectable_profiles: () => (readPins(), servers.flatMap(server => profilesFor(server.id).filter(p => usable(p) && (pinnedProfiles === null || pinnedProfiles.some(k=>sameKey(k,{server_id:server.id,inbound_id:p.inbound_id,email:p.email})))).map(p => ({...p, server_id:server.id, server_name:server.name, country:server.country})))),
    list_pinned_profiles: () => { readPins(); return pinnedProfiles === null ? null : pinnedProfiles.map(k=>({...k})); },
    set_profile_pinned: ({serverId,inboundId,email,pinned}) => { if(fail('set_profile_pinned')) throw 'Не удалось изменить отметку (mock)'; readPins(); const key={server_id:serverId,inbound_id:inboundId,email}, all=allKeys(); if(pinned && !all.some(k=>sameKey(k,key))) throw 'Клиент недоступен'; if(pinnedProfiles===null) pinnedProfiles=all; pinnedProfiles=pinnedProfiles.filter(k=>!sameKey(k,key)); if(pinned) pinnedProfiles.push(key); savePins(); return null; },
    open_admin: () => null,
    panel_hostname: ({url}) => { try { return new URL(url).hostname; } catch { throw 'Некорректный адрес панели'; } },
    save_server: ({id, name, url, country, sshTarget, panelHost, token}) => {
      if (fail('save_server')) throw 'Не удалось сохранить сервер';
      if (id && !servers.some(server => server.id === id)) throw 'Сервер не найден';
      if (!id && !token?.trim()) throw 'Укажите API-токен';
      const saved = {id: id || 'd'.repeat(32), name, url, country: country || null, ssh_target: sshTarget || null, panel_host: panelHost || null};
      const index = servers.findIndex(server => server.id === saved.id);
      if (index < 0) servers.push(saved); else servers[index] = saved;
      return saved;
    },
    delete_server: ({serverId}) => { readPins(); if(pinnedProfiles!==null) { pinnedProfiles=pinnedProfiles.filter(k=>k.server_id!==serverId); savePins(); } const index = servers.findIndex(server => server.id === serverId); if (index >= 0) servers.splice(index, 1); return null; },
    list_inbound_templates: () => [{id:'VLESS-XHTTP-443',name:'VLESS-XHTTP-443',description:'VLESS, XHTTP и TLS',remark:'VLESS-XHTTP-443',port:443,path:'/'},{id:'VLESS-VISION-8443',name:'VLESS-VISION-8443',description:'VLESS, TCP и TLS (Vision)',remark:'VLESS-VISION-8443',port:8443,path:'/'}],
    create_server_inbound: ({serverId,templateId,params:data}) => { if(fail('create_server_inbound')) throw 'Не удалось создать inbound (mock)'; const created={id:inboundSequence++,remark:data.remark,port:data.port,protocol:'vless',enable:true,transport:templateId==='VLESS-VISION-8443'?'tcp':'xhttp'}; savedInboundMap.set(serverId,[...inbounds(serverId),created]); return created.id; },
    new_wizard_id: () => { if (fail('new_wizard_id')) throw 'Не удалось подготовить мастер (mock)'; const id = String(wizardSequence++).padStart(32, '0'); wizardInboundMap.set(id, []); wizardProfileMap.set(id, []); return id; },
    stage_wizard_token: ({wizardId, token}) => { if (fail('stage_wizard_token')) throw 'Не удалось сохранить токен в Keychain (mock)'; wizardTokens.set(wizardId, token); return null; },
    clear_wizard_token: ({wizardId}) => { if (fail('clear_wizard_token')) throw 'Не удалось удалить временный токен (mock)'; wizardTokens.delete(wizardId); return null; },
    list_wizard_inbounds: ({wizardId}) => {
      if (fail('list_wizard_inbounds')) throw 'Не удалось загрузить inbound-ы панели (mock)';
      if (params.get('existing_inbounds') === '1') { wizardInboundMap.set(wizardId, defaultInbounds(wizardId)); return defaultInbounds(wizardId); }
      return wizardInboundMap.get(wizardId) || [];
    },
    create_wizard_inbound: ({wizardId, templateId, params: data}) => {
      if (fail('create_wizard_inbound')) throw 'Не удалось выпустить TLS-сертификат: проверьте DNS и доступность порта 80 (mock)';
      const created = {id: inboundSequence++, remark:data.remark, port:data.port, protocol:'vless', enable:true, transport:templateId==='VLESS-VISION-8443'?'tcp':'xhttp', server_id:wizardId};
      wizardInboundMap.set(wizardId, [...(wizardInboundMap.get(wizardId)||[]), created]); return created.id;
    },
    create_wizard_client: ({wizardId, inboundId, email}) => {
      if (fail('create_wizard_client')) throw 'Не удалось создать клиента (mock)';
      const inbound = [...defaultInbounds(wizardId), ...(wizardInboundMap.get(wizardId)||[])].find(i => i.id === inboundId);
      if (!inbound) throw 'Inbound не найден';
      wizardProfileMap.set(wizardId, [...(wizardProfileMap.get(wizardId)||[]), profile(email, inbound)]); return `Клиент ${email} создан (mock)`;
    },
    wizard_client_qr: () => { if (fail('wizard_client_qr')) throw 'Не удалось получить ссылку клиента (mock)'; const size=25; return {link:'vless://mock-wizard-profile',size,pixels:Array.from({length:size*size},(_,i)=>((i*7+(i>>3))%3)===0)}; },
    save_wizard_server: ({wizardId, panel, country}) => {
      if (fail('save_wizard_server')) throw 'Не удалось сохранить сервер (mock)';
      const saved={id:wizardId,name:panel.name,url:panel.url,ssh_target:panel.ssh_target,panel_host:panel.panel_host,country:country||null};
      servers.push(saved); savedInboundMap.set(saved.id,wizardInboundMap.get(wizardId)||[]); savedProfileMap.set(saved.id,wizardProfileMap.get(wizardId)||[]); wizardTokens.delete(wizardId); return saved;
    },
    cached_server_inbounds: ({serverId}) => inbounds(serverId),
    list_inbounds: ({serverId}) => inbounds(serverId),
    list_client_profiles: ({serverId}) => profilesFor(serverId),
    refresh_client_profiles: ({serverId}) => profilesFor(serverId),
    create_client: ({email}) => `Клиент ${email} создан (mock)`,
    client_qr: () => { const size = 25; return {link: 'vless://mock', size, pixels: Array.from({length: size * size}, (_, i) => ((i * 7 + (i >> 3)) % 3) === 0)}; },
    connect_profile: async () => { if (fail('connect_profile')) throw 'VPN запущен, но трафик через сервер не проходит: DNS и TCP недоступны.'; await delay(1200); mode = 'tun'; return 'VPN подключён через utun10 (mock)'; },
    xray_stop: () => { mode = 'off'; return null; },
    // Like the real command, resolves only when the installation has finished; the page polls install_progress meanwhile.
    install_panel: async ({target}) => {
      install = {running: true, finished: false, success: false, log: [], url: null, username: null, password: null, token: null};
      for (const line of installScript) { await delay(600); install.log.push(line); }
      const ok = !fail('install_panel');
      Object.assign(install, {running: false, finished: true, success: ok, url: ok ? 'http://203.0.113.9:2053/mock/' : null,
        username: ok ? 'mockadmin' : null, password: ok ? 'mockpass' : null, token: ok && params.get('no_token') !== '1' ? 'mock-token' : null});
      if (!ok) throw 'Установка завершилась с ошибкой (mock)';
      return null;
    },
    install_progress: () => JSON.parse(JSON.stringify(install)),
    clear_install: () => { install = {running: false, finished: false, success: false, log: [], url: null, username: null, password: null, token: null}; return null; },
  };

  window.__TAURI_INTERNALS__ = {
    invoke: async (cmd, args = {}) => {
      if (!(cmd in handlers)) throw `mock: команда не реализована: ${cmd}`;
      await delay(cmd === 'install_progress' ? 30 : 250);
      return handlers[cmd](args);
    },
  };
  console.info('[dev] mock backend active; add ?fail=<command> to force an error');
})();
