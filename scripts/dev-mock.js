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
  const warpState = new Set();
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
  const usable = p => p.enabled && p.inbound_enabled && ['vless', 'hysteria'].includes(p.protocol) && p.has_local_config;
  const allKeys = () => servers.flatMap(s => profilesFor(s.id).filter(usable).map(p => ({server_id:s.id,inbound_id:p.inbound_id,email:p.email})));
  const sameKey = (a,b) => a.server_id===b.server_id && a.inbound_id===b.inbound_id && a.email===b.email;
  const imported = []; let importedSeq = 1;
  let statsTick = 0;
  let logLevel = 'warning';
  let bypassState = { bittorrent: true, entries: [] };
let mode = 'off';
  let install = {running: false, finished: false, success: false, log: [], url: null, username: null, password: null, token: null};
  const installScript = [
    'Подключаюсь по SSH…', 'Скачиваю установщик 3x-ui…', 'Устанавливаю зависимости…',
    'Генерирую учётные данные панели…', 'Запускаю x-ui.service…', 'Установка завершена.',
  ];

  const handlers = {
    build_info: () => 'v0.0.0-dev · mock',
    vpn_stats: () => { statsTick += 1; const t = Date.now(); return { ts_ms: t, vpn: { up: statsTick * 40000, down: statsTick * 900000 }, direct: { up: statsTick * 300000, down: statsTick * 2500000 } }; },
    get_log_level: () => logLevel,
    set_log_level: ({ verbose }) => { logLevel = verbose ? 'info' : 'warning'; return 'ok'; },
    get_bypass_settings: () => bypassState,
    set_bypass_settings: ({ bittorrent, entries }) => { if (entries.some(e => /\s/.test(e))) throw 'Не похоже на домен, IP или подсеть: ' + entries[0]; bypassState = { bittorrent, entries }; return bypassState; },
    // Latency marks for every visible profile, cycling through fast / medium / slow / no answer / UDP.
    get_probe_results: () => { const all = [...handlers.list_connectable_profiles().map(p => `${p.server_id}:${p.inbound_id}:${p.email}`), ...imported.map(i => `imported:${i.id}`)]; const ts = Math.floor(Date.now()/1000) - 42; const out = {}; all.forEach((k, i) => { const v = [{ms:38},{ms:212},{ms:530},{ms:null,error:'таймаут'},{udp:true}][i % 5]; out[k] = { ms: v.ms ?? null, error: v.error ?? null, ts, udp: !!v.udp }; }); return out; },
    awg_list_servers: () => [{id:'a1', name:'silicon-awg', ssh_target:'root@95.182.101.33', port:47821, server_public_key:'k'}],
    awg_clients: () => [{name:'mac', address:'10.8.1.2'}],
    awg_status: () => 'active\nactive\n---\n  latest handshake: 12 seconds ago\n',
    awg_install: ({name}) => ({id:'a2', name, ssh_target:'root@x', port:41000, server_public_key:'k'}),
    awg_add_client: ({client}) => ({path:'/Users/me/Downloads/'+client+'.conf', conf:'[Interface]\nPrivateKey = …', link:'vpn://AAAA…', qr_svg:'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 4"><rect width="2" height="2"/><rect x="2" y="2" width="2" height="2"/></svg>'}),
    awg_delete_client: () => null, awg_uninstall: () => null, awg_reveal: () => null,
    probe_now: () => null,
    get_exit_ip: () => '203.0.113.7',
    get_vpn_mode: () => mode,
    list_servers: () => servers,
    list_connectable_profiles: () => (readPins(), servers.flatMap(server => profilesFor(server.id).filter(p => usable(p) && (pinnedProfiles === null || pinnedProfiles.some(k=>sameKey(k,{server_id:server.id,inbound_id:p.inbound_id,email:p.email})))).map(p => ({...p, server_id:server.id, server_name:server.name, country:server.country})))),
    list_pinned_profiles: () => { readPins(); return pinnedProfiles === null ? null : pinnedProfiles.map(k=>({...k})); },
    set_profile_pinned: ({serverId,inboundId,email,pinned}) => { if(fail('set_profile_pinned')) throw 'Не удалось изменить отметку (mock)'; readPins(); const key={server_id:serverId,inbound_id:inboundId,email}, all=allKeys(); if(pinned && !all.some(k=>sameKey(k,key))) throw 'Клиент недоступен'; if(pinnedProfiles===null) pinnedProfiles=all; pinnedProfiles=pinnedProfiles.filter(k=>!sameKey(k,key)); if(pinned) pinnedProfiles.push(key); savePins(); return null; },
    select_mcp_profile: () => null,
    get_mcp_profile: () => null,
    import_profiles: ({text, name}) => {
      if (fail('import_profiles')) throw 'Не удалось импортировать (mock)';
      const links = (text.match(/(?:vless|hysteria2|hy2):\/\/\S+/g) || []).map(l => l.replace(/^hy2:/, 'hysteria2:'));
      if (!links.length) throw 'В тексте нет ссылки vless://';
      const added = [];
      for (const link of links) {
        if (!/^vless:\/\/[0-9a-f-]{36}@[^:/]+:\d+/.test(link) && !/^hysteria2:\/\/[^@]+@[^:/]+:\d+/.test(link)) continue;
        if (imported.some(i => i.link === link)) continue;
        const u = new URL(link.replace('vless://', 'http://'));
        const item = {id: String(importedSeq++).padStart(32, '0'), link, name: (name || decodeURIComponent(u.hash.slice(1)) || u.hostname), host: u.hostname, port: Number(u.port) || 443, transport: link.startsWith('hysteria2:') ? 'hysteria2' : (u.searchParams.get('type') || 'tcp'), security: u.searchParams.get('security') || ''};
        imported.push(item); added.push({id: item.id, name: item.name, host: item.host, port: item.port, transport: item.transport, security: item.security});
      }
      if (!added.length) throw 'Некорректная ссылка или конфигурация уже импортирована';
      return added;
    },
    list_imported_profiles: () => imported.map(({link, ...rest}) => rest),
    rename_imported_profile: ({id, name}) => { const i = imported.find(i => i.id === id); if (!i) throw 'Конфигурация не найдена'; i.name = name; return null; },
    delete_imported_profile: ({id}) => { const k = imported.findIndex(i => i.id === id); if (k < 0) throw 'Конфигурация не найдена'; imported.splice(k, 1); return null; },
    connect_imported_profile: async ({id}) => { if (!imported.some(i => i.id === id)) throw 'Конфигурация не найдена'; if (fail('connect_profile')) throw 'VPN запущен, но трафик через сервер не проходит: DNS и TCP недоступны.'; await delay(800); mode = 'tun'; return 'VPN подключён (mock, импорт)'; },
    open_admin: () => null,
    panel_hostname: ({url}) => { try { return new URL(url).hostname; } catch { throw 'Некорректный адрес панели'; } },
    list_ssh_keys: () => [
      {name: 'id_ed25519_vpn_client', kind: 'ed25519', comment: 'me@mac', app_key: true},
      {name: 'id_rsa', kind: 'rsa', comment: 'work@laptop', app_key: false},
    ],
    list_orphan_ssh_pubs: () => ['id_old_laptop'],
    get_default_ssh_key: () => window.__mockDefaultSshKey || null,
    set_default_ssh_key: ({key}) => {
      if (key && !['id_ed25519_vpn_client', 'id_rsa'].includes(key)) throw `SSH-ключ ${key} не найден в ~/.ssh`;
      window.__mockDefaultSshKey = key || null;
    },
    save_server: ({id, name, url, country, sshTarget, panelHost, token, sshKey}) => {
      if (fail('save_server')) throw 'Не удалось сохранить сервер';
      if (id && !servers.some(server => server.id === id)) throw 'Сервер не найден';
      if (!id && !token?.trim()) throw 'Укажите API-токен';
      const saved = {id: id || 'd'.repeat(32), name, url, country: country || null, ssh_target: sshTarget || null, panel_host: panelHost || null, ssh_key: sshKey || null};
      const index = servers.findIndex(server => server.id === saved.id);
      if (index < 0) servers.push(saved); else servers[index] = saved;
      return saved;
    },
    delete_server: ({serverId}) => { readPins(); if(pinnedProfiles!==null) { pinnedProfiles=pinnedProfiles.filter(k=>k.server_id!==serverId); savePins(); } const index = servers.findIndex(server => server.id === serverId); if (index >= 0) servers.splice(index, 1); return null; },
    list_inbound_templates: () => [{id:'VLESS-XHTTP-443',name:'VLESS-XHTTP-443',description:'VLESS, XHTTP и TLS',remark:'VLESS-XHTTP-443',port:443,path:'/'},{id:'VLESS-VISION-8443',name:'VLESS-VISION-8443',description:'VLESS, TCP и TLS (Vision)',remark:'VLESS-VISION-8443',port:8443,path:'/'}],
    create_server_inbound: ({serverId,templateId,params:data}) => { if(fail('create_server_inbound')) throw 'Не удалось создать inbound (mock)'; const created={id:inboundSequence++,remark:data.remark,port:data.port,protocol:'vless',enable:true,transport:templateId==='VLESS-VISION-8443'?'tcp':'xhttp'}; savedInboundMap.set(serverId,[...inbounds(serverId),created]); return created.id; },
    new_wizard_id: () => { if (fail('new_wizard_id')) throw 'Не удалось подготовить мастер (mock)'; const id = String(wizardSequence++).padStart(32, '0'); wizardInboundMap.set(id, []); wizardProfileMap.set(id, []); return id; },
    stage_wizard_token: ({wizardId, token}) => { if (fail('stage_wizard_token')) throw 'Не удалось сохранить токен (mock)'; wizardTokens.set(wizardId, token); return null; },
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
      const saved={id:wizardId,name:panel.name,url:panel.url,ssh_target:panel.ssh_target,panel_host:panel.panel_host,ssh_key:panel.ssh_key||null,country:country||null};
      servers.push(saved); savedInboundMap.set(saved.id,wizardInboundMap.get(wizardId)||[]); savedProfileMap.set(saved.id,wizardProfileMap.get(wizardId)||[]); wizardTokens.delete(wizardId); return saved;
    },
    cached_server_inbounds: ({serverId}) => inbounds(serverId),
    list_inbounds: ({serverId}) => inbounds(serverId),
    list_client_profiles: ({serverId}) => profilesFor(serverId),
    refresh_client_profiles: ({serverId}) => profilesFor(serverId),
    list_geo_lists: () => ({geoip:['cn','ir','private','ru','ua','us'], geosite:['category-bank-ru','category-ecommerce-ru','category-gov-ru','category-ru','google','netflix','telegram','tld-ru','tld-cn','youtube']}),
    server_warp_status: ({serverId}) => warpState.has(serverId),
    enable_server_warp: async ({serverId}) => { await new Promise(r=>setTimeout(r,600)); if(window.__warpFail) throw new Error('Панель не зарегистрировала WARP'); warpState.add(serverId); return 'WARP включён на сервере (мок)'; },
    disable_server_warp: async ({serverId}) => { await new Promise(r=>setTimeout(r,600)); warpState.delete(serverId); return 'WARP отключён на сервере (мок)'; },
    delete_inbound: ({serverId,inboundId}) => { const list=inbounds(serverId); const clients=profilesFor(serverId); savedProfileMap.set(serverId,clients); const index=list.findIndex(i=>i.id===inboundId); if(index<0) throw 'Inbound не найден (mock)'; const [gone]=list.splice(index,1); savedInboundMap.set(serverId,list); for(let n=clients.length-1;n>=0;n--) if(clients[n].inbound_id===inboundId) clients.splice(n,1); savedProfileMap.set(serverId,clients); return `Удалён inbound ${inboundId} (${gone.remark}) (mock)`; },
    create_client: ({email}) => `Клиент ${email} создан (mock)`,
    client_qr: () => { const size = 25; return {link: 'vless://mock', size, pixels: Array.from({length: size * size}, (_, i) => ((i * 7 + (i >> 3)) % 3) === 0)}; },
    connect_profile: async () => { if (fail('connect_profile')) throw 'VPN запущен, но трафик через сервер не проходит: DNS и TCP недоступны.'; await delay(1200); mode = 'tun'; return 'VPN подключён через utun10 (mock)'; },
    xray_stop: () => { mode = 'off'; return null; },
    // Like the real command, resolves only when the installation has finished; the page polls install_progress meanwhile.
    install_panel: async ({target, password, installKey, sshKey}) => {
      if (password !== undefined && password !== null && !password) throw 'Пароль не должен быть пустым';
      window.__lastInstallArgs = {target, hasPassword: !!password, installKey, sshKey};
      install = {running: true, finished: false, success: false, log: [], url: null, username: null, password: null, token: null};
      for (const line of installScript) { await delay(600); install.log.push(line); }
      if (password && installKey) install.log.push('Ваш публичный SSH-ключ добавлен на сервер.');
      if (password && fail('wrong_password')) { Object.assign(install, {running: false, finished: true, success: false}); install.log.push('SSH: доступ отклонён; проверьте пароль или ключ и права.'); throw 'Установка завершилась с ошибкой'; }
      const ok = !fail('install_panel');
      Object.assign(install, {running: false, finished: true, success: ok, url: ok ? 'http://203.0.113.9:2053/mock/' : null,
        username: ok ? 'mockadmin' : null, password: ok ? 'mockpass' : null, token: ok && params.get('no_token') !== '1' ? 'mock-token' : null, local_only: ok && (!password || installKey),
        // like the backend: the chosen key, else the default pair that was authorized by a password install
        ssh_key: ok ? (sshKey || (password && installKey ? 'id_ed25519_vpn_client' : null)) : null});
      if (ok && (!password || installKey)) install.log.push('✓ Панель закрыта от интернета: слушает только 127.0.0.1, приложение управляет ею через SSH-туннель.');
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
