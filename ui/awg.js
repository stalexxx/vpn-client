// AmneziaWG + WARP as one kind of inbound of the selected server (needs admin.js loaded first: invoke, $, window.reloadEntries).
(() => {
  let pinned = new Set(), entry = null, savedPath = null, shareConf = '', uninstallArmed = false, busyAwg = false;
  const awgOf = () => entry?.awg || null;
  const status = text => { $('client-status').textContent = text || ''; };
  const installStatus = text => { $('awg-install-status').textContent = text || ''; };

  // Live output of the install: polled while it runs, left in place afterwards so the result can be read.
  let logTimer = null;
  async function pollInstallLog() {
    try {
      const box = $('awg-log'), lines = await invoke('awg_install_log');
      const stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 24;
      box.textContent = lines.join('\n');
      if (stick) box.scrollTop = box.scrollHeight;
    } catch { /* the log is informational; the install result is reported separately */ }
  }
  function startInstallLog() { $('awg-log').hidden = false; $('awg-log').textContent = ''; clearInterval(logTimer); logTimer = setInterval(pollInstallLog, 700); }
  function stopInstallLog() { clearInterval(logTimer); logTimer = null; pollInstallLog(); }

  async function copy(text, what) {
    try { await navigator.clipboard.writeText(text); }
    catch { const t = document.createElement('textarea'); t.value = text; document.body.append(t); t.select(); const ok = document.execCommand('copy'); t.remove(); if (!ok) { status('Не удалось скопировать — выделите текст вручную.'); return; } }
    status(`${what} скопирован${what.endsWith('а') ? 'а' : ''} в буфер обмена.`);
  }
  const hostOfTarget = t => t.split('@').pop().replace(/:\d+$/, '');

  // Same layout as VLESS clients: one row per client, "QR и ссылка" opens the shared share card.
  function renderClients(list) {
    const root = $('awg-clients'); root.replaceChildren();
    $('awg-count').textContent = `UDP ${awgOf().port} · ${list.length} клиентов`;
    if (!list.length) { const p = document.createElement('p'); p.className = 'empty-state'; p.style.margin = '12px'; p.textContent = 'Нет клиентов в этом inbound-е.'; root.append(p); }
    list.forEach(c => {
      const row = document.createElement('div'); row.className = 'client-row';
      const identity = document.createElement('span'); identity.className = 'client-identity'; identity.textContent = c.name; identity.title = `${c.name} · ${c.address}`;
      const type = document.createElement('span'); type.className = 'client-type'; type.textContent = `AmneziaWG · WARP · ${c.address}`;
      const pinLabel = document.createElement('label'); pinLabel.className = 'client-pin';
      const pin = document.createElement('input'); pin.type = 'checkbox'; pin.checked = pinned.has(c.name);
      pin.addEventListener('change', async () => {
        const server = awgOf(); if (!server) return; pin.disabled = true; const want = pin.checked;
        status(want ? 'Добавляем на главный экран (загружаем конфиг)…' : 'Убираем с главного экрана…');
        try { await invoke('awg_set_pinned', { id: server.id, client: c.name, pinned: want }); want ? pinned.add(c.name) : pinned.delete(c.name); status(want ? `Клиент ${c.name} добавлен на главный экран.` : `Клиент ${c.name} убран с главного экрана.`); }
        catch (e) { pin.checked = !want; status(`Не удалось изменить отметку: ${e}`); } finally { pin.disabled = false; }
      });
      pinLabel.append(pin, document.createTextNode('На главном экране'));
      const actions = document.createElement('span'); actions.className = 'client-actions';
      const view = document.createElement('button'); view.type = 'button'; view.textContent = 'QR и ссылка';
      view.addEventListener('click', async () => {
        const server = awgOf(); if (busyAwg || !server) return; busyAwg = true; view.disabled = true; status('Загружаем конфиг…');
        try { showResult(await invoke('awg_client_config', { id: server.id, client: c.name })); status(`Конфиг клиента ${c.name} сохранён в ${savedPath}.`); }
        catch (e) { status(`${e}`); } finally { busyAwg = false; view.disabled = false; }
      });
      const del = document.createElement('button'); del.type = 'button'; del.className = 'danger'; del.textContent = 'Удалить';
      del.addEventListener('click', async () => {
        const server = awgOf(); if (busyAwg || !server) return; busyAwg = true; del.disabled = true;
        try { await invoke('awg_delete_client', { id: server.id, client: c.name }); $('client-share').hidden = true; status(`Клиент ${c.name} удалён.`); await loadDetail(); }
        catch (e) { status(`Не удалось удалить клиента: ${e}`); del.disabled = false; } finally { busyAwg = false; }
      });
      actions.append(view, del); row.append(identity, type, pinLabel, actions); root.append(row);
    });
  }
  async function loadDetail() {
    const server = awgOf(); if (!server) return;
    const id = server.id;
    const [clients, st, pins] = await Promise.all([invoke('awg_clients', { id }), invoke('awg_status', { id }).catch(e => `Статус недоступен: ${e}`), invoke('awg_pinned', { id }).catch(() => [])]);
    if (awgOf()?.id !== id) return;
    pinned = new Set(pins);
    renderClients(clients);
    const warp = /latest handshake: ([^\n]+)/.exec(st);
    $('awg-state').textContent = warp ? `WARP: рукопожатие ${warp[1]}.` : 'WARP: рукопожатия ещё не было — проверьте сервер.';
  }
  // Fills the share card used by VLESS clients with the AmneziaWG result (SVG QR, vpn:// link, .conf).
  function showResult(r) {
    savedPath = r.path; shareConf = r.conf;
    $('client-qr').hidden = true; $('client-qr-svg').innerHTML = r.qr_svg; $('client-qr-svg').hidden = false;
    $('client-link').value = r.link; $('copy-conf').hidden = false; $('reveal-conf').hidden = false; $('client-share').hidden = false;
  }
  function hideResult() { savedPath = null; shareConf = ''; $('client-share').hidden = true; }

  async function addClient(client) {
    const server = awgOf(); if (busyAwg || !server) return;
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(client)) { status('Имя клиента AmneziaWG: латиница, цифры, - и _ (до 32 символов).'); return; }
    busyAwg = true; status('Создаём клиента…');
    try {
      const r = await invoke('awg_add_client', { id: server.id, client });
      showResult(r); status(`Клиент создан. Конфиг сохранён: ${r.path}; ключи секретные.`); await loadDetail();
    } catch (e) { status(`Не удалось создать клиента: ${e}`); } finally { busyAwg = false; }
  }

  // Called by admin.js whenever another server (or a refreshed list) is selected.
  function show(next) {
    const sameServer = awgOf() && next?.awg && awgOf().id === next.awg.id;
    entry = next || null;
    const server = awgOf();
    $('awg-section').hidden = !server; $('awg-inbound').hidden = !server;
    uninstallArmed = false; $('awg-uninstall').textContent = 'Удалить с сервера';
    if (!server) { hideResult(); status(''); return; }
    $('awg-inbound-port').textContent = server.port;
    if (sameServer) return;
    hideResult(); status('');
    $('awg-clients').replaceChildren(); $('awg-count').textContent = `UDP ${server.port}`; $('awg-state').textContent = 'Загружаем…';
    loadDetail().catch(e => { $('awg-state').textContent = `Не удалось получить данные: ${e}`; });
  }

  function openInstall(target) {
    entry = target;
    $('awg-install-host').textContent = `${target.name} · ${hostOfTarget(target.host.ssh_target)}`;
    installStatus(''); $('awg-log').hidden = true; $('awg-log').textContent = ''; $('awg-port').value = '';
    $('awg-install-modal').hidden = false;
  }
  function closeInstall() { if (!busyAwg) $('awg-install-modal').hidden = true; }
  $('awg-install-close').addEventListener('click', closeInstall);

  $('awg-install').addEventListener('click', async () => {
    if (busyAwg || !entry?.host) return;
    const target = entry, host = target.host, portText = $('awg-port').value.trim();
    const port = portText ? Number(portText) : null;
    if (portText && !(Number.isInteger(port) && port >= 1024 && port <= 65535)) { installStatus('UDP-порт: число от 1024 до 65535.'); return; }
    busyAwg = true; $('awg-install').disabled = true; installStatus('Устанавливаем AmneziaWG и WARP (1–3 минуты)…');
    startInstallLog();
    try {
      const s = await invoke('awg_install', { name: host.name, sshTarget: host.ssh_target, sshKey: host.ssh_key || null, port, tools: $('awg-tools').value, country: host.country || null });
      installStatus(`Готово: UDP ${s.port}.`);
      await window.reloadEntries(target.key);
      $('awg-install-modal').hidden = true;
    } catch (e) { installStatus(`Не удалось установить: ${e}`); }
    finally { busyAwg = false; $('awg-install').disabled = false; stopInstallLog(); }
  });

  $('copy-conf').addEventListener('click', () => copy(shareConf, 'Конфиг'));
  $('reveal-conf').addEventListener('click', () => { if (savedPath) invoke('awg_reveal', { path: savedPath }).catch(e => status(`${e}`)); });
  $('awg-uninstall').addEventListener('click', async () => {
    const server = awgOf(); if (busyAwg || !server) return;
    if (!uninstallArmed) { uninstallArmed = true; $('awg-uninstall').textContent = 'Точно удалить? Клиенты перестанут работать'; setTimeout(() => { uninstallArmed = false; $('awg-uninstall').textContent = 'Удалить с сервера'; }, 5000); return; }
    busyAwg = true; $('server-status').textContent = 'Удаляем AmneziaWG с сервера…';
    const key = entry.key;
    try { await invoke('awg_uninstall', { id: server.id }); await window.reloadEntries(key); $('server-status').textContent = 'AmneziaWG удалён с сервера.'; }
    catch (e) { $('server-status').textContent = `Не удалось удалить: ${e}`; } finally { busyAwg = false; uninstallArmed = false; }
  });

  window.awgUi = { show, openInstall, addClient };
})();
