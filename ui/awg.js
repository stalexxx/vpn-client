// AmneziaWG + WARP servers: install over SSH, manage clients (needs admin.js loaded first: invoke, $).
(() => {
  let awgServers = [], current = null, savedPath = null, uninstallArmed = false, busyAwg = false;
  const status = text => { $('awg-status').textContent = text || ''; };
  const hostOfTarget = t => t.split('@').pop().replace(/:\d+$/, '');
  function fillKeys(select, keys) {
    select.replaceChildren();
    const d = document.createElement('option'); d.value = ''; d.textContent = 'По умолчанию'; select.append(d);
    keys.forEach(k => { const o = document.createElement('option'); o.value = k.name; o.textContent = k.name; select.append(o); });
  }
  function renderServers() {
    const root = $('awg-servers'); root.replaceChildren();
    if (!awgServers.length) { const p = document.createElement('p'); p.className = 'workspace-empty'; p.textContent = 'Серверов AmneziaWG пока нет.'; root.append(p); }
    awgServers.forEach(s => {
      const b = document.createElement('button'); b.type = 'button'; b.className = 'server-card'; b.setAttribute('aria-pressed', String(current?.id === s.id));
      b.textContent = `${s.name} · ${hostOfTarget(s.ssh_target)}:${s.port}`; b.addEventListener('click', () => openServer(s)); root.append(b);
    });
  }
  async function refresh() { awgServers = await invoke('awg_list_servers').catch(() => []); renderServers(); }
  function renderClients(list) {
    const root = $('awg-clients'); root.replaceChildren();
    if (!list.length) { const p = document.createElement('p'); p.className = 'empty-state'; p.textContent = 'Клиентов пока нет.'; root.append(p); }
    list.forEach(c => {
      const row = document.createElement('div'); row.className = 'client-row';
      const name = document.createElement('span'); name.className = 'client-identity'; name.textContent = `${c.name} · ${c.address}`;
      const del = document.createElement('button'); del.type = 'button'; del.className = 'danger small'; del.textContent = 'Удалить';
      del.addEventListener('click', async () => {
        if (busyAwg) return; busyAwg = true; del.disabled = true;
        try { await invoke('awg_delete_client', { id: current.id, client: c.name }); status(`Клиент ${c.name} удалён.`); await loadDetail(); }
        catch (e) { status(`Не удалось удалить клиента: ${e}`); del.disabled = false; } finally { busyAwg = false; }
      });
      row.append(name, del); root.append(row);
    });
  }
  async function loadDetail() {
    const id = current.id;
    const [clients, st] = await Promise.all([invoke('awg_clients', { id }), invoke('awg_status', { id }).catch(e => `Статус недоступен: ${e}`)]);
    if (current?.id !== id) return;
    renderClients(clients);
    const warp = /latest handshake: ([^\n]+)/.exec(st);
    $('awg-state').textContent = warp ? `WARP: рукопожатие ${warp[1]}.` : 'WARP: рукопожатия ещё не было — проверьте сервер.';
  }
  async function openServer(s) {
    current = s; savedPath = null; uninstallArmed = false; $('awg-uninstall').textContent = 'Удалить AmneziaWG с сервера';
    $('awg-detail').hidden = false; $('awg-detail-title').textContent = `${s.name} · UDP ${s.port}`; $('awg-conf').hidden = true; $('awg-reveal').hidden = true; $('awg-state').textContent = 'Загружаем…'; renderServers();
    try { await loadDetail(); } catch (e) { $('awg-state').textContent = `Не удалось получить данные: ${e}`; }
  }
  $('open-awg').addEventListener('click', async () => {
    const keys = await invoke('list_ssh_keys').catch(() => []); fillKeys($('awg-key'), keys);
    $('awg-modal').hidden = false; status(''); await refresh();
  });
  $('awg-close').addEventListener('click', () => { if (!busyAwg) $('awg-modal').hidden = true; });
  $('awg-install').addEventListener('click', async () => {
    if (busyAwg) return;
    const name = $('awg-name').value.trim(), target = $('awg-ssh').value.trim(), portText = $('awg-port').value.trim();
    if (!name || !/^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+(:\d+)?$/.test(target)) { status('Укажите название и SSH-цель в формате root@хост[:порт].'); return; }
    const port = portText ? Number(portText) : null;
    if (portText && !(Number.isInteger(port) && port >= 1024 && port <= 65535)) { status('UDP-порт: число от 1024 до 65535.'); return; }
    busyAwg = true; $('awg-install').disabled = true; status('Устанавливаем AmneziaWG и WARP (1–3 минуты)…');
    try { const s = await invoke('awg_install', { name, sshTarget: target, sshKey: $('awg-key').value || null, port }); status(`Готово: ${s.name}, UDP ${s.port}.`); await refresh(); await openServer(awgServers.find(x => x.id === s.id) || s); }
    catch (e) { status(`Не удалось установить: ${e}`); } finally { busyAwg = false; $('awg-install').disabled = false; }
  });
  $('awg-add-form').addEventListener('submit', async ev => {
    ev.preventDefault(); if (busyAwg || !current) return;
    const client = $('awg-client-name').value.trim();
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(client)) { status('Имя клиента: латиница, цифры, - и _ (до 32 символов).'); return; }
    busyAwg = true; status('Создаём клиента…');
    try {
      const r = await invoke('awg_add_client', { id: current.id, client });
      savedPath = r.path; $('awg-conf').value = r.conf; $('awg-conf').hidden = false; $('awg-reveal').hidden = false; $('awg-client-name').value = '';
      status(`Конфиг сохранён: ${r.path}. Импортируйте его в приложение Amnezia; ключи в файле секретные.`); await loadDetail();
    } catch (e) { status(`Не удалось создать клиента: ${e}`); } finally { busyAwg = false; }
  });
  $('awg-reveal').addEventListener('click', () => { if (savedPath) invoke('awg_reveal', { path: savedPath }).catch(e => status(`${e}`)); });
  $('awg-uninstall').addEventListener('click', async () => {
    if (busyAwg || !current) return;
    if (!uninstallArmed) { uninstallArmed = true; $('awg-uninstall').textContent = 'Точно удалить? Клиенты перестанут работать'; setTimeout(() => { uninstallArmed = false; $('awg-uninstall').textContent = 'Удалить AmneziaWG с сервера'; }, 5000); return; }
    busyAwg = true; status('Удаляем…');
    try { await invoke('awg_uninstall', { id: current.id }); current = null; $('awg-detail').hidden = true; status('AmneziaWG удалён с сервера.'); await refresh(); }
    catch (e) { status(`Не удалось удалить: ${e}`); } finally { busyAwg = false; uninstallArmed = false; }
  });
})();
