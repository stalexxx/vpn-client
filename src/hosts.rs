//! A server as the user sees it: name, country and how to reach it over SSH. What runs on it (a 3x-ui panel,
//! AmneziaWG) is stored separately and matched to the host by the SSH host name.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Host {
    pub id: String,
    pub name: String,
    pub ssh_target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

fn store_path() -> Result<std::path::PathBuf, String> { Ok(crate::compat::data_dir()?.join("hosts.json")) }

fn read_hosts() -> Result<Vec<Host>, String> {
    match std::fs::read(store_path()?) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("hosts.json: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.to_string()),
    }
}

fn write_hosts(hosts: &[Host]) -> Result<(), String> {
    let path = store_path()?;
    let dir = path.parent().ok_or("Invalid data path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut temp, hosts).map_err(|e| e.to_string())?;
    crate::compat::restrict_path(temp.path()).map_err(|e| e.to_string())?;
    temp.persist(&path).map_err(|e| e.to_string())?;
    Ok(())
}

fn new_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    crate::compat::random_bytes(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn same_host(a: &str, b: &str) -> bool { crate::ssh_host(a).eq_ignore_ascii_case(crate::ssh_host(b)) }

/// Adds a host record for every panel or AmneziaWG server that has none yet (servers created before hosts existed).
pub fn adopt(hosts: &mut Vec<Host>, panels: &[crate::Server], awg: &[crate::amnezia::AwgServer]) -> Result<bool, String> {
    let mut changed = false;
    let known: Vec<(String, String, Option<String>, Option<String>)> = panels.iter()
        .filter_map(|s| Some((s.panel.name.clone(), s.panel.ssh_target.clone()?, s.panel.ssh_key.clone(), s.country.clone())))
        .chain(awg.iter().map(|s| (s.name.clone(), s.ssh_target.clone(), s.ssh_key.clone(), s.country.clone())))
        .collect();
    for (name, ssh_target, ssh_key, country) in known {
        if hosts.iter().any(|h| same_host(&h.ssh_target, &ssh_target)) { continue; }
        hosts.push(Host { id: new_id()?, name, ssh_target, ssh_key, country });
        changed = true;
    }
    Ok(changed)
}

pub fn list_hosts() -> Result<Vec<Host>, String> {
    let mut hosts = read_hosts()?;
    if adopt(&mut hosts, &crate::list_servers()?, &crate::amnezia::list_servers()?)? { write_hosts(&hosts)?; }
    Ok(hosts)
}

pub fn save_host(id: Option<String>, name: &str, ssh_target: &str, ssh_key: Option<String>, country: Option<String>) -> Result<Host, String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 { return Err("Название: от 1 до 128 символов".into()); }
    if !crate::valid_ssh_target(ssh_target) { return Err("SSH-цель в формате root@хост или root@хост:порт".into()); }
    let ssh_key = ssh_key.filter(|k| !k.is_empty());
    if ssh_key.as_deref().is_some_and(|k| !crate::valid_ssh_key_setting(k)) { return Err("Некорректное имя SSH-ключа".into()); }
    let country = country.filter(|c| !c.is_empty());
    if country.as_deref().is_some_and(|c| !crate::is_country_code(c)) { return Err("Выберите страну из списка".into()); }
    let mut hosts = list_hosts()?;
    if hosts.iter().any(|h| Some(&h.id) != id.as_ref() && same_host(&h.ssh_target, ssh_target)) { return Err("Сервер с таким хостом уже есть".into()); }
    let host = Host { id: id.clone().unwrap_or(new_id()?), name: name.to_owned(), ssh_target: ssh_target.to_owned(), ssh_key, country };
    match id {
        Some(id) => *hosts.iter_mut().find(|h| h.id == id).ok_or("Сервер не найден")? = host.clone(),
        None => hosts.push(host.clone()),
    }
    write_hosts(&hosts)?;
    Ok(host)
}

/// Forgets the host and what the app stores about it; nothing is touched on the machine itself.
pub fn delete_host(id: &str) -> Result<(), String> {
    let mut hosts = list_hosts()?;
    let host = hosts.iter().find(|h| h.id == id).ok_or("Сервер не найден")?.clone();
    for panel in crate::list_servers()?.into_iter().filter(|s| s.panel.ssh_target.as_deref().is_some_and(|t| same_host(t, &host.ssh_target))) { crate::delete_server(&panel.id)?; }
    for awg in crate::amnezia::list_servers()?.into_iter().filter(|s| same_host(&s.ssh_target, &host.ssh_target)) { let _ = crate::unpin_awg(&format!("{}:", awg.id)); crate::amnezia::forget(&awg.id)?; }
    hosts.retain(|h| h.id != id);
    write_hosts(&hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn awg(name: &str, target: &str) -> crate::amnezia::AwgServer { crate::amnezia::AwgServer { id: "i".into(), name: name.into(), ssh_target: target.into(), ssh_key: None, port: 1, server_public_key: String::new(), country: Some("DE".into()) } }
    #[test]
    fn adopts_servers_without_host_once() {
        let mut hosts = vec![];
        assert!(adopt(&mut hosts, &[], &[awg("A", "root@1.2.3.4:22")]).unwrap());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].country.as_deref(), Some("DE"));
        assert!(!adopt(&mut hosts, &[], &[awg("A", "root@1.2.3.4")]).unwrap());
    }
}
