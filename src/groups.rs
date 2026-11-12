//! User-defined groups of connection configs (shown in the main window).
//! A config belongs to at most one group; configs outside any group are "ungrouped".
//! Member keys are the UI's profile keys: `server_id:inbound_id:email` or `imported:<id>`.
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};

const MAX_GROUPS: usize = 50;
const MAX_NAME_CHARS: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileGroup { pub id: String, pub name: String, pub members: Vec<String> }

#[derive(Default, Serialize, Deserialize)]
struct GroupFile { #[serde(default)] groups: Vec<ProfileGroup> }

static GROUP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn groups_path() -> Result<PathBuf, String> { Ok(super::config_path()?.with_file_name("profile-groups.json")) }

fn read_groups(path: &Path) -> Result<Vec<ProfileGroup>, String> {
    match fs::read(path) {
        Ok(data) => serde_json::from_slice::<GroupFile>(&data).map(|file| file.groups).map_err(|_| "Список групп повреждён".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}

fn write_groups(path: &Path, groups: &[ProfileGroup]) -> Result<(), String> {
    let dir = path.parent().ok_or("Некорректный путь к спискам групп")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    super::compat::restrict_file(file.as_file()).map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, &GroupFile { groups: groups.to_vec() }).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Read-modify-write under one lock, so concurrent UI calls cannot lose each other's changes.
fn update(path: &Path, change: impl FnOnce(&mut Vec<ProfileGroup>) -> Result<(), String>) -> Result<(), String> {
    let _guard = GROUP_LOCK.lock().map_err(|_| "Не удалось заблокировать список групп")?;
    let mut groups = read_groups(path)?;
    change(&mut groups)?;
    write_groups(path, &groups)
}

fn valid_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(format!("Название группы: от 1 до {MAX_NAME_CHARS} символов"));
    }
    Ok(name.to_owned())
}

fn valid_group_id(id: &str) -> bool { id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) }

pub fn valid_member(key: &str) -> bool {
    if let Some(id) = key.strip_prefix("imported:") { return valid_group_id(id); }
    let mut parts = key.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(server), Some(inbound), Some(email)) => valid_group_id(server)
            && inbound.parse::<u64>().is_ok_and(|n| n > 0)
            && !email.is_empty() && email.len() <= 128,
        _ => false,
    }
}

fn find_index(groups: &[ProfileGroup], id: &str) -> Result<usize, String> {
    if !valid_group_id(id) { return Err("Некорректный идентификатор группы".into()); }
    groups.iter().position(|g| g.id == id).ok_or_else(|| "Группа не найдена".into())
}

fn create_in(groups: &mut Vec<ProfileGroup>, name: &str) -> Result<ProfileGroup, String> {
    if groups.len() >= MAX_GROUPS { return Err(format!("Не больше {MAX_GROUPS} групп")); }
    let group = ProfileGroup { id: super::new_server_id()?, name: valid_name(name)?, members: Vec::new() };
    groups.push(group.clone());
    Ok(group)
}

fn move_in(groups: &mut [ProfileGroup], member: &str, target: Option<&str>) -> Result<(), String> {
    if !valid_member(member) { return Err("Некорректная конфигурация".into()); }
    let target = match target { Some(id) => Some(find_index(groups, id)?), None => None };
    for group in groups.iter_mut() { group.members.retain(|m| m != member); }
    if let Some(index) = target { groups[index].members.push(member.to_owned()); }
    Ok(())
}

pub fn list_profile_groups() -> Result<Vec<ProfileGroup>, String> {
    let _guard = GROUP_LOCK.lock().map_err(|_| "Не удалось заблокировать список групп")?;
    read_groups(&groups_path()?)
}

pub fn create_profile_group(name: &str) -> Result<ProfileGroup, String> {
    let mut created = None;
    update(&groups_path()?, |groups| { created = Some(create_in(groups, name)?); Ok(()) })?;
    created.ok_or_else(|| "Группа не создана".into())
}

pub fn rename_profile_group(id: &str, name: &str) -> Result<(), String> {
    update(&groups_path()?, |groups| {
        let index = find_index(groups, id)?;
        groups[index].name = valid_name(name)?;
        Ok(())
    })
}

/// Deleting a group does not delete its configs: they become ungrouped.
pub fn delete_profile_group(id: &str) -> Result<(), String> {
    update(&groups_path()?, |groups| { let index = find_index(groups, id)?; groups.remove(index); Ok(()) })
}

/// Puts a config into `group`, or into no group when `group` is `None`.
pub fn move_profile_to_group(member: &str, group: Option<&str>) -> Result<(), String> {
    update(&groups_path()?, |groups| move_in(groups, member, group))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_MEMBER: &str = "0123456789abcdef0123456789abcdef:7:alice@example.com";
    const IMPORT_MEMBER: &str = "imported:fedcba9876543210fedcba9876543210";

    #[test]
    fn member_keys_match_the_ui_format() {
        assert!(valid_member(SERVER_MEMBER));
        assert!(valid_member(IMPORT_MEMBER));
        assert!(valid_member("0123456789abcdef0123456789abcdef:7:name:with:colons"));
        assert!(!valid_member("0123456789ABCDEF0123456789abcdef:7:alice"), "uppercase server id");
        assert!(!valid_member("0123456789abcdef0123456789abcdef:0:alice"), "inbound id must be positive");
        assert!(!valid_member("0123456789abcdef0123456789abcdef:7:"), "email required");
        assert!(!valid_member("imported:../../etc"));
        assert!(!valid_member("junk"));
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(valid_name("  Работа  ").unwrap(), "Работа");
        assert!(valid_name("   ").is_err());
        assert!(valid_name(&"я".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert!(valid_name("bad\nname").is_err());
    }

    #[test]
    fn a_config_is_in_at_most_one_group() {
        let mut groups = Vec::new();
        let a = create_in(&mut groups, "Работа").unwrap();
        let b = create_in(&mut groups, "Дом").unwrap();
        move_in(&mut groups, SERVER_MEMBER, Some(&a.id)).unwrap();
        move_in(&mut groups, SERVER_MEMBER, Some(&b.id)).unwrap();
        assert!(groups[0].members.is_empty());
        assert_eq!(groups[1].members, vec![SERVER_MEMBER.to_string()]);
        move_in(&mut groups, SERVER_MEMBER, None).unwrap();
        assert!(groups.iter().all(|g| g.members.is_empty()));
    }

    #[test]
    fn moving_needs_an_existing_group_and_a_valid_config() {
        let mut groups = Vec::new();
        create_in(&mut groups, "Работа").unwrap();
        assert!(move_in(&mut groups, SERVER_MEMBER, Some("ffffffffffffffffffffffffffffffff")).is_err());
        assert!(move_in(&mut groups, "not-a-key", None).is_err());
        assert!(groups[0].members.is_empty());
    }

    #[test]
    fn group_count_is_limited() {
        let mut groups = Vec::new();
        for i in 0..MAX_GROUPS { create_in(&mut groups, &format!("g{i}")).unwrap(); }
        assert!(create_in(&mut groups, "one more").is_err());
    }

    #[test]
    fn groups_survive_a_round_trip_and_rename_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile-groups.json");
        let created = std::cell::RefCell::new(None);
        update(&path, |groups| { *created.borrow_mut() = Some(create_in(groups, "Работа")?); Ok(()) }).unwrap();
        let group = created.into_inner().unwrap();
        update(&path, |groups| move_in(groups, IMPORT_MEMBER, Some(&group.id))).unwrap();
        assert_eq!(read_groups(&path).unwrap()[0].members, vec![IMPORT_MEMBER.to_string()]);
        update(&path, |groups| { let i = find_index(groups, &group.id)?; groups[i].name = valid_name("Дом")?; Ok(()) }).unwrap();
        assert_eq!(read_groups(&path).unwrap()[0].name, "Дом");
        update(&path, |groups| { let i = find_index(groups, &group.id)?; groups.remove(i); Ok(()) }).unwrap();
        assert!(read_groups(&path).unwrap().is_empty());
    }

    #[test]
    fn missing_file_means_no_groups() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_groups(&dir.path().join("none.json")).unwrap().is_empty());
    }
}
