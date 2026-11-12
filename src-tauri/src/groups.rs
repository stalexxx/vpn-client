//! Tauri commands for user-defined config groups (the logic lives in `vpn_core::groups`).
use vpn_core::groups::{self, ProfileGroup};

#[tauri::command]
pub fn list_profile_groups() -> Result<Vec<ProfileGroup>, String> { groups::list_profile_groups() }

#[tauri::command]
pub fn create_profile_group(name: String) -> Result<ProfileGroup, String> { groups::create_profile_group(&name) }

#[tauri::command]
pub fn rename_profile_group(id: String, name: String) -> Result<(), String> { groups::rename_profile_group(&id, &name) }

#[tauri::command]
pub fn delete_profile_group(id: String) -> Result<(), String> { groups::delete_profile_group(&id) }

#[tauri::command]
pub fn move_profile_to_group(member: String, group: Option<String>) -> Result<(), String> {
    groups::move_profile_to_group(&member, group.as_deref())
}
