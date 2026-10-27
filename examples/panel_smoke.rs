use std::io::Read;
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: panel_smoke URL SSH_TARGET HOST".into());
    }
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let token = input
        .lines()
        .find_map(|line| line.strip_prefix("apiToken:").map(str::trim))
        .filter(|s| !s.is_empty())
        .ok_or("Token was not issued")?;
    let panel = vpn_core::Panel {
        name: "test".into(),
        url: args[1].clone(),
        ssh_target: Some(args[2].clone()),
        panel_host: Some(args[3].clone()),
    };
    let inbounds = vpn_core::list_inbounds_for(&panel, token)?;
    println!(
        "API request succeeded; inbounds: {}",
        inbounds.as_array().map_or(0, Vec::len)
    );
    Ok(())
}
