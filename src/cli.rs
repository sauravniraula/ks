use crate::session::{self, Session};
use crate::storage::{Group, VaultData, VaultStore};
use crate::{app, mcp};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use rpassword::prompt_password;

#[derive(Parser)]
#[command(name = "ks")]
#[command(version)]
#[command(about = "Encrypted desktop and CLI key store")]
pub struct Cli {
    /// Use this group for list/search, or make it active when logging in.
    #[arg(short = 'g', long = "group", global = true, value_name = "GROUP")]
    pub selected_group: Option<String>,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Open the desktop application.
    App,
    /// Unlock the vault for terminal commands.
    Login {
        /// Read the password from an environment variable instead of prompting.
        #[arg(long, value_name = "VAR")]
        password_env: Option<String>,
    },
    /// Remove the terminal login session.
    Logout,
    /// Show active group and secret counts.
    Status,
    /// Switch the active group.
    Switch {
        /// Group name to make active.
        group: String,
    },
    /// List keys in the active group.
    List {
        /// Also print values.
        #[arg(short, long)]
        values: bool,
    },
    /// Search keys in the active or selected group (case-insensitive).
    Search {
        /// Text to find in a secret key.
        query: String,
        /// Also print values.
        #[arg(short, long)]
        values: bool,
    },
    /// Print a value from the active group.
    Get {
        /// Secret key.
        key: String,
    },
    /// Set a key/value in the active group.
    Set {
        /// Secret key.
        key: String,
        /// Secret value.
        value: String,
    },
    /// Delete a key from the active group.
    Delete {
        /// Secret key.
        key: String,
    },
    /// Manage groups.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// List all groups.
    Groups,
    /// Start the local authenticated MCP server.
    StartMcpServer {
        /// Local HTTP port (binds only to 127.0.0.1).
        #[arg(long, default_value_t = 8765)]
        port: u16,
    },
}

#[derive(Subcommand)]
pub enum GroupCommand {
    /// Create a group and switch to it.
    Create {
        /// Group name.
        name: String,
    },
    /// Delete a group.
    Delete {
        /// Group name.
        name: String,
        /// Read the password from an environment variable instead of prompting.
        #[arg(long, value_name = "VAR")]
        password_env: Option<String>,
    },
}

pub fn run(command: Commands, group: Option<String>) -> Result<()> {
    if group.is_some()
        && !matches!(
            &command,
            Commands::Login { .. } | Commands::List { .. } | Commands::Search { .. }
        )
    {
        return Err(anyhow!(
            "-g/--group is only supported with login, list, and search"
        ));
    }
    match command {
        Commands::App => app::run(),
        Commands::Login { password_env } => login(group, password_env),
        Commands::Logout => logout(),
        Commands::Status => status(),
        Commands::Switch { group } => switch_group(&group),
        Commands::List { values } => list(values, group.as_deref()),
        Commands::Search { query, values } => search(&query, values, group.as_deref()),
        Commands::Get { key } => get(&key),
        Commands::Set { key, value } => set(&key, &value),
        Commands::Delete { key } => delete(&key),
        Commands::Group { command } => match command {
            GroupCommand::Create { name } => create_group(&name),
            GroupCommand::Delete { name, password_env } => delete_group(&name, password_env),
        },
        Commands::Groups => groups(),
        Commands::StartMcpServer { port } => mcp::start(port),
    }
}

fn login(group: Option<String>, password_env: Option<String>) -> Result<()> {
    let store = VaultStore::new()?;
    let mut vault = if store.exists() {
        let password = read_password("Password: ", password_env.as_deref())?;
        store.unlock(&password)?
    } else {
        let password = read_password("Create password: ", password_env.as_deref())?;
        if password_env.is_none() {
            let confirm =
                prompt_password("Confirm password: ").context("failed to read password")?;
            if password != confirm {
                return Err(anyhow!("passwords do not match"));
            }
        }
        store.create(&password)?
    };

    if let Some(group) = group {
        vault.switch_group(&group)?;
    }

    session::save(&Session::new(vault.key(), vault.active_group())?)?;
    println!("Logged in. Active group: {}", vault.active_group());
    Ok(())
}

fn read_password(prompt: &str, password_env: Option<&str>) -> Result<String> {
    if let Some(name) = password_env {
        return std::env::var(name).with_context(|| format!("{name} is not set"));
    }
    if let Ok(password) = std::env::var("KS_PASSWORD") {
        return Ok(password);
    }
    prompt_password(prompt).context("failed to read password")
}

fn logout() -> Result<()> {
    if session::clear()? {
        println!("Logged out");
    } else {
        println!("No active session");
    }
    Ok(())
}

fn status() -> Result<()> {
    let store = VaultStore::new()?;
    if !store.exists() {
        println!("No vault exists yet. Run `ks login` or open `ks app` to create one.");
        return Ok(());
    }

    match unlock_from_session() {
        Ok(vault) => {
            println!("Logged in");
            println!("Active group: {}", vault.active_group());
            println!("Groups: {}", vault.data().groups.len());
            for (name, group) in &vault.data().groups {
                println!("  {}: {} secrets", name, group.secrets.len());
            }
        }
        Err(err) => {
            println!("Logged out");
            println!("Reason: {err}");
        }
    }
    Ok(())
}

fn switch_group(group: &str) -> Result<()> {
    let mut vault = unlock_from_session()?;
    vault.switch_group(group)?;
    session::save(&Session::new(vault.key(), vault.active_group())?)?;
    println!("Active group: {}", vault.active_group());
    Ok(())
}

fn selected_group<'a>(data: &'a VaultData, selected: Option<&str>) -> Result<(&'a str, &'a Group)> {
    let name = selected.unwrap_or(&data.active_group);
    let (name, group) = data
        .groups
        .get_key_value(name)
        .ok_or_else(|| anyhow!("group '{name}' does not exist"))?;
    Ok((name, group))
}

fn list(values: bool, selected: Option<&str>) -> Result<()> {
    let vault = unlock_from_session()?;
    let (name, group) = selected_group(vault.data(), selected)?;
    if group.secrets.is_empty() {
        println!("No secrets in group '{name}'");
        return Ok(());
    }
    for (key, value) in &group.secrets {
        if values {
            println!("{key}={value}");
        } else {
            println!("{key}");
        }
    }
    Ok(())
}

fn search_matches<'a>(
    group: &'a Group,
    query: &str,
) -> impl Iterator<Item = (&'a String, &'a String)> {
    let query = query.to_lowercase();
    group
        .secrets
        .iter()
        .filter(move |(key, _)| key.to_lowercase().contains(&query))
}

fn search(query: &str, values: bool, selected: Option<&str>) -> Result<()> {
    let vault = unlock_from_session()?;
    let (_, group) = selected_group(vault.data(), selected)?;
    for (key, value) in search_matches(group, query) {
        if values {
            println!("{key}={value}");
        } else {
            println!("{key}");
        }
    }
    Ok(())
}

fn get(key: &str) -> Result<()> {
    let vault = unlock_from_session()?;
    match vault.get(key)? {
        Some(value) => {
            println!("{value}");
            Ok(())
        }
        None => Err(anyhow!(
            "key '{key}' not found in group '{}'",
            vault.active_group()
        )),
    }
}

fn set(key: &str, value: &str) -> Result<()> {
    let mut vault = unlock_from_session()?;
    vault.set(key, value)?;
    println!("Set '{key}' in group '{}'", vault.active_group());
    Ok(())
}

fn delete(key: &str) -> Result<()> {
    let mut vault = unlock_from_session()?;
    if vault.delete(key)? {
        println!("Deleted '{key}' from group '{}'", vault.active_group());
        Ok(())
    } else {
        Err(anyhow!(
            "key '{key}' not found in group '{}'",
            vault.active_group()
        ))
    }
}

fn create_group(name: &str) -> Result<()> {
    let mut vault = unlock_from_session()?;
    vault.create_group(name)?;
    session::save(&Session::new(vault.key(), vault.active_group())?)?;
    println!("Created group '{name}'");
    println!("Active group: {}", vault.active_group());
    Ok(())
}

fn delete_group(name: &str, password_env: Option<String>) -> Result<()> {
    let mut vault = unlock_from_session()?;
    let password = read_password("Password to delete group: ", password_env.as_deref())?;
    VaultStore::new()?
        .unlock(&password)
        .context("failed to verify password for group deletion")?;
    vault.delete_group(name)?;
    session::save(&Session::new(vault.key(), vault.active_group())?)?;
    println!("Deleted group '{name}'");
    println!("Active group: {}", vault.active_group());
    Ok(())
}

fn groups() -> Result<()> {
    let vault = unlock_from_session()?;
    for (name, group) in &vault.data().groups {
        if name == vault.active_group() {
            println!("* {name}: {} secrets", group.secrets.len());
        } else {
            println!("  {name}: {} secrets", group.secrets.len());
        }
    }
    Ok(())
}

fn unlock_from_session() -> Result<crate::storage::UnlockedVault> {
    let session = session::load()?;
    let store = VaultStore::new()?;
    let mut vault = store.unlock_with_key(session.key()?)?;
    if vault.active_group() != session.active_group
        && vault.data().groups.contains_key(&session.active_group)
    {
        vault.switch_group(&session.active_group)?;
    }
    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Group, VaultData};

    #[test]
    fn group_flag_before_list_is_accepted() {
        assert!(Cli::try_parse_from(["ks", "-g", "work", "list"]).is_ok());
    }

    #[test]
    fn switch_positional_does_not_set_global_group_flag() {
        let args = Cli::try_parse_from(["ks", "switch", "work"]).unwrap();
        assert!(args.selected_group.is_none());
    }

    #[test]
    fn group_flag_is_not_silently_ignored_by_other_commands() {
        let error = run(Commands::Status, Some("work".into())).unwrap_err();
        assert!(error
            .to_string()
            .contains("only supported with login, list, and search"));
    }

    #[test]
    fn selected_group_uses_override_without_changing_active_group() {
        let mut data = VaultData::default();
        data.groups.insert("work".into(), Group::default());

        let (name, _) = selected_group(&data, Some("work")).unwrap();
        assert_eq!(name, "work");
        assert_eq!(data.active_group, "default");
        assert_eq!(selected_group(&data, None).unwrap().0, "default");
    }

    #[test]
    fn selected_group_rejects_missing_group() {
        let data = VaultData::default();
        assert_eq!(
            selected_group(&data, Some("missing"))
                .unwrap_err()
                .to_string(),
            "group 'missing' does not exist"
        );
    }

    #[test]
    fn search_accepts_query_with_group_before_or_after_command() {
        for args in [
            ["ks", "-g", "work", "search", "api"],
            ["ks", "search", "api", "-g", "work"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn search_matches_only_key_substrings_ignoring_case() {
        let mut group = Group::default();
        group.secrets.insert("API_TOKEN".into(), "hidden".into());
        group.secrets.insert("other".into(), "api value".into());

        let keys: Vec<_> = search_matches(&group, "api")
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(keys, ["API_TOKEN"]);
        assert_eq!(search_matches(&group, "absent").count(), 0);
    }

    #[test]
    fn mcp_server_command_accepts_port() {
        assert!(Cli::try_parse_from(["ks", "start-mcp-server", "--port", "8989"]).is_ok());
    }
}
