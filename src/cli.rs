use crate::app;
use crate::session::{self, Session};
use crate::storage::VaultStore;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use rpassword::prompt_password;

#[derive(Parser)]
#[command(name = "ks")]
#[command(about = "Encrypted desktop and CLI key store")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Open the desktop application.
    App,
    /// Unlock the vault for terminal commands.
    Login {
        /// Switch to this group after login.
        #[arg(short, long)]
        group: Option<String>,
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

pub fn run(command: Commands) -> Result<()> {
    match command {
        Commands::App => app::run(),
        Commands::Login {
            group,
            password_env,
        } => login(group, password_env),
        Commands::Logout => logout(),
        Commands::Status => status(),
        Commands::Switch { group } => switch_group(&group),
        Commands::List { values } => list(values),
        Commands::Get { key } => get(&key),
        Commands::Set { key, value } => set(&key, &value),
        Commands::Delete { key } => delete(&key),
        Commands::Group { command } => match command {
            GroupCommand::Create { name } => create_group(&name),
            GroupCommand::Delete { name, password_env } => delete_group(&name, password_env),
        },
        Commands::Groups => groups(),
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

fn list(values: bool) -> Result<()> {
    let vault = unlock_from_session()?;
    let group = vault.active_group_ref()?;
    if group.secrets.is_empty() {
        println!("No secrets in group '{}'", vault.active_group());
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
