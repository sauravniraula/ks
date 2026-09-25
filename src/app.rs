use crate::api_keys::Access;
use crate::storage::{UnlockedVault, VaultStore};
use anyhow::{Context as AnyhowContext, Result};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf, time::Duration};

const APP_DIR: &str = "rust_keystore";
const WINDOW_SETTINGS_FILE: &str = "window.json";
const APP_VERSION_LABEL: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const APP_TITLE: &str = concat!("KS Encrypted Key Store v", env!("CARGO_PKG_VERSION"));
const DEFAULT_WINDOW_SIZE: [f32; 2] = [1040.0, 680.0];
const MIN_WINDOW_SIZE: [f32; 2] = [820.0, 560.0];
const LOGO_BYTES: &[u8] = include_bytes!("../assets/logo.png");
const DESKTOP_ICON_BYTES: &[u8] = include_bytes!("../assets/icon.png");
const BG: egui::Color32 = egui::Color32::from_gray(14);
const PANEL: egui::Color32 = egui::Color32::from_gray(24);
const PANEL_ALT: egui::Color32 = egui::Color32::from_gray(19);
const BORDER: egui::Color32 = egui::Color32::from_gray(58);
const TEXT: egui::Color32 = egui::Color32::from_gray(238);
const MUTED: egui::Color32 = egui::Color32::from_gray(156);
const SELECTED: egui::Color32 = egui::Color32::from_gray(214);
const SELECTED_BG: egui::Color32 = egui::Color32::from_gray(52);
const FIELD_BG: egui::Color32 = egui::Color32::from_gray(31);
const HOVER_BG: egui::Color32 = egui::Color32::from_gray(42);
const DANGER_TEXT: egui::Color32 = egui::Color32::from_gray(205);
const DANGER_BG: egui::Color32 = egui::Color32::from_gray(34);

pub fn run() -> Result<()> {
    let initial_window_size = load_window_size().unwrap_or(DEFAULT_WINDOW_SIZE);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(initial_window_size)
            .with_min_inner_size(MIN_WINDOW_SIZE)
            .with_icon(load_app_icon()?),
        ..Default::default()
    };

    eframe::run_native(
        APP_TITLE,
        options,
        Box::new(|cc| {
            apply_fonts(&cc.egui_ctx);
            apply_style(&cc.egui_ctx);
            let logo = load_logo_texture(&cc.egui_ctx)?;
            let menu_icon = load_menu_texture(&cc.egui_ctx)?;
            Ok(Box::new(KeyStoreApp::new(
                logo,
                menu_icon,
                initial_window_size,
            )))
        }),
    )
    .map_err(|err| anyhow::anyhow!("failed to launch desktop app: {err}"))
}

#[derive(Clone)]
enum ApiKeyForm {
    Create,
    Edit(String),
}

struct KeyStoreApp {
    logo: egui::TextureHandle,
    menu_icon: egui::TextureHandle,
    last_window_size: [f32; 2],
    store: Result<VaultStore, String>,
    vault: Option<UnlockedVault>,
    password: String,
    confirm_password: String,
    selected_key: Option<String>,
    edit_key: String,
    edit_value: String,
    show_secret_value: bool,
    secret_search: String,
    new_key: String,
    new_value: String,
    new_group: String,
    rename_group_name: String,
    rename_group_error: String,
    rename_group_needs_focus: bool,
    delete_group_password: String,
    delete_group_error: String,
    change_current_password: String,
    change_new_password: String,
    change_confirm_password: String,
    change_password_error: String,
    show_change_password: bool,
    change_password_needs_focus: bool,
    export_path: Option<PathBuf>,
    export_password: String,
    export_error: String,
    export_password_needs_focus: bool,
    import_path: Option<PathBuf>,
    import_password: String,
    import_error: String,
    import_password_needs_focus: bool,
    pending_rename_group: Option<String>,
    pending_delete_group: Option<String>,
    pending_delete_secret: Option<String>,
    show_api_keys: bool,
    api_key_form: Option<ApiKeyForm>,
    api_key_name: String,
    api_key_permissions: BTreeMap<String, Access>,
    api_key_unlimited: bool,
    api_key_expiry_date: String,
    api_key_error: String,
    api_issued_token: Option<String>,
    pending_delete_api_key: Option<String>,
    login_password_needs_focus: bool,
    copied_at: Option<f64>,
    message: String,
}

impl KeyStoreApp {
    fn new(
        logo: egui::TextureHandle,
        menu_icon: egui::TextureHandle,
        last_window_size: [f32; 2],
    ) -> Self {
        Self {
            logo,
            menu_icon,
            last_window_size,
            store: VaultStore::new().map_err(|err| err.to_string()),
            vault: None,
            password: String::new(),
            confirm_password: String::new(),
            selected_key: None,
            edit_key: String::new(),
            edit_value: String::new(),
            show_secret_value: false,
            secret_search: String::new(),
            new_key: String::new(),
            new_value: String::new(),
            new_group: String::new(),
            rename_group_name: String::new(),
            rename_group_error: String::new(),
            rename_group_needs_focus: false,
            delete_group_password: String::new(),
            delete_group_error: String::new(),
            change_current_password: String::new(),
            change_new_password: String::new(),
            change_confirm_password: String::new(),
            change_password_error: String::new(),
            show_change_password: false,
            change_password_needs_focus: false,
            export_path: None,
            export_password: String::new(),
            export_error: String::new(),
            export_password_needs_focus: false,
            import_path: None,
            import_password: String::new(),
            import_error: String::new(),
            import_password_needs_focus: false,
            pending_rename_group: None,
            pending_delete_group: None,
            pending_delete_secret: None,
            show_api_keys: false,
            api_key_form: None,
            api_key_name: String::new(),
            api_key_permissions: BTreeMap::new(),
            api_key_unlimited: true,
            api_key_expiry_date: String::new(),
            api_key_error: String::new(),
            api_issued_token: None,
            pending_delete_api_key: None,
            login_password_needs_focus: true,
            copied_at: None,
            message: String::new(),
        }
    }

    fn store(&self) -> Result<&VaultStore, String> {
        self.store.as_ref().map_err(|err| err.clone())
    }

    fn unlock_or_create(&mut self) {
        self.message.clear();
        let result = (|| -> Result<UnlockedVault> {
            let store = self.store().map_err(anyhow::Error::msg)?;
            if store.exists() {
                store.unlock(&self.password)
            } else {
                if self.password != self.confirm_password {
                    anyhow::bail!("passwords do not match");
                }
                store.create(&self.password)
            }
        })();

        match result {
            Ok(vault) => {
                self.vault = Some(vault);
                self.login_password_needs_focus = true;
                self.password.clear();
                self.confirm_password.clear();
                self.message = "Unlocked".to_string();
            }
            Err(err) => self.message = err.to_string(),
        }
    }

    fn refresh_selected_value(&mut self) {
        let Some(vault) = &self.vault else {
            return;
        };
        let Some(key) = &self.selected_key else {
            return;
        };

        match vault.get(key) {
            Ok(Some(value)) => {
                self.edit_key = key.clone();
                self.edit_value = value.clone();
                self.show_secret_value = false;
            }
            _ => {
                self.selected_key = None;
                self.edit_key.clear();
                self.edit_value.clear();
                self.show_secret_value = false;
                self.copied_at = None;
            }
        }
    }

    fn create_group(&mut self) {
        if let Some(vault) = &mut self.vault {
            match vault.create_group(&self.new_group) {
                Ok(()) => {
                    self.message = format!("Created group '{}'", self.new_group);
                    self.new_group.clear();
                    self.selected_key = None;
                    self.edit_key.clear();
                    self.edit_value.clear();
                    self.show_secret_value = false;
                    self.copied_at = None;
                }
                Err(err) => self.message = err.to_string(),
            }
        }
    }

    fn save_secret(&mut self) {
        if let Some(vault) = &mut self.vault {
            match vault.set(&self.new_key, &self.new_value) {
                Ok(()) => {
                    self.selected_key = Some(self.new_key.clone());
                    self.edit_key = self.new_key.clone();
                    self.edit_value = self.new_value.clone();
                    self.show_secret_value = false;
                    self.copied_at = None;
                    self.message = format!("Saved '{}'", self.new_key);
                    self.new_key.clear();
                    self.new_value.clear();
                }
                Err(err) => self.message = err.to_string(),
            }
        }
    }

    fn update_secret(&mut self, key: &str) {
        if let Some(vault) = &mut self.vault {
            match vault.rename_secret(key, &self.edit_key, &self.edit_value) {
                Ok(()) => {
                    if key == self.edit_key {
                        self.message = format!("Updated '{key}'");
                    } else {
                        self.message = format!("Renamed '{key}' to '{}'", self.edit_key);
                    }
                    self.selected_key = Some(self.edit_key.clone());
                    self.show_secret_value = false;
                    self.copied_at = None;
                }
                Err(err) => self.message = err.to_string(),
            }
        }
    }

    fn request_rename_group(&mut self, group: String) {
        self.rename_group_name = group.clone();
        self.rename_group_error.clear();
        self.rename_group_needs_focus = true;
        self.pending_rename_group = Some(group);
    }

    fn cancel_rename_group(&mut self) {
        self.pending_rename_group = None;
        self.rename_group_name.clear();
        self.rename_group_error.clear();
        self.rename_group_needs_focus = false;
    }

    fn confirm_rename_group(&mut self) {
        let Some(group) = self.pending_rename_group.clone() else {
            return;
        };
        let new_group = self.rename_group_name.clone();

        if let Some(vault) = &mut self.vault {
            match vault.rename_group(&group, &new_group) {
                Ok(()) => {
                    if group == new_group {
                        self.message = format!("Group '{group}' unchanged");
                    } else {
                        self.message = format!("Renamed group '{group}' to '{new_group}'");
                    }
                    self.cancel_rename_group();
                }
                Err(err) => self.rename_group_error = err.to_string(),
            }
        }
    }

    fn request_delete_group(&mut self, group: String) {
        self.pending_delete_group = Some(group);
        self.delete_group_password.clear();
        self.delete_group_error.clear();
    }

    fn confirm_delete_group(&mut self) {
        let Some(group) = self.pending_delete_group.clone() else {
            return;
        };
        let verified = self
            .store()
            .map_err(anyhow::Error::msg)
            .and_then(|store| store.unlock(&self.delete_group_password).map(|_| ()));
        if let Err(err) = verified {
            self.delete_group_error = format!("Failed to verify password: {err}");
            return;
        }

        self.delete_group_password.clear();
        self.delete_group_error.clear();
        if let Some(vault) = &mut self.vault {
            let deleted_active = vault.active_group() == group;
            match vault.delete_group(&group) {
                Ok(()) => {
                    self.message = format!("Deleted group '{group}'");
                    self.pending_delete_group = None;
                    if deleted_active {
                        self.selected_key = None;
                        self.edit_key.clear();
                        self.edit_value.clear();
                        self.show_secret_value = false;
                        self.copied_at = None;
                    }
                }
                Err(err) => self.delete_group_error = err.to_string(),
            }
        }
    }

    fn request_delete_secret(&mut self, key: String) {
        self.pending_delete_secret = Some(key);
    }

    fn confirm_delete_secret(&mut self) {
        let Some(key) = self.pending_delete_secret.clone() else {
            return;
        };
        if let Some(vault) = &mut self.vault {
            match vault.delete(&key) {
                Ok(true) => {
                    self.message = format!("Deleted '{key}'");
                    self.pending_delete_secret = None;
                    if self.selected_key.as_ref() == Some(&key) {
                        self.selected_key = None;
                        self.edit_key.clear();
                        self.edit_value.clear();
                        self.show_secret_value = false;
                        self.copied_at = None;
                    }
                }
                Ok(false) => {
                    self.message = format!("'{key}' was already missing");
                    self.pending_delete_secret = None;
                }
                Err(err) => self.message = err.to_string(),
            }
        }
    }

    fn request_change_password(&mut self) {
        self.change_current_password.clear();
        self.change_new_password.clear();
        self.change_confirm_password.clear();
        self.change_password_error.clear();
        self.show_change_password = true;
        self.change_password_needs_focus = true;
    }

    fn cancel_change_password(&mut self) {
        self.change_current_password.clear();
        self.change_new_password.clear();
        self.change_confirm_password.clear();
        self.change_password_error.clear();
        self.show_change_password = false;
        self.change_password_needs_focus = false;
    }

    fn confirm_change_password(&mut self) {
        self.change_password_error.clear();
        let result = (|| -> Result<()> {
            if self.change_new_password != self.change_confirm_password {
                anyhow::bail!("passwords do not match");
            }
            let store = self.store().map_err(anyhow::Error::msg)?;
            store
                .unlock(&self.change_current_password)
                .context("failed to verify current password")?;
            let vault = self
                .vault
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("vault is locked"))?;
            vault.change_password(&self.change_new_password)?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.cancel_change_password();
                self.message = "Password changed".to_string();
            }
            Err(err) => self.change_password_error = err.to_string(),
        }
    }

    fn request_export(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export encrypted vault")
            .add_filter("KS vault export", &["json"])
            .set_file_name("ks-export.json")
            .save_file()
        else {
            return;
        };

        self.export_path = Some(path);
        self.export_password.clear();
        self.export_error.clear();
        self.export_password_needs_focus = true;
    }

    fn cancel_export(&mut self) {
        self.export_path = None;
        self.export_password.clear();
        self.export_error.clear();
        self.export_password_needs_focus = false;
    }

    fn confirm_export(&mut self) {
        self.export_error.clear();
        let Some(path) = self.export_path.clone() else {
            return;
        };

        let result = (|| -> Result<()> {
            let vault = self
                .vault
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("vault is locked"))?;
            vault.export_to_path(&path, &self.export_password)?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.cancel_export();
                self.message = format!("Exported vault to {}", path.display());
            }
            Err(err) => self.export_error = err.to_string(),
        }
    }

    fn request_import(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Import encrypted vault")
            .add_filter("KS vault export", &["json"])
            .pick_file()
        else {
            return;
        };

        self.import_path = Some(path);
        self.import_password.clear();
        self.import_error.clear();
        self.import_password_needs_focus = true;
    }

    fn cancel_import(&mut self) {
        self.import_path = None;
        self.import_password.clear();
        self.import_error.clear();
        self.import_password_needs_focus = false;
    }

    fn confirm_import(&mut self) {
        self.import_error.clear();
        let Some(path) = self.import_path.clone() else {
            return;
        };

        let result = (|| -> Result<()> {
            let vault = self
                .vault
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("vault is locked"))?;
            vault.import_from_path(&path, &self.import_password)?;
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.api_issued_token = None;
                self.api_key_form = None;
                self.selected_key = None;
                self.edit_key.clear();
                self.edit_value.clear();
                self.secret_search.clear();
                self.show_secret_value = false;
                self.copied_at = None;
                self.cancel_import();
                self.message = format!("Imported vault from {}", path.display());
            }
            Err(err) => self.import_error = err.to_string(),
        }
    }

    fn open_api_key_form(&mut self, id: Option<String>) {
        self.api_key_error.clear();
        self.api_issued_token = None;
        self.api_key_permissions.clear();
        self.api_key_name.clear();
        self.api_key_expiry_date.clear();
        self.api_key_unlimited = true;
        if let Some(id) = id {
            if let Some(record) = self
                .vault
                .as_ref()
                .and_then(|vault| vault.data().api_keys.get(&id))
            {
                self.api_key_name = record.name.clone();
                self.api_key_permissions = record.permissions.clone();
                self.api_key_unlimited = record.expires_at.is_none();
                if let Some(expires_at) = record.expires_at {
                    self.api_key_expiry_date = chrono::DateTime::from_timestamp(expires_at, 0)
                        .map(|date| date.format("%Y-%m-%d").to_string())
                        .unwrap_or_default();
                }
                self.api_key_form = Some(ApiKeyForm::Edit(id));
            }
        } else {
            self.api_key_form = Some(ApiKeyForm::Create);
        }
    }

    fn save_api_key_form(&mut self) {
        let result = (|| -> Result<String> {
            let expires_at = parse_expiry_date(self.api_key_unlimited, &self.api_key_expiry_date)?;
            let vault = self
                .vault
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("vault is locked"))?;
            let (_, token) = match self.api_key_form.as_ref() {
                Some(ApiKeyForm::Create) => vault.create_api_key(
                    &self.api_key_name,
                    self.api_key_permissions.clone(),
                    expires_at,
                )?,
                Some(ApiKeyForm::Edit(id)) => vault.edit_api_key(
                    id,
                    &self.api_key_name,
                    self.api_key_permissions.clone(),
                    expires_at,
                )?,
                None => return Err(anyhow::anyhow!("API key form is closed")),
            };
            Ok(token)
        })();
        match result {
            Ok(token) => {
                self.api_key_form = None;
                self.api_key_error.clear();
                self.api_issued_token = Some(token);
                self.message =
                    "API key saved. Copy the new token now; it will not be shown again.".into();
            }
            Err(err) => self.api_key_error = err.to_string(),
        }
    }

    fn confirm_delete_api_key(&mut self) {
        let Some(id) = self.pending_delete_api_key.clone() else {
            return;
        };
        match self
            .vault
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("vault is locked"))
            .and_then(|vault| vault.delete_api_key(&id))
        {
            Ok(()) => {
                self.pending_delete_api_key = None;
                self.api_issued_token = None;
                self.message = "API key deleted".into();
            }
            Err(err) => self.message = err.to_string(),
        }
    }

    fn logout_vault(&mut self) {
        self.vault = None;
        self.show_api_keys = false;
        self.api_key_form = None;
        self.api_issued_token = None;
        self.pending_delete_api_key = None;
        self.selected_key = None;
        self.edit_key.clear();
        self.edit_value.clear();
        self.show_secret_value = false;
        self.cancel_rename_group();
        self.delete_group_password.clear();
        self.delete_group_error.clear();
        self.pending_delete_group = None;
        self.pending_delete_secret = None;
        self.cancel_change_password();
        self.cancel_export();
        self.cancel_import();
        self.login_password_needs_focus = true;
        self.copied_at = None;
        self.message = "Logged out".to_string();
    }

    fn remember_window_size(&mut self, ctx: &egui::Context) {
        let Some(size) = ctx.input(|input| input.viewport().inner_rect.map(|rect| rect.size()))
        else {
            return;
        };
        let size = clamp_window_size([size.x.round(), size.y.round()]);
        if size == self.last_window_size {
            return;
        }

        self.last_window_size = size;
        if let Err(err) = save_window_size(size) {
            self.message = format!("Failed to save window size: {err}");
        }
    }
}

impl eframe::App for KeyStoreApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.remember_window_size(ctx);

        if self.vault.is_none() {
            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(BG))
                .show(ctx, |ui| self.login_view(ui));
            return;
        }

        self.top_bar(ctx);

        if self.show_api_keys {
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::none()
                        .fill(BG)
                        .inner_margin(egui::Margin::same(22.0)),
                )
                .show(ctx, |ui| self.api_keys_view(ui));
            self.api_key_dialogs(ctx);
            return;
        }

        egui::SidePanel::left("groups_sidebar")
            .exact_width(260.0)
            .resizable(false)
            .frame(
                egui::Frame::none()
                    .fill(PANEL_ALT)
                    .stroke(egui::Stroke::new(1.0, BORDER))
                    .inner_margin(egui::Margin::symmetric(16.0, 16.0)),
            )
            .show(ctx, |ui| self.groups_panel(ui));

        egui::SidePanel::left("secrets_sidebar")
            .exact_width(330.0)
            .resizable(false)
            .frame(
                egui::Frame::none()
                    .fill(BG)
                    .stroke(egui::Stroke::new(1.0, BORDER))
                    .inner_margin(egui::Margin::same(16.0)),
            )
            .show(ctx, |ui| self.keys_panel(ui));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(18.0)),
            )
            .show(ctx, |ui| self.editor_workspace(ui));

        self.confirmation_dialogs(ctx);
    }
}

impl KeyStoreApp {
    fn api_keys_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("← Back").clicked() {
                self.show_api_keys = false;
            }
            ui.add_space(12.0);
            section_title(ui, "API Keys");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(primary_button("Create API Key")).clicked() {
                    self.open_api_key_form(None);
                }
            });
        });
        ui.add_space(12.0);
        ui.label(
            egui::RichText::new("Keys authorize the local MCP server. Tokens are only shown once.")
                .color(MUTED),
        );
        if !self.message.is_empty() {
            ui.label(egui::RichText::new(&self.message).color(MUTED));
        }
        let records = self
            .vault
            .as_ref()
            .map(|vault| vault.data().api_keys.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        egui::ScrollArea::vertical().show(ui, |ui| {
            if records.is_empty() {
                empty_state(ui, "No API keys yet");
            }
            for record in records {
                card_frame().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&record.name).color(TEXT).strong());
                        let expiry = record
                            .expires_at
                            .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0))
                            .map(|date| format!("Expires {} UTC", date.format("%Y-%m-%d")))
                            .unwrap_or_else(|| "Unlimited".to_string());
                        ui.label(egui::RichText::new(expiry).color(MUTED));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(danger_button("Delete")).clicked() {
                                self.pending_delete_api_key = Some(record.id.clone());
                            }
                            if ui.add(secondary_button("Edit")).clicked() {
                                self.open_api_key_form(Some(record.id.clone()));
                            }
                        });
                    });
                    ui.label(
                        egui::RichText::new(format!("{} groups", record.permissions.len()))
                            .color(MUTED),
                    );
                });
                ui.add_space(8.0);
            }
        });
    }

    fn api_key_dialogs(&mut self, ctx: &egui::Context) {
        if let Some(form) = self.api_key_form.clone() {
            let mut open = true;
            let title = match form {
                ApiKeyForm::Create => "Create API Key",
                ApiKeyForm::Edit(_) => "Edit API Key",
            };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(true)
                .order(egui::Order::Foreground)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_min_width(410.0);
                    ui.label("Name");
                    ui.add_sized(
                        [ui.available_width(), 32.0],
                        padded_singleline(&mut self.api_key_name, "Key name"),
                    );
                    ui.add_space(10.0);
                    ui.label("Group access");
                    let groups = self
                        .vault
                        .as_ref()
                        .map(|vault| vault.data().groups.keys().cloned().collect::<Vec<_>>())
                        .unwrap_or_default();
                    for group in groups {
                        ui.horizontal(|ui| {
                            let mut enabled = self.api_key_permissions.contains_key(&group);
                            ui.checkbox(&mut enabled, &group);
                            if enabled {
                                let mut access = *self
                                    .api_key_permissions
                                    .get(&group)
                                    .unwrap_or(&Access::ReadOnly);
                                ui.selectable_value(&mut access, Access::ReadOnly, "Read only");
                                ui.selectable_value(&mut access, Access::ReadWrite, "Read + write");
                                self.api_key_permissions.insert(group.clone(), access);
                            } else {
                                self.api_key_permissions.remove(&group);
                            }
                        });
                    }
                    ui.add_space(10.0);
                    ui.checkbox(&mut self.api_key_unlimited, "Unlimited expiry");
                    if !self.api_key_unlimited {
                        ui.label("Expiry date (UTC, YYYY-MM-DD)");
                        ui.add_sized(
                            [ui.available_width(), 32.0],
                            padded_singleline(&mut self.api_key_expiry_date, "YYYY-MM-DD"),
                        );
                    }
                    if matches!(form, ApiKeyForm::Edit(_)) {
                        ui.label(
                            egui::RichText::new(
                                "Saving rotates this key; the previous token stops working.",
                            )
                            .color(MUTED),
                        );
                    }
                    if !self.api_key_error.is_empty() {
                        ui.label(egui::RichText::new(&self.api_key_error).color(DANGER_TEXT));
                    }
                    ui.horizontal(|ui| {
                        if ui.add(primary_button("Save")).clicked() {
                            self.save_api_key_form();
                        }
                        if ui.add(secondary_button("Cancel")).clicked() {
                            self.api_key_form = None;
                        }
                    });
                });
            if !open {
                self.api_key_form = None;
            }
        }
        if let Some(token) = self.api_issued_token.clone() {
            let mut open = true;
            egui::Window::new("Copy API Key")
                .collapsible(false)
                .resizable(true)
                .order(egui::Order::Foreground)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_min_width(450.0);
                    ui.label("Copy this token now. It cannot be viewed again.");
                    let mut display = token.clone();
                    ui.add_sized(
                        [ui.available_width(), 36.0],
                        egui::TextEdit::singleline(&mut display)
                            .font(egui::TextStyle::Monospace)
                            .interactive(false),
                    );
                    ui.horizontal(|ui| {
                        if ui.add(primary_button("Copy token")).clicked() {
                            ui.ctx().copy_text(token.clone());
                        }
                        if ui.add(secondary_button("Done")).clicked() {
                            self.api_issued_token = None;
                        }
                    });
                });
            if !open {
                self.api_issued_token = None;
            }
        }
        if let Some(id) = self.pending_delete_api_key.clone() {
            let mut open = true;
            egui::Window::new("Delete API Key")
                .collapsible(false)
                .resizable(false)
                .order(egui::Order::Foreground)
                .open(&mut open)
                .show(ctx, |ui| {
                    let name = self
                        .vault
                        .as_ref()
                        .and_then(|vault| vault.data().api_keys.get(&id))
                        .map(|key| key.name.as_str())
                        .unwrap_or("this key");
                    ui.label(format!(
                        "Delete {name}? This revokes its token immediately."
                    ));
                    ui.horizontal(|ui| {
                        if ui.add(danger_button("Delete")).clicked() {
                            self.confirm_delete_api_key();
                        }
                        if ui.add(secondary_button("Cancel")).clicked() {
                            self.pending_delete_api_key = None;
                        }
                    });
                });
            if !open {
                self.pending_delete_api_key = None;
            }
        }
    }

    fn login_view(&mut self, ui: &mut egui::Ui) {
        let vault_exists = self.store().map(|store| store.exists()).unwrap_or(false);
        let title = if vault_exists {
            "Unlock vault"
        } else {
            "Create encrypted vault"
        };
        let subtitle = if vault_exists {
            "Enter your password to open your local encrypted key store."
        } else {
            "Choose a password. Secrets are stored locally in an encrypted vault."
        };

        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() * 0.18).max(28.0));
            card_frame().show(ui, |ui| {
                ui.set_width(390.0);
                logo_mark(ui, &self.logo, 74.0);
                ui.add_space(12.0);
                ui.label(egui::RichText::new(title).size(20.0).color(TEXT));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(subtitle).color(MUTED));
                ui.add_space(18.0);

                let password_response = ui.add_sized(
                    [ui.available_width(), 38.0],
                    padded_singleline(&mut self.password, "Password").password(true),
                );
                if self.login_password_needs_focus {
                    password_response.request_focus();
                    self.login_password_needs_focus = false;
                }
                let mut submit = text_submitted(ui, &password_response);
                if !vault_exists {
                    ui.add_space(8.0);
                    let confirm_response = ui.add_sized(
                        [ui.available_width(), 38.0],
                        padded_singleline(&mut self.confirm_password, "Confirm password")
                            .password(true),
                    );
                    submit |= text_submitted(ui, &confirm_response);
                }
                ui.add_space(16.0);

                let label = if vault_exists {
                    "Unlock"
                } else {
                    "Create vault"
                };
                submit |= ui
                    .add_sized([ui.available_width(), 40.0], primary_button(label))
                    .clicked();
                if submit {
                    self.unlock_or_create();
                }

                if !self.message.is_empty() {
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new(&self.message).color(message_color()));
                }
            });
        });
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_bar")
            .exact_height(64.0)
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .stroke(egui::Stroke::new(1.0, BORDER))
                    .inner_margin(egui::Margin::symmetric(22.0, 12.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    logo_mark(ui, &self.logo, 40.0);
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new("Encrypted Key Store")
                            .size(16.0)
                            .strong()
                            .color(TEXT),
                    );
                    ui.label(
                        egui::RichText::new(APP_VERSION_LABEL)
                            .size(12.0)
                            .color(MUTED),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(action) = settings_menu(ui) {
                            match action {
                                SettingsAction::Import => self.request_import(),
                                SettingsAction::Export => self.request_export(),
                                SettingsAction::ChangePassword => self.request_change_password(),
                                SettingsAction::ApiKeys => self.show_api_keys = true,
                                SettingsAction::Logout => self.logout_vault(),
                            }
                        }
                    });
                });
            });
    }

    fn editor_workspace(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            self.detail_panel(ui);
            ui.add_space(14.0);
            self.add_secret_panel(ui);
        });
    }

    fn groups_panel(&mut self, ui: &mut egui::Ui) {
        let groups = self
            .vault
            .as_ref()
            .map(|vault| {
                vault
                    .data()
                    .groups
                    .iter()
                    .map(|(name, group)| (name.clone(), group.secrets.len()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let active = self
            .vault
            .as_ref()
            .map(|vault| vault.active_group().to_string())
            .unwrap_or_default();

        ui.horizontal(|ui| {
            section_title(ui, "Groups");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(groups.len().to_string())
                        .size(13.0)
                        .color(MUTED),
                );
            });
        });
        ui.add_space(10.0);

        egui::ScrollArea::vertical()
            .id_salt("groups_scroll")
            .auto_shrink([false, false])
            .max_height((ui.available_height() - 130.0).max(60.0))
            .show(ui, |ui| {
                for (group, count) in groups {
                    let selected = group == active;
                    let response = group_row(
                        ui,
                        &group,
                        count,
                        selected,
                        group != "default",
                        &self.menu_icon,
                    );
                    ui.add_space(6.0);
                    if response.rename_requested {
                        self.request_rename_group(group);
                    } else if response.delete_requested {
                        self.request_delete_group(group);
                    } else if response.row.clicked() {
                        if let Some(vault) = &mut self.vault {
                            match vault.switch_group(&group) {
                                Ok(()) => {
                                    self.selected_key = None;
                                    self.edit_key.clear();
                                    self.edit_value.clear();
                                    self.show_secret_value = false;
                                    self.copied_at = None;
                                    self.delete_group_password.clear();
                                    self.delete_group_error.clear();
                                    self.message = format!("Active group: {group}");
                                }
                                Err(err) => self.message = err.to_string(),
                            }
                        }
                    }
                }
            });

        ui.add_space(14.0);
        ui.separator();
        ui.add_space(12.0);
        let group_response = ui.add_sized(
            [ui.available_width(), 34.0],
            padded_singleline(&mut self.new_group, "New group"),
        );
        ui.add_space(8.0);
        let submit_group = text_submitted(ui, &group_response)
            || ui
                .add_sized([ui.available_width(), 34.0], primary_button("Create Group"))
                .clicked();
        if submit_group {
            self.create_group();
        }
    }

    fn keys_panel(&mut self, ui: &mut egui::Ui) {
        let secrets = self
            .vault
            .as_ref()
            .and_then(|vault| vault.active_group_ref().ok())
            .map(|group| group.secrets.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        ui.horizontal(|ui| {
            section_title(ui, "Secrets");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(secrets.len().to_string())
                        .size(13.0)
                        .color(MUTED),
                );
            });
        });
        ui.add_space(10.0);
        ui.add_sized(
            [ui.available_width(), 34.0],
            padded_singleline(&mut self.secret_search, "Search secrets"),
        );
        ui.add_space(10.0);

        let search = self.secret_search.trim().to_lowercase();
        let visible_secrets = if search.is_empty() {
            secrets
        } else {
            secrets
                .into_iter()
                .filter(|key| key.to_lowercase().contains(&search))
                .collect::<Vec<_>>()
        };

        egui::ScrollArea::vertical()
            .id_salt("secrets_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if visible_secrets.is_empty() {
                    let message = if search.is_empty() {
                        "No secrets in this group"
                    } else {
                        "No matching secrets"
                    };
                    empty_state(ui, message);
                }
                for key in visible_secrets {
                    let selected = self.selected_key.as_ref() == Some(&key);
                    let response = secret_row(ui, &key, selected);
                    ui.add_space(8.0);
                    if response.clicked() {
                        self.selected_key = Some(key);
                        self.refresh_selected_value();
                        self.copied_at = None;
                    }
                }
            });
    }

    fn detail_panel(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "Editor");
            let Some(key) = self.selected_key.clone() else {
                empty_state(ui, "Select a secret to view or edit it");
                return;
            };

            ui.label(egui::RichText::new("Key").color(MUTED).size(12.0));
            let key_response = ui.add_sized(
                [ui.available_width(), 36.0],
                padded_singleline(&mut self.edit_key, "Key").font(egui::TextStyle::Monospace),
            );
            ui.add_space(18.0);
            ui.horizontal(|ui| {
                let now = ui.input(|input| input.time);
                ui.label(egui::RichText::new("Value").color(MUTED).size(12.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if copy_icon_button(ui).clicked() {
                        ui.ctx().copy_text(self.edit_value.clone());
                        self.copied_at = Some(now);
                        ui.ctx().request_repaint_after(Duration::from_secs(1));
                    }
                    if secret_visibility_icon_button(ui, self.show_secret_value).clicked() {
                        self.show_secret_value = !self.show_secret_value;
                    }
                    if let Some(copied_at) = self.copied_at {
                        let remaining = 1.0 - (now - copied_at);
                        if remaining > 0.0 {
                            ui.ctx()
                                .request_repaint_after(Duration::from_secs_f64(remaining));
                            ui.label(egui::RichText::new("Copied").color(MUTED).size(12.0));
                        } else {
                            self.copied_at = None;
                        }
                    }
                });
            });
            ui.add_sized(
                [ui.available_width(), 150.0],
                egui::TextEdit::multiline(&mut self.edit_value)
                    .desired_rows(7)
                    .margin(field_margin())
                    .hint_text("Value")
                    .password(!self.show_secret_value),
            );
            ui.add_space(14.0);

            ui.horizontal(|ui| {
                let submit_update = text_submitted(ui, &key_response)
                    || ui
                        .add_sized([120.0, 36.0], primary_button("Update"))
                        .clicked();
                if submit_update {
                    self.update_secret(&key);
                }
                if ui
                    .add_sized([100.0, 36.0], danger_button("Delete"))
                    .clicked()
                {
                    self.request_delete_secret(key.clone());
                }
            });
        });
    }

    fn add_secret_panel(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            section_title(ui, "Add secret");
            ui.add_space(10.0);
            let key_response = ui.add_sized(
                [ui.available_width(), 36.0],
                padded_singleline(&mut self.new_key, "Key"),
            );
            ui.add_space(8.0);
            let value_response = ui.add_sized(
                [ui.available_width(), 36.0],
                padded_singleline(&mut self.new_value, "Value"),
            );
            ui.add_space(10.0);
            let submit_secret = text_submitted(ui, &key_response)
                || text_submitted(ui, &value_response)
                || ui
                    .add_sized([160.0, 36.0], primary_button("Save Secret"))
                    .clicked();
            if submit_secret {
                self.save_secret();
            }
        });
    }

    fn confirmation_dialogs(&mut self, ctx: &egui::Context) {
        if let Some(group) = self.pending_rename_group.clone() {
            let mut open = true;
            egui::Window::new("Rename group")
                .collapsible(false)
                .resizable(false)
                .order(egui::Order::Foreground)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_width(320.0);
                    ui.label(egui::RichText::new(format!("Rename group \"{group}\"")).color(TEXT));
                    ui.add_space(8.0);
                    let name_response = ui.add_sized(
                        [ui.available_width(), 36.0],
                        padded_singleline(&mut self.rename_group_name, "Group name"),
                    );
                    if self.rename_group_needs_focus {
                        name_response.request_focus();
                        self.rename_group_needs_focus = false;
                    }
                    if !self.rename_group_error.is_empty() {
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&self.rename_group_error).color(DANGER_TEXT));
                    }
                    ui.add_space(12.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let confirm = text_submitted(ui, &name_response)
                            || ui
                                .add_sized([92.0, 34.0], primary_button("Rename"))
                                .clicked();
                        if confirm {
                            self.confirm_rename_group();
                        }
                        if ui
                            .add_sized([86.0, 34.0], secondary_button("Cancel"))
                            .clicked()
                        {
                            self.cancel_rename_group();
                        }
                    });
                });
            if !open {
                self.cancel_rename_group();
            }
        }

        if let Some(group) = self.pending_delete_group.clone() {
            let mut open = true;
            egui::Window::new("Delete group")
                .collapsible(false)
                .resizable(false)
                .order(egui::Order::Foreground)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_width(320.0);
                    ui.label(egui::RichText::new(format!("Delete group \"{group}\"?")).color(TEXT));
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(
                            "Enter your vault password to delete this group and its secrets.",
                        )
                        .color(MUTED),
                    );
                    ui.add_space(8.0);
                    let password_response = ui.add_sized(
                        [ui.available_width(), 36.0],
                        padded_singleline(&mut self.delete_group_password, "Password")
                            .password(true),
                    );
                    if !self.delete_group_error.is_empty() {
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&self.delete_group_error).color(DANGER_TEXT));
                    }
                    ui.add_space(12.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let confirm = text_submitted(ui, &password_response)
                            || ui
                                .add_sized([92.0, 34.0], danger_button("Delete"))
                                .clicked();
                        if confirm {
                            self.confirm_delete_group();
                        }
                        if ui
                            .add_sized([86.0, 34.0], secondary_button("Cancel"))
                            .clicked()
                        {
                            self.pending_delete_group = None;
                            self.delete_group_password.clear();
                            self.delete_group_error.clear();
                        }
                    });
                });
            if !open {
                self.pending_delete_group = None;
                self.delete_group_password.clear();
                self.delete_group_error.clear();
            }
        }

        if let Some(key) = self.pending_delete_secret.clone() {
            let mut open = true;
            egui::Window::new("Delete secret")
                .collapsible(false)
                .resizable(false)
                .order(egui::Order::Foreground)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_width(320.0);
                    ui.label(egui::RichText::new(format!("Delete \"{key}\"?")).color(TEXT));
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("This will remove the secret from the active group.")
                            .color(MUTED),
                    );
                    ui.add_space(12.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_sized([92.0, 34.0], danger_button("Delete"))
                            .clicked()
                        {
                            self.confirm_delete_secret();
                        }
                        if ui
                            .add_sized([86.0, 34.0], secondary_button("Cancel"))
                            .clicked()
                        {
                            self.pending_delete_secret = None;
                        }
                    });
                });
            if !open {
                self.pending_delete_secret = None;
            }
        }

        if let Some(path) = self.export_path.clone() {
            let mut open = true;
            egui::Window::new("Export vault")
                .collapsible(false)
                .resizable(false)
                .order(egui::Order::Foreground)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_width(360.0);
                    ui.label(
                        egui::RichText::new("Encrypt this export with a password.").color(TEXT),
                    );
                    ui.add_space(4.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(path.display().to_string())
                                .size(12.0)
                                .color(MUTED),
                        )
                        .wrap(),
                    );
                    ui.add_space(10.0);
                    let password_response = ui.add_sized(
                        [ui.available_width(), 36.0],
                        padded_singleline(&mut self.export_password, "Export password")
                            .password(true),
                    );
                    if self.export_password_needs_focus {
                        password_response.request_focus();
                        self.export_password_needs_focus = false;
                    }
                    if !self.export_error.is_empty() {
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&self.export_error).color(DANGER_TEXT));
                    }
                    ui.add_space(12.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let confirm = text_submitted(ui, &password_response)
                            || ui
                                .add_sized([92.0, 34.0], primary_button("Export"))
                                .clicked();
                        if confirm {
                            self.confirm_export();
                        }
                        if ui
                            .add_sized([86.0, 34.0], secondary_button("Cancel"))
                            .clicked()
                        {
                            self.cancel_export();
                        }
                    });
                });
            if !open {
                self.cancel_export();
            }
        }

        if let Some(path) = self.import_path.clone() {
            let mut open = true;
            egui::Window::new("Import vault")
                .collapsible(false)
                .resizable(false)
                .order(egui::Order::Foreground)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_width(360.0);
                    ui.label(
                        egui::RichText::new("Enter the password for this export.").color(TEXT),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("Importing replaces the current vault contents.")
                            .color(MUTED),
                    );
                    ui.add_space(4.0);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(path.display().to_string())
                                .size(12.0)
                                .color(MUTED),
                        )
                        .wrap(),
                    );
                    ui.add_space(10.0);
                    let password_response = ui.add_sized(
                        [ui.available_width(), 36.0],
                        padded_singleline(&mut self.import_password, "Export password")
                            .password(true),
                    );
                    if self.import_password_needs_focus {
                        password_response.request_focus();
                        self.import_password_needs_focus = false;
                    }
                    if !self.import_error.is_empty() {
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&self.import_error).color(DANGER_TEXT));
                    }
                    ui.add_space(12.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let confirm = text_submitted(ui, &password_response)
                            || ui
                                .add_sized([92.0, 34.0], primary_button("Import"))
                                .clicked();
                        if confirm {
                            self.confirm_import();
                        }
                        if ui
                            .add_sized([86.0, 34.0], secondary_button("Cancel"))
                            .clicked()
                        {
                            self.cancel_import();
                        }
                    });
                });
            if !open {
                self.cancel_import();
            }
        }

        if self.show_change_password {
            let mut open = true;
            egui::Window::new("Change password")
                .collapsible(false)
                .resizable(false)
                .order(egui::Order::Foreground)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.set_width(340.0);
                    ui.label(egui::RichText::new("Choose a new vault password.").color(TEXT));
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(
                            "Enter your current password before re-encrypting the vault.",
                        )
                        .color(MUTED),
                    );
                    ui.add_space(10.0);
                    let current_response = ui.add_sized(
                        [ui.available_width(), 36.0],
                        padded_singleline(&mut self.change_current_password, "Current password")
                            .password(true),
                    );
                    if self.change_password_needs_focus {
                        current_response.request_focus();
                        self.change_password_needs_focus = false;
                    }
                    ui.add_space(8.0);
                    let new_response = ui.add_sized(
                        [ui.available_width(), 36.0],
                        padded_singleline(&mut self.change_new_password, "New password")
                            .password(true),
                    );
                    ui.add_space(8.0);
                    let confirm_response = ui.add_sized(
                        [ui.available_width(), 36.0],
                        padded_singleline(
                            &mut self.change_confirm_password,
                            "Confirm new password",
                        )
                        .password(true),
                    );
                    if !self.change_password_error.is_empty() {
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(&self.change_password_error).color(DANGER_TEXT),
                        );
                    }
                    ui.add_space(12.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let confirm = text_submitted(ui, &current_response)
                            || text_submitted(ui, &new_response)
                            || text_submitted(ui, &confirm_response)
                            || ui
                                .add_sized([92.0, 34.0], primary_button("Change"))
                                .clicked();
                        if confirm {
                            self.confirm_change_password();
                        }
                        if ui
                            .add_sized([86.0, 34.0], secondary_button("Cancel"))
                            .clicked()
                        {
                            self.cancel_change_password();
                        }
                    });
                });
            if !open {
                self.cancel_change_password();
            }
        }
    }
}

fn apply_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(22.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Small,
        egui::FontId::new(12.0, egui::FontFamily::Proportional),
    );
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = egui::Color32::from_gray(8);
    style.visuals.faint_bg_color = PANEL_ALT;
    style.visuals.window_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.inactive.bg_fill = FIELD_BG;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.hovered.bg_fill = HOVER_BG;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_gray(92));
    style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.active.bg_fill = SELECTED_BG;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_gray(118));
    style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.selection.bg_fill = SELECTED_BG;
    style.visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::from_gray(118));
    ctx.set_style(style);
}

fn apply_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "Inter".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/fonts/Inter-Variable.ttf")),
    );
    fonts.font_data.insert(
        "NotoSansMono".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/fonts/NotoSansMono-Regular.ttf")),
    );

    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "Inter".to_owned());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "NotoSansMono".to_owned());

    ctx.set_fonts(fonts);
}

fn load_logo_texture(ctx: &egui::Context) -> Result<egui::TextureHandle> {
    load_texture(ctx, "ks_logo", LOGO_BYTES)
}

fn load_menu_texture(ctx: &egui::Context) -> Result<egui::TextureHandle> {
    load_texture(ctx, "ks_menu", include_bytes!("../assets/menu.png"))
}

fn load_app_icon() -> Result<egui::IconData> {
    eframe::icon_data::from_png_bytes(DESKTOP_ICON_BYTES)
        .context("failed to load desktop app icon from assets/icon.png")
}

fn load_texture(
    ctx: &egui::Context,
    name: &'static str,
    bytes: &'static [u8],
) -> Result<egui::TextureHandle> {
    let image = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)?.to_rgba8();
    let size = [image.width() as usize, image.height() as usize];
    let pixels = image.into_raw();
    let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);

    Ok(ctx.load_texture(
        name,
        color_image,
        egui::TextureOptions::LINEAR.with_mipmap_mode(Some(egui::TextureFilter::Linear)),
    ))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct WindowSettings {
    width: f32,
    height: f32,
}

fn load_window_size() -> Result<[f32; 2]> {
    let path = window_settings_path()?;
    if !path.exists() {
        return Ok(DEFAULT_WINDOW_SIZE);
    }

    let content =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let settings: WindowSettings = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    Ok(clamp_window_size([settings.width, settings.height]))
}

fn save_window_size(size: [f32; 2]) -> Result<()> {
    let path = window_settings_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let settings = WindowSettings {
        width: size[0],
        height: size[1],
    };
    let content =
        serde_json::to_string_pretty(&settings).context("failed to encode window settings")?;
    fs::write(&path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn window_settings_path() -> Result<PathBuf> {
    let mut path = dirs::config_dir().context("could not find config directory")?;
    path.push(APP_DIR);
    path.push(WINDOW_SETTINGS_FILE);
    Ok(path)
}

fn clamp_window_size(size: [f32; 2]) -> [f32; 2] {
    [
        size[0].clamp(MIN_WINDOW_SIZE[0], 4096.0),
        size[1].clamp(MIN_WINDOW_SIZE[1], 3072.0),
    ]
}

fn card_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(PANEL)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(18.0))
}

fn section_title(ui: &mut egui::Ui, title: &str) {
    ui.label(egui::RichText::new(title).size(18.0).strong().color(TEXT));
}

fn empty_state(ui: &mut egui::Ui, message: &str) {
    ui.add_space(18.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new(message).color(MUTED));
    });
}

fn logo_mark(ui: &mut egui::Ui, logo: &egui::TextureHandle, height: f32) -> egui::Response {
    let [width_px, height_px] = logo.size();
    let aspect = width_px as f32 / height_px as f32;
    let size = egui::vec2(height * aspect, height);

    ui.add(egui::Image::from_texture(logo).fit_to_exact_size(size))
}

struct GroupRowResponse {
    row: egui::Response,
    rename_requested: bool,
    delete_requested: bool,
}

fn group_row(
    ui: &mut egui::Ui,
    name: &str,
    count: usize,
    selected: bool,
    can_manage: bool,
    menu_icon: &egui::TextureHandle,
) -> GroupRowResponse {
    let fill = if selected { SELECTED_BG } else { PANEL_ALT };
    let stroke = if selected {
        egui::Stroke::new(1.0, egui::Color32::from_gray(88))
    } else {
        egui::Stroke::new(1.0, egui::Color32::TRANSPARENT)
    };

    let mut rename_requested = false;
    let mut delete_requested = false;
    let mut row = None;
    egui::Frame::none()
        .fill(fill)
        .stroke(stroke)
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::symmetric(10.0, 8.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let menu_width = if can_manage { 28.0 } else { 0.0 };
                let label_width = (ui.available_width() - 34.0 - menu_width).max(32.0);
                row = Some(clickable_row_text(
                    ui,
                    name,
                    egui::vec2(label_width, 24.0),
                    14.0,
                    egui::FontFamily::Proportional,
                    if selected { SELECTED } else { TEXT },
                ));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if can_manage {
                        match group_actions_menu(ui, menu_icon) {
                            Some(GroupAction::Rename) => rename_requested = true,
                            Some(GroupAction::Delete) => delete_requested = true,
                            None => {}
                        }
                    }
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(count.to_string())
                                .size(12.0)
                                .color(MUTED),
                        )
                        .selectable(false),
                    );
                });
            });
        })
        .response;

    GroupRowResponse {
        row: row.expect("group row text button should be present"),
        rename_requested,
        delete_requested,
    }
}

fn secret_row(ui: &mut egui::Ui, key: &str, selected: bool) -> egui::Response {
    let fill = if selected { SELECTED_BG } else { BG };
    let stroke = if selected {
        egui::Stroke::new(1.0, egui::Color32::from_gray(88))
    } else {
        egui::Stroke::new(1.0, BORDER)
    };

    let mut row = None;
    egui::Frame::none()
        .fill(fill)
        .stroke(stroke)
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin {
            left: 12.0,
            right: 12.0,
            top: 10.0,
            bottom: 6.0,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), 28.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    row = Some(clickable_row_text(
                        ui,
                        key,
                        egui::vec2(ui.available_width(), 28.0),
                        13.0,
                        egui::FontFamily::Monospace,
                        if selected { SELECTED } else { TEXT },
                    ));
                },
            );
        })
        .response;

    row.expect("secret row text button should be present")
}

fn clickable_row_text(
    ui: &mut egui::Ui,
    text: &str,
    size: egui::Vec2,
    font_size: f32,
    family: egui::FontFamily,
    color: egui::Color32,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        ui.painter().with_clip_rect(rect).text(
            rect.left_center(),
            egui::Align2::LEFT_CENTER,
            text,
            egui::FontId::new(font_size, family),
            color,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

enum GroupAction {
    Rename,
    Delete,
}

fn group_actions_menu(ui: &mut egui::Ui, menu_icon: &egui::TextureHandle) -> Option<GroupAction> {
    let image = egui::Image::from_texture(menu_icon).fit_to_exact_size(egui::vec2(18.0, 18.0));
    let menu = egui::menu::menu_custom_button(
        ui,
        egui::Button::image(image)
            .frame(false)
            .min_size(egui::vec2(24.0, 24.0)),
        |ui| {
            ui.set_min_width(110.0);
            let mut action = None;
            if ui.button("Rename").clicked() {
                action = Some(GroupAction::Rename);
                ui.close_menu();
            }
            if ui
                .button(egui::RichText::new("Delete").color(DANGER_TEXT))
                .clicked()
            {
                action = Some(GroupAction::Delete);
                ui.close_menu();
            }
            action
        },
    );

    menu.response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text("Group actions");
    menu.inner.flatten()
}

enum SettingsAction {
    ApiKeys,
    Import,
    Export,
    ChangePassword,
    Logout,
}

fn settings_menu(ui: &mut egui::Ui) -> Option<SettingsAction> {
    let button = egui::Button::new(egui::RichText::new("⚙").size(18.0).color(TEXT))
        .frame(false)
        .min_size(egui::vec2(32.0, 32.0));
    let menu = egui::menu::menu_custom_button(ui, button, |ui| {
        ui.set_min_width(150.0);
        let mut action = None;
        if ui.button("API Keys").clicked() {
            action = Some(SettingsAction::ApiKeys);
            ui.close_menu();
        }
        ui.separator();
        if ui.button("Import").clicked() {
            action = Some(SettingsAction::Import);
            ui.close_menu();
        }
        if ui.button("Export").clicked() {
            action = Some(SettingsAction::Export);
            ui.close_menu();
        }
        ui.separator();
        if ui.button("Change Password").clicked() {
            action = Some(SettingsAction::ChangePassword);
            ui.close_menu();
        }
        if ui.button("Logout").clicked() {
            action = Some(SettingsAction::Logout);
            ui.close_menu();
        }
        action
    });

    menu.response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text("Settings");
    menu.inner.flatten()
}

fn secret_visibility_icon_button(ui: &mut egui::Ui, visible: bool) -> egui::Response {
    let size = egui::vec2(20.0, 20.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());

    if ui.is_rect_visible(rect) {
        let fill = if response.is_pointer_button_down_on() {
            SELECTED_BG
        } else if response.hovered() {
            HOVER_BG
        } else {
            FIELD_BG
        };
        let stroke = egui::Stroke::new(1.0_f32, if response.hovered() { MUTED } else { BORDER });
        let painter = ui.painter();
        painter.rect(rect, egui::Rounding::same(4.0), fill, stroke);

        let center = rect.center();
        let icon_stroke = egui::Stroke::new(1.25_f32, TEXT);
        let mut top = Vec::with_capacity(9);
        let mut bottom = Vec::with_capacity(9);
        for i in 0..=8 {
            let t = i as f32 / 8.0;
            let x = center.x - 5.5 + 11.0 * t;
            let arc = (std::f32::consts::PI * t).sin() * 3.5;
            top.push(egui::pos2(x, center.y - arc));
            bottom.push(egui::pos2(x, center.y + arc));
        }
        painter.add(egui::Shape::line(top, icon_stroke));
        painter.add(egui::Shape::line(bottom, icon_stroke));
        painter.circle_filled(center, 1.6, TEXT);

        if visible {
            painter.line_segment(
                [
                    center + egui::vec2(-5.0, 5.0),
                    center + egui::vec2(5.0, -5.0),
                ],
                icon_stroke,
            );
        }
    }

    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(if visible {
            "Hide secret value"
        } else {
            "Reveal secret value"
        })
}

fn copy_icon_button(ui: &mut egui::Ui) -> egui::Response {
    let size = egui::vec2(20.0, 20.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());

    if ui.is_rect_visible(rect) {
        let fill = if response.is_pointer_button_down_on() {
            SELECTED_BG
        } else if response.hovered() {
            HOVER_BG
        } else {
            FIELD_BG
        };
        let stroke = egui::Stroke::new(1.0, if response.hovered() { MUTED } else { BORDER });
        let painter = ui.painter();
        painter.rect(rect, egui::Rounding::same(4.0), fill, stroke);

        let back =
            egui::Rect::from_min_size(rect.center() - egui::vec2(4.0, 5.0), egui::vec2(7.0, 9.0));
        let front = back.translate(egui::vec2(3.0, 3.0));
        let icon_stroke = egui::Stroke::new(1.25, TEXT);
        painter.rect_stroke(back, egui::Rounding::same(1.5), icon_stroke);
        painter.rect_stroke(front, egui::Rounding::same(1.5), icon_stroke);
    }

    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text("Copy secret value")
}

fn padded_singleline<'a>(value: &'a mut String, hint: &'static str) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(value)
        .hint_text(hint)
        .vertical_align(egui::Align::Center)
        .margin(field_margin())
}

fn field_margin() -> egui::Margin {
    egui::Margin {
        left: 10.0,
        right: 6.0,
        top: 7.0,
        bottom: 7.0,
    }
}

fn text_submitted(ui: &egui::Ui, response: &egui::Response) -> bool {
    response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter))
}

fn primary_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(label).size(14.0).color(TEXT))
        .fill(egui::Color32::from_gray(44))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(78)))
        .rounding(egui::Rounding::same(6.0))
}

fn secondary_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(label).color(TEXT))
        .fill(FIELD_BG)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .rounding(egui::Rounding::same(6.0))
}

fn danger_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(label).color(DANGER_TEXT))
        .fill(DANGER_BG)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .rounding(egui::Rounding::same(6.0))
}

fn parse_expiry_date(unlimited: bool, date: &str) -> Result<Option<i64>> {
    if unlimited {
        return Ok(None);
    }
    let date = chrono::NaiveDate::parse_from_str(date.trim(), "%Y-%m-%d")
        .context("enter an expiry date as YYYY-MM-DD")?;
    let end_of_day = date
        .and_hms_opt(23, 59, 59)
        .ok_or_else(|| anyhow::anyhow!("invalid expiry date"))?
        .and_utc()
        .timestamp();
    if end_of_day <= crate::api_keys::now()? {
        return Err(anyhow::anyhow!("expiry must be in the future"));
    }
    Ok(Some(end_of_day))
}

fn message_color() -> egui::Color32 {
    MUTED
}

#[cfg(test)]
mod api_key_tests {
    use super::*;
    use crate::api_keys;

    #[test]
    fn desktop_form_issues_token_and_edit_rotates_it() {
        let path = std::env::temp_dir().join(format!("ks-ui-test-{}.json", api_keys::new_id()));
        let store = VaultStore::for_test(path.clone());
        let vault = store.create("test-only-password").unwrap();
        let ctx = egui::Context::default();
        let image = egui::ColorImage::new([1, 1], egui::Color32::WHITE);
        let texture = ctx.load_texture("test", image, Default::default());
        let mut app = KeyStoreApp::new(texture.clone(), texture, DEFAULT_WINDOW_SIZE);
        app.vault = Some(vault);

        app.open_api_key_form(None);
        app.api_key_name = "my client".into();
        app.api_key_permissions
            .insert("default".into(), Access::ReadOnly);
        app.save_api_key_form();
        assert!(app.api_key_error.is_empty());
        let old_token = app.api_issued_token.clone().unwrap();
        let old_id = app
            .vault
            .as_ref()
            .unwrap()
            .data()
            .api_keys
            .keys()
            .next()
            .unwrap()
            .clone();

        app.open_api_key_form(Some(old_id));
        app.api_key_permissions
            .insert("default".into(), Access::ReadWrite);
        app.save_api_key_form();
        let vault = app.vault.as_ref().unwrap();
        assert!(api_keys::authenticate(&old_token, vault).is_err());
        assert_eq!(
            api_keys::authenticate(app.api_issued_token.as_deref().unwrap(), vault)
                .unwrap()
                .permissions["default"],
            Access::ReadWrite
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn expiry_date_is_end_of_day_utc_and_unlimited_is_optional() {
        let date = (chrono::Utc::now() + chrono::Duration::days(10))
            .format("%Y-%m-%d")
            .to_string();
        let expires = parse_expiry_date(false, &date).unwrap().unwrap();
        assert_eq!(
            chrono::DateTime::from_timestamp(expires, 0)
                .unwrap()
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
            format!("{date} 23:59:59")
        );
        assert_eq!(parse_expiry_date(true, "").unwrap(), None);
        assert!(parse_expiry_date(false, "invalid").is_err());
        assert!(parse_expiry_date(false, "2000-01-01").is_err());
    }
}
