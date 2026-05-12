use crate::storage::{UnlockedVault, VaultStore};
use anyhow::Result;
use eframe::egui;

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
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 680.0])
            .with_min_inner_size([820.0, 560.0]),
        ..Default::default()
    };

    eframe::run_native(
        "KS Encrypted Key Store",
        options,
        Box::new(|cc| {
            apply_fonts(&cc.egui_ctx);
            apply_style(&cc.egui_ctx);
            let logo = load_logo_texture(&cc.egui_ctx)?;
            Ok(Box::new(KeyStoreApp::new(logo)))
        }),
    )
    .map_err(|err| anyhow::anyhow!("failed to launch desktop app: {err}"))
}

struct KeyStoreApp {
    logo: egui::TextureHandle,
    store: Result<VaultStore, String>,
    vault: Option<UnlockedVault>,
    password: String,
    confirm_password: String,
    selected_key: Option<String>,
    edit_value: String,
    new_key: String,
    new_value: String,
    new_group: String,
    message: String,
}

impl KeyStoreApp {
    fn new(logo: egui::TextureHandle) -> Self {
        Self {
            logo,
            store: VaultStore::new().map_err(|err| err.to_string()),
            vault: None,
            password: String::new(),
            confirm_password: String::new(),
            selected_key: None,
            edit_value: String::new(),
            new_key: String::new(),
            new_value: String::new(),
            new_group: String::new(),
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
            Ok(Some(value)) => self.edit_value = value.clone(),
            _ => {
                self.selected_key = None;
                self.edit_value.clear();
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
                    self.edit_value.clear();
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
                    self.edit_value = self.new_value.clone();
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
            match vault.set(key, &self.edit_value) {
                Ok(()) => self.message = format!("Updated '{key}'"),
                Err(err) => self.message = err.to_string(),
            }
        }
    }
}

impl eframe::App for KeyStoreApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.vault.is_none() {
            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(BG))
                .show(ctx, |ui| self.login_view(ui));
            return;
        }

        self.top_bar(ctx);
        self.status_bar(ctx);

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
    }
}

impl KeyStoreApp {
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
        let active = self
            .vault
            .as_ref()
            .map(|vault| vault.active_group().to_string())
            .unwrap_or_default();

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
                    ui.add_space(16.0);
                    ui.label(
                        egui::RichText::new(format!("Active: {active}"))
                            .size(13.0)
                            .color(MUTED),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(secondary_button("Lock")).clicked() {
                            self.vault = None;
                            self.selected_key = None;
                            self.edit_value.clear();
                            self.message = "Locked".to_string();
                        }
                    });
                });
            });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        if self.message.is_empty() {
            return;
        }

        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(36.0)
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .stroke(egui::Stroke::new(1.0, BORDER))
                    .inner_margin(egui::Margin::symmetric(22.0, 8.0)),
            )
            .show(ctx, |ui| {
                ui.label(egui::RichText::new(&self.message).color(message_color()));
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
            .max_height((ui.available_height() - 160.0).max(160.0))
            .show(ui, |ui| {
                for (group, count) in groups {
                    let selected = group == active;
                    let response = group_row(ui, &group, count, selected);
                    ui.add_space(6.0);
                    if response.clicked() {
                        if let Some(vault) = &mut self.vault {
                            match vault.switch_group(&group) {
                                Ok(()) => {
                                    self.selected_key = None;
                                    self.edit_value.clear();
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

        if active != "default" {
            ui.add_space(8.0);
            if ui
                .add_sized(
                    [ui.available_width(), 34.0],
                    danger_button("Delete Active Group"),
                )
                .clicked()
            {
                if let Some(vault) = &mut self.vault {
                    match vault.delete_group(&active) {
                        Ok(()) => {
                            self.message = format!("Deleted group '{active}'");
                            self.selected_key = None;
                            self.edit_value.clear();
                        }
                        Err(err) => self.message = err.to_string(),
                    }
                }
            }
        }
    }

    fn keys_panel(&mut self, ui: &mut egui::Ui) {
        let active = self
            .vault
            .as_ref()
            .map(|vault| vault.active_group().to_string())
            .unwrap_or_default();
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
        ui.label(egui::RichText::new(active).color(MUTED).size(13.0));
        ui.add_space(12.0);

        egui::ScrollArea::vertical()
            .id_salt("secrets_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if secrets.is_empty() {
                    empty_state(ui, "No secrets in this group");
                }
                for key in secrets {
                    let selected = self.selected_key.as_ref() == Some(&key);
                    let response = secret_row(ui, &key, selected);
                    ui.add_space(8.0);
                    if response.clicked() {
                        self.selected_key = Some(key);
                        self.refresh_selected_value();
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
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(&key)
                    .size(19.0)
                    .monospace()
                    .strong()
                    .color(TEXT),
            );
            ui.add_space(18.0);
            ui.label(egui::RichText::new("Value").color(MUTED).size(12.0));
            ui.add_sized(
                [ui.available_width(), 150.0],
                egui::TextEdit::multiline(&mut self.edit_value)
                    .desired_rows(7)
                    .hint_text("Value"),
            );
            ui.add_space(14.0);

            ui.horizontal(|ui| {
                if ui
                    .add_sized([120.0, 36.0], primary_button("Update"))
                    .clicked()
                {
                    self.update_secret(&key);
                }
                if ui
                    .add_sized([100.0, 36.0], danger_button("Delete"))
                    .clicked()
                {
                    if let Some(vault) = &mut self.vault {
                        match vault.delete(&key) {
                            Ok(true) => {
                                self.message = format!("Deleted '{key}'");
                                self.selected_key = None;
                                self.edit_value.clear();
                            }
                            Ok(false) => self.message = format!("'{key}' was already missing"),
                            Err(err) => self.message = err.to_string(),
                        }
                    }
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
    let image = image::load_from_memory_with_format(
        include_bytes!("../assets/logo.png"),
        image::ImageFormat::Png,
    )?
    .to_rgba8();
    let size = [image.width() as usize, image.height() as usize];
    let pixels = image.into_raw();
    let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);

    Ok(ctx.load_texture(
        "ks_logo",
        color_image,
        egui::TextureOptions::LINEAR.with_mipmap_mode(Some(egui::TextureFilter::Linear)),
    ))
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

fn group_row(ui: &mut egui::Ui, name: &str, count: usize, selected: bool) -> egui::Response {
    let fill = if selected { SELECTED_BG } else { PANEL_ALT };
    let stroke = if selected {
        egui::Stroke::new(1.0, egui::Color32::from_gray(88))
    } else {
        egui::Stroke::new(1.0, egui::Color32::TRANSPARENT)
    };

    egui::Frame::none()
        .fill(fill)
        .stroke(stroke)
        .rounding(egui::Rounding::same(6.0))
        .inner_margin(egui::Margin::symmetric(10.0, 8.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(name).size(14.0).color(if selected {
                    SELECTED
                } else {
                    TEXT
                }));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(count.to_string())
                            .size(12.0)
                            .color(MUTED),
                    );
                });
            });
        })
        .response
        .interact(egui::Sense::click())
}

fn secret_row(ui: &mut egui::Ui, key: &str, selected: bool) -> egui::Response {
    let fill = if selected { SELECTED_BG } else { BG };
    let stroke = if selected {
        egui::Stroke::new(1.0, egui::Color32::from_gray(88))
    } else {
        egui::Stroke::new(1.0, BORDER)
    };

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
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(key)
                                .size(13.0)
                                .monospace()
                                .color(if selected { SELECTED } else { TEXT }),
                        )
                        .selectable(false),
                    );
                },
            );
        })
        .response
        .interact(egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn padded_singleline<'a>(value: &'a mut String, hint: &'static str) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(value)
        .hint_text(hint)
        .vertical_align(egui::Align::Center)
        .margin(egui::Margin {
            left: 10.0,
            right: 6.0,
            top: 7.0,
            bottom: 7.0,
        })
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

fn message_color() -> egui::Color32 {
    MUTED
}
