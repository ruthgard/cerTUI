use std::{
    cmp::Ordering,
    collections::HashSet,
    env,
    ffi::OsStr,
    fs, io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use arboard::Clipboard;
use chrono::{TimeZone, Utc};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode, KeyEvent,
        KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use omarchy_cert_core::{
    days_until_expiry, inspect_local_path, inspect_remote, CertInfo, LocalCertFormat,
    PasswordRequiredError, ProtectedStoreKind,
};
use ratatui::layout::Margin;
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
        Wrap,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::timeout;

const HISTORY_FILE: &str = "history.json";
const LEGACY_HISTORY_FILE: &str = ".certlist";

#[tokio::main]
async fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>) -> Result<()> {
    let tick_rate = Duration::from_millis(200);
    let mut app = initialize_app();
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            match event::read()? {
                CEvent::Key(key) => {
                    if key.code == KeyCode::Char('q') && key.modifiers.is_empty() {
                        if let Err(err) = app.persist_state() {
                            app.set_status(format!("Failed to save history: {err}"));
                            continue;
                        }
                        return Ok(());
                    }

                    if let Err(err) = handle_key(&mut app, key).await {
                        app.set_status(format!("Error: {err}"));
                    }
                }
                CEvent::Mouse(mouse) => {
                    if let Err(err) = handle_mouse(&mut app, mouse) {
                        app.set_status(format!("Error: {err}"));
                    }
                }
                CEvent::Resize(_, _)
                | CEvent::FocusGained
                | CEvent::FocusLost
                | CEvent::Paste(_) => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }
}

async fn handle_key(app: &mut App, key: KeyEvent) -> Result<()> {
    if app.find_dialog_active() {
        handle_find_dialog(app, key).await?;
        return Ok(());
    }

    if app.password_dialog_active() {
        handle_password_dialog(app, key).await?;
        return Ok(());
    }

    if app.cert_fullscreen_active() {
        handle_cert_fullscreen(app, key)?;
        return Ok(());
    }

    if app.cert_modal_active() {
        handle_cert_modal(app, key)?;
        return Ok(());
    }

    if handle_global_keys(app, &key).await? {
        return Ok(());
    }

    match app.focus {
        Focus::Input => handle_input_focus(app, key).await?,
        Focus::History => handle_history_focus(app, key).await?,
        Focus::HistorySearch => handle_history_search_focus(app, key)?,
        Focus::Table => handle_table_focus(app, key).await?,
        Focus::TableSearch => handle_table_search_focus(app, key)?,
    }

    Ok(())
}

fn handle_mouse(app: &mut App, event: MouseEvent) -> Result<()> {
    let x = event.column;
    let y = event.row;

    if app.cert_fullscreen_active() {
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left)) {
            app.close_cert_fullscreen();
        }
        return Ok(());
    }

    if app.password_dialog_active() {
        // Ignore mouse interactions while password dialog is active for now.
        return Ok(());
    }

    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(area) = app.input_area {
                if point_in_rect(area, x, y) {
                    if !app.is_input_editing() {
                        app.start_input_editing_with(false);
                        app.set_status("Editing target: Enter submits, Esc cancels.");
                    }
                    app.focus = Focus::Input;
                    return Ok(());
                }
            }

            if let Some(view) = app.history_view.clone() {
                if point_in_rect(view.area, x, y) {
                    app.focus = Focus::History;
                    let inner = view.area.inner(&Margin::new(1, 1));
                    if inner.width > 0 && inner.height > 0 && point_in_rect(inner, x, y) {
                        let row = y.saturating_sub(inner.y) as usize;
                        let idx = view.offset.saturating_add(row);
                        if idx < view.indices.len() {
                            app.apply_selection(view.indices[idx]);
                        }
                    }
                    return Ok(());
                }
            }

            if let Some(view) = app.table_view.clone() {
                if point_in_rect(view.area, x, y) {
                    app.focus = Focus::Table;
                    let inner = view.area.inner(&Margin::new(1, 1));
                    if inner.width > 0 && inner.height > 0 && point_in_rect(inner, x, y) {
                        if y > inner.y {
                            let row = y - inner.y - 1; // skip header row
                            let idx = view.offset.saturating_add(row as usize);
                            if idx < view.indices.len() {
                                app.table_state.select(Some(idx));
                                app.ensure_table_selection();
                                app.open_cert_modal();
                                return Ok(());
                            }
                        }
                    }
                    return Ok(());
                }
            }

            if let Some(area) = app.filter_area {
                if point_in_rect(area, x, y) {
                    match app.focus {
                        Focus::History | Focus::HistorySearch => app.start_history_search(),
                        Focus::Table | Focus::TableSearch => app.start_table_search(),
                        Focus::Input => {
                            if app.selected.is_some() {
                                app.start_table_search();
                            } else {
                                app.start_history_search();
                            }
                        }
                    }
                    return Ok(());
                }
            }

            if let Some(area) = app.cert_pem_area {
                if point_in_rect(area, x, y) {
                    if let Some((_, _, cert)) = app.cert_modal_info() {
                        match copy_pem_to_clipboard(&cert.pem) {
                            Ok(_) => app.set_status("Certificate PEM copied to clipboard."),
                            Err(err) => {
                                app.set_status(format!("Failed to copy certificate PEM: {err}"))
                            }
                        }
                    }
                    return Ok(());
                }
            }
        }
        MouseEventKind::ScrollDown => {
            if let Some(view) = app.history_view.as_ref() {
                if point_in_rect(view.area, x, y) {
                    app.focus = Focus::History;
                    app.move_selection(1);
                    return Ok(());
                }
            }
            if let Some(view) = app.table_view.as_ref() {
                if point_in_rect(view.area, x, y) {
                    app.focus = Focus::Table;
                    app.move_table_selection(1);
                    return Ok(());
                }
            }
        }
        MouseEventKind::ScrollUp => {
            if let Some(view) = app.history_view.as_ref() {
                if point_in_rect(view.area, x, y) {
                    app.focus = Focus::History;
                    app.move_selection(-1);
                    return Ok(());
                }
            }
            if let Some(view) = app.table_view.as_ref() {
                if point_in_rect(view.area, x, y) {
                    app.focus = Focus::Table;
                    app.move_table_selection(-1);
                    return Ok(());
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn initialize_app() -> App {
    let mut app = App::default();
    let default_status = "Press Enter to edit the target (Enter submits, Esc cancels). Ctrl+F opens the find dialog to scan for certificates. T/H/C focus Target/History/Certificates. Tab cycles focus when not editing; Tab autocompletes paths when editing. / filters the focused list. Ctrl+R refreshes selection. Ctrl+L clears history. Delete/x remove history entries. q quits.";
    app.set_status(default_status);

    let (settings, settings_msg) = match Settings::load() {
        Ok(pair) => pair,
        Err(err) => {
            let fallback = Settings::default();
            (
                fallback.clone(),
                format!(
                    "Failed to load settings ({}); using default timeout {}s.",
                    err, fallback.timeout_secs
                ),
            )
        }
    };
    app.settings = settings;

    let (theme, theme_msg) = load_theme();
    app.theme = theme;

    match load_entries_from_disk() {
        Ok((mut entries, load_msg, mark_dirty)) => {
            if mark_dirty {
                app.dirty = true;
            }
            let mut parts = vec![settings_msg, theme_msg];
            if let Some(msg) = load_msg {
                parts.push(msg);
            }

            if !entries.is_empty() {
                for entry in &mut entries {
                    entry.rehydrate_label();
                }
                app.entries = entries;
                app.ensure_selection();
                parts.push(format!(
                    "Loaded {} entries from {}.",
                    app.entries.len(),
                    history_display_path()
                ));
            } else {
                parts.push(default_status.to_string());
            }

            parts.push(format!("Timeout {}s.", app.settings.timeout_secs));
            app.set_status(parts.join(" "));
        }
        Err(err) => {
            app.set_status(format!(
                "{} {}; failed to load {}: {err}.",
                settings_msg,
                theme_msg,
                history_display_path()
            ));
        }
    }
    app
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Input,
    History,
    HistorySearch,
    Table,
    TableSearch,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Chain,
    Subject,
    Issuer,
    NotAfter,
    DaysLeft,
}

impl SortKey {
    fn label(self) -> &'static str {
        match self {
            SortKey::Chain => "chain order",
            SortKey::Subject => "subject",
            SortKey::Issuer => "issuer",
            SortKey::NotAfter => "not-after",
            SortKey::DaysLeft => "days left",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortOrder {
    Asc,
    Desc,
}

impl SortOrder {
    fn toggle(self) -> Self {
        match self {
            SortOrder::Asc => SortOrder::Desc,
            SortOrder::Desc => SortOrder::Asc,
        }
    }

    fn label(self) -> &'static str {
        match self {
            SortOrder::Asc => "ascending",
            SortOrder::Desc => "descending",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum TargetKind {
    Remote { host: String, port: u16 },
    Local { path: PathBuf },
}

impl TargetKind {
    fn label(&self) -> String {
        match self {
            TargetKind::Remote { host, port } => format!("{host}:{port}"),
            TargetKind::Local { path } => path.display().to_string(),
        }
    }

    fn descriptor(&self) -> String {
        match self {
            TargetKind::Remote { .. } => format!("Remote {}", self.label()),
            TargetKind::Local { .. } => format!("Local {}", self.label()),
        }
    }

    fn loading_message(&self) -> String {
        match self {
            TargetKind::Remote { .. } => format!("Fetching {} ...", self.label()),
            TargetKind::Local { .. } => format!("Loading {} ...", self.label()),
        }
    }

    fn color(&self, theme: &Theme) -> Color {
        match self {
            TargetKind::Remote { .. } => theme.remote,
            TargetKind::Local { .. } => theme.local,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct TargetEntry {
    label: String,
    kind: TargetKind,
    certs: Vec<CertInfo>,
    status: String,
    #[serde(default)]
    local_format: Option<LocalCertFormat>,
    #[serde(default)]
    local_is_dir: Option<bool>,
    #[serde(skip)]
    protected: Option<ProtectedState>,
}

impl TargetEntry {
    fn new(
        kind: TargetKind,
        certs: Vec<CertInfo>,
        local_format: Option<LocalCertFormat>,
        local_is_dir: Option<bool>,
        status: String,
    ) -> Self {
        let label = kind.label();
        Self {
            label,
            kind,
            certs,
            status,
            local_format,
            local_is_dir,
            protected: None,
        }
    }

    fn title(&self) -> String {
        self.kind.descriptor()
    }

    fn rehydrate_label(&mut self) {
        self.label = self.kind.label();
    }

    fn matches_filter(&self, needle: &str) -> bool {
        let needle = needle.to_ascii_lowercase();
        let label_match = self.label.to_ascii_lowercase().contains(&needle);
        let status_match = self.status.to_ascii_lowercase().contains(&needle);
        label_match || status_match
    }
}

#[derive(Clone)]
struct Settings {
    timeout_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self { timeout_secs: 5 }
    }
}

impl Settings {
    fn load() -> Result<(Self, String)> {
        let path = settings_path()?;
        if !path.exists() {
            let settings = Settings::default();
            settings.save()?;
            let msg = format!(
                "Created settings at {} with default timeout {}s.",
                settings_display_path(),
                settings.timeout_secs
            );
            return Ok((settings, msg));
        }

        let data = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if data.trim().is_empty() {
            let settings = Settings::default();
            settings.save()?;
            let msg = format!(
                "Settings file was empty; restored defaults (timeout {}s) at {}.",
                settings.timeout_secs,
                settings_display_path()
            );
            return Ok((settings, msg));
        }

        let raw: SettingsFile = serde_json::from_str(&data)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let timeout_secs = raw.timeout_secs.unwrap_or(Settings::default().timeout_secs);
        let settings = Settings { timeout_secs };
        let msg = format!(
            "Loaded settings from {} (timeout {}s).",
            settings_display_path(),
            timeout_secs
        );
        Ok((settings, msg))
    }

    fn save(&self) -> Result<()> {
        let path = settings_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let raw = SettingsFile {
            timeout_secs: Some(self.timeout_secs),
        };
        let data =
            serde_json::to_string_pretty(&raw).context("failed to serialize settings file")?;
        fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct SettingsFile {
    timeout_secs: Option<u64>,
}

#[derive(Clone)]
struct Theme {
    highlight: Color,
    remote: Color,
    local: Color,
    muted: Color,
    success: Color,
    warning: Color,
    danger: Color,
}

impl Theme {
    fn default() -> Self {
        Self {
            highlight: Color::Yellow,
            remote: Color::Cyan,
            local: Color::Green,
            muted: Color::Gray,
            success: Color::Green,
            warning: Color::Yellow,
            danger: Color::Red,
        }
    }
}

#[derive(Clone)]
struct App {
    input: String,
    status: String,
    focus: Focus,
    input_edit_mode: bool,
    entries: Vec<TargetEntry>,
    selected: Option<usize>,
    history_filter: Option<String>,
    history_search_buffer: String,
    table_filter: Option<String>,
    table_search_buffer: String,
    sort_key: SortKey,
    sort_order: SortOrder,
    dirty: bool,
    history_state: ListState,
    table_state: TableState,
    settings: Settings,
    theme: Theme,
    find_dialog: Option<FindDialog>,
    last_find_root: Option<PathBuf>,
    password_dialog: Option<PasswordDialog>,
    cert_modal: Option<CertModal>,
    cert_fullscreen: bool,
    input_area: Option<Rect>,
    history_view: Option<HistoryViewCache>,
    table_view: Option<TableViewCache>,
    filter_area: Option<Rect>,
    cert_pem_area: Option<Rect>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            input: String::new(),
            status: String::new(),
            focus: Focus::Input,
            input_edit_mode: true,
            entries: Vec::new(),
            selected: None,
            history_filter: None,
            history_search_buffer: String::new(),
            table_filter: None,
            table_search_buffer: String::new(),
            sort_key: SortKey::Chain,
            sort_order: SortOrder::Asc,
            dirty: false,
            history_state: ListState::default(),
            table_state: TableState::default(),
            settings: Settings::default(),
            theme: Theme::default(),
            find_dialog: None,
            last_find_root: None,
            password_dialog: None,
            cert_modal: None,
            cert_fullscreen: false,
            input_area: None,
            history_view: None,
            table_view: None,
            filter_area: None,
            cert_pem_area: None,
        }
    }
}

#[derive(Clone)]
struct FindDialog {
    input: String,
}

#[derive(Clone)]
struct CertModal {
    entry_index: usize,
    cert_index: usize,
}

#[derive(Clone)]
struct ProtectedState {
    kind: ProtectedStoreKind,
    last_error: Option<String>,
}

impl ProtectedState {
    fn new(kind: ProtectedStoreKind, last_error: Option<String>) -> Self {
        Self { kind, last_error }
    }
}

#[derive(Clone)]
struct PasswordDialog {
    entry_index: usize,
    kind: ProtectedStoreKind,
    input: String,
}

#[derive(Clone)]
struct HistoryViewCache {
    area: Rect,
    indices: Vec<usize>,
    offset: usize,
}

impl Default for HistoryViewCache {
    fn default() -> Self {
        Self {
            area: Rect::new(0, 0, 0, 0),
            indices: Vec::new(),
            offset: 0,
        }
    }
}

#[derive(Clone)]
struct TableViewCache {
    area: Rect,
    indices: Vec<usize>,
    offset: usize,
}

impl Default for TableViewCache {
    fn default() -> Self {
        Self {
            area: Rect::new(0, 0, 0, 0),
            indices: Vec::new(),
            offset: 0,
        }
    }
}

impl App {
    fn set_status<S: Into<String>>(&mut self, s: S) {
        self.status = s.into();
    }

    fn is_input_editing(&self) -> bool {
        self.input_edit_mode
    }

    fn start_input_editing_with(&mut self, clear: bool) {
        if clear {
            self.input.clear();
        }
        self.input_edit_mode = true;
        self.focus = Focus::Input;
    }

    fn stop_input_editing(&mut self) {
        self.input_edit_mode = false;
    }

    fn restore_selected_input(&mut self) {
        if let Some(idx) = self.selected {
            if let Some(entry) = self.entries.get(idx) {
                self.input = entry.label.clone();
                return;
            }
        }
        self.input.clear();
    }

    fn default_find_root(&self) -> PathBuf {
        if let Some(path) = &self.last_find_root {
            return path.clone();
        }
        env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/"))
    }

    fn open_find_dialog(&mut self) {
        let default_root = self.default_find_root();
        self.find_dialog = Some(FindDialog {
            input: default_root.display().to_string(),
        });
        self.set_status(
            "Find certificates: Enter to confirm, Esc to cancel, Tab autocompletes paths.",
        );
    }

    fn close_find_dialog(&mut self) {
        self.find_dialog = None;
    }

    fn find_dialog_active(&self) -> bool {
        self.find_dialog.is_some()
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn upsert_entry(&mut self, entry: TargetEntry) {
        if let Some(pos) = self.entries.iter().position(|e| e.kind == entry.kind) {
            self.entries.remove(pos);
        }
        self.entries.insert(0, entry);
        self.mark_dirty();
        self.select_actual(0);
    }

    fn clear_entries(&mut self) {
        self.entries.clear();
        self.selected = None;
        self.history_filter = None;
        self.history_search_buffer.clear();
        self.table_filter = None;
        self.table_search_buffer.clear();
        self.history_state.select(None);
        self.table_state.select(None);
        self.cert_modal = None;
        self.cert_fullscreen = false;
        self.password_dialog = None;
        self.input.clear();
        self.input_edit_mode = true;
        self.mark_dirty();
    }

    fn visible_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = Vec::new();
        if let Some(filter) = self.history_filter.as_ref() {
            for (idx, entry) in self.entries.iter().enumerate() {
                if entry.matches_filter(filter) {
                    indices.push(idx);
                }
            }
        } else {
            indices.extend(0..self.entries.len());
        }
        indices
    }

    fn apply_selection(&mut self, idx: usize) {
        self.selected = Some(idx);
        if let Some(entry) = self.entries.get(idx) {
            self.input = entry.label.clone();
            self.status = entry.status.clone();
        }
        self.stop_input_editing();
        self.sync_history_state();
        self.reset_table_selection();
    }

    fn select_actual(&mut self, actual_idx: usize) {
        if self.entries.is_empty() {
            self.selected = None;
            self.history_state.select(None);
            return;
        }
        let visible = self.visible_indices();
        if visible.is_empty() {
            self.selected = None;
            self.history_state.select(None);
            return;
        }
        let idx = if visible.contains(&actual_idx) {
            actual_idx
        } else {
            visible[0]
        };
        self.apply_selection(idx);
    }

    fn move_selection(&mut self, delta: isize) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            self.selected = None;
            self.history_state.select(None);
            return;
        }
        let current_actual = self.selected.unwrap_or(visible[0]);
        let current_pos = visible
            .iter()
            .position(|index| *index == current_actual)
            .unwrap_or(0);
        let max_pos = visible.len() as isize - 1;
        let next_pos = (current_pos as isize + delta).clamp(0, max_pos) as usize;
        let next_actual = visible[next_pos];
        self.apply_selection(next_actual);
    }

    fn remove_selected_entry(&mut self) -> Option<TargetEntry> {
        let idx = self.selected?;
        let entry = self.entries.remove(idx);
        self.selected = None;
        self.history_state.select(None);
        if self.entries.is_empty() {
            self.input.clear();
            self.input_edit_mode = true;
        } else {
            self.ensure_selection();
        }
        self.mark_dirty();
        Some(entry)
    }

    fn ensure_selection(&mut self) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            self.selected = None;
            self.history_state.select(None);
            return;
        }
        if let Some(sel) = self.selected {
            if visible.iter().any(|idx| *idx == sel) {
                self.sync_history_state();
                return;
            }
        }
        self.apply_selection(visible[0]);
    }

    fn selected_visible_pos(&self, visible: &[usize]) -> Option<usize> {
        let selected = self.selected?;
        visible.iter().position(|idx| *idx == selected)
    }

    fn current_entry(&self) -> Option<&TargetEntry> {
        self.selected.and_then(|idx| self.entries.get(idx))
    }

    fn current_kind(&self) -> Option<&TargetKind> {
        self.current_entry().map(|entry| &entry.kind)
    }

    fn password_dialog_active(&self) -> bool {
        self.password_dialog.is_some()
    }

    fn open_password_dialog(&mut self, entry_index: usize, kind: ProtectedStoreKind) {
        self.password_dialog = Some(PasswordDialog {
            entry_index,
            kind,
            input: String::new(),
        });
        self.set_status(format!(
            "{} locked — enter password (Enter submits, Esc cancels).",
            self.entries
                .get(entry_index)
                .map(|entry| entry.title())
                .unwrap_or_default()
        ));
    }

    fn close_password_dialog(&mut self) {
        self.password_dialog = None;
    }

    fn entry_protected(&self, idx: usize) -> Option<&ProtectedState> {
        self.entries
            .get(idx)
            .and_then(|entry| entry.protected.as_ref())
    }

    fn set_entry_protected(
        &mut self,
        idx: usize,
        state: ProtectedState,
        local_format: Option<LocalCertFormat>,
        local_is_dir: Option<bool>,
    ) {
        if let Some(entry) = self.entries.get_mut(idx) {
            entry.protected = Some(state);
            entry.certs.clear();
            if let Some(format) = local_format {
                entry.local_format = Some(format);
            }
            if let Some(is_dir) = local_is_dir {
                entry.local_is_dir = Some(is_dir);
            }
            if Some(idx) == self.selected {
                self.reset_table_selection();
            }
            self.mark_dirty();
        }
    }

    fn update_entry_certs(
        &mut self,
        idx: usize,
        kind: TargetKind,
        loaded: LoadedCerts,
        status: String,
    ) {
        if let Some(entry) = self.entries.get_mut(idx) {
            entry.certs = loaded.certs;
            entry.status = status;
            entry.protected = None;
            entry.label = kind.label();
            entry.local_format = loaded.local_format;
            entry.local_is_dir = loaded.local_is_dir;
        }
        self.mark_dirty();
        self.table_state.select(None);
        self.ensure_table_selection();
    }

    fn cert_modal_active(&self) -> bool {
        self.cert_modal.is_some()
    }

    fn cert_fullscreen_active(&self) -> bool {
        self.cert_fullscreen
    }

    fn filter_active(&self) -> bool {
        matches!(self.focus, Focus::HistorySearch | Focus::TableSearch)
    }

    fn filtered_cert_indices_current(&self) -> Vec<usize> {
        let Some(entry_idx) = self.selected else {
            return Vec::new();
        };
        let entry = &self.entries[entry_idx];
        self.filtered_cert_indices(entry)
    }

    fn ensure_table_selection(&mut self) {
        let indices = self.filtered_cert_indices_current();
        if indices.is_empty() {
            self.table_state.select(None);
            self.cert_modal = None;
            self.cert_fullscreen = false;
            return;
        }
        let current = self
            .table_state
            .selected()
            .unwrap_or(0)
            .min(indices.len() - 1);
        self.table_state.select(Some(current));
        if let Some(modal) = self.cert_modal.as_ref() {
            if Some(modal.entry_index) != self.selected || !indices.contains(&modal.cert_index) {
                self.cert_modal = None;
                self.cert_fullscreen = false;
            }
        }
    }

    fn reset_table_selection(&mut self) {
        self.table_state.select(None);
        self.cert_modal = None;
        self.cert_fullscreen = false;
        self.ensure_table_selection();
    }

    fn move_table_selection(&mut self, delta: isize) {
        let indices = self.filtered_cert_indices_current();
        if indices.is_empty() {
            self.table_state.select(None);
            return;
        }
        let current = self
            .table_state
            .selected()
            .unwrap_or(0)
            .min(indices.len() - 1);
        let max_pos = indices.len() as isize - 1;
        let next = (current as isize + delta).clamp(0, max_pos) as usize;
        self.table_state.select(Some(next));
    }

    fn current_cert_index(&self) -> Option<usize> {
        let indices = self.filtered_cert_indices_current();
        let selected = self.table_state.selected()?;
        indices.get(selected).copied()
    }

    fn open_cert_modal(&mut self) {
        if let Some(entry_idx) = self.selected {
            if let Some(state) = self.entry_protected(entry_idx).cloned() {
                self.cert_modal = None;
                self.cert_fullscreen = false;
                self.open_password_dialog(entry_idx, state.kind);
                return;
            }
        }
        if let (Some(entry_idx), Some(cert_idx)) = (self.selected, self.current_cert_index()) {
            let candidate = CertModal {
                entry_index: entry_idx,
                cert_index: cert_idx,
            };
            let needs_status = match self.cert_modal.as_ref() {
                Some(current)
                    if current.entry_index == candidate.entry_index
                        && current.cert_index == candidate.cert_index =>
                {
                    false
                }
                _ => true,
            };
            self.cert_modal = Some(candidate);
            self.cert_fullscreen = false;
            if needs_status {
                self.set_status("Certificate details shown. Esc to close.");
            }
        }
    }

    fn close_cert_modal(&mut self) {
        self.cert_modal = None;
        self.cert_fullscreen = false;
        self.cert_pem_area = None;
    }

    fn open_cert_fullscreen(&mut self) {
        if self.cert_modal.is_some() {
            if !self.cert_fullscreen {
                self.cert_fullscreen = true;
                self.set_status("Certificate fullscreen view. Press any key to exit.");
            }
        }
    }

    fn close_cert_fullscreen(&mut self) {
        if self.cert_fullscreen {
            self.cert_fullscreen = false;
            if self.cert_modal.is_some() {
                self.set_status("Certificate details shown. Esc to close.");
            }
        }
    }

    fn cert_modal_info(&self) -> Option<(&TargetEntry, usize, &CertInfo)> {
        let modal = self.cert_modal.as_ref()?;
        if Some(modal.entry_index) != self.selected {
            return None;
        }
        let entry = self.entries.get(modal.entry_index)?;
        let cert = entry.certs.get(modal.cert_index)?;
        Some((entry, modal.cert_index, cert))
    }

    fn start_history_search(&mut self) {
        self.focus = Focus::HistorySearch;
        self.history_search_buffer = self.history_filter.clone().unwrap_or_default();
        self.set_status("History search: type to filter, Enter to confirm, Esc to clear.");
    }

    fn update_history_filter(&mut self) {
        let trimmed = self.history_search_buffer.trim().to_string();
        if trimmed.is_empty() {
            self.history_filter = None;
        } else {
            self.history_filter = Some(trimmed);
        }
        self.ensure_selection();
    }

    fn finish_history_search(&mut self) {
        self.focus = Focus::History;
        self.ensure_selection();
    }

    fn cancel_history_search(&mut self) {
        self.history_search_buffer.clear();
        self.history_filter = None;
        self.focus = Focus::History;
        self.ensure_selection();
        self.set_status("History filter cleared.");
    }

    fn start_table_search(&mut self) {
        self.focus = Focus::TableSearch;
        self.table_search_buffer = self.table_filter.clone().unwrap_or_default();
        self.set_status("Certificate search: type to filter, Enter to confirm, Esc to clear.");
    }

    fn update_table_filter(&mut self) {
        let trimmed = self.table_search_buffer.trim().to_string();
        if trimmed.is_empty() {
            self.table_filter = None;
        } else {
            self.table_filter = Some(trimmed);
        }
        self.ensure_table_selection();
    }

    fn finish_table_search(&mut self) {
        self.focus = Focus::Table;
        self.ensure_table_selection();
    }

    fn cancel_table_search(&mut self) {
        self.table_search_buffer.clear();
        self.table_filter = None;
        self.focus = Focus::Table;
        self.set_status("Certificate filter cleared.");
        self.reset_table_selection();
    }

    fn set_sort(&mut self, key: SortKey) {
        if key == SortKey::Chain {
            self.sort_key = SortKey::Chain;
            self.sort_order = SortOrder::Asc;
            self.set_status("Sorting by chain order.");
            self.ensure_table_selection();
            return;
        }
        if self.sort_key == key {
            self.sort_order = self.sort_order.toggle();
        } else {
            self.sort_key = key;
            self.sort_order = SortOrder::Asc;
        }
        self.set_status(format!(
            "Sorting certificates by {} ({})",
            self.sort_key.label(),
            self.sort_order.label()
        ));
        self.ensure_table_selection();
    }

    fn filtered_cert_indices(&self, entry: &TargetEntry) -> Vec<usize> {
        let mut indices: Vec<usize> = entry.certs.iter().enumerate().map(|(idx, _)| idx).collect();
        if let Some(filter) = self.table_filter.as_ref() {
            let needle = filter.to_ascii_lowercase();
            indices.retain(|idx| cert_matches_filter(&entry.certs[*idx], &needle));
        }
        self.sort_indices(entry, &mut indices);
        indices
    }

    fn sort_indices(&self, entry: &TargetEntry, indices: &mut Vec<usize>) {
        match self.sort_key {
            SortKey::Chain => {}
            SortKey::Subject => indices.sort_by(|a, b| {
                entry.certs[*a]
                    .subject
                    .cmp(&entry.certs[*b].subject)
                    .then_with(|| a.cmp(b))
            }),
            SortKey::Issuer => indices.sort_by(|a, b| {
                entry.certs[*a]
                    .issuer
                    .cmp(&entry.certs[*b].issuer)
                    .then_with(|| a.cmp(b))
            }),
            SortKey::NotAfter => indices.sort_by(|a, b| {
                compare_options(
                    entry.certs[*a].not_after_ts,
                    entry.certs[*b].not_after_ts,
                    Ordering::Equal,
                )
                .then_with(|| a.cmp(b))
            }),
            SortKey::DaysLeft => indices.sort_by(|a, b| {
                let left_a = days_until_expiry(&entry.certs[*a]);
                let left_b = days_until_expiry(&entry.certs[*b]);
                compare_options(left_a, left_b, Ordering::Equal).then_with(|| a.cmp(b))
            }),
        }
        if self.sort_key != SortKey::Chain && self.sort_order == SortOrder::Desc {
            indices.reverse();
        }
    }

    fn sync_history_state(&mut self) {
        let visible = self.visible_indices();
        let selected_pos = self.selected_visible_pos(&visible);
        if self.history_state.selected() != selected_pos {
            self.history_state.select(selected_pos);
        }
    }

    fn persist_state(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        save_entries(&self.entries)?;
        self.dirty = false;
        Ok(())
    }
}

fn compare_options<T: Ord>(a: Option<T>, b: Option<T>, when_none: Ordering) -> Ordering {
    match (a, b) {
        (Some(av), Some(bv)) => av.cmp(&bv),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => when_none,
    }
}

fn cert_matches_filter(cert: &CertInfo, needle: &str) -> bool {
    let subject = cert.subject.to_ascii_lowercase();
    if subject.contains(needle) {
        return true;
    }
    let issuer = cert.issuer.to_ascii_lowercase();
    if issuer.contains(needle) {
        return true;
    }
    if let Some(fp) = cert.sha256_fingerprint.as_ref() {
        if fp.to_ascii_lowercase().contains(needle) {
            return true;
        }
    }
    if cert
        .san
        .iter()
        .any(|san| san.to_ascii_lowercase().contains(needle))
    {
        return true;
    }
    if let Some(ts) = cert.not_after_ts {
        if let Some(dt) = Utc.timestamp_opt(ts, 0).single() {
            if dt.to_rfc3339().to_ascii_lowercase().contains(needle) {
                return true;
            }
        }
    }
    false
}

async fn handle_global_keys(app: &mut App, key: &KeyEvent) -> Result<bool> {
    let input_editing = matches!(app.focus, Focus::Input) && app.is_input_editing();
    if input_editing {
        return Ok(false);
    }

    if key.code == KeyCode::Char('l') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.clear_entries();
        app.set_status("History cleared.");
        if let Err(err) = app.persist_state() {
            app.set_status(format!("History cleared but failed to save: {err}"));
        }
        return Ok(true);
    }

    if key.code == KeyCode::Char('r') && key.modifiers.contains(KeyModifiers::CONTROL) {
        if let Some(kind) = app.current_kind().cloned() {
            app.set_status(kind.loading_message());
            match load_certs_for(kind.clone(), app.settings.timeout_secs, None).await {
                Ok(loaded) => {
                    let status_message = describe_fetch(&kind, &loaded.certs);
                    let entry = TargetEntry::new(
                        kind,
                        loaded.certs,
                        loaded.local_format,
                        loaded.local_is_dir,
                        status_message.clone(),
                    );
                    app.upsert_entry(entry);
                    if let Err(err) = app.persist_state() {
                        app.set_status(format!("{status_message} (failed to save: {err})"));
                    } else {
                        app.set_status(status_message);
                    }
                }
                Err(err) => {
                    if let (TargetKind::Local { path }, Some(password_err)) =
                        (&kind, err.downcast_ref::<PasswordRequiredError>())
                    {
                        let (status_message, local_format) =
                            password_required_feedback(&kind, password_err);
                        if let Some(idx) = app.selected {
                            app.set_entry_protected(
                                idx,
                                ProtectedState::new(
                                    password_err.kind(),
                                    password_err.last_error().map(|s| s.to_string()),
                                ),
                                local_format,
                                Some(path.is_dir()),
                            );
                            if let Some(entry) = app.entries.get_mut(idx) {
                                entry.status = status_message.clone();
                            }
                        } else {
                            let mut entry = TargetEntry::new(
                                kind.clone(),
                                Vec::new(),
                                local_format,
                                Some(path.is_dir()),
                                status_message.clone(),
                            );
                            entry.protected = Some(ProtectedState::new(
                                password_err.kind(),
                                password_err.last_error().map(|s| s.to_string()),
                            ));
                            app.upsert_entry(entry);
                        }
                        app.set_status(status_message);
                    } else {
                        app.set_status(format!("Error: {err}"));
                    }
                }
            }
        }
        return Ok(true);
    }

    if key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('f') | KeyCode::Char('F'))
    {
        app.open_find_dialog();
        return Ok(true);
    }

    if key.modifiers.is_empty() {
        if let KeyCode::Char(c) = key.code {
            if c.eq_ignore_ascii_case(&'e') {
                if !app.is_input_editing() && !app.filter_active() {
                    app.start_input_editing_with(false);
                    app.set_status("Editing target: Enter submits, Esc cancels.");
                    return Ok(true);
                }
            }

            if app.filter_active() {
                return Ok(false);
            }

            let target_focus = match c.to_ascii_lowercase() {
                't' => Some(Focus::Input),
                'h' => Some(Focus::History),
                'c' => Some(Focus::Table),
                _ => None,
            };

            if let Some(target) = target_focus {
                let in_text_mode = matches!(app.focus, Focus::HistorySearch | Focus::TableSearch);
                if in_text_mode && !matches!(target, Focus::Input) {
                    return Ok(false);
                }
                let previous_focus = app.focus;
                focus_section(app, target);
                if previous_focus == target && matches!(target, Focus::Input) {
                    return Ok(false);
                }
                return Ok(true);
            }

            if c == '/' {
                match app.focus {
                    Focus::History | Focus::HistorySearch => {
                        app.start_history_search();
                        return Ok(true);
                    }
                    Focus::Table | Focus::TableSearch => {
                        app.start_table_search();
                        return Ok(true);
                    }
                    Focus::Input => {}
                }
            }
        }
    }

    if key.code == KeyCode::Tab && key.modifiers.contains(KeyModifiers::SHIFT) {
        focus_prev(app);
        return Ok(true);
    }

    if key.code == KeyCode::BackTab {
        focus_prev(app);
        return Ok(true);
    }

    if key.code == KeyCode::Tab && !key.modifiers.contains(KeyModifiers::SHIFT) {
        focus_next(app);
        return Ok(true);
    }

    Ok(false)
}

async fn handle_input_focus(app: &mut App, key: KeyEvent) -> Result<()> {
    if !app.is_input_editing() {
        match key.code {
            KeyCode::Enter => {
                app.start_input_editing_with(true);
                app.set_status("Editing target: Enter submits, Esc cancels.");
            }
            KeyCode::Esc => {
                app.restore_selected_input();
                app.set_status("Target editing cancelled.");
            }
            KeyCode::Up => focus_prev(app),
            KeyCode::Down => focus_next(app),
            _ => {}
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Enter => {
            let trimmed = app.input.trim();
            if trimmed.is_empty() {
                app.stop_input_editing();
                return Ok(());
            }
            let kind = match parse_target(trimmed) {
                Ok(kind) => kind,
                Err(err) => {
                    app.set_status(format!("Error: {err}"));
                    app.stop_input_editing();
                    return Ok(());
                }
            };
            app.set_status(kind.loading_message());
            let loaded = match load_certs_for(kind.clone(), app.settings.timeout_secs, None).await {
                Ok(loaded) => loaded,
                Err(err) => {
                    if let (TargetKind::Local { path }, Some(password_err)) =
                        (&kind, err.downcast_ref::<PasswordRequiredError>())
                    {
                        let (status_message, local_format) =
                            password_required_feedback(&kind, password_err);
                        let mut entry = TargetEntry::new(
                            kind.clone(),
                            Vec::new(),
                            local_format,
                            Some(path.is_dir()),
                            status_message.clone(),
                        );
                        entry.protected = Some(ProtectedState::new(
                            password_err.kind(),
                            password_err.last_error().map(|s| s.to_string()),
                        ));
                        app.upsert_entry(entry);
                        app.set_status(status_message);
                    } else {
                        app.set_status(format!("Error: {err}"));
                    }
                    app.stop_input_editing();
                    return Ok(());
                }
            };
            let status_message = describe_fetch(&kind, &loaded.certs);
            let entry = TargetEntry::new(
                kind.clone(),
                loaded.certs,
                loaded.local_format,
                loaded.local_is_dir,
                status_message.clone(),
            );
            app.upsert_entry(entry);
            if let Err(err) = app.persist_state() {
                app.set_status(format!("{status_message} (failed to save: {err})"));
            } else {
                app.set_status(status_message);
            }
            app.stop_input_editing();
        }
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Esc => {
            app.restore_selected_input();
            app.stop_input_editing();
            app.set_status("Target editing cancelled.");
        }
        KeyCode::Tab if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            if try_autocomplete_input(app) {
                return Ok(());
            }
        }
        KeyCode::Char(c) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
            {
                app.input.push(c);
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_history_focus(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Up => app.move_selection(-1),
        KeyCode::Down => app.move_selection(1),
        KeyCode::Enter => {
            focus_section(app, Focus::Input);
        }
        KeyCode::Esc => focus_section(app, Focus::Input),
        KeyCode::Delete => {
            if let Some(entry) = app.remove_selected_entry() {
                let label = entry.kind.label();
                app.set_status(format!("Removed {label} from history."));
                if let Err(err) = app.persist_state() {
                    app.set_status(format!("Removed {label} but failed to save: {err}"));
                }
            }
        }
        KeyCode::Char(c) => {
            let command = c.to_ascii_lowercase();
            match command {
                's' => app.set_sort(SortKey::Subject),
                'i' => app.set_sort(SortKey::Issuer),
                'n' => app.set_sort(SortKey::NotAfter),
                'd' => app.set_sort(SortKey::DaysLeft),
                'o' => app.set_sort(SortKey::Chain),
                'x' => {
                    if let Some(entry) = app.remove_selected_entry() {
                        let label = entry.kind.label();
                        app.set_status(format!("Removed {label} from history."));
                        if let Err(err) = app.persist_state() {
                            app.set_status(format!("Removed {label} but failed to save: {err}"));
                        }
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_history_search_focus(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => app.cancel_history_search(),
        KeyCode::Enter => {
            app.update_history_filter();
            app.finish_history_search();
        }
        KeyCode::Backspace => {
            app.history_search_buffer.pop();
            app.update_history_filter();
        }
        KeyCode::Char(c) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
            {
                app.history_search_buffer.push(c);
                app.update_history_filter();
            }
        }
        KeyCode::Up => app.move_selection(-1),
        KeyCode::Down => app.move_selection(1),
        _ => {}
    }
    Ok(())
}

async fn handle_password_dialog(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            if let Some(dialog) = app.password_dialog.as_mut() {
                dialog.input.clear();
            }
            app.close_password_dialog();
            app.set_status("Password prompt cancelled.");
        }
        KeyCode::Backspace => {
            if let Some(dialog) = app.password_dialog.as_mut() {
                dialog.input.pop();
            }
        }
        KeyCode::Char(c) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
            {
                if let Some(dialog) = app.password_dialog.as_mut() {
                    dialog.input.push(c);
                }
            }
        }
        KeyCode::Enter => {
            let (entry_index, entry_kind, entry_title, password) =
                match app.password_dialog.as_ref() {
                    Some(dialog) => {
                        let password = dialog.input.clone();
                        match app.entries.get(dialog.entry_index) {
                            Some(entry) => (
                                dialog.entry_index,
                                entry.kind.clone(),
                                entry.title(),
                                password,
                            ),
                            None => {
                                app.close_password_dialog();
                                app.set_status("Entry no longer available.");
                                return Ok(());
                            }
                        }
                    }
                    None => return Ok(()),
                };

            app.set_status(format!("Unlocking {entry_title} ..."));
            let certs_result = load_certs_for(
                entry_kind.clone(),
                app.settings.timeout_secs,
                Some(password.clone()),
            )
            .await;

            if let Some(dialog) = app.password_dialog.as_mut() {
                dialog.input.clear();
            }
            drop(password);

            match certs_result {
                Ok(loaded) => {
                    let status_message = describe_fetch(&entry_kind, &loaded.certs);
                    app.update_entry_certs(
                        entry_index,
                        entry_kind.clone(),
                        loaded,
                        status_message.clone(),
                    );
                    app.close_password_dialog();
                    app.select_actual(entry_index);
                    if let Err(err) = app.persist_state() {
                        app.set_status(format!("{status_message} (failed to save: {err})"));
                    } else {
                        app.set_status(status_message.clone());
                    }
                    app.open_cert_modal();
                }
                Err(err) => {
                    if let Some(password_err) = err.downcast_ref::<PasswordRequiredError>() {
                        let (status_message, local_format) =
                            password_required_feedback(&entry_kind, password_err);
                        app.set_entry_protected(
                            entry_index,
                            ProtectedState::new(
                                password_err.kind(),
                                password_err.last_error().map(|s| s.to_string()),
                            ),
                            local_format,
                            match &entry_kind {
                                TargetKind::Local { path } => Some(path.is_dir()),
                                _ => None,
                            },
                        );
                        if let Some(entry) = app.entries.get_mut(entry_index) {
                            entry.status = status_message.clone();
                        }
                        app.set_status(status_message);
                    } else {
                        app.close_password_dialog();
                        app.set_status(format!("Error: {err}"));
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn handle_cert_modal(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.close_cert_modal();
        }
        KeyCode::Enter => {
            app.close_cert_modal();
        }
        KeyCode::Up => {
            app.move_table_selection(-1);
            app.open_cert_modal();
        }
        KeyCode::Down => {
            app.move_table_selection(1);
            app.open_cert_modal();
        }
        KeyCode::Char(c) => {
            if matches!(c, 'f' | 'F') {
                app.open_cert_fullscreen();
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_cert_fullscreen(app: &mut App, _key: KeyEvent) -> Result<()> {
    app.close_cert_fullscreen();
    Ok(())
}

async fn handle_table_focus(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Char(c) => {
            let command = c.to_ascii_lowercase();
            match command {
                's' => app.set_sort(SortKey::Subject),
                'i' => app.set_sort(SortKey::Issuer),
                'n' => app.set_sort(SortKey::NotAfter),
                'd' => app.set_sort(SortKey::DaysLeft),
                'o' => app.set_sort(SortKey::Chain),
                _ => {}
            }
        }
        KeyCode::Esc => app.focus = Focus::Input,
        KeyCode::Enter => {
            app.open_cert_modal();
        }
        KeyCode::Up => app.move_table_selection(-1),
        KeyCode::Down => app.move_table_selection(1),
        _ => {}
    }
    Ok(())
}

fn handle_table_search_focus(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => app.cancel_table_search(),
        KeyCode::Enter => {
            app.update_table_filter();
            app.finish_table_search();
        }
        KeyCode::Backspace => {
            app.table_search_buffer.pop();
            app.update_table_filter();
        }
        KeyCode::Char(c) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
            {
                app.table_search_buffer.push(c);
                app.update_table_filter();
            }
        }
        KeyCode::Up => app.move_table_selection(-1),
        KeyCode::Down => app.move_table_selection(1),
        _ => {}
    }
    Ok(())
}

async fn handle_find_dialog(app: &mut App, key: KeyEvent) -> Result<()> {
    let mut status_update: Option<String> = None;
    let mut close_dialog = false;
    let mut exit_early = false;
    let mut import_path: Option<PathBuf> = None;

    {
        let dialog = match app.find_dialog.as_mut() {
            Some(dialog) => dialog,
            None => return Ok(()),
        };

        match key.code {
            KeyCode::Enter => {
                let trimmed = dialog.input.trim();
                let root_candidate = if trimmed.is_empty() {
                    app.default_find_root()
                } else {
                    expand_path(trimmed)
                };

                let root_candidate = if root_candidate.is_file() {
                    root_candidate
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or(root_candidate)
                } else {
                    root_candidate
                };

                if !root_candidate.exists() {
                    status_update = Some(format!(
                        "Find failed: {} does not exist.",
                        root_candidate.display()
                    ));
                    exit_early = true;
                } else if !root_candidate.is_dir() {
                    status_update = Some(format!(
                        "Find failed: {} is not a directory.",
                        root_candidate.display()
                    ));
                    exit_early = true;
                } else {
                    let resolved = fs::canonicalize(&root_candidate).unwrap_or(root_candidate);
                    import_path = Some(resolved);
                }
            }
            KeyCode::Esc => {
                close_dialog = true;
                exit_early = true;
                status_update = Some("Find cancelled.".to_string());
            }
            KeyCode::Backspace => {
                dialog.input.pop();
            }
            KeyCode::Tab if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                match autocomplete_path_buffer(&mut dialog.input) {
                    AutocompleteResult::Applied { changed } => {
                        if changed {
                            status_update =
                                Some(format!("Find path autocompleted to {}", dialog.input));
                        }
                    }
                    AutocompleteResult::NoMatch => {
                        status_update = Some("No completion found for find path.".to_string());
                    }
                    AutocompleteResult::NotEligible => {}
                }
            }
            KeyCode::BackTab => match autocomplete_path_buffer(&mut dialog.input) {
                AutocompleteResult::Applied { changed } => {
                    if changed {
                        status_update =
                            Some(format!("Find path autocompleted to {}", dialog.input));
                    }
                }
                AutocompleteResult::NoMatch => {
                    status_update = Some("No completion found for find path.".to_string());
                }
                AutocompleteResult::NotEligible => {}
            },
            KeyCode::Char(c) => {
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT)
                {
                    dialog.input.push(c);
                }
            }
            _ => {}
        }
    }

    if let Some(message) = status_update {
        app.set_status(message);
    }

    if let Some(root) = import_path {
        app.close_find_dialog();
        app.last_find_root = Some(root.clone());
        import_system_certificates(app, root).await?;
        return Ok(());
    }

    if close_dialog {
        app.close_find_dialog();
    }

    if exit_early {
        return Ok(());
    }

    Ok(())
}

async fn import_system_certificates(app: &mut App, root: PathBuf) -> Result<()> {
    app.set_status(format!(
        "Searching for certificate files under {} (this can take a while)...",
        root.display()
    ));
    let (paths, had_warnings) = discover_certificate_paths(&root).await?;
    if paths.is_empty() {
        app.set_status(format!(
            "No certificate files found under {}.",
            root.display()
        ));
        return Ok(());
    }

    let mut seen_paths: HashSet<PathBuf> = app
        .entries
        .iter()
        .filter_map(|entry| {
            if let TargetKind::Local { path } = &entry.kind {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();

    let total = paths.len();
    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut failures = 0usize;

    for (idx, path) in paths.into_iter().enumerate() {
        if !seen_paths.insert(path.clone()) {
            skipped += 1;
            continue;
        }

        let label = path.display().to_string();
        app.set_status(format!(
            "Loading certificates {}/{}: {}",
            idx + 1,
            total,
            label
        ));

        let kind = TargetKind::Local { path: path.clone() };
        match load_certs_for(kind.clone(), app.settings.timeout_secs, None).await {
            Ok(loaded) => {
                if loaded.certs.is_empty() {
                    skipped += 1;
                    continue;
                }
                let status_message = describe_fetch(&kind, &loaded.certs);
                let entry = TargetEntry::new(
                    kind,
                    loaded.certs,
                    loaded.local_format,
                    loaded.local_is_dir,
                    status_message.clone(),
                );
                app.upsert_entry(entry);
                imported += 1;
            }
            Err(err) => {
                if let Some(password_err) = err.downcast_ref::<PasswordRequiredError>() {
                    failures += 1;
                    let (status_message, _) = password_required_feedback(&kind, password_err);
                    app.set_status(format!("Skipping {label}: {status_message}"));
                    continue;
                }
                failures += 1;
                app.set_status(format!("Skipping {label}: {err}"));
            }
        }
    }

    if imported == 0 {
        let mut message = format!(
            "No new certificate entries were added from the scan under {}.",
            root.display()
        );
        if skipped > 0 {
            message.push_str(&format!(" Skipped {skipped} duplicates or empty files."));
        }
        if failures > 0 {
            message.push_str(&format!(" {failures} paths failed to load."));
        }
        if had_warnings {
            message.push_str(" Some directories could not be scanned (permission denied).");
        }
        app.set_status(message);
        return Ok(());
    }

    if let Err(err) = app.persist_state() {
        app.set_status(format!(
            "Imported {imported} certificate entries but failed to save history: {err}"
        ));
    } else {
        let mut summary = format!(
            "Imported {imported} certificate entries from {}.",
            root.display()
        );
        if skipped > 0 {
            summary.push_str(&format!(" Skipped {skipped} duplicates or empty files."));
        }
        if failures > 0 {
            summary.push_str(&format!(" {failures} paths failed to load."));
        }
        if had_warnings {
            summary.push_str(" Some directories could not be scanned (permission denied).");
        }
        app.set_status(summary);
    }

    Ok(())
}

async fn discover_certificate_paths(root: &Path) -> Result<(Vec<PathBuf>, bool)> {
    let root = root.to_path_buf();
    let output = tokio::task::spawn_blocking(move || -> Result<_> {
        let patterns = [
            "*.pem", "*.crt", "*.cer", "*.der", "*.p7b", "*.p7c", "*.p12", "*.pfx",
        ];
        let mut command = Command::new("find");
        command.arg(&root);
        command.args(["-type", "f", "("]);
        for (idx, pattern) in patterns.iter().enumerate() {
            if idx > 0 {
                command.arg("-o");
            }
            command.arg("-iname");
            command.arg(pattern);
        }
        command.args([")", "-print0"]);
        let output = command
            .output()
            .with_context(|| format!("failed to execute find starting at {}", root.display()))?;
        Ok(output)
    })
    .await??;

    let had_warnings = !output.stderr.is_empty() || !output.status.success();
    let mut paths = Vec::new();
    for chunk in output.stdout.split(|b| *b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let os_path = OsStr::from_bytes(chunk);
        paths.push(PathBuf::from(os_path));
    }
    paths.sort();
    paths.dedup();

    Ok((paths, had_warnings))
}

fn focus_next(app: &mut App) {
    match app.focus {
        Focus::Input => {
            app.stop_input_editing();
            app.ensure_selection();
            app.focus = Focus::History;
        }
        Focus::History => {
            app.focus = Focus::Table;
        }
        Focus::Table => {
            app.stop_input_editing();
            app.focus = Focus::Input;
        }
        Focus::HistorySearch => {
            app.finish_history_search();
            focus_next(app);
        }
        Focus::TableSearch => {
            app.finish_table_search();
            focus_next(app);
        }
    }
}

fn focus_prev(app: &mut App) {
    match app.focus {
        Focus::Input => {
            app.stop_input_editing();
            app.ensure_selection();
            app.focus = Focus::Table;
        }
        Focus::History => {
            app.focus = Focus::Input;
        }
        Focus::Table => {
            app.ensure_selection();
            app.focus = Focus::History;
        }
        Focus::HistorySearch => {
            app.finish_history_search();
            focus_prev(app);
        }
        Focus::TableSearch => {
            app.finish_table_search();
            focus_prev(app);
        }
    }
}

fn focus_section(app: &mut App, target: Focus) {
    if matches!(app.focus, Focus::HistorySearch) {
        app.finish_history_search();
    } else if matches!(app.focus, Focus::TableSearch) {
        app.finish_table_search();
    }

    match target {
        Focus::Input => {
            app.stop_input_editing();
            app.focus = Focus::Input;
        }
        Focus::History => {
            app.ensure_selection();
            app.focus = Focus::History;
        }
        Focus::Table => {
            app.ensure_selection();
            app.focus = Focus::Table;
        }
        Focus::HistorySearch | Focus::TableSearch => {}
    }
}

fn looks_like_path(input: &str) -> bool {
    let trimmed = input.trim();
    trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with('~')
        || trimmed.contains('/')
        || trimmed.contains('\\')
}

fn expand_path(input: &str) -> PathBuf {
    if input == "~" {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home);
        }
    } else if let Some(stripped) = input.strip_prefix("~/") {
        if let Ok(home) = env::var("HOME") {
            let mut buf = PathBuf::from(home);
            buf.push(stripped);
            return buf;
        }
    }
    PathBuf::from(input)
}

fn path_exists(input: &str) -> bool {
    let expanded = expand_path(input);
    expanded.exists()
}

fn parse_target(input: &str) -> Result<TargetKind> {
    if let Some((host, port_part)) = input.rsplit_once(':') {
        if host.is_empty() {
            bail!("Target is missing host before ':'");
        }
        let port = if port_part.is_empty() {
            443
        } else {
            port_part.parse().context("invalid port")?
        };
        return Ok(TargetKind::Remote {
            host: host.to_string(),
            port,
        });
    }

    if looks_like_path(input) || path_exists(input) {
        let path = expand_path(input);
        if path.as_os_str().is_empty() {
            bail!("Path is empty");
        }
        return Ok(TargetKind::Local { path });
    }

    Ok(TargetKind::Remote {
        host: input.to_string(),
        port: 443,
    })
}

fn describe_fetch(kind: &TargetKind, certs: &[CertInfo]) -> String {
    let count = certs.len();
    let base = match kind {
        TargetKind::Remote { host, port } => format!("Fetched {count} cert(s) from {host}:{port}"),
        TargetKind::Local { path } => format!("Loaded {count} cert(s) from {}", path.display()),
    };
    if let Some(extra) = leaf_summary(certs) {
        format!("{base}. {extra}.")
    } else {
        format!("{base}.")
    }
}

fn leaf_summary(certs: &[CertInfo]) -> Option<String> {
    let leaf = certs.first()?;
    let days = days_until_expiry(leaf)?;
    if days >= 0 {
        Some(format!("Leaf expires in {days} days"))
    } else {
        Some(format!("Leaf expired {} days ago", -days))
    }
}

fn password_required_feedback(
    kind: &TargetKind,
    error: &PasswordRequiredError,
) -> (String, Option<LocalCertFormat>) {
    let mut status = format!(
        "Password required for {} ({})",
        kind.label(),
        error.kind().label()
    );
    if let Some(extra) = error.last_error() {
        status.push_str(&format!(": {extra}"));
    }
    status.push_str(" — press Enter in details to unlock.");
    let format = match error.kind() {
        ProtectedStoreKind::Pkcs12 => Some(LocalCertFormat::Pkcs12),
        ProtectedStoreKind::JavaKeystore => Some(LocalCertFormat::JavaKeystore),
    };
    (status, format)
}

struct LoadedCerts {
    certs: Vec<CertInfo>,
    local_format: Option<LocalCertFormat>,
    local_is_dir: Option<bool>,
}

impl LoadedCerts {
    fn remote(certs: Vec<CertInfo>) -> Self {
        Self {
            certs,
            local_format: None,
            local_is_dir: None,
        }
    }

    fn local(certs: Vec<CertInfo>, format: LocalCertFormat, is_dir: bool) -> Self {
        Self {
            certs,
            local_format: Some(format),
            local_is_dir: Some(is_dir),
        }
    }
}

async fn load_certs_for(
    kind: TargetKind,
    timeout_secs: u64,
    password: Option<String>,
) -> Result<LoadedCerts> {
    match kind {
        TargetKind::Remote { host, port } => {
            let host_for_fetch = host.clone();
            let label = format!("{}:{}", host, port);
            let handle = tokio::task::spawn_blocking(move || -> Result<Vec<CertInfo>> {
                let report = inspect_remote(&host_for_fetch, port, None)?;
                Ok(report.certs)
            });
            match timeout(Duration::from_secs(timeout_secs), handle).await {
                Ok(join_result) => {
                    let certs = join_result??;
                    Ok(LoadedCerts::remote(certs))
                }
                Err(_) => Err(anyhow!(
                    "Timed out after {}s while fetching {}",
                    timeout_secs,
                    label
                )),
            }
        }
        TargetKind::Local { path } => {
            let pass = password;
            let handle = tokio::task::spawn_blocking(
                move || -> Result<(Vec<CertInfo>, LocalCertFormat, bool)> {
                    let report = inspect_local_path(&path, pass.as_deref())?;
                    Ok((report.certs, report.format, report.is_dir))
                },
            );
            let (certs, format, is_dir) = handle.await??;
            Ok(LoadedCerts::local(certs, format, is_dir))
        }
    }
}

fn ui(f: &mut Frame<'_>, app: &mut App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Length(5),
        ])
        .split(f.size());

    render_input(f, app, layout[0]);
    render_body(f, app, layout[1]);
    render_filter_bar(f, app, layout[2]);
    render_status_panel(f, app, layout[3]);
    render_shortcuts(f, app, layout[4]);

    app.cert_pem_area = None;

    if app.find_dialog_active() {
        render_find_dialog(f, app);
    }
    if app.password_dialog_active() {
        render_password_dialog(f, app);
    } else if app.cert_fullscreen_active() {
        render_cert_fullscreen(f, app);
    } else if app.cert_modal_active() {
        render_cert_modal(f, app);
    }
}

fn shortcut_span(text: &str, theme: &Theme) -> Span<'static> {
    Span::styled(text.to_string(), Style::default().fg(theme.highlight))
}

fn section_title(shortcut: char, text: &str, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::raw(" ["),
        shortcut_span(&shortcut.to_ascii_uppercase().to_string(), theme),
        Span::raw("] "),
        Span::raw(text.to_string()),
    ])
}

fn label_span(label: &str, theme: &Theme) -> Span<'static> {
    Span::styled(format!("{label}: "), Style::default().fg(theme.muted))
}

fn render_input(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    app.input_area = Some(area);
    let label = if app.is_input_editing() {
        "target (editing — host:port or path)"
    } else {
        "target (host:port or path)"
    };
    let title = section_title('t', label, &app.theme);
    let mut block = Block::default().borders(Borders::ALL).title(title);
    if matches!(app.focus, Focus::Input) {
        block = block.border_style(Style::default().fg(app.theme.highlight));
    }
    let input = Paragraph::new(app.input.as_str()).block(block);
    f.render_widget(input, area);
}

fn render_body(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    app.history_view = None;
    app.table_view = None;
    let body_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    render_history_panel(f, app, body_chunks[0]);
    render_table_panel(f, app, body_chunks[1]);
}

fn render_history_panel(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    let history_label = match (&app.history_filter, app.focus) {
        (Some(filter), _) => format!("history (/ {filter})"),
        (None, Focus::HistorySearch) => "history (search)".to_string(),
        _ => "history".to_string(),
    };

    let history_title = section_title('h', &history_label, &app.theme);

    let mut block = Block::default().borders(Borders::ALL).title(history_title);
    if matches!(app.focus, Focus::History | Focus::HistorySearch) {
        block = block.border_style(Style::default().fg(app.theme.highlight));
    }

    let visible_indices = app.visible_indices();
    app.history_view = Some(HistoryViewCache {
        area,
        indices: visible_indices.clone(),
        offset: app.history_state.offset(),
    });
    if visible_indices.is_empty() {
        let empty = Paragraph::new("No entries yet").block(block);
        f.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem> = visible_indices
        .iter()
        .map(|idx| {
            let entry = &app.entries[*idx];
            ListItem::new(history_line(entry, &app.theme))
        })
        .collect();

    let history = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .fg(app.theme.highlight)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let selected_pos = app.selected_visible_pos(&visible_indices);
    if app.history_state.selected() != selected_pos {
        app.history_state.select(selected_pos);
    }
    f.render_stateful_widget(history, area, &mut app.history_state);
}

fn icon_for_entry(entry: &TargetEntry) -> &'static str {
    match &entry.kind {
        TargetKind::Remote { .. } => "",
        TargetKind::Local { .. } => {
            if entry.local_is_dir.unwrap_or(false) {
                ""
            } else {
                match entry.local_format {
                    Some(LocalCertFormat::Pkcs12) => "",
                    Some(LocalCertFormat::Pkcs7) => "",
                    Some(LocalCertFormat::JavaKeystore) => "",
                    _ => "",
                }
            }
        }
    }
}

fn history_line(entry: &TargetEntry, theme: &Theme) -> Line<'static> {
    let color = entry.kind.color(theme);
    let mut spans = vec![
        Span::styled(
            icon_for_entry(entry).to_string(),
            Style::default().fg(color),
        ),
        Span::raw(" "),
    ];

    match &entry.kind {
        TargetKind::Local { path } => {
            let file_name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());
            let parent = path
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| ".".to_string());
            spans.push(Span::styled(file_name, Style::default().fg(color)));
            spans.push(Span::raw(format!(" [{}] ", entry.certs.len())));
            spans.push(Span::styled(parent, Style::default().fg(theme.muted)));
        }
        TargetKind::Remote { .. } => {
            spans.push(Span::styled(
                entry.label.clone(),
                Style::default().fg(color),
            ));
            spans.push(Span::raw(format!(" [{}] ", entry.certs.len())));
        }
    }

    if !entry.status.is_empty() {
        spans.push(Span::raw(" — "));
        let status_color = if entry.protected.is_some() {
            theme.warning
        } else {
            theme.muted
        };
        spans.push(Span::styled(
            entry.status.clone(),
            Style::default().fg(status_color),
        ));
    }

    Line::from(spans)
}

fn render_table_panel(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    app.ensure_table_selection();

    let mut view_indices: Vec<usize> = Vec::new();
    let (rows, total, filtered) = if let Some(entry_idx) = app.selected {
        let entry = &app.entries[entry_idx];
        let indices = app.filtered_cert_indices(entry);
        let total = entry.certs.len();
        let filtered = indices.len();
        view_indices = indices.clone();
        let rows: Vec<Row> = indices
            .into_iter()
            .map(|idx| {
                let cert = &entry.certs[idx];
                let not_after = cert
                    .not_after_ts
                    .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| "-".to_string());

                let days_value = days_until_expiry(cert);
                let (days_str, style) = match days_value {
                    Some(d) if d < 0 => (format!("{d}"), Style::default().fg(app.theme.danger)),
                    Some(d) if d <= 30 => (format!("{d}"), Style::default().fg(app.theme.warning)),
                    Some(d) => (format!("{d}"), Style::default().fg(app.theme.success)),
                    None => ("-".to_string(), Style::default().fg(app.theme.muted)),
                };

                Row::new(vec![
                    Cell::from(idx.to_string()),
                    Cell::from(cert.subject.clone()),
                    Cell::from(cert.issuer.clone()),
                    Cell::from(not_after),
                    Cell::from(days_str).style(style),
                ])
            })
            .collect();
        (rows, total, filtered)
    } else {
        (Vec::new(), 0, 0)
    };

    app.table_view = Some(TableViewCache {
        area,
        indices: view_indices,
        offset: app.table_state.offset(),
    });

    let table_label = if let Some(entry) = app.current_entry() {
        let mut base = format!(
            "certificates — {} — showing {filtered}/{total}",
            entry.title()
        );
        if entry.protected.is_some() {
            base.push_str(" — password required");
        }
        base
    } else {
        "certificates (no results yet)".to_string()
    };

    let table_title = section_title('c', &table_label, &app.theme);

    let mut table_block = Block::default().borders(Borders::ALL).title(table_title);
    if matches!(app.focus, Focus::Table | Focus::TableSearch) {
        table_block = table_block.border_style(Style::default().fg(app.theme.highlight));
    }

    let header = Row::new(vec![
        header_with_sort("Index", SortKey::Chain, app),
        header_with_sort("Subject", SortKey::Subject, app),
        header_with_sort("Issuer", SortKey::Issuer, app),
        header_with_sort("Not After (UTC)", SortKey::NotAfter, app),
        header_with_sort("Days Left", SortKey::DaysLeft, app),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let widths = [
        Constraint::Length(6),
        Constraint::Percentage(30),
        Constraint::Percentage(30),
        Constraint::Length(25),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(table_block)
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .fg(app.theme.highlight)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_filter_bar(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    app.filter_area = Some(area);
    let (title, line, highlight) = match app.focus {
        Focus::History | Focus::HistorySearch => (
            section_title('/', "filter — history", &app.theme),
            history_filter_line(app),
            matches!(app.focus, Focus::HistorySearch),
        ),
        Focus::Table | Focus::TableSearch => (
            section_title('/', "filter — certificates", &app.theme),
            table_filter_line(app),
            matches!(app.focus, Focus::TableSearch),
        ),
        _ => (
            section_title('/', "filter", &app.theme),
            Line::from(vec![
                Span::raw("Focus "),
                shortcut_span("H", &app.theme),
                Span::raw(" or "),
                shortcut_span("C", &app.theme),
                Span::raw(" panes and press "),
                shortcut_span("/", &app.theme),
                Span::raw(" to filter"),
            ]),
            false,
        ),
    };

    let mut block = Block::default().borders(Borders::ALL).title(title);
    if highlight {
        block = block.border_style(Style::default().fg(app.theme.highlight));
    }

    let paragraph = Paragraph::new(line).block(block);
    f.render_widget(paragraph, area);
}

fn render_shortcuts(f: &mut Frame<'_>, app: &App, area: Rect) {
    let lines = vec![
        Line::from(vec![
            shortcut_span("Enter", &app.theme),
            Span::raw(": edit target (submit)   "),
            shortcut_span("Esc", &app.theme),
            Span::raw(": cancel edit   "),
            shortcut_span("Tab", &app.theme),
            Span::raw(": cycle focus   "),
            shortcut_span("Ctrl+F", &app.theme),
            Span::raw(": find certificates   "),
            shortcut_span("Ctrl+R", &app.theme),
            Span::raw(": refresh"),
        ]),
        Line::from(vec![
            shortcut_span("/", &app.theme),
            Span::raw(": filter list   "),
            shortcut_span("Delete", &app.theme),
            Span::raw("/"),
            shortcut_span("x", &app.theme),
            Span::raw(": remove history entry   "),
            shortcut_span("Enter", &app.theme),
            Span::raw(" (certs): details   "),
            shortcut_span("F", &app.theme),
            Span::raw(" (details): fullscreen   "),
            shortcut_span("Ctrl+L", &app.theme),
            Span::raw(": clear history"),
        ]),
        Line::from(vec![
            shortcut_span("S", &app.theme),
            Span::raw("/"),
            shortcut_span("I", &app.theme),
            Span::raw("/"),
            shortcut_span("N", &app.theme),
            Span::raw("/"),
            shortcut_span("D", &app.theme),
            Span::raw("/"),
            shortcut_span("O", &app.theme),
            Span::raw(": sort certificates"),
        ]),
    ];

    let shortcuts = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" shortcuts "))
        .wrap(Wrap { trim: true });
    f.render_widget(shortcuts, area);
}

fn history_filter_line(app: &App) -> Line<'static> {
    if matches!(app.focus, Focus::HistorySearch) {
        Line::from(vec![
            shortcut_span("/", &app.theme),
            Span::raw(app.history_search_buffer.clone()),
        ])
    } else if let Some(filter) = app.history_filter.as_ref() {
        Line::from(vec![
            Span::raw("Active: "),
            shortcut_span("/", &app.theme),
            Span::raw(filter.clone()),
        ])
    } else {
        Line::from(vec![
            Span::raw("Press "),
            shortcut_span("/", &app.theme),
            Span::raw(" to search history"),
        ])
    }
}

fn table_filter_line(app: &App) -> Line<'static> {
    if matches!(app.focus, Focus::TableSearch) {
        Line::from(vec![
            shortcut_span("/", &app.theme),
            Span::raw(app.table_search_buffer.clone()),
        ])
    } else if let Some(filter) = app.table_filter.as_ref() {
        Line::from(vec![
            Span::raw("Active: "),
            shortcut_span("/", &app.theme),
            Span::raw(filter.clone()),
        ])
    } else if let Some(entry) = app.current_entry() {
        if entry.protected.is_some() {
            Line::from(vec![
                Span::raw("Locked: "),
                shortcut_span("Enter", &app.theme),
                Span::raw(" to unlock"),
            ])
        } else {
            Line::from(vec![
                Span::raw("Press "),
                shortcut_span("/", &app.theme),
                Span::raw(" to search certificates"),
            ])
        }
    } else {
        Line::from(vec![
            Span::raw("Press "),
            shortcut_span("/", &app.theme),
            Span::raw(" to search certificates"),
        ])
    }
}

fn render_status_panel(f: &mut Frame<'_>, app: &App, area: Rect) {
    let clock = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let second_line = format!(
        "Sort: {} ({})   Timeout: {}s   {}",
        app.sort_key.label(),
        app.sort_order.label(),
        app.settings.timeout_secs,
        clock
    );
    let content = format!("{}\n{}", app.status, second_line);
    let status = Paragraph::new(content)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title(" status "));
    f.render_widget(status, area);
}

fn render_password_dialog(f: &mut Frame<'_>, app: &App) {
    let Some(dialog) = app.password_dialog.as_ref() else {
        return;
    };
    let Some(entry) = app.entries.get(dialog.entry_index) else {
        return;
    };

    let area = centered_rect(60, 8, f.size());
    f.render_widget(Clear, area);

    let title = format!(" Unlock {} ", entry.title());
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(inner);

    let mut lines = Vec::new();
    lines.push(Line::from(format!(
        "{} ({} store)",
        entry.kind.label(),
        dialog.kind.label()
    )));
    if let Some(state) = entry.protected.as_ref() {
        if let Some(err) = state.last_error.as_ref() {
            lines.push(Line::from(format!("Last error: {err}")));
        } else {
            lines.push(Line::default());
        }
    } else {
        lines.push(Line::default());
    }
    lines.push(Line::from(vec![
        shortcut_span("Enter", &app.theme),
        Span::raw(": submit   "),
        shortcut_span("Esc", &app.theme),
        Span::raw(": cancel"),
    ]));
    let info = Paragraph::new(lines);
    f.render_widget(info, chunks[0]);

    f.render_widget(Paragraph::new(""), chunks[1]);

    let display: String = dialog.input.chars().map(|_| '*').collect();

    let mut input_block = Block::default().borders(Borders::ALL).title(" password ");
    input_block = input_block.border_style(Style::default().fg(app.theme.highlight));
    let input = Paragraph::new(display).block(input_block);
    f.render_widget(input, chunks[2]);
}

fn render_find_dialog(f: &mut Frame<'_>, app: &App) {
    let Some(dialog) = app.find_dialog.as_ref() else {
        return;
    };
    let area = centered_rect(70, 7, f.size());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" find certificates ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(inner);

    let default_root = app.default_find_root();
    let instructions = Paragraph::new(vec![
        Line::from("Choose the starting directory for certificate discovery."),
        Line::from(format!(
            "Leave blank to use default: {}",
            default_root.display()
        )),
        Line::from(vec![
            shortcut_span("Enter", &app.theme),
            Span::raw(": confirm   "),
            shortcut_span("Esc", &app.theme),
            Span::raw(": cancel   "),
            shortcut_span("Tab", &app.theme),
            Span::raw(": autocomplete path"),
        ]),
    ]);
    f.render_widget(instructions, chunks[0]);

    f.render_widget(Paragraph::new(""), chunks[1]);

    let mut input_block = Block::default().borders(Borders::ALL).title(" start path ");
    input_block = input_block.border_style(Style::default().fg(app.theme.highlight));
    let input = Paragraph::new(dialog.input.as_str()).block(input_block);
    f.render_widget(input, chunks[2]);
}

fn render_cert_modal(f: &mut Frame<'_>, app: &mut App) {
    let Some((entry, idx, cert)) = app.cert_modal_info() else {
        return;
    };

    let mut width = ((f.size().width as u32 * 3) / 4) as u16;
    let mut height = ((f.size().height as u32 * 3) / 4) as u16;
    width = width.max(60).min(f.size().width);
    height = height.max(20).min(f.size().height);

    let area = centered_rect(width, height, f.size());
    f.render_widget(Clear, area);

    let title = format!(" certificate details — {} (index {}) ", entry.title(), idx);
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let not_before = cert
        .not_before_ts
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "-".to_string());
    let not_after = cert
        .not_after_ts
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "-".to_string());
    let days_left = days_until_expiry(cert)
        .map(|d| d.to_string())
        .unwrap_or_else(|| "-".to_string());
    let fingerprint = cert
        .sha256_fingerprint
        .as_deref()
        .unwrap_or("-")
        .to_string();
    let san_display = if cert.san.is_empty() {
        "-".to_string()
    } else {
        cert.san.join(", ")
    };

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(inner);

    let details_block = Block::default().borders(Borders::ALL).title(" details ");
    let details_lines = vec![
        Line::from(vec![
            label_span("Subject", &app.theme),
            Span::raw(cert.subject.clone()),
        ]),
        Line::from(vec![
            label_span("Issuer", &app.theme),
            Span::raw(cert.issuer.clone()),
        ]),
        Line::from(vec![
            label_span("Not Before (UTC)", &app.theme),
            Span::raw(not_before),
        ]),
        Line::from(vec![
            label_span("Not After (UTC)", &app.theme),
            Span::raw(not_after),
        ]),
        Line::from(vec![
            label_span("Days Left", &app.theme),
            Span::raw(days_left),
        ]),
        Line::from(vec![
            label_span("SHA-256 Fingerprint", &app.theme),
            Span::raw(fingerprint),
        ]),
        Line::from(vec![
            label_span("Subject Alternative Names", &app.theme),
            Span::raw(san_display),
        ]),
        Line::default(),
        Line::from(vec![
            shortcut_span("Esc", &app.theme),
            Span::raw(": close   "),
            shortcut_span("Up", &app.theme),
            Span::raw("/"),
            shortcut_span("Down", &app.theme),
            Span::raw(": switch certificate   "),
            shortcut_span("F", &app.theme),
            Span::raw(": fullscreen"),
        ]),
    ];
    let details = Paragraph::new(details_lines)
        .wrap(Wrap { trim: true })
        .block(details_block);
    f.render_widget(details, layout[0]);

    let pem_block = Block::default()
        .borders(Borders::ALL)
        .title(" certificate (PEM) ");
    let pem = Paragraph::new(cert.pem.as_str())
        .wrap(Wrap { trim: false })
        .block(pem_block);
    f.render_widget(pem, layout[1]);
    app.cert_pem_area = Some(layout[1]);
}

fn render_cert_fullscreen(f: &mut Frame<'_>, app: &App) {
    let Some((entry, idx, cert)) = app.cert_modal_info() else {
        return;
    };

    f.render_widget(Clear, f.size());

    let fullscreen_title = Line::from(vec![
        Span::raw(" ["),
        shortcut_span("F", &app.theme),
        Span::raw("] fullscreen certificate — "),
        Span::raw(format!("{} (index {}) ", entry.title(), idx)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(fullscreen_title);

    let inner = block.inner(f.size());
    f.render_widget(block, f.size());

    let not_before = cert
        .not_before_ts
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "-".to_string());
    let not_after = cert
        .not_after_ts
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "-".to_string());
    let days_left = days_until_expiry(cert)
        .map(|d| d.to_string())
        .unwrap_or_else(|| "-".to_string());

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        label_span("Subject", &app.theme),
        Span::raw(cert.subject.clone()),
    ]));
    lines.push(Line::from(vec![
        label_span("Issuer", &app.theme),
        Span::raw(cert.issuer.clone()),
    ]));
    lines.push(Line::from(vec![
        label_span("Not Before (UTC)", &app.theme),
        Span::raw(not_before),
    ]));
    lines.push(Line::from(vec![
        label_span("Not After (UTC)", &app.theme),
        Span::raw(not_after),
    ]));
    lines.push(Line::from(vec![
        label_span("Days Left", &app.theme),
        Span::raw(days_left),
    ]));
    lines.push(Line::default());
    lines.push(Line::from(vec![
        shortcut_span("Any key", &app.theme),
        Span::raw(": exit fullscreen"),
    ]));
    lines.push(Line::default());

    for pem_line in cert.pem.lines() {
        lines.push(Line::from(pem_line.to_string()));
    }

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(paragraph, inner);
}

fn copy_pem_to_clipboard(pem: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().context("clipboard unavailable")?;
    clipboard
        .set_text(pem.to_string())
        .context("failed to copy PEM to clipboard")?;
    Ok(())
}

fn point_in_rect(area: Rect, x: u16, y: u16) -> bool {
    x >= area.x
        && x < area.x.saturating_add(area.width)
        && y >= area.y
        && y < area.y.saturating_add(area.height)
}

fn centered_rect(width: u16, height: u16, container: Rect) -> Rect {
    let width = width.min(container.width);
    let height = height.min(container.height);
    let x = container.x + (container.width.saturating_sub(width)) / 2;
    let y = container.y + (container.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width, height)
}

fn header_with_sort(label: &str, key: SortKey, app: &App) -> String {
    if app.sort_key == key && key != SortKey::Chain {
        let suffix = match app.sort_order {
            SortOrder::Asc => "^",
            SortOrder::Desc => "v",
        };
        format!("{label} {suffix}")
    } else {
        label.to_string()
    }
}

enum AutocompleteResult {
    Applied { changed: bool },
    NoMatch,
    NotEligible,
}

fn try_autocomplete_input(app: &mut App) -> bool {
    match autocomplete_path_buffer(&mut app.input) {
        AutocompleteResult::Applied { changed } => {
            if changed {
                app.set_status(format!("Path autocompleted to {}", app.input));
            }
            true
        }
        AutocompleteResult::NoMatch => {
            app.set_status("No completion found for path input.");
            true
        }
        AutocompleteResult::NotEligible => false,
    }
}

fn autocomplete_path_buffer(buffer: &mut String) -> AutocompleteResult {
    let trimmed = buffer.trim();
    if trimmed.is_empty() {
        return AutocompleteResult::NotEligible;
    }
    if !(looks_like_path(trimmed) || path_exists(trimmed)) {
        return AutocompleteResult::NotEligible;
    }
    match autocomplete_path(trimmed) {
        Some(completed) => {
            let changed = completed != trimmed;
            buffer.clear();
            buffer.push_str(&completed);
            AutocompleteResult::Applied { changed }
        }
        None => AutocompleteResult::NoMatch,
    }
}

fn autocomplete_path(input: &str) -> Option<String> {
    let sep = std::path::MAIN_SEPARATOR;
    let trimmed = input.trim_end();
    let had_sep = trimmed.ends_with(sep);

    let (prefix, stem) = if had_sep {
        (trimmed.to_string(), String::new())
    } else if let Some(pos) = trimmed.rfind(sep) {
        (trimmed[..=pos].to_string(), trimmed[pos + 1..].to_string())
    } else {
        (String::new(), trimmed.to_string())
    };

    let dir_path = if prefix.is_empty() {
        PathBuf::from(".")
    } else if prefix == sep.to_string() {
        PathBuf::from(std::path::MAIN_SEPARATOR.to_string())
    } else {
        expand_path(prefix.trim_end_matches(sep))
    };

    let entries = fs::read_dir(&dir_path).ok()?;
    let mut matches: Vec<(String, bool)> = Vec::new();
    for entry in entries {
        let entry = entry.ok()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&stem) {
            matches.push((name, entry.path().is_dir()));
        }
    }
    if matches.is_empty() {
        return None;
    }
    matches.sort_by(|a, b| a.0.cmp(&b.0));

    let mut common = matches[0].0.clone();
    for (candidate, _) in &matches[1..] {
        common = common_prefix(&common, candidate);
        if common.is_empty() {
            break;
        }
    }

    let replacement = if common.len() > stem.len() {
        common
    } else if matches.len() == 1 {
        matches[0].0.clone()
    } else {
        stem.clone()
    };

    let single_dir = matches.len() == 1 && matches[0].0 == replacement && matches[0].1;
    let mut result = prefix.clone();
    result.push_str(&replacement);
    if single_dir && !result.ends_with(sep) {
        result.push(sep);
    }
    Some(result)
}

fn common_prefix(a: &str, b: &str) -> String {
    let mut prefix = String::new();
    for (ca, cb) in a.chars().zip(b.chars()) {
        if ca == cb {
            prefix.push(ca);
        } else {
            break;
        }
    }
    prefix
}

fn config_dir() -> Result<PathBuf> {
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("omarchy-cert-tui"));
    }
    let home = env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".config").join("omarchy-cert-tui"))
}

fn settings_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("settings.json"))
}

fn settings_display_path() -> String {
    match settings_path() {
        Ok(path) => path.display().to_string(),
        Err(_) => "~/.config/omarchy-cert-tui/settings.json".to_string(),
    }
}

fn omarchy_theme_path() -> Result<PathBuf> {
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("omarchy").join("theme.json"));
    }
    let home = env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("omarchy")
        .join("theme.json"))
}

fn load_theme() -> (Theme, String) {
    let mut theme = Theme::default();
    let path = match omarchy_theme_path() {
        Ok(p) => p,
        Err(err) => {
            return (
                theme,
                format!("Unable to resolve omarchy theme path ({err}); using defaults."),
            )
        }
    };

    if !path.exists() {
        return (
            theme,
            format!(
                "Omarchy theme not found at {}; using defaults.",
                path.display()
            ),
        );
    }

    let data = match fs::read_to_string(&path) {
        Ok(d) => d,
        Err(err) => {
            return (
                theme,
                format!(
                    "Failed to read {} ({err}); using default colors.",
                    path.display()
                ),
            )
        }
    };

    let json: Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(err) => {
            return (
                theme,
                format!(
                    "Failed to parse {} ({err}); using default colors.",
                    path.display()
                ),
            )
        }
    };

    let mut applied: Vec<&str> = Vec::new();

    if let Some(color) = find_color(&json, &["highlight", "accent", "primary"]) {
        theme.highlight = color;
        applied.push("highlight");
    }
    if let Some(color) = find_color(&json, &["remote", "url", "network", "cyan", "info"]) {
        theme.remote = color;
        applied.push("remote");
    }
    if let Some(color) = find_color(&json, &["local", "folder", "directory", "green"]) {
        theme.local = color;
        applied.push("local");
    }
    if let Some(color) = find_color(&json, &["muted", "comment", "dim", "gray"]) {
        theme.muted = color;
        applied.push("muted");
    }
    if let Some(color) = find_color(&json, &["success", "ok", "positive", "green"]) {
        theme.success = color;
        applied.push("success");
    }
    if let Some(color) = find_color(&json, &["warning", "alert", "yellow"]) {
        theme.warning = color;
        applied.push("warning");
    }
    if let Some(color) = find_color(&json, &["danger", "error", "red", "critical"]) {
        theme.danger = color;
        applied.push("danger");
    }

    let summary = if applied.is_empty() {
        format!(
            "Loaded {} but found no recognized color keys; defaults remain.",
            path.display()
        )
    } else {
        format!(
            "Loaded theme from {} (applied {}).",
            path.display(),
            applied.join(", ")
        )
    };

    (theme, summary)
}

fn find_color(value: &Value, keys: &[&str]) -> Option<Color> {
    for key in keys {
        if let Some(color) = find_color_by_key(value, key) {
            return Some(color);
        }
    }
    None
}

fn find_color_by_key(value: &Value, target: &str) -> Option<Color> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(target) {
                if let Some(color) = value_to_color(found) {
                    return Some(color);
                }
            }
            for v in map.values() {
                if let Some(color) = find_color_by_key(v, target) {
                    return Some(color);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                if let Some(color) = find_color_by_key(item, target) {
                    return Some(color);
                }
            }
        }
        _ => {}
    }
    None
}

fn value_to_color(value: &Value) -> Option<Color> {
    match value {
        Value::String(s) => parse_hex_color(s),
        Value::Array(arr) if arr.len() >= 3 => {
            let mut rgb = [0u8; 3];
            for (idx, component) in arr.iter().take(3).enumerate() {
                if let Some(v) = component.as_u64() {
                    if v <= 255 {
                        rgb[idx] = v as u8;
                    }
                }
            }
            Some(Color::Rgb(rgb[0], rgb[1], rgb[2]))
        }
        _ => None,
    }
}

fn parse_hex_color(input: &str) -> Option<Color> {
    let trimmed = input.trim();
    let hex = trimmed.strip_prefix('#').unwrap_or(trimmed);
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    match hex.len() {
        6 => {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            Some(Color::Rgb(r, g, b))
        }
        3 => {
            let r = u8::from_str_radix(&hex[0..1].repeat(2), 16).ok()?;
            let g = u8::from_str_radix(&hex[1..2].repeat(2), 16).ok()?;
            let b = u8::from_str_radix(&hex[2..3].repeat(2), 16).ok()?;
            Some(Color::Rgb(r, g, b))
        }
        _ => None,
    }
}

fn persistence_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(HISTORY_FILE))
}

fn legacy_history_path() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(LEGACY_HISTORY_FILE))
}

fn history_display_path() -> String {
    match persistence_path() {
        Ok(path) => path.display().to_string(),
        Err(_) => format!("~/.config/omarchy-cert-tui/{HISTORY_FILE}"),
    }
}

fn load_entries_from_disk() -> Result<(Vec<TargetEntry>, Option<String>, bool)> {
    let path = persistence_path()?;
    if path.exists() {
        let data = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if data.trim().is_empty() {
            return Ok((Vec::new(), None, false));
        }
        let entries: Vec<TargetEntry> = serde_json::from_str(&data)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        return Ok((entries, None, false));
    }

    if let Ok(legacy) = legacy_history_path() {
        if legacy.exists() {
            let data = fs::read_to_string(&legacy)
                .with_context(|| format!("failed to read {}", legacy.display()))?;
            if data.trim().is_empty() {
                return Ok((
                    Vec::new(),
                    Some(format!("Legacy history at {} was empty.", legacy.display())),
                    true,
                ));
            }
            let entries: Vec<TargetEntry> = serde_json::from_str(&data)
                .with_context(|| format!("failed to parse {}", legacy.display()))?;
            let message = Some(format!(
                "Migrated history from {} to {}.",
                legacy.display(),
                history_display_path()
            ));
            return Ok((entries, message, true));
        }
    }

    Ok((Vec::new(), None, false))
}

fn save_entries(entries: &[TargetEntry]) -> Result<()> {
    let path = persistence_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let data =
        serde_json::to_string_pretty(entries).context("failed to serialize persisted entries")?;
    fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))?;
    if let Ok(legacy) = legacy_history_path() {
        if legacy.exists() {
            let _ = fs::remove_file(legacy);
        }
    }
    Ok(())
}
