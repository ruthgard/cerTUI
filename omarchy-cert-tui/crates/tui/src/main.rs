use std::{
    cmp::Ordering,
    env, fs, io,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{TimeZone, Utc};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode, KeyEvent,
        KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use omarchy_cert_core::{days_until_expiry, inspect_local_path, inspect_remote, CertInfo};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table},
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
            if let CEvent::Key(key) = event::read()? {
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
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }
}

async fn handle_key(app: &mut App, key: KeyEvent) -> Result<()> {
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

fn initialize_app() -> App {
    let mut app = App::default();
    let default_status = "Type host[:port] (443 default) or path, Enter to inspect. Tab cycles focus / autocompletes paths. / filters the focused list. Ctrl+R refreshes selection. Ctrl+L clears history. q quits.";
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

    fn icon(&self) -> &'static str {
        match self {
            TargetKind::Remote { .. } => "", // Nerd Font globe
            TargetKind::Local { .. } => "",  // Nerd Font folder
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
}

impl TargetEntry {
    fn new(kind: TargetKind, certs: Vec<CertInfo>, status: String) -> Self {
        let label = kind.label();
        Self {
            label,
            kind,
            certs,
            status,
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
    settings: Settings,
    theme: Theme,
}

impl Default for App {
    fn default() -> Self {
        Self {
            input: String::new(),
            status: String::new(),
            focus: Focus::Input,
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
            settings: Settings::default(),
            theme: Theme::default(),
        }
    }
}

impl App {
    fn set_status<S: Into<String>>(&mut self, s: S) {
        self.status = s.into();
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
        self.sync_history_state();
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
    }

    fn finish_table_search(&mut self) {
        self.focus = Focus::Table;
    }

    fn cancel_table_search(&mut self) {
        self.table_search_buffer.clear();
        self.table_filter = None;
        self.focus = Focus::Table;
        self.set_status("Certificate filter cleared.");
    }

    fn set_sort(&mut self, key: SortKey) {
        if key == SortKey::Chain {
            self.sort_key = SortKey::Chain;
            self.sort_order = SortOrder::Asc;
            self.set_status("Sorting by chain order.");
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
            match load_certs_for(kind.clone(), app.settings.timeout_secs).await {
                Ok(certs) => {
                    let status_message = describe_fetch(&kind, &certs);
                    let entry = TargetEntry::new(kind, certs, status_message.clone());
                    app.upsert_entry(entry);
                    if let Err(err) = app.persist_state() {
                        app.set_status(format!("{status_message} (failed to save: {err})"));
                    } else {
                        app.set_status(status_message);
                    }
                }
                Err(err) => app.set_status(format!("Error: {err}")),
            }
        }
        return Ok(true);
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
        if matches!(app.focus, Focus::Input) && try_autocomplete_input(app) {
            return Ok(true);
        }
        focus_next(app);
        return Ok(true);
    }

    if key.code == KeyCode::Char('/') && key.modifiers.is_empty() {
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

    Ok(false)
}

async fn handle_input_focus(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Enter => {
            let trimmed = app.input.trim();
            if trimmed.is_empty() {
                return Ok(());
            }
            let kind = match parse_target(trimmed) {
                Ok(kind) => kind,
                Err(err) => {
                    app.set_status(format!("Error: {err}"));
                    return Ok(());
                }
            };
            app.set_status(kind.loading_message());
            let certs = match load_certs_for(kind.clone(), app.settings.timeout_secs).await {
                Ok(certs) => certs,
                Err(err) => {
                    app.set_status(format!("Error: {err}"));
                    return Ok(());
                }
            };
            let status_message = describe_fetch(&kind, &certs);
            let entry = TargetEntry::new(kind, certs, status_message.clone());
            app.upsert_entry(entry);
            if let Err(err) = app.persist_state() {
                app.set_status(format!("{status_message} (failed to save: {err})"));
            } else {
                app.set_status(status_message);
            }
        }
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Esc => {
            app.input.clear();
        }
        KeyCode::Char(c) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
            {
                app.input.push(c);
            }
        }
        KeyCode::Up => {
            focus_prev(app);
        }
        KeyCode::Down => {
            focus_next(app);
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
            app.focus = Focus::Input;
        }
        KeyCode::Esc => app.focus = Focus::Input,
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
        KeyCode::Up => focus_prev(app),
        KeyCode::Down => focus_next(app),
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
        KeyCode::Up => focus_prev(app),
        KeyCode::Down => focus_next(app),
        _ => {}
    }
    Ok(())
}

fn focus_next(app: &mut App) {
    match app.focus {
        Focus::Input => {
            app.ensure_selection();
            app.focus = Focus::History;
        }
        Focus::History => {
            app.focus = Focus::Table;
        }
        Focus::Table => {
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

async fn load_certs_for(kind: TargetKind, timeout_secs: u64) -> Result<Vec<CertInfo>> {
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
                    Ok(certs)
                }
                Err(_) => Err(anyhow!(
                    "Timed out after {}s while fetching {}",
                    timeout_secs,
                    label
                )),
            }
        }
        TargetKind::Local { path } => {
            let handle = tokio::task::spawn_blocking(move || -> Result<Vec<CertInfo>> {
                let report = inspect_local_path(&path)?;
                Ok(report.certs)
            });
            let certs = handle.await??;
            Ok(certs)
        }
    }
}

fn ui(f: &mut Frame<'_>, app: &mut App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(7),
            Constraint::Length(3),
        ])
        .split(f.size());

    render_input(f, app, layout[0]);
    render_body(f, app, layout[1]);
    render_status_panel(f, app, layout[2]);
}

fn render_input(f: &mut Frame<'_>, app: &App, area: Rect) {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .title(" target (host:port or path) ");
    if matches!(app.focus, Focus::Input) {
        block = block.border_style(Style::default().fg(app.theme.highlight));
    }
    let input = Paragraph::new(app.input.as_str()).block(block);
    f.render_widget(input, area);
}

fn render_body(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(46), Constraint::Min(20)])
        .split(area);

    render_history_panel(f, app, body_chunks[0]);
    render_table_panel(f, app, body_chunks[1]);
}

fn render_history_panel(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(5),
        ])
        .split(area);

    let history_title = match (&app.history_filter, app.focus) {
        (Some(filter), _) => format!(" history (/ {filter}) "),
        (None, Focus::HistorySearch) => " history (search) ".to_string(),
        _ => " history ".to_string(),
    };

    let mut block = Block::default().borders(Borders::ALL).title(history_title);
    if matches!(app.focus, Focus::History | Focus::HistorySearch) {
        block = block.border_style(Style::default().fg(app.theme.highlight));
    }

    let visible_indices = app.visible_indices();
    if visible_indices.is_empty() {
        let empty = Paragraph::new("No entries yet").block(block);
        f.render_widget(empty, chunks[0]);
    } else {
        let items: Vec<ListItem> = visible_indices
            .iter()
            .map(|idx| {
                let entry = &app.entries[*idx];
                let color = entry.kind.color(&app.theme);
                let line = Line::from(vec![
                    Span::styled(entry.kind.icon(), Style::default().fg(color)),
                    Span::raw(" "),
                    Span::styled(entry.label.as_str(), Style::default().fg(color)),
                    Span::raw(format!(" [{}]", entry.certs.len())),
                    Span::raw(" "),
                    Span::styled(entry.status.as_str(), Style::default().fg(app.theme.muted)),
                ]);
                ListItem::new(line)
            })
            .collect();

        let history = List::new(items)
            .block(block)
            .highlight_style(Style::default().fg(app.theme.highlight))
            .highlight_symbol("> ");

        let selected_pos = app.selected_visible_pos(&visible_indices);
        if app.history_state.selected() != selected_pos {
            app.history_state.select(selected_pos);
        }
        f.render_stateful_widget(history, chunks[0], &mut app.history_state);
    }

    let mut filter_block = Block::default()
        .borders(Borders::ALL)
        .title(" history filter ");
    if matches!(app.focus, Focus::HistorySearch) {
        filter_block = filter_block.border_style(Style::default().fg(app.theme.highlight));
    }

    let filter_text = if matches!(app.focus, Focus::HistorySearch) {
        format!("/{}", app.history_search_buffer)
    } else if let Some(filter) = app.history_filter.as_ref() {
        format!("Active: /{filter}")
    } else {
        "Press / while history focused to search".to_string()
    };

    let filter_widget = Paragraph::new(filter_text).block(filter_block);
    f.render_widget(filter_widget, chunks[1]);

    let hints = Paragraph::new(vec![
        Line::from("Tab: cycle focus (Input → History → Table)   Shift+Tab: reverse   Ctrl+R: refresh selection"),
        Line::from("Ctrl+L: clear history   Up/Down: move history entries   Enter: return to input"),
        Line::from("/: search focused list   s/i/n/d/o: sort certificates (history or table)"),
    ])
    .block(Block::default().borders(Borders::ALL).title(" shortcuts "));
    f.render_widget(hints, chunks[2]);
}

fn render_table_panel(f: &mut Frame<'_>, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(area);

    let (rows, total, filtered) = if let Some(entry) = app.current_entry() {
        let indices = app.filtered_cert_indices(entry);
        let total = entry.certs.len();
        let filtered = indices.len();
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

    let title = if let Some(entry) = app.current_entry() {
        format!("{} — showing {filtered}/{total} certs", entry.title())
    } else {
        "No results yet".to_string()
    };

    let mut table_block = Block::default().borders(Borders::ALL).title(title);
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
        .column_spacing(1);

    f.render_widget(table, chunks[0]);

    let mut filter_block = Block::default()
        .borders(Borders::ALL)
        .title(" certificate filter ");
    if matches!(app.focus, Focus::TableSearch) {
        filter_block = filter_block.border_style(Style::default().fg(app.theme.highlight));
    }
    let filter_text = if matches!(app.focus, Focus::TableSearch) {
        format!("/{}", app.table_search_buffer)
    } else if let Some(filter) = app.table_filter.as_ref() {
        format!("Active: /{filter}")
    } else {
        "Press / while table focused to search certificates".to_string()
    };
    let filter_widget = Paragraph::new(filter_text).block(filter_block);
    f.render_widget(filter_widget, chunks[1]);
}

fn render_status_panel(f: &mut Frame<'_>, app: &App, area: Rect) {
    let clock = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let status = Paragraph::new(vec![
        Line::from(app.status.clone()),
        Line::from(format!(
            "Sort: {} ({})",
            app.sort_key.label(),
            app.sort_order.label()
        )),
        Line::from(format!("Timeout: {}s", app.settings.timeout_secs)),
        Line::from(clock.to_string()),
    ])
    .block(Block::default().borders(Borders::ALL).title(" status "));
    f.render_widget(status, area);
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

fn try_autocomplete_input(app: &mut App) -> bool {
    let trimmed = app.input.trim();
    if trimmed.is_empty() {
        return false;
    }
    if !(looks_like_path(trimmed) || path_exists(trimmed)) {
        return false;
    }
    match autocomplete_path(trimmed) {
        Some(completed) => {
            if completed != trimmed {
                app.input = completed.clone();
                app.set_status(format!("Path autocompleted to {completed}"));
            }
            true
        }
        None => {
            app.set_status("No completion found for path input.");
            true
        }
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
