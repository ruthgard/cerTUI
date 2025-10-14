
use std::io;
use std::time::{Duration, Instant};
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*, widgets::*};
use chrono::Utc;
use omarchy_cert_core::{inspect_remote, days_until_expiry, CertInfo};

enum Event<I> {
    Input(I),
    Tick,
}

#[derive(Default)]
struct App {
    input: String,
    status: String,
    last_fetch: Option<Instant>,
    current_host: Option<String>,
    certs: Vec<CertInfo>,
}

impl App {
    fn set_status<S: Into<String>>(&mut self, s: S) { self.status = s.into(); }
}

#[tokio::main]
async fn main() -> Result<()> {
    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal).await;

    // restore terminal
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
    let mut app = App::default();
    app.set_status("Type host:port and press Enter. (q to quit)");
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, &app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let CEvent::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Enter => {
                        let target = app.input.trim().to_string();
                        if target.is_empty() { continue; }
                        app.set_status(format!("Fetching {} ...", target));
                        // Parse target
                        let (host, port) = match target.rsplit_once(':') {
                            Some((h, p)) => {
                                match p.parse::<u16>() { Ok(pp)=> (h.to_string(), pp), Err(_)=> { app.set_status("Invalid port"); continue; } }
                            }
                            None => { app.set_status("Target must be host:port"); continue; }
                        };
                        let sni = None::<String>; // could be extended to prompt
                        // Fetch in blocking task
                        let result = tokio::task::spawn_blocking(move || {
                            inspect_remote(&host, port, sni.as_deref())
                        }).await?;
                        match result {
                            Ok(report) => {
                                app.current_host = Some(format!("{}:{}", report.host, report.port));
                                app.certs = report.certs;
                                app.last_fetch = Some(Instant::now());
                                let leaf = app.certs.first()
                                    .and_then(|c| days_until_expiry(c))
                                    .map(|d| format!("{d} days"))
                                    .unwrap_or_else(|| "n/a".to_string());
                                app.set_status(format!("Fetched. Leaf expires in {}", leaf));
                            }
                            Err(e) => {
                                app.set_status(format!("Error: {}", e));
                            }
                        }
                    }
                    KeyCode::Backspace => { app.input.pop(); }
                    KeyCode::Char(c) => { app.input.push(c); }
                    KeyCode::Tab => {} // future: focus switch
                    KeyCode::Esc => { app.input.clear(); }
                    KeyCode::Char('r') => {
                        if let Some(cur) = app.current_host.clone() {
                            app.input = cur;
                        }
                    }
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(3), Constraint::Min(5), Constraint::Length(1)].as_ref())
        .split(f.size());

    // Input
    let input = Paragraph::new(app.input.as_ref())
        .style(Style::default())
        .block(Block::default().borders(Borders::ALL).title(" host:port "));
    f.render_widget(input, chunks[0]);

    // Table of certs
    let header = Row::new(vec![
        "Index", "Subject", "Issuer", "Not After (UTC)", "Days Left"
    ]).style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app.certs.iter().enumerate().map(|(i, c)| {
        let not_after = c.not_after.map(|d| d.to_rfc3339()).unwrap_or_else(|| "-".into());
        let days = days_until_expiry(c).map(|d| d.to_string()).unwrap_or_else(|| "-".into());
        Row::new(vec![
            i.to_string(),
            c.subject.clone(),
            c.issuer.clone(),
            not_after,
            days,
        ])
    }).collect();

    let table = Table::new(rows)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(
            app.current_host.as_deref().unwrap_or("No results yet"),
        ))
        .widths(&[
            Constraint::Length(5),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
            Constraint::Length(25),
            Constraint::Length(10),
        ])
        .column_spacing(1);

    f.render_widget(table, chunks[1]);

    // Status
    let clock = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let status = Paragraph::new(format!("{}  |  {}", app.status, clock))
        .block(Block::default().borders(Borders::ALL).title(" status "));
    f.render_widget(status, chunks[2]);
}
