use super::*;
use crossterm::{
    cursor::Show,
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Text},
    widgets::{Block as Border, List, ListState, Paragraph, Wrap},
};
use std::io::IsTerminal;

/// Edit a private draft in the terminal. Ctrl-S in the browser commits it.
pub fn tui(p: &Paths) -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "the SSH config editor needs an interactive terminal"
    );
    let mut app = App::new(vault::load(p)?.config);
    enable_raw_mode()?;
    let _restore = RestoreTerminal;
    execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    loop {
        terminal.draw(|f| app.draw(f))?;
        match event::read()? {
            Event::Key(key) if key.kind != KeyEventKind::Release => match app.key(p, key) {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(e) => app.notice = format!("{e:#}"),
            },
            Event::Paste(text) => match &mut app.screen {
                Screen::Form(form) => form.fields[form.focus].paste(&text, false),
                Screen::Raw { buffer, .. } => buffer.paste(&text, true),
                _ => {}
            },
            _ => {}
        }
    }
}

struct RestoreTerminal;

impl Drop for RestoreTerminal {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            Show
        );
    }
}

struct App {
    original: String,
    draft: String,
    cursor: usize,
    selected: BTreeSet<usize>,
    notice: String,
    screen: Screen,
}

enum Screen {
    Browse,
    Form(Box<Form>),
    Raw {
        target: Option<usize>,
        buffer: Buffer,
    },
    Preview {
        selection: Selection,
        top: usize,
        left: u16,
        confirm: Option<bool>,
    },
    Quit,
}

impl App {
    fn new(original: String) -> Self {
        Self {
            draft: original.clone(),
            original,
            cursor: 0,
            selected: BTreeSet::new(),
            notice: String::new(),
            screen: Screen::Browse,
        }
    }

    fn dirty(&self) -> bool {
        self.original != self.draft
    }

    fn stage(&mut self, draft: String, cursor: usize) {
        if draft == self.draft {
            self.notice = "No changes.".into();
        } else {
            self.notice = if self.selected.is_empty() {
                "Staged; Ctrl-S in the browser saves to the encrypted vault.".into()
            } else {
                "Staged; export selection cleared after edit. Ctrl-S saves to the encrypted vault."
                    .into()
            };
            self.draft = draft;
            self.selected.clear();
        }
        self.cursor = cursor.min(blocks(&self.draft).len().saturating_sub(1));
        self.screen = Screen::Browse;
    }

    fn save(&mut self, p: &Paths) -> Result<()> {
        if self.dirty() {
            vault::edit_config(p, |current| {
                replace_if_current(current, &self.original, &self.draft)
            })?;
            self.original.clone_from(&self.draft);
            self.notice = "Saved to the encrypted vault.".into();
        } else {
            self.notice = "No changes to save.".into();
        }
        Ok(())
    }

    fn key(&mut self, p: &Paths, key: KeyEvent) -> Result<bool> {
        let apply = is_ctrl(key, 's') || key.code == KeyCode::F(2);
        match &mut self.screen {
            Screen::Browse => return self.browse(p, key, apply),
            Screen::Raw { target, buffer } => {
                if key.code == KeyCode::Esc {
                    self.screen = Screen::Browse;
                    self.notice.clear();
                } else if apply {
                    let draft = match *target {
                        Some(index) => {
                            let mut doc = self.draft.clone();
                            replace_block(&mut doc, index, buffer.text.clone())?;
                            doc
                        }
                        None => buffer.text.clone(),
                    };
                    self.stage(draft, self.cursor);
                } else {
                    buffer.key(key, true);
                }
            }
            Screen::Form(form) => {
                if key.code == KeyCode::Esc {
                    self.screen = Screen::Browse;
                    self.notice.clear();
                } else if apply {
                    let mut draft = self.draft.clone();
                    let fallback = line_ending(&draft);
                    ensure!(
                        form.target.is_some() || !form.fields[0].text.trim().is_empty(),
                        "enter at least one Host pattern"
                    );
                    let edited = apply_form(
                        &form.source,
                        form.fields.each_ref().map(|f| f.text.as_str()),
                        fallback,
                    )?;
                    let index = match form.target {
                        Some(i) => {
                            replace_block(&mut draft, i, edited)?;
                            i
                        }
                        None => {
                            let i = blocks(&draft).len();
                            append_block(&mut draft, &edited, fallback);
                            i
                        }
                    };
                    self.stage(draft, index);
                } else {
                    match key.code {
                        KeyCode::Tab | KeyCode::Down => {
                            form.focus = (form.focus + 1) % FIELDS.len()
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            form.focus = (form.focus + FIELDS.len() - 1) % FIELDS.len()
                        }
                        _ => form.fields[form.focus].key(key, false),
                    }
                }
            }
            Screen::Preview {
                selection,
                top,
                left,
                confirm,
            } => match (key.code, *confirm) {
                (KeyCode::Esc | KeyCode::Char('n'), Some(_)) => *confirm = None,
                (KeyCode::Esc, None) => {
                    self.screen = Screen::Browse;
                    self.notice.clear();
                }
                (KeyCode::Char('y'), Some(include)) if key.modifiers.is_empty() => {
                    self.notice = selection.install(include)?;
                    self.screen = Screen::Browse;
                }
                (KeyCode::Char('i'), None) => *confirm = Some(false),
                (KeyCode::Char('I'), None) => *confirm = Some(true),
                (KeyCode::Down, _) => *top = top.saturating_add(1),
                (KeyCode::Up, _) => *top = top.saturating_sub(1),
                (KeyCode::PageDown, _) => *top = top.saturating_add(10),
                (KeyCode::PageUp, _) => *top = top.saturating_sub(10),
                (KeyCode::Left, _) => *left = left.saturating_sub(4),
                (KeyCode::Right, _) => *left = left.saturating_add(4),
                (KeyCode::Home, _) => {
                    *top = 0;
                    *left = 0;
                }
                _ => {}
            },
            Screen::Quit => match key.code {
                KeyCode::Char('y') => return Ok(true),
                KeyCode::Esc | KeyCode::Char('n') => self.screen = Screen::Browse,
                _ => {}
            },
        }
        Ok(false)
    }

    fn browse(&mut self, p: &Paths, key: KeyEvent, apply: bool) -> Result<bool> {
        if apply {
            self.save(p)?;
            return Ok(false);
        }
        if is_ctrl(key, 'c') || key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
            if !self.dirty() {
                return Ok(true);
            }
            self.screen = Screen::Quit;
            return Ok(false);
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return Ok(false);
        }
        let list = blocks(&self.draft);
        let last = list.len().saturating_sub(1);
        let entry = list.get(self.cursor);
        let shifting = key.modifiers.contains(KeyModifiers::SHIFT);
        match key.code {
            KeyCode::Up if !shifting => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down if !shifting => self.cursor = (self.cursor + 1).min(last),
            KeyCode::PageUp => self.cursor = self.cursor.saturating_sub(10),
            KeyCode::PageDown => self.cursor = (self.cursor + 10).min(last),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = last,
            KeyCode::Char('K') | KeyCode::Up => {
                self.move_to(self.cursor.saturating_sub(1));
            }
            KeyCode::Char('J') | KeyCode::Down => {
                self.move_to((self.cursor + 1).min(last));
            }
            KeyCode::Char(' ') if entry.is_some() => {
                let number = self.cursor + 1;
                if !self.selected.remove(&number) {
                    self.selected.insert(number);
                }
                self.notice.clear();
            }
            KeyCode::Char('d') if entry.is_some() => {
                let mut draft = self.draft.clone();
                draft.replace_range(entry.unwrap().range.clone(), "");
                self.stage(draft, self.cursor);
            }
            KeyCode::Char('n') => {
                let source = format!("Host{}", line_ending(&self.draft));
                self.screen = Screen::Form(Box::new(Form::new(None, &source)));
                self.notice.clear();
            }
            KeyCode::Char('e') | KeyCode::Enter if entry.is_some_and(|b| b.kind == Kind::Host) => {
                self.screen = Screen::Form(Box::new(Form::new(
                    Some(self.cursor),
                    entry.unwrap().text(&self.draft),
                )));
                self.notice.clear();
            }
            KeyCode::Char('e' | 'r') | KeyCode::Enter if entry.is_some() => {
                self.screen = Screen::Raw {
                    target: Some(self.cursor),
                    buffer: Buffer::new(entry.unwrap().text(&self.draft)),
                };
                self.notice.clear();
            }
            KeyCode::Char('R') => {
                self.screen = Screen::Raw {
                    target: None,
                    buffer: Buffer::new(&self.draft),
                };
                self.notice.clear();
            }
            KeyCode::Char('p') => {
                ensure!(
                    !self.dirty(),
                    "save staged edits with Ctrl-S before previewing a persistent export"
                );
                self.screen = Screen::Preview {
                    selection: Selection::new(&self.draft, &self.selected)?,
                    top: 0,
                    left: 0,
                    confirm: None,
                };
                self.notice.clear();
            }
            KeyCode::Char('l') if !self.dirty() => {
                *self = Self::new(vault::load(p)?.config);
                self.notice = "Reloaded the encrypted vault.".into();
            }
            _ => {}
        }
        Ok(false)
    }

    fn move_to(&mut self, next: usize) {
        if let Some(draft) = move_block(&self.draft, self.cursor, next) {
            self.stage(draft, next);
            self.notice =
                "Reordered; review OpenSSH precedence. Selection cleared; Ctrl-S saves.".into();
        } else {
            self.notice = "Cannot move past the preamble or boundary.".into();
        }
    }

    fn draw(&mut self, f: &mut Frame) {
        let [head, main, help, notice] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .areas(f.area());
        let title = if self.dirty() {
            "sshp · SSH config  [unsaved]"
        } else {
            "sshp · SSH config"
        };
        f.render_widget(
            Paragraph::new(title).style(Style::new().add_modifier(Modifier::BOLD)),
            head,
        );
        let hints = match &mut self.screen {
            Screen::Browse => {
                draw_browser(f, main, &self.draft, self.cursor, &self.selected);
                "↑↓ Navigate · e Form · r Block raw · R Full raw · n New · d Delete\nJ/K Move · Space Select · p Export preview · Ctrl-S Save · l Reload · q Quit"
            }
            Screen::Quit => {
                f.render_widget(
                    Paragraph::new("Discard all unsaved changes and quit? [y/N]"),
                    main,
                );
                "y Discard · n / Esc Return to editing"
            }
            Screen::Form(form) => {
                form.draw(f, main);
                "Tab / ↑↓ Change field · Ctrl-S / F2 Stage · Esc Cancel\nEdits the first occurrence only; use raw for quoting and other options."
            }
            Screen::Raw { target, buffer } => {
                buffer.draw(
                    f,
                    main,
                    if target.is_none() {
                        "Full config"
                    } else {
                        "Raw block"
                    },
                );
                "Ctrl-S / F2 Stage · Esc Cancel · arrows, Home/End, Page Up/Down"
            }
            Screen::Preview {
                selection,
                top,
                left,
                confirm,
            } => {
                draw_preview(f, main, selection, top, *left);
                match confirm {
                    Some(true) => {
                        "Write persistent plaintext AND add the Include to ~/.ssh/config? [y/N]"
                    }
                    Some(false) => "Write persistent plaintext at the previewed location? [y/N]",
                    None => {
                        "↑↓ / ←→ Scroll · i Install plaintext · I Install and add Include · Esc Back"
                    }
                }
            }
        };
        f.render_widget(Paragraph::new(hints).wrap(Wrap { trim: false }), help);
        f.render_widget(
            Paragraph::new(visible(&self.notice))
                .style(Style::new().fg(Color::Yellow))
                .wrap(Wrap { trim: true }),
            notice,
        );
    }
}

fn replace_if_current(current: &mut String, old: &str, draft: &str) -> Result<()> {
    ensure!(
        current == old,
        "vault config changed while the editor was open; your draft has not been saved"
    );
    *current = draft.to_owned();
    Ok(())
}

fn is_ctrl(key: KeyEvent, c: char) -> bool {
    key.code == KeyCode::Char(c) && key.modifiers.contains(KeyModifiers::CONTROL)
}

fn draw_browser(f: &mut Frame, rect: Rect, draft: &str, cursor: usize, selected: &BTreeSet<usize>) {
    let constraints = [Constraint::Percentage(40), Constraint::Percentage(60)];
    let [list, detail] = if rect.width > 64 {
        Layout::horizontal(constraints).areas(rect)
    } else {
        Layout::vertical(constraints).areas(rect)
    };
    let blocks = blocks(draft);
    let entries = blocks.iter().enumerate().map(|(i, b)| {
        let n = i + 1;
        let check = if selected.contains(&n) { 'x' } else { ' ' };
        format!("[{check}] {n:>3} {}", visible(&b.label(draft)))
    });
    let mut state = ListState::default().with_selected(blocks.get(cursor).map(|_| cursor));
    f.render_stateful_widget(
        List::new(entries)
            .block(Border::bordered().title(format!("Source blocks · {} selected", selected.len())))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
        list,
        &mut state,
    );
    let text = if let Some(block) = blocks.get(cursor) {
        Text::from(
            block
                .text(draft)
                .lines()
                .take(detail.height as usize)
                .map(|line| Line::raw(visible(line)))
                .collect::<Vec<_>>(),
        )
    } else {
        Text::raw("No blocks. Press n to add a Host, or R to edit the full config.")
    };
    f.render_widget(
        Paragraph::new(text)
            .block(Border::bordered().title("Source"))
            .wrap(Wrap { trim: false }),
        detail,
    );
}

fn draw_preview(f: &mut Frame, area: Rect, selection: &Selection, top: &mut usize, left: u16) {
    let border = Border::bordered().title("Selected export · explicit blocks in source order");
    let inner = border.inner(area);
    f.render_widget(border, area);
    if inner.is_empty() {
        return;
    }
    let mut lines = vec![Line::raw("Persistent plaintext. Proposed directive:")];
    lines.push(Line::raw(visible(selection.include_line.trim_end())));
    for warning in &selection.warnings {
        let mut line = String::new();
        for word in warning.split_ascii_whitespace() {
            if !line.is_empty() && line.len() + word.len() + 1 > usize::from(inner.width) {
                lines.push(Line::styled(
                    std::mem::take(&mut line),
                    Style::new().fg(Color::Yellow),
                ));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        lines.push(Line::styled(line, Style::new().fg(Color::Yellow)));
    }
    lines.push(Line::raw(""));
    let count = lines.len() + selection.text.lines().count();
    *top = (*top).min(count.saturating_sub(inner.height as usize));
    let lines = lines
        .into_iter()
        .chain(selection.text.lines().map(|s| Line::raw(visible(s))))
        .skip(*top)
        .take(inner.height as usize)
        .collect::<Vec<_>>();
    f.render_widget(Paragraph::new(lines).scroll((0, left)), inner);
}

struct Form {
    target: Option<usize>,
    source: String,
    fields: [Buffer; FIELDS.len()],
    focus: usize,
}

impl Form {
    fn new(target: Option<usize>, source: &str) -> Self {
        Self {
            target,
            source: source.to_owned(),
            fields: form_values(source).map(|text| {
                let mut b = Buffer::new(&text);
                b.cursor = text.len();
                b
            }),
            focus: 0,
        }
    }

    fn draw(&mut self, f: &mut Frame, rect: Rect) {
        let [banner, main] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(rect);
        f.render_widget(
            Paragraph::new(if self.target.is_some() {
                "Edit Host"
            } else {
                "New Host"
            }),
            banner,
        );
        if main.height == 0 {
            return;
        }
        let count = (main.height as usize / 3).clamp(1, FIELDS.len());
        let start = self.focus.saturating_sub(count - 1);
        for i in start..(start + count).min(FIELDS.len()) {
            let input = Rect::new(
                main.x,
                main.y + ((i - start) * 3) as u16,
                main.width,
                main.height.min(3),
            );
            if i == self.focus {
                self.fields[i].draw(f, input, FIELDS[i]);
            } else {
                f.render_widget(
                    Paragraph::new(visible(&self.fields[i].text))
                        .block(Border::bordered().title(FIELDS[i])),
                    input,
                );
            }
        }
    }
}

struct Buffer {
    text: String,
    cursor: usize,
    top: usize,
    left: u16,
    column: Option<usize>,
    newline: &'static str,
}

impl Buffer {
    fn new(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            cursor: 0,
            top: 0,
            left: 0,
            column: None,
            newline: line_ending(text),
        }
    }

    fn insert(&mut self, s: &str) {
        self.text.insert_str(self.cursor, s);
        self.cursor += s.len();
        self.column = None;
        self.snap_newline();
    }

    fn paste(&mut self, s: &str, multiline: bool) {
        if multiline {
            let normalized = s.replace("\r\n", "\n").replace('\r', "\n");
            self.insert(&normalized.replace('\n', self.newline));
        } else if !s.contains(['\r', '\n']) {
            self.insert(s);
        }
    }

    fn line(&self, at: usize) -> (usize, usize) {
        let start = self.text[..at].rfind('\n').map_or(0, |i| i + 1);
        let lf = self.text[at..].find('\n').map(|i| at + i);
        let end = lf.map_or(self.text.len(), |i| {
            if i > start && self.text.as_bytes()[i - 1] == b'\r' {
                i - 1
            } else {
                i
            }
        });
        (start, end)
    }

    fn previous(&self) -> usize {
        let s = &self.text[..self.cursor];
        if s.ends_with("\r\n") {
            s.len() - 2
        } else {
            s.char_indices().next_back().map_or(0, |(i, _)| i)
        }
    }

    fn next(&self) -> usize {
        let s = &self.text[self.cursor..];
        self.cursor
            + if s.starts_with("\r\n") {
                2
            } else {
                s.chars().next().map_or(0, char::len_utf8)
            }
    }

    fn vertical(&mut self, down: bool) {
        let (start, end) = self.line(self.cursor);
        let col = *self
            .column
            .get_or_insert_with(|| self.text[start..self.cursor].chars().count());
        let other = if down {
            let Some(lf) = self.text[end..].find('\n') else {
                return;
            };
            end + lf + 1
        } else {
            if start == 0 {
                return;
            }
            start - 1
        };
        let (start, end) = self.line(other);
        self.cursor = self.text[start..end]
            .char_indices()
            .nth(col)
            .map_or(end, |(i, _)| start + i);
    }

    fn key(&mut self, key: KeyEvent, multiline: bool) {
        if multiline {
            match key.code {
                KeyCode::Up => return self.vertical(false),
                KeyCode::Down => return self.vertical(true),
                KeyCode::PageUp | KeyCode::PageDown => {
                    for _ in 0..10 {
                        self.vertical(key.code == KeyCode::PageDown);
                    }
                    return;
                }
                _ => {}
            }
        }
        self.column = None;
        match key.code {
            KeyCode::Left => self.cursor = self.previous(),
            KeyCode::Right => self.cursor = self.next(),
            KeyCode::Home => {
                self.cursor = if key.modifiers.contains(KeyModifiers::CONTROL) {
                    0
                } else {
                    self.line(self.cursor).0
                }
            }
            KeyCode::End => {
                self.cursor = if key.modifiers.contains(KeyModifiers::CONTROL) {
                    self.text.len()
                } else {
                    self.line(self.cursor).1
                }
            }
            KeyCode::Enter if multiline => self.insert(self.newline),
            KeyCode::Tab if multiline => self.insert("\t"),
            KeyCode::Backspace => {
                let prev = self.previous();
                self.text.replace_range(prev..self.cursor, "");
                self.cursor = prev;
                self.snap_newline();
            }
            KeyCode::Delete => {
                self.text.replace_range(self.cursor..self.next(), "");
                self.snap_newline();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && !c.is_control() =>
            {
                self.insert(c.encode_utf8(&mut [0; 4]));
            }
            _ => {}
        }
    }

    fn snap_newline(&mut self) {
        // Deleting a character can join a formerly separate CR and LF.
        if self.cursor > 0
            && self.text.as_bytes().get(self.cursor - 1..=self.cursor) == Some(b"\r\n")
        {
            self.cursor -= 1;
        }
    }

    fn draw(&mut self, f: &mut Frame, area: Rect, title: &str) {
        let border = Border::bordered().title(title);
        let inner = border.inner(area);
        f.render_widget(border, area);
        if inner.is_empty() {
            return;
        }
        let before = &self.text[..self.cursor];
        let row = before.bytes().filter(|&b| b == b'\n').count();
        let col = Line::raw(visible(before.rsplit('\n').next().unwrap_or("")))
            .width()
            .min(u16::MAX as usize) as u16;
        self.top = self
            .top
            .min(row)
            .max((row + 1).saturating_sub(inner.height as usize));
        self.left = self.left.min(col).max(col.saturating_sub(inner.width - 1));
        let mut source = self.text.split('\n').skip(self.top).peekable();
        let lines = (0..inner.height)
            .map_while(|_| {
                let line = source.next()?;
                let line = if source.peek().is_some() {
                    line.strip_suffix('\r').unwrap_or(line)
                } else {
                    line
                };
                Some(Line::raw(visible(line)))
            })
            .collect::<Vec<_>>();
        f.render_widget(Paragraph::new(lines).scroll((0, self.left)), inner);
        f.set_cursor_position((
            inner.x + (col - self.left),
            inner.y + (row - self.top) as u16,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn paths() -> Paths {
        Paths {
            repo: "unused".into(),
            runtime: "unused".into(),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn refuses_to_replace_config_when_the_vault_changed() {
        let mut current = "Host newer".to_owned();
        assert!(replace_if_current(&mut current, "Host original", "Host draft").is_err());
        assert_eq!(current, "Host newer");
        replace_if_current(&mut current, "Host newer", "Host draft").unwrap();
        assert_eq!(current, "Host draft");
    }

    #[test]
    fn raw_buffer_moves_and_edits_utf8_and_crlf_without_transcoding() {
        let input = "東京\nab\r\n終";
        let mut b = Buffer::new(input);
        b.key(key(KeyCode::End), true);
        b.key(key(KeyCode::Down), true);
        assert_eq!(b.cursor, "東京\nab".len());
        b.key(key(KeyCode::Right), true);
        assert_eq!(&b.text[b.cursor..], "終");
        b.key(key(KeyCode::Backspace), true);
        assert_eq!(b.text, "東京\nab終");
        b.key(key(KeyCode::Char('é')), true);
        assert_eq!(b.text, "東京\nabé終");
        b.key(key(KeyCode::Enter), true);
        assert_eq!(b.text, "東京\nabé\n終");
        let mut b = Buffer::new("a\rX\nb");
        b.cursor = 2;
        b.key(key(KeyCode::Delete), true);
        assert_eq!(b.text, "a\r\nb");
        assert_eq!(b.cursor, 1);
    }

    #[test]
    fn editor_applies_to_draft_and_noop_does_not_clear_export_selection() {
        let p = paths();
        let original = "Host a\r\n\tUser old";
        let mut app = App::new(original.into());
        app.key(&p, key(KeyCode::Char(' '))).unwrap();
        app.key(&p, key(KeyCode::Char('e'))).unwrap();
        app.key(&p, key(KeyCode::F(2))).unwrap();
        assert_eq!(app.draft, original);
        assert!(!app.selected.is_empty());
        app.key(&p, key(KeyCode::Char('e'))).unwrap();
        for code in [
            KeyCode::Tab,
            KeyCode::Tab,
            KeyCode::Char('a'),
            KeyCode::F(2),
        ] {
            app.key(&p, key(code)).unwrap();
        }
        assert_eq!(app.original, original);
        assert_eq!(app.draft, "Host a\r\n\tUser olda");
        assert!(app.selected.is_empty() && app.dirty());
    }

    #[test]
    fn ratatui_renders_browser_and_editing_on_small_terminals() {
        let p = paths();
        let mut app = App::new("Host test\r\n\tUser a\r\nHost *\r\n".into());
        for (width, height) in [(100, 28), (42, 12), (1, 1)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            app.key(&p, key(KeyCode::Char('e'))).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            app.key(&p, key(KeyCode::Esc)).unwrap();
        }
    }
}
