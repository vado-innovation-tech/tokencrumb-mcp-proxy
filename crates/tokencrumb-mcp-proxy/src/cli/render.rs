//! Plain-text rendering of the former `rich` output: box-drawn panels, two-column
//! grids and (on a terminal only) a little colour.
//!
//! `inspect` and `audit-verify` use a stable plain-text panel, whose
//! layout follows the one `rich` produced — title centred in the top border, one space
//! of padding, rows aligned in columns — without its wrapping or truncation: a long
//! public key or Datalog line stays whole.

use std::io::IsTerminal as _;

/// Display width of a line (one column per character; the output is ASCII apart from
/// a few `·`/`—` separators, which are single-width).
fn width(text: &str) -> usize {
    text.chars().count()
}

/// A panel around `lines`, `title` centred in the top border.
pub fn panel(title: &str, lines: &[String]) -> String {
    let content = lines.iter().map(|l| width(l)).max().unwrap_or(0);
    let label = format!(" {title} ");
    // Inner width: the content plus one space each side, never narrower than the
    // title with at least one rule character on each side of it.
    let inner = (content + 2).max(width(&label) + 2);
    let rule = inner - width(&label);
    let left = rule / 2;
    let mut out = String::new();
    out.push('╭');
    out.push_str(&"─".repeat(left));
    out.push_str(&label);
    out.push_str(&"─".repeat(rule - left));
    out.push_str("╮\n");
    for line in lines {
        out.push_str("│ ");
        out.push_str(line);
        out.push_str(&" ".repeat(inner - 2 - width(line)));
        out.push_str(" │\n");
    }
    out.push('╰');
    out.push_str(&"─".repeat(inner));
    out.push_str("╯\n");
    out
}

/// Two columns separated by two spaces, the first padded to its widest cell.
pub fn grid(rows: &[(&str, String)]) -> Vec<String> {
    let first = rows.iter().map(|(k, _)| width(k)).max().unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("{k}{}  {v}", " ".repeat(first - width(k))))
        .collect()
}

/// Which stream a styled fragment is written to.
#[derive(Clone, Copy)]
pub enum Stream {
    Stdout,
    Stderr,
}

fn colour_enabled(stream: Stream) -> bool {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    }
}

/// `text` in an SGR style (`"1;31"` bold red, `"32"` green…) when `stream` is a
/// terminal; the bare text otherwise, so piped output never carries escape codes.
pub fn paint(text: &str, sgr: &str, stream: Stream) -> String {
    if colour_enabled(stream) {
        format!("\x1b[{sgr}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_matches_rich_layout() {
        let lines = vec![
            "budget_cap(5);".to_owned(),
            "check if resource($r), $r.starts_with(\"/a/\");".to_owned(),
        ];
        let expected = "\
╭──────────── block 1 · attenuation ────────────╮
│ budget_cap(5);                                │
│ check if resource($r), $r.starts_with(\"/a/\"); │
╰───────────────────────────────────────────────╯
";
        assert_eq!(panel("block 1 · attenuation", &lines), expected);
    }

    #[test]
    fn a_title_wider_than_the_content_widens_the_panel() {
        let out = panel("audit-verify", &["x".to_owned()]);
        let top = out.lines().next().unwrap();
        assert!(top.starts_with("╭─ audit-verify ─╮"), "{top}");
    }

    #[test]
    fn grid_aligns_columns() {
        let rows = grid(&[("log", "a".into()), ("entries", "3".into())]);
        assert_eq!(rows, ["log      a", "entries  3"]);
    }
}
