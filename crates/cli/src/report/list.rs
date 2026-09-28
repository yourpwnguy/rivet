//! Rule catalog listing for `--list-rules`.
//!
//! Prints every rule with its number, base severity, and description in a
//! scannable layout. Rules sit back to back with no blank line between them
//! so all ten fit in a viewport; the R-number/severity/rule-id line is the
//! visual separator. Severity is colored to match the text report. Long
//! descriptions wrap onto indented continuation lines so the output stays
//! readable at any terminal width.

use rivet_core::rules::rule_catalog;
use rivet_core::severity::Severity;

/// Print the rule catalog to stdout.
///
/// `color` follows the same TTY/NO_COLOR/TERM rules as the text report so
/// piped output stays machine-clean.
pub fn print(color: bool) {
    let catalog = rule_catalog();
    println!("rivet rules ({})\n", catalog.len());
    for (idx, (id, severity, description)) in catalog.iter().enumerate() {
        let number = format!("R{:02}", idx + 1);
        let severity_label = severity.to_string().to_uppercase();
        let severity_cell = if color {
            format!(
                "{}{:<8}{}",
                severity_color(*severity),
                severity_label,
                "\x1b[0m"
            )
        } else {
            format!("{:<8}", severity_label)
        };
        println!("{}  {}  {}", number, severity_cell, id.as_str());
        println!("{}", wrap_text(description, 72, 15));
    }
}

/// ANSI color per severity, matching the text report.
fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "\x1b[1;31m", // bold red
        Severity::High => "\x1b[31m",       // red
        Severity::Medium => "\x1b[33m",     // yellow
        Severity::Low => "\x1b[34m",        // blue
        Severity::Info => "\x1b[2m",        // dim
    }
}

/// Word-wrap `text` to `width` columns, indenting every line by `indent`
/// spaces. Words longer than the wrap width overflow rather than break.
fn wrap_text(text: &str, width: usize, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::new();
    let mut line_len = 0;
    let mut first = true;
    for word in text.split_whitespace() {
        if first {
            out.push_str(&pad);
            out.push_str(word);
            line_len = indent + word.len();
            first = false;
        } else if line_len + 1 + word.len() > width {
            out.push('\n');
            out.push_str(&pad);
            out.push_str(word);
            line_len = indent + word.len();
        } else {
            out.push(' ');
            out.push_str(word);
            line_len += 1 + word.len();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_long_descriptions_with_indent() {
        let wrapped = wrap_text(
            "pull_request_target workflow checking out PR head code; downgrades to INFO when metadata-only",
            72,
            15,
        );
        let lines: Vec<&str> = wrapped.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("               "));
        assert!(lines[1].starts_with("               "));
        assert!(lines[0].len() <= 72);
    }

    #[test]
    fn short_descriptions_stay_on_one_line() {
        let wrapped = wrap_text("reusable workflow called with a mutable ref", 72, 15);
        assert_eq!(wrapped.lines().count(), 1);
    }
}
