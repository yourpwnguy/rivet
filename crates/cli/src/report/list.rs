//! Rule catalog listing for `--list-rules`.
//!
//! Prints every rule with its number, base severity, and description in a
//! scannable layout. Rules sit back to back with no blank line between them
//! so all ten fit in a viewport; the R-number/severity/rule-id line is the
//! visual separator. Severity is colored to match the text report. Long
//! descriptions wrap onto indented continuation lines so the output stays
//! readable at any terminal width.

use std::io::Write;

use rivet_core::rules::rule_catalog;

use super::{RESET, severity_color};

/// Column descriptions wrap at, tuned to fit an 80-column terminal.
const WRAP_WIDTH: usize = 72;

/// Indent for a rule's description lines, aligning them under the rule id
/// that precedes them (`R01  CRITICAL  `).
const DESC_INDENT: usize = 15;

/// Write the rule catalog to `out`.
///
/// `color` follows the same TTY/NO_COLOR/TERM rules as the text report so
/// piped output stays machine-clean. Writing goes through an explicit
/// `Write` rather than `println!` so a closed pipe (`rivet -l | head`)
/// surfaces as an error for the caller to handle instead of a panic.
pub fn write<W: Write>(out: &mut W, color: bool) -> std::io::Result<()> {
    let catalog = rule_catalog();
    writeln!(out, "rivet rules ({})\n", catalog.len())?;
    for (idx, (id, severity, description)) in catalog.iter().enumerate() {
        let severity_label = severity.to_string().to_uppercase();
        let severity_cell = if color {
            format!(
                "{}{:<8}{}",
                severity_color(*severity),
                severity_label,
                RESET
            )
        } else {
            format!("{:<8}", severity_label)
        };
        writeln!(out, "R{:02}  {}  {}", idx + 1, severity_cell, id.as_str())?;
        writeln!(out, "{}", wrap_text(description, WRAP_WIDTH, DESC_INDENT))?;
    }
    Ok(())
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

    /// Indentation as a string, for readable prefix assertions.
    fn pad() -> String {
        " ".repeat(DESC_INDENT)
    }

    #[test]
    fn wraps_long_descriptions_with_indent() {
        let wrapped = wrap_text(
            "pull_request_target workflow checking out PR head code; downgrades to INFO when metadata-only",
            WRAP_WIDTH,
            DESC_INDENT,
        );
        let lines: Vec<&str> = wrapped.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| l.starts_with(&pad())));
        assert!(lines.iter().all(|l| l.len() <= WRAP_WIDTH));
    }

    #[test]
    fn short_descriptions_stay_on_one_line() {
        let wrapped = wrap_text(
            "reusable workflow called with a mutable ref",
            WRAP_WIDTH,
            DESC_INDENT,
        );
        assert_eq!(wrapped.lines().count(), 1);
    }

    /// Renders every rule with a number, and no color when disabled.
    #[test]
    fn writes_numbered_rules_without_ansi_when_uncolored() {
        let mut buf = Vec::new();
        write(&mut buf, false).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.starts_with("rivet rules (10)\n"));
        for (idx, rule) in rule_catalog().iter().enumerate() {
            assert!(
                out.contains(&format!("R{:02}", idx + 1)),
                "missing R number"
            );
            assert!(out.contains(rule.0.as_str()), "missing {}", rule.0);
        }
        assert!(!out.contains('\x1b'), "uncolored output must not emit ANSI");
    }

    /// The whole catalog must fit an 80-column terminal, otherwise the
    /// `rivet -l` listing becomes a scroll rather than an overview.
    #[test]
    fn every_line_fits_an_80_column_terminal() {
        let mut buf = Vec::new();
        write(&mut buf, false).unwrap();
        let out = String::from_utf8(buf).unwrap();
        for line in out.lines() {
            assert!(line.len() <= 80, "line exceeds 80 columns: {line:?}");
        }
    }
}
