//! Extraction and classification of `${{ }}` expressions.
//!
//! rivet never *evaluates* expressions — it pattern-matches their syntax.
//! This is a deliberate scope boundary (see README "Limitations"): a
//! context reference hidden inside a ternary
//! (`${{ cond && github.event.x || 'safe' }}`) is not attributed to the
//! untrusted set.

/// A single `${{ ... }}` expression found in workflow text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expr<'a> {
    /// The expression body, e.g. `github.event.issue.title`.
    pub text: &'a str,
    /// 1-based line where the expression starts.
    pub line: usize,
}

/// Extract every `${{ ... }}` expression from `raw`, in file order.
///
/// Scanning ends each expression at the first `}}`, matching GitHub's own
/// lexer closely enough for audit purposes. An unterminated expression
/// stops the scan — there is nothing more to find.
pub fn extract(raw: &str) -> Vec<Expr<'_>> {
    fn newlines(s: &str) -> usize {
        s.bytes().filter(|&b| b == b'\n').count()
    }

    let mut out = Vec::new();
    let mut search_from = 0;
    let mut line = 1;
    while let Some(rel) = raw[search_from..].find("${{") {
        let start = search_from + rel;
        let expr_line = line + newlines(&raw[search_from..start]);
        let after_open = start + 3;
        let Some(rel_end) = raw[after_open..].find("}}") else {
            break;
        };
        let text = raw[after_open..after_open + rel_end].trim();
        if !text.is_empty() {
            out.push(Expr {
                text,
                line: expr_line,
            });
        }
        let consumed = after_open + rel_end + 2;
        line += newlines(&raw[search_from..consumed]);
        search_from = consumed;
    }
    out
}

/// Contexts whose values are fully attacker-controlled in at least one
/// common trigger. Prefix-matched so `github.event.commits.*.message` is
/// covered by the `github.event.commits` entry.
const UNTRUSTED_PREFIXES: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.head_commit.message",
    "github.event.commits",
    "github.event.pull_request.head.ref",
    "github.actor",
];

/// True if `text` references an attacker-controllable context (R01).
pub fn is_untrusted(text: &str) -> bool {
    let text = text.trim_start();
    UNTRUSTED_PREFIXES.iter().any(|p| text.starts_with(p))
}

/// True if `text` references `${{ secrets.* }}` (R05, R07).
pub fn references_secrets(text: &str) -> bool {
    text.contains("secrets.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_expressions_with_lines() {
        let raw = "run: |\n  echo ${{ github.event.issue.title }}\n  echo ok\n";
        let exprs = extract(raw);
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].text, "github.event.issue.title");
        assert_eq!(exprs[0].line, 2);
    }

    #[test]
    fn skips_empty_expressions() {
        assert!(extract("echo ${{ }}").is_empty());
        assert!(extract("echo ${{}}").is_empty());
    }

    #[test]
    fn detects_untrusted_contexts() {
        assert!(is_untrusted("github.event.issue.title"));
        assert!(is_untrusted("github.event.commits[0].message"));
        assert!(is_untrusted("github.event.pull_request.head.ref"));
        assert!(is_untrusted("github.actor"));
        // Trusted / event-owned contexts must not match.
        assert!(!is_untrusted("github.repository"));
        assert!(!is_untrusted("github.event.pull_request.number"));
    }

    /// Multiple expressions on one line and across lines: the scanner must
    /// advance past each one and keep the line counter correct, which is
    /// what lets R01 point at the right line in a multi-line `run:` block.
    #[test]
    fn tracks_lines_across_multiple_expressions() {
        let raw = "a ${{ one }} b ${{ two }}\nc ${{ three }}\n";
        let exprs = extract(raw);
        let got: Vec<(&str, usize)> = exprs.iter().map(|e| (e.text, e.line)).collect();
        assert_eq!(got, vec![("one", 1), ("two", 1), ("three", 2)]);
    }

    /// Expressions split across lines are still one expression; the line
    /// recorded is where the `${{` starts, not where the body ends.
    #[test]
    fn multiline_expression_anchors_at_opening_delimiter() {
        let raw = "run: |\n  echo ${{ format(\n    '{0}', x) }}\n";
        let exprs = extract(raw);
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].line, 2);
    }

    /// An unterminated `${{` must stop the scan rather than panic or loop.
    #[test]
    fn unterminated_expression_stops_scan() {
        let exprs = extract("echo ${{ github.event.issue.title");
        assert!(exprs.is_empty());
    }

    #[test]
    fn detects_secret_references() {
        assert!(references_secrets("secrets.API_KEY"));
        assert!(references_secrets("format('{0}', secrets.TOKEN)"));
        assert!(!references_secrets("github.event.issue.title"));
        // The `secrets` context itself, without a member access.
        assert!(!references_secrets("secrets"));
    }
}
