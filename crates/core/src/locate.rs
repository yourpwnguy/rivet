//! Locate a known string inside raw workflow text.
//!
//! Findings must point at real `file:line` positions, but serde_yaml
//! discards source positions. After parsing, we re-locate the exact string
//! a rule matched (a `uses:` value, the head of a `run:` script) by
//! scanning the raw file. First match wins; workflow files are small, so a
//! linear scan per needle is cheaper than building an index.

/// 1-based line number of the first line containing `needle`.
///
/// Returns `None` for an empty needle (every line "contains" it, which
/// would be a meaningless anchor).
pub fn find_line(raw: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    raw.lines().position(|l| l.contains(needle)).map(|i| i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_first_matching_line() {
        assert_eq!(find_line("a\nb\nc\n", "b"), Some(2));
        assert_eq!(find_line("a\n  b: 1\n", "b: 1"), Some(2));
        assert_eq!(find_line("a\nb\n", "z"), None);
        assert_eq!(find_line("a\nb\n", ""), None);
    }
}
