//! Classification of `uses:` references (R03, R08).
//!
//! A reference is either immutable (a full commit SHA — the only safe
//! pattern) or mutable (a tag or branch HEAD that can be force-pushed by
//! whoever controls the upstream repo).

/// How an action or reusable workflow is referenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    /// `@<40-char hex SHA>` — immutable.
    Sha,
    /// `@v1`, `@v2.1` — a mutable tag that can be force-pushed.
    MutableTag,
    /// `@master`, `@main`, `@dev`, `@latest`, `@HEAD` — a branch HEAD.
    BranchHead,
    /// `./.github/...` — first-party, trusted.
    Local,
    /// Anything else (short SHA, missing ref) — treated as mutable.
    Unknown,
}

/// Classify a `uses:` value.
pub fn classify(uses: &str) -> RefKind {
    if uses.starts_with("./") {
        return RefKind::Local;
    }
    let Some((_, r#ref)) = uses.split_once('@') else {
        // No ref at all — the action resolves to its default branch.
        return RefKind::BranchHead;
    };
    if r#ref.len() == 40 && r#ref.bytes().all(|b| b.is_ascii_hexdigit()) {
        return RefKind::Sha;
    }
    if matches!(r#ref, "master" | "main" | "dev" | "latest" | "HEAD") {
        return RefKind::BranchHead;
    }
    RefKind::MutableTag
}

/// True if the `uses:` value targets a reusable workflow
/// (`org/repo/.github/workflows/x.yml@ref`) rather than an action.
pub fn is_reusable(uses: &str) -> bool {
    let target = uses.split('@').next().unwrap_or(uses);
    target.contains(".github/workflows/") && (target.ends_with(".yml") || target.ends_with(".yaml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_refs() {
        const SHA: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert_eq!(classify(&format!("actions/checkout@{SHA}")), RefKind::Sha);
        assert_eq!(classify("actions/checkout@v3"), RefKind::MutableTag);
        assert_eq!(classify("actions/checkout@v2.1"), RefKind::MutableTag);
        assert_eq!(classify("actions/checkout@master"), RefKind::BranchHead);
        assert_eq!(classify("actions/checkout@latest"), RefKind::BranchHead);
        assert_eq!(classify("actions/checkout"), RefKind::BranchHead);
        assert_eq!(classify("./.github/actions/x"), RefKind::Local);
    }

    #[test]
    fn detects_reusable_workflows() {
        assert!(is_reusable("org/repo/.github/workflows/x.yml@main"));
        assert!(is_reusable("org/repo/.github/workflows/x.yaml@v1"));
        assert!(!is_reusable("actions/checkout@v4"));
    }
}
