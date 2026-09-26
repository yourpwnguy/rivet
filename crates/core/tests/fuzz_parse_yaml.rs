//! Fuzz the YAML parser: arbitrary input must never panic.
//!
//! Two proptest strategies:
//! * arbitrary strings (capped), and
//! * "YAML soup" — token sequences drawn from the lexical alphabet of
//!   workflows and their attackers (`${{`, tabs, aliases, quotes).
//!
//! The invariant under test is simply that `parse_workflow` returns
//! `Result` — malformed input is a parse error, never a panic or crash.

use proptest::prelude::*;
use rivet_core::parse::parse_workflow;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn arbitrary_strings_never_panic(s in "(?s).{0,2048}") {
        let _ = parse_workflow(&s);
    }

    #[test]
    fn yaml_soup_never_panic(tokens in prop::collection::vec(yaml_token(), 0..300)) {
        let _ = parse_workflow(&tokens.join(" "));
    }

    #[test]
    fn alias_bombs_never_hang_or_panic(
        depth in 1..64usize,
        body in "(?s).{0,64}",
    ) {
        // A billion-laughs style document: nested aliases expanding linearly.
        // libyaml handles aliases without recursion blowup; rivet caps the
        // damage by refusing anything but a clean parse/error.
        let mut doc = String::from("a: &a\n");
        for _ in 0..depth {
            doc.push_str("  - *a\n");
        }
        doc.push_str(&body);
        let _ = parse_workflow(&doc);
    }
}

/// Tokens from the lexical alphabet of workflows and their attackers.
fn yaml_token() -> impl Strategy<Value = &'static str> {
    prop::sample::select(&[
        "${{",
        "}}",
        "secrets.",
        "github.event.issue.title",
        "github.actor",
        "on",
        "true",
        "jobs",
        "run",
        "uses",
        "permissions",
        "write-all",
        "self-hosted",
        "pull_request_target",
        "actions/checkout@v3",
        "ACTIONS_STEP_DEBUG",
        "#",
        "\t",
        ":",
        "-",
        "null",
        "~",
        "[]",
        "{}",
        "\n",
        " ",
        "\"",
        "'",
        "\\",
        "yes",
        "no",
        "0x1f",
        "*anchor",
        "&anchor",
        "!tag",
        ">",
        "|",
        "%",
        "@",
    ])
}
