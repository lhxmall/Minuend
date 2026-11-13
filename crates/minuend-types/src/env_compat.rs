//! B9 (#47): environment-variable rename compatibility.
//!
//! PR #44 renamed every `OPERP_*` operator variable to `MINUEND_*` with no
//! fallback, so an operator who upgraded with the old name configured was
//! silently ignored (e.g. a watcher with `OPERP_WATCH_MNEMONIC` quietly fell
//! back to print-only). These helpers read the new name first and fall back
//! to the legacy name with a deprecation warning on stderr.

/// Prefix of the pre-#44 operator variables.
pub const LEGACY_ENV_PREFIX: &str = "OPERP_";
/// Prefix of the current operator variables.
pub const ENV_PREFIX: &str = "MINUEND_";

/// The legacy (`OPERP_*`) spelling of a `MINUEND_*` variable name.
pub fn legacy_env_name(name: &str) -> Option<String> {
    name.strip_prefix(ENV_PREFIX)
        .map(|rest| format!("{LEGACY_ENV_PREFIX}{rest}"))
}

/// Pure resolution rule (no process env access, so it is unit-testable):
/// a non-empty new value wins; otherwise a non-empty legacy value is used.
/// Returns the chosen value plus an optional warning to print.
pub fn resolve_env_compat(
    name: &str,
    new_val: Option<String>,
    legacy_name: &str,
    legacy_val: Option<String>,
) -> (Option<String>, Option<String>) {
    let new_val = new_val.filter(|v| !v.is_empty());
    let legacy_val = legacy_val.filter(|v| !v.is_empty());
    match (new_val, legacy_val) {
        (Some(n), Some(_)) => (
            Some(n),
            Some(format!(
                "warning: both {name} and deprecated {legacy_name} are set; using {name} and ignoring {legacy_name}"
            )),
        ),
        (Some(n), None) => (Some(n), None),
        (None, Some(l)) => (
            Some(l),
            Some(format!(
                "warning: {legacy_name} is deprecated (renamed in #44); using its value, please rename it to {name}"
            )),
        ),
        (None, None) => (None, None),
    }
}

/// Read `name` (a `MINUEND_*` variable) from the environment, falling back
/// to its `OPERP_*` spelling with a deprecation warning on stderr (printed
/// once per variable per process). Empty values count as unset.
pub fn env_var_compat(name: &str) -> Option<String> {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let legacy = legacy_env_name(name)?;
    let (val, warn) = resolve_env_compat(
        name,
        std::env::var(name).ok(),
        &legacy,
        std::env::var(&legacy).ok(),
    );
    if let Some(w) = warn {
        let first = WARNED
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .map(|mut set| set.insert(name.to_string()))
            .unwrap_or(true);
        if first {
            eprintln!("{w}");
        }
    }
    val
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_name_maps_prefix() {
        assert_eq!(
            legacy_env_name("MINUEND_WATCH_MNEMONIC").as_deref(),
            Some("OPERP_WATCH_MNEMONIC")
        );
        assert_eq!(legacy_env_name("PATH"), None);
    }

    #[test]
    fn new_name_wins_and_legacy_falls_back_with_warning() {
        let s = |v: &str| Some(v.to_string());
        let (v, w) = resolve_env_compat("MINUEND_X", s("new"), "OPERP_X", None);
        assert_eq!((v.as_deref(), w), (Some("new"), None));

        let (v, w) = resolve_env_compat("MINUEND_X", None, "OPERP_X", s("old"));
        assert_eq!(v.as_deref(), Some("old"));
        assert!(w.unwrap().contains("deprecated"));

        let (v, w) = resolve_env_compat("MINUEND_X", s("new"), "OPERP_X", s("old"));
        assert_eq!(v.as_deref(), Some("new"));
        assert!(w.unwrap().contains("ignoring OPERP_X"));

        // Empty counts as unset on both sides.
        let (v, w) = resolve_env_compat("MINUEND_X", s(""), "OPERP_X", s("old"));
        assert_eq!(v.as_deref(), Some("old"));
        assert!(w.is_some());
        assert_eq!(
            resolve_env_compat("MINUEND_X", s(""), "OPERP_X", s("")),
            (None, None)
        );
    }
}
