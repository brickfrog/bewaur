//! Normalized comparison of AUR account names and git author display names.
//!
//! AUR RPC exposes account names (`Submitter`, `Maintainer`); git exposes
//! arbitrary UTF-8 display names (`%an`). The same person routinely appears as
//! `Alice B` in one and `alice-b` in the other, so comparisons that span those
//! two namespaces must normalize before testing equality.

/// Reduce an identity to its ASCII alphanumeric lowercase core.
///
/// Returns an empty string for identities with no ASCII alphanumerics (e.g.
/// `"日本"`), which is why callers must never treat two empty keys as a match —
/// see [`same_identity`].
pub fn identity_key(identity: &str) -> String {
    identity
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Compare two identities, normalizing when both reduce to a non-empty key.
///
/// Falls back to a trimmed raw comparison when either key is empty. Without the
/// fallback, two distinct non-ASCII identities would both normalize to `""` and
/// compare equal — a false negative in exactly the takeover checks that depend
/// on spotting a *different* author.
pub fn same_identity(left: &str, right: &str) -> bool {
    let left_key = identity_key(left);
    let right_key = identity_key(right);
    if left_key.is_empty() || right_key.is_empty() {
        return left.trim() == right.trim();
    }
    left_key == right_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_punctuation_and_case() {
        assert_eq!(identity_key("Alice B"), "aliceb");
        assert_eq!(identity_key("alice-b"), "aliceb");
        assert_eq!(identity_key("A.L.I.C.E_42"), "alice42");
    }

    #[test]
    fn non_ascii_reduces_to_empty() {
        assert_eq!(identity_key("日本"), "");
        // Only the ASCII letters survive; Ü/ï/ö/é are all filtered out.
        assert_eq!(identity_key("Ünïcödé"), "ncd");
    }

    #[test]
    fn display_name_variants_are_the_same_identity() {
        assert!(same_identity("Alice B", "alice-b"));
        assert!(same_identity("alice b", "ALICE_B"));
    }

    #[test]
    fn distinct_identities_are_not_equal() {
        assert!(!same_identity("alice", "mallory"));
    }

    #[test]
    fn distinct_non_ascii_identities_are_not_equal() {
        // Both normalize to "", so the raw fallback is what keeps them apart.
        assert!(!same_identity("日本", "中文"));
        assert!(same_identity("日本", "日本"));
    }

    #[test]
    fn empty_key_against_ascii_key_is_not_a_match() {
        assert!(!same_identity("日本", "alice"));
    }
}
