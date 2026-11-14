use crate::shared::patterns::{CompiledPattern, load_patterns};
use std::sync::OnceLock;

static PATTERNS: OnceLock<Vec<CompiledPattern>> = OnceLock::new();

pub fn compiled_patterns() -> &'static Vec<CompiledPattern> {
    PATTERNS.get_or_init(|| load_patterns("pkgbuild_analysis"))
}
