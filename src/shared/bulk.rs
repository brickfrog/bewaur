use crate::coordinator;
use crate::shared::aur_rpc;
use crate::shared::models::AurPackage;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

pub const RPC_BATCH_SIZE: usize = 150;
const RPC_MAX_URL_LENGTH: usize = 4000;
pub const MAX_RETRIES: u32 = 3;
pub const RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct BatchMetadata {
    pub packages: HashMap<String, AurPackage>,
    pub missing: Vec<String>,
}

fn metadata_chunks(names: &[String]) -> Result<Vec<Vec<&str>>, String> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();

    for name in names {
        if current.len() == RPC_BATCH_SIZE {
            chunks.push(std::mem::take(&mut current));
        }

        current.push(name.as_str());
        if aur_rpc::info_url_len(&current)? > RPC_MAX_URL_LENGTH {
            let overflow = current.pop().expect("just pushed a package name");
            if current.is_empty() {
                return Err(format!(
                    "Package name '{overflow}' exceeds the AUR RPC URL length limit"
                ));
            }

            chunks.push(std::mem::take(&mut current));
            current.push(overflow);
            if aur_rpc::info_url_len(&current)? > RPC_MAX_URL_LENGTH {
                return Err(format!(
                    "Package name '{overflow}' exceeds the AUR RPC URL length limit"
                ));
            }
        }
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    Ok(chunks)
}

fn batch_fetch_metadata_with<F>(names: &[String], mut fetch: F) -> Result<BatchMetadata, String>
where
    F: FnMut(&[&str]) -> Result<Vec<AurPackage>, String>,
{
    let mut map = HashMap::new();
    let chunks = metadata_chunks(names)?;
    let chunk_count = chunks.len();

    for (index, chunk) in chunks.iter().enumerate() {
        let packages = fetch(chunk).map_err(|e| {
            format!(
                "Batch metadata fetch failed for chunk {}/{} ({} packages): {e}",
                index + 1,
                chunk_count,
                chunk.len()
            )
        })?;
        let requested: HashSet<&str> = chunk.iter().copied().collect();
        for pkg in packages {
            if !requested.contains(pkg.name.as_str()) {
                return Err(format!(
                    "AUR RPC returned unexpected package {:?} for chunk {}/{}",
                    pkg.name,
                    index + 1,
                    chunk_count
                ));
            }
            let name = pkg.name.clone();
            if map.insert(name.clone(), pkg).is_some() {
                return Err(format!("AUR RPC returned duplicate package {name:?}"));
            }
        }
    }

    let missing = names
        .iter()
        .filter(|name| !map.contains_key(name.as_str()))
        .cloned()
        .collect();
    Ok(BatchMetadata {
        packages: map,
        missing,
    })
}

/// Fetch AUR metadata for a batch of package names via the RPC API.
pub fn batch_fetch_metadata(names: &[String]) -> Result<BatchMetadata, String> {
    batch_fetch_metadata_with(names, aur_rpc::fetch_packages_info)
}

/// Concurrent maintainer lookups during a bulk prefetch. Bounded so a large
/// `--all-installed` scan does not burst the AUR RPC endpoint.
const MAINTAINER_FETCH_CONCURRENCY: usize = 4;

/// Per-maintainer prefetch outcome. A failed lookup is kept as an error rather
/// than dropped: an empty list would read as "unknown" to the reputation and
/// adoption checks and silently disable them.
pub type MaintainerPackages = HashMap<String, Result<Vec<AurPackage>, String>>;

/// Fetch one maintainer's package list, retrying with exponential backoff.
pub fn fetch_maintainer_packages_with_retry(maintainer: &str) -> Result<Vec<AurPackage>, String> {
    fetch_with_retry(
        || aur_rpc::fetch_maintainer_packages(maintainer),
        RETRY_BASE_DELAY,
    )
}

fn fetch_with_retry<T>(
    mut fetch: impl FnMut() -> Result<T, String>,
    base_delay: Duration,
) -> Result<T, String> {
    let mut attempt = 0;
    loop {
        match fetch() {
            Ok(value) => return Ok(value),
            Err(_) if attempt + 1 < MAX_RETRIES => {
                std::thread::sleep(base_delay * 2u32.pow(attempt));
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Pre-fetch all maintainer package lists with bounded concurrency and retry.
pub fn prefetch_maintainer_packages(metadata: &HashMap<String, AurPackage>) -> MaintainerPackages {
    let maintainers: Vec<&str> = metadata
        .values()
        .filter_map(|pkg| pkg.maintainer.as_deref())
        .collect::<HashSet<&str>>()
        .into_iter()
        .collect();

    eprintln!(
        "  Fetching maintainer data for {} unique maintainers...",
        maintainers.len()
    );

    let fetch_all = || {
        maintainers
            .par_iter()
            .map(|m| (m.to_string(), fetch_maintainer_packages_with_retry(m)))
            .collect()
    };
    match rayon::ThreadPoolBuilder::new()
        .num_threads(MAINTAINER_FETCH_CONCURRENCY)
        .build()
    {
        Ok(pool) => pool.install(fetch_all),
        Err(_) => maintainers
            .iter()
            .map(|m| (m.to_string(), fetch_maintainer_packages_with_retry(m)))
            .collect(),
    }
}

/// The prefetched package list for `metadata`'s maintainer. Orphaned packages
/// have none to fetch; a maintainer whose lookup failed, or was never
/// prefetched, is an incomplete scan input and an error.
pub fn maintainer_packages_for(
    metadata: &AurPackage,
    prefetched: &MaintainerPackages,
) -> Result<Vec<AurPackage>, String> {
    let Some(maintainer) = metadata.maintainer.as_deref() else {
        return Ok(Vec::new());
    };
    match prefetched.get(maintainer) {
        Some(Ok(packages)) => Ok(packages.clone()),
        Some(Err(error)) => Err(format!(
            "maintainer package lookup for {maintainer} failed: {error}"
        )),
        None => Err(format!(
            "maintainer package lookup for {maintainer} was not performed"
        )),
    }
}

/// Clone repo with retry + exponential backoff. Returns PackageContext or error.
pub fn clone_with_retry(
    name: &str,
    metadata: AurPackage,
    maintainer_packages: Vec<AurPackage>,
) -> Result<coordinator::ScanContext, String> {
    for attempt in 0..MAX_RETRIES {
        match coordinator::build_context_prefetched(
            name,
            metadata.clone(),
            maintainer_packages.clone(),
        ) {
            Ok(ctx) => return Ok(ctx),
            Err(_e) if attempt + 1 < MAX_RETRIES => {
                let delay = RETRY_BASE_DELAY * 2u32.pow(attempt);
                std::thread::sleep(delay);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str) -> AurPackage {
        AurPackage {
            name: name.to_string(),
            package_base: Some(name.to_string()),
            url: None,
            num_votes: 0,
            popularity: 0.0,
            out_of_date: None,
            maintainer: None,
            submitter: None,
            first_submitted: 0,
            last_modified: 0,
            license: None,
        }
    }

    #[test]
    fn failed_maintainer_lookup_is_an_error_not_an_empty_list() {
        let mut owned = package("owned");
        owned.maintainer = Some("alice".to_string());
        let mut prefetched = MaintainerPackages::new();
        prefetched.insert("alice".to_string(), Err("HTTP 503".to_string()));
        let error = maintainer_packages_for(&owned, &prefetched).unwrap_err();
        assert!(error.contains("alice") && error.contains("503"), "{error}");

        assert!(maintainer_packages_for(&owned, &MaintainerPackages::new()).is_err());

        prefetched.insert("alice".to_string(), Ok(vec![package("a"), package("b")]));
        assert_eq!(
            maintainer_packages_for(&owned, &prefetched).unwrap().len(),
            2
        );

        let orphan = package("orphan");
        assert!(
            maintainer_packages_for(&orphan, &prefetched)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn fetch_with_retry_retries_transient_failures_then_gives_up() {
        let mut calls = 0;
        let value = fetch_with_retry(
            || {
                calls += 1;
                if calls < 3 {
                    Err("transient".to_string())
                } else {
                    Ok(calls)
                }
            },
            Duration::ZERO,
        );
        assert_eq!(value, Ok(3));

        let mut calls = 0;
        let error = fetch_with_retry::<()>(
            || {
                calls += 1;
                Err(format!("attempt {calls}"))
            },
            Duration::ZERO,
        );
        assert_eq!(error, Err(format!("attempt {MAX_RETRIES}")));
    }

    #[test]
    fn batch_fetch_aggregates_all_count_limited_chunks() {
        let names: Vec<String> = (0..=RPC_BATCH_SIZE)
            .map(|index| format!("package-{index}"))
            .collect();
        let mut chunk_sizes = Vec::new();

        let metadata = batch_fetch_metadata_with(&names, |chunk| {
            chunk_sizes.push(chunk.len());
            Ok(chunk.iter().map(|name| package(name)).collect())
        })
        .unwrap();

        assert_eq!(chunk_sizes, vec![RPC_BATCH_SIZE, 1]);
        assert_eq!(metadata.packages.len(), names.len());
        assert!(metadata.missing.is_empty());
        assert!(
            names
                .iter()
                .all(|name| metadata.packages.contains_key(name))
        );
    }

    #[test]
    fn metadata_chunks_respect_encoded_url_length_and_order() {
        let names: Vec<String> = (0..80)
            .map(|index| format!("package-{index}-{}+suffix", "x".repeat(80)))
            .collect();

        let chunks = metadata_chunks(&names).unwrap();
        assert!(chunks.len() > 1, "test data should exceed one URL");
        for chunk in &chunks {
            assert!(chunk.len() <= RPC_BATCH_SIZE);
            assert!(aur_rpc::info_url_len(chunk).unwrap() <= RPC_MAX_URL_LENGTH);
        }

        let flattened: Vec<&str> = chunks.iter().flatten().copied().collect();
        let expected: Vec<&str> = names.iter().map(String::as_str).collect();
        assert_eq!(flattened, expected);
    }

    #[test]
    fn batch_fetch_propagates_chunk_failure_without_partial_result() {
        let names: Vec<String> = (0..=RPC_BATCH_SIZE)
            .map(|index| format!("package-{index}"))
            .collect();
        let mut calls = 0;

        let error = batch_fetch_metadata_with(&names, |chunk| {
            calls += 1;
            if calls == 2 {
                Err("simulated transport failure".to_string())
            } else {
                Ok(chunk.iter().map(|name| package(name)).collect())
            }
        })
        .unwrap_err();

        assert_eq!(calls, 2);
        assert!(error.contains("chunk 2/2"), "{error}");
        assert!(error.contains("simulated transport failure"), "{error}");
    }

    #[test]
    fn oversized_single_name_is_rejected() {
        let names = vec!["x".repeat(RPC_MAX_URL_LENGTH)];
        let error = metadata_chunks(&names).unwrap_err();
        assert!(error.contains("exceeds the AUR RPC URL length limit"));
    }

    #[test]
    fn batch_fetch_reports_missing_names_in_request_order() {
        let names = vec![
            "first".to_string(),
            "missing".to_string(),
            "last".to_string(),
        ];
        let metadata = batch_fetch_metadata_with(&names, |chunk| {
            Ok(chunk
                .iter()
                .filter(|name| **name != "missing")
                .map(|name| package(name))
                .collect())
        })
        .unwrap();

        assert_eq!(metadata.missing, vec!["missing"]);
        assert_eq!(metadata.packages.len(), 2);
    }

    #[test]
    fn batch_fetch_rejects_unexpected_and_duplicate_rows() {
        let names = vec!["expected".to_string()];
        let unexpected =
            batch_fetch_metadata_with(&names, |_| Ok(vec![package("unexpected")])).unwrap_err();
        assert!(unexpected.contains("unexpected package"), "{unexpected}");

        let duplicate = batch_fetch_metadata_with(&names, |_| {
            Ok(vec![package("expected"), package("expected")])
        })
        .unwrap_err();
        assert!(duplicate.contains("duplicate package"), "{duplicate}");
    }
}
