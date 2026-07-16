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

fn batch_fetch_metadata_with<F>(
    names: &[String],
    mut fetch: F,
) -> Result<HashMap<String, AurPackage>, String>
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
        for pkg in packages {
            map.insert(pkg.name.clone(), pkg);
        }
    }

    Ok(map)
}

/// Fetch AUR metadata for a batch of package names via the RPC API.
pub fn batch_fetch_metadata(names: &[String]) -> Result<HashMap<String, AurPackage>, String> {
    batch_fetch_metadata_with(names, aur_rpc::fetch_packages_info)
}

/// Pre-fetch all maintainer package lists in parallel.
pub fn prefetch_maintainer_packages(
    metadata: &HashMap<String, AurPackage>,
) -> HashMap<String, Vec<AurPackage>> {
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

    maintainers
        .par_iter()
        .filter_map(|m| {
            aur_rpc::fetch_maintainer_packages(m)
                .ok()
                .map(|pkgs| (m.to_string(), pkgs))
        })
        .collect()
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
        assert_eq!(metadata.len(), names.len());
        assert!(names.iter().all(|name| metadata.contains_key(name)));
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
}
