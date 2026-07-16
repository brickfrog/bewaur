//! Fail-closed, non-extracting inspection of built ALPM package artifacts.

use bzip2::read::MultiBzDecoder;
use flate2::read::MultiGzDecoder;
use liblzma::read::XzDecoder;
use liblzma::stream::{CONCATENATED, Stream};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};
use tar::Archive;

use crate::shared::config::Config;
use crate::shared::scoring::{ScanResult, Tier};

const MAX_COMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 40 * 1024 * 1024 * 1024;
const MAX_LOGICAL_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_RAW_HEADERS: usize = 200_000;
const MAX_REAL_ENTRIES: usize = 200_000;
const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_TOTAL_PATH_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_INSTALL_BYTES: u64 = 1024 * 1024;
const MAX_MTREE_TEXT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FINDINGS: usize = 1024;
const MAX_XZ_DECODER_MEMORY: u64 = 256 * 1024 * 1024;
const MAX_ZSTD_WINDOW_LOG: u32 = 27;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionKind {
    Bzip2,
    Gzip,
    Xz,
    Zstd,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactSeverity {
    Warning,
    Block,
}

impl std::fmt::Display for ArtifactSeverity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Warning => write!(formatter, "WARNING"),
            Self::Block => write!(formatter, "BLOCK"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactDisposition {
    Clean,
    Review,
    Block,
}

impl std::fmt::Display for ArtifactDisposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(formatter, "CLEAN"),
            Self::Review => write!(formatter, "REVIEW"),
            Self::Block => write!(formatter, "BLOCK"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactFinding {
    pub id: String,
    pub severity: ArtifactSeverity,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactIdentity {
    pub pkgname: String,
    pub pkgbase: String,
    pub pkgver: String,
    pub arch: String,
}

#[derive(Debug, Serialize)]
pub struct ArtifactReport {
    pub artifact: String,
    pub sha256: String,
    pub compressed_bytes: u64,
    pub entries: usize,
    pub logical_bytes: u64,
    pub package: ArtifactIdentity,
    pub has_install_script: bool,
    pub findings: Vec<ArtifactFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_scan: Option<ScanResult>,
    pub disposition: ArtifactDisposition,
    pub blocked: bool,
}

#[derive(Debug, Serialize)]
pub struct ArtifactOutcome {
    pub artifact: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ArtifactReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ArtifactOutcome {
    pub fn inspected(report: ArtifactReport) -> Self {
        Self {
            artifact: report.artifact.clone(),
            report: Some(report),
            error: None,
        }
    }

    pub fn failed(path: &Path, error: String) -> Self {
        Self {
            artifact: path.display().to_string(),
            report: None,
            error: Some(error),
        }
    }

    pub fn blocks(&self) -> bool {
        self.error.is_some() || self.report.as_ref().is_some_and(|report| report.blocked)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveEntryKind {
    File,
    Directory,
    Symlink,
    Hardlink,
}

struct ArchiveContents {
    entries: usize,
    logical_bytes: u64,
    pkginfo: Vec<u8>,
    buildinfo: Vec<u8>,
    mtree: Vec<u8>,
    install_script: Option<String>,
    findings: Vec<ArtifactFinding>,
}

/// Inspect one exact package archive without extracting or executing it.
pub fn inspect_artifact(
    path: &Path,
    expected_pkgbase: Option<&str>,
    config: &Config,
) -> Result<ArtifactReport, String> {
    if let Some(expected) = expected_pkgbase {
        crate::shared::aur_git::validate_package_name(expected)
            .map_err(|error| format!("invalid expected package base: {error}"))?;
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "artifact file name is not valid UTF-8".to_string())?;
    let (package_suffix, settings) = compression_for_name(file_name)?;
    let (mut file, compressed_bytes) = open_artifact(path)?;
    let mut verification_file = file
        .try_clone()
        .map_err(|error| format!("cannot duplicate artifact descriptor: {error}"))?;
    let (initial_sha256, initial_bytes) = hash_open_file(&mut verification_file)?;
    if initial_bytes != compressed_bytes {
        return Err("artifact size changed before inspection".to_string());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind artifact: {error}"))?;

    let contents = inspect_open_archive(file, settings)?;

    let (final_sha256, final_bytes) = hash_open_file(&mut verification_file)?;
    if initial_sha256 != final_sha256 || initial_bytes != final_bytes {
        return Err("artifact changed while it was being inspected".to_string());
    }

    validate_mtree(&contents.mtree)?;
    let package = parse_and_validate_identity(
        &contents.pkginfo,
        &contents.buildinfo,
        file_name,
        package_suffix,
        expected_pkgbase,
    )?;

    let install_scan = contents.install_script.as_deref().map(|script| {
        crate::coordinator::scan_install_script_with_config(&package.pkgname, script, config)
    });
    let install_blocks = install_scan
        .as_ref()
        .is_some_and(|scan| scan.tier >= Tier::Sketchy);
    let has_warning = !contents.findings.is_empty()
        || install_scan
            .as_ref()
            .is_some_and(|scan| !scan.signals.is_empty());
    let structural_block = contents
        .findings
        .iter()
        .any(|finding| finding.severity == ArtifactSeverity::Block);
    let blocked = structural_block || install_blocks;
    let disposition = if blocked {
        ArtifactDisposition::Block
    } else if has_warning {
        ArtifactDisposition::Review
    } else {
        ArtifactDisposition::Clean
    };

    Ok(ArtifactReport {
        artifact: path.display().to_string(),
        sha256: initial_sha256,
        compressed_bytes,
        entries: contents.entries,
        logical_bytes: contents.logical_bytes,
        package,
        has_install_script: contents.install_script.is_some(),
        findings: contents.findings,
        install_scan,
        disposition,
        blocked,
    })
}

fn compression_for_name(file_name: &str) -> Result<(&'static str, CompressionKind), String> {
    let supported = [
        (".pkg.tar.zst", CompressionKind::Zstd),
        (".pkg.tar.bz2", CompressionKind::Bzip2),
        (".pkg.tar.gz", CompressionKind::Gzip),
        (".pkg.tar.xz", CompressionKind::Xz),
        (".pkg.tar", CompressionKind::None),
    ];
    for (suffix, settings) in supported {
        if file_name.ends_with(suffix) {
            return Ok((suffix, settings));
        }
    }
    Err(format!(
        "unsupported ALPM package name or compression for {file_name:?}; supported suffixes are .pkg.tar, .zst, .gz, .xz, and .bz2"
    ))
}

fn open_artifact(path: &Path) -> Result<(File, u64), String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect artifact {}: {error}", path.display()))?;
    if path_metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symlinked artifact input: {}",
            path.display()
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("cannot open artifact {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened artifact: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "artifact is not a regular file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_COMPRESSED_BYTES {
        return Err(format!(
            "compressed artifact exceeds the {MAX_COMPRESSED_BYTES} byte limit"
        ));
    }
    Ok((file, metadata.len()))
}

fn hash_open_file(file: &mut File) -> Result<(String, u64), String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind artifact for hashing: {error}"))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash artifact: {error}"))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| "artifact byte count overflowed".to_string())?;
        if bytes > MAX_COMPRESSED_BYTES {
            return Err(format!(
                "compressed artifact exceeds the {MAX_COMPRESSED_BYTES} byte limit"
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok((format!("{:x}", hasher.finalize()), bytes))
}

fn inspect_open_archive(
    file: File,
    compression: CompressionKind,
) -> Result<ArchiveContents, String> {
    let decoder = open_decoder(file, compression)?;
    let bounded = decoder.take(MAX_DECOMPRESSED_BYTES + 1);
    let mut archive = Archive::new(bounded);
    archive.set_ignore_zeros(true);

    let mut raw_headers = 0usize;
    let mut real_entries = 0usize;
    let mut logical_bytes = 0u64;
    let mut total_path_bytes = 0usize;
    let mut entry_kinds = HashMap::new();
    let mut link_paths = HashSet::new();
    let mut pkginfo = None;
    let mut buildinfo = None;
    let mut mtree = None;
    let mut install_script = None;
    let mut findings = Vec::new();

    {
        let entries = archive
            .entries()
            .map_err(|error| format!("cannot read artifact entries: {error}"))?
            .raw(true);
        for entry in entries {
            raw_headers = raw_headers
                .checked_add(1)
                .ok_or_else(|| "artifact header count overflowed".to_string())?;
            if raw_headers > MAX_RAW_HEADERS {
                return Err(format!(
                    "artifact exceeds the {MAX_RAW_HEADERS} raw-header limit"
                ));
            }

            let mut entry =
                entry.map_err(|error| format!("cannot read artifact entry: {error}"))?;
            let entry_type = entry.header().entry_type();
            if entry_type.is_gnu_longname()
                || entry_type.is_gnu_longlink()
                || entry_type.is_pax_local_extensions()
                || entry_type.is_pax_global_extensions()
            {
                return Err(
                    "artifact uses GNU/PAX extension headers that the bounded raw inspector does not yet support"
                        .to_string(),
                );
            }
            if entry_type.is_gnu_sparse() {
                return Err("artifact contains an unsupported sparse entry".to_string());
            }

            real_entries = real_entries
                .checked_add(1)
                .ok_or_else(|| "artifact entry count overflowed".to_string())?;
            if real_entries > MAX_REAL_ENTRIES {
                return Err(format!(
                    "artifact exceeds the {MAX_REAL_ENTRIES} entry limit"
                ));
            }

            let path = normalize_archive_path(entry.header().path_bytes().as_ref())?;
            if entry_kinds.contains_key(&path) {
                return Err(format!("artifact contains duplicate path {path:?}"));
            }
            add_path_bytes(&mut total_path_bytes, path.len())?;

            let size = entry.size();
            let mode = entry
                .header()
                .mode()
                .map_err(|error| format!("cannot read mode for {path:?}: {error}"))?
                & 0o7777;
            let kind = if entry_type.is_file() {
                logical_bytes = logical_bytes
                    .checked_add(size)
                    .ok_or_else(|| "artifact logical size overflowed".to_string())?;
                if logical_bytes > MAX_LOGICAL_BYTES {
                    return Err(format!(
                        "artifact exceeds the {MAX_LOGICAL_BYTES} byte logical-size limit"
                    ));
                }
                ArchiveEntryKind::File
            } else if entry_type.is_dir() {
                if size != 0 {
                    return Err(format!("directory entry {path:?} has a data body"));
                }
                ArchiveEntryKind::Directory
            } else if entry_type.is_symlink() {
                if size != 0 {
                    return Err(format!("symlink entry {path:?} has a data body"));
                }
                let target = entry
                    .header()
                    .link_name_bytes()
                    .ok_or_else(|| format!("symlink {path:?} has no target"))?;
                validate_symlink_target(&path, target.as_ref())?;
                link_paths.insert(path.clone());
                ArchiveEntryKind::Symlink
            } else if entry_type.is_hard_link() {
                if size != 0 {
                    return Err(format!("hardlink entry {path:?} has a data body"));
                }
                let target = entry
                    .header()
                    .link_name_bytes()
                    .ok_or_else(|| format!("hardlink {path:?} has no target"))?;
                let target = normalize_archive_path(target.as_ref())?;
                if entry_kinds.get(&target) != Some(&ArchiveEntryKind::File) {
                    return Err(format!(
                        "hardlink {path:?} does not target an earlier regular archive path: {target:?}"
                    ));
                }
                link_paths.insert(path.clone());
                ArchiveEntryKind::Hardlink
            } else {
                return Err(format!(
                    "artifact contains forbidden special or unknown entry type at {path:?}"
                ));
            };

            add_mode_and_path_findings(&mut findings, &path, kind, mode)?;
            match path.as_str() {
                ".PKGINFO" => {
                    require_metadata_file(kind, &path)?;
                    pkginfo = Some(read_entry_limited(
                        &mut entry,
                        size,
                        MAX_METADATA_BYTES,
                        ".PKGINFO",
                    )?);
                }
                ".BUILDINFO" => {
                    require_metadata_file(kind, &path)?;
                    buildinfo = Some(read_entry_limited(
                        &mut entry,
                        size,
                        MAX_METADATA_BYTES,
                        ".BUILDINFO",
                    )?);
                }
                ".MTREE" => {
                    require_metadata_file(kind, &path)?;
                    mtree = Some(read_entry_limited(
                        &mut entry,
                        size,
                        MAX_METADATA_BYTES,
                        ".MTREE",
                    )?);
                }
                ".INSTALL" => {
                    require_metadata_file(kind, &path)?;
                    let content =
                        read_entry_limited(&mut entry, size, MAX_INSTALL_BYTES, ".INSTALL")?;
                    let content = String::from_utf8(content)
                        .map_err(|_| ".INSTALL is not valid UTF-8".to_string())?;
                    install_script = Some(content);
                    push_finding(
                        &mut findings,
                        ArtifactFinding {
                            id: "A-INSTALL-SCRIPTLET".to_string(),
                            severity: ArtifactSeverity::Warning,
                            description:
                                "Package contains a transaction-time scriptlet executed by pacman"
                                    .to_string(),
                            path: Some(path.clone()),
                        },
                    )?;
                }
                _ => {}
            }
            entry_kinds.insert(path, kind);
        }
    }

    if archive.into_inner().limit() == 0 {
        return Err(format!(
            "decompressed artifact exceeds the {MAX_DECOMPRESSED_BYTES} byte limit"
        ));
    }
    reject_link_pivots(&entry_kinds, &link_paths)?;
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.path.cmp(&right.path))
    });

    Ok(ArchiveContents {
        entries: real_entries,
        logical_bytes,
        pkginfo: pkginfo.ok_or_else(|| "artifact is missing root .PKGINFO".to_string())?,
        buildinfo: buildinfo.ok_or_else(|| "artifact is missing root .BUILDINFO".to_string())?,
        mtree: mtree.ok_or_else(|| "artifact is missing root .MTREE".to_string())?,
        install_script,
        findings,
    })
}

fn add_path_bytes(total: &mut usize, path_bytes: usize) -> Result<(), String> {
    *total = total
        .checked_add(path_bytes)
        .ok_or_else(|| "artifact path byte count overflowed".to_string())?;
    if *total > MAX_TOTAL_PATH_BYTES {
        return Err(format!(
            "artifact exceeds the {MAX_TOTAL_PATH_BYTES} byte aggregate-path limit"
        ));
    }
    Ok(())
}

fn open_decoder(file: File, compression: CompressionKind) -> Result<Box<dyn Read>, String> {
    match compression {
        CompressionKind::Bzip2 => Ok(Box::new(MultiBzDecoder::new(file))),
        CompressionKind::Gzip => Ok(Box::new(MultiGzDecoder::new(file))),
        CompressionKind::Xz => {
            let stream = Stream::new_stream_decoder(MAX_XZ_DECODER_MEMORY, CONCATENATED)
                .map_err(|error| format!("cannot initialize bounded xz decoder: {error}"))?;
            Ok(Box::new(XzDecoder::new_stream(file, stream)))
        }
        CompressionKind::Zstd => {
            let mut decoder = zstd::stream::read::Decoder::new(file)
                .map_err(|error| format!("cannot initialize zstd decoder: {error}"))?;
            decoder
                .window_log_max(MAX_ZSTD_WINDOW_LOG)
                .map_err(|error| format!("cannot bound zstd decoder window: {error}"))?;
            Ok(Box::new(decoder))
        }
        CompressionKind::None => Ok(Box::new(file)),
    }
}

fn normalize_archive_path(bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() {
        return Err("artifact contains an empty path".to_string());
    }
    if bytes.len() > MAX_PATH_BYTES {
        return Err(format!(
            "artifact path exceeds the {MAX_PATH_BYTES} byte limit"
        ));
    }
    let value =
        std::str::from_utf8(bytes).map_err(|_| "artifact contains a non-UTF-8 path".to_string())?;
    if value.contains('\\') {
        return Err(format!(
            "artifact path contains an ambiguous backslash: {value:?}"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!(
            "artifact path contains control characters: {value:?}"
        ));
    }
    if value.starts_with('/') {
        return Err(format!("artifact path is absolute: {value:?}"));
    }
    let without_trailing_slash = value.trim_end_matches('/');
    if without_trailing_slash.is_empty() || value.contains("//") {
        return Err(format!("artifact contains an invalid path: {value:?}"));
    }

    let mut normalized = Vec::new();
    for component in without_trailing_slash.split('/') {
        if component == "." {
            return Err(format!("artifact path contains a '.' component: {value:?}"));
        }
        if component == ".." {
            return Err(format!("artifact path traverses with '..': {value:?}"));
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(format!(
                "artifact path component exceeds the {MAX_COMPONENT_BYTES} byte limit"
            ));
        }
        normalized.push(component);
    }
    if normalized.is_empty() {
        return Err(format!("artifact contains an empty path: {value:?}"));
    }
    Ok(normalized.join("/"))
}

fn validate_symlink_target(link_path: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES {
        return Err(format!(
            "symlink {link_path:?} has an empty or oversized target"
        ));
    }
    let target = std::str::from_utf8(bytes)
        .map_err(|_| format!("symlink {link_path:?} has a non-UTF-8 target"))?;
    if target.contains('\\') || target.chars().any(char::is_control) {
        return Err(format!(
            "symlink {link_path:?} has an invalid target {target:?}"
        ));
    }
    // Absolute package symlinks are valid ALPM payloads and are common in
    // official packages. Treat their leading slash as the installation root;
    // relative targets begin at the link's parent directory.
    let absolute = target.starts_with('/');
    let mut resolved: Vec<&str> = if absolute {
        Vec::new()
    } else {
        let mut parent: Vec<&str> = link_path.split('/').collect();
        parent.pop();
        parent
    };
    for component in Path::new(target).components() {
        match component {
            Component::Normal(component) => {
                let component = component
                    .to_str()
                    .ok_or_else(|| format!("symlink {link_path:?} has a non-UTF-8 target"))?;
                if component.len() > MAX_COMPONENT_BYTES {
                    return Err(format!(
                        "symlink {link_path:?} has an oversized target component"
                    ));
                }
                resolved.push(component);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if resolved.pop().is_none() {
                    return Err(format!(
                        "symlink {link_path:?} escapes the installation root through {target:?}"
                    ));
                }
            }
            Component::RootDir if absolute => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "symlink {link_path:?} has an absolute target {target:?}"
                ));
            }
        }
    }
    Ok(())
}

fn reject_link_pivots(
    entry_kinds: &HashMap<String, ArchiveEntryKind>,
    link_paths: &HashSet<String>,
) -> Result<(), String> {
    for path in entry_kinds.keys() {
        for (index, _) in path.match_indices('/') {
            let ancestor = &path[..index];
            if link_paths.contains(ancestor) {
                return Err(format!(
                    "archive path {path:?} is nested beneath link entry {ancestor:?}"
                ));
            }
        }
    }
    Ok(())
}

fn require_metadata_file(kind: ArchiveEntryKind, path: &str) -> Result<(), String> {
    if kind != ArchiveEntryKind::File {
        return Err(format!("root metadata entry {path} is not a regular file"));
    }
    Ok(())
}

fn read_entry_limited(
    entry: &mut impl Read,
    declared_size: u64,
    limit: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    if declared_size > limit {
        return Err(format!("{label} exceeds the {limit} byte limit"));
    }
    let mut content = Vec::with_capacity(declared_size as usize);
    entry
        .take(limit + 1)
        .read_to_end(&mut content)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    if content.len() as u64 > limit {
        return Err(format!("{label} exceeds the {limit} byte limit"));
    }
    if content.len() as u64 != declared_size {
        return Err(format!(
            "{label} body length does not match its declared archive size"
        ));
    }
    Ok(content)
}

fn validate_mtree(compressed: &[u8]) -> Result<(), String> {
    let mut decoder = MultiGzDecoder::new(compressed);
    let mut content = Vec::new();
    decoder
        .by_ref()
        .take(MAX_MTREE_TEXT_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|error| format!("cannot decompress .MTREE: {error}"))?;
    if content.len() as u64 > MAX_MTREE_TEXT_BYTES {
        return Err(format!(
            "decompressed .MTREE exceeds the {MAX_MTREE_TEXT_BYTES} byte limit"
        ));
    }
    let text = std::str::from_utf8(&content)
        .map_err(|_| "decompressed .MTREE is not valid UTF-8".to_string())?;
    if text.lines().next() != Some("#mtree") {
        return Err("decompressed .MTREE does not begin with #mtree".to_string());
    }
    Ok(())
}

fn parse_and_validate_identity(
    pkginfo: &[u8],
    buildinfo: &[u8],
    file_name: &str,
    package_suffix: &str,
    expected_pkgbase: Option<&str>,
) -> Result<ArtifactIdentity, String> {
    let pkginfo = parse_assignments(pkginfo, ".PKGINFO")?;
    let buildinfo = parse_assignments(buildinfo, ".BUILDINFO")?;
    let package = ArtifactIdentity {
        pkgname: required_single(&pkginfo, "pkgname", ".PKGINFO")?,
        pkgbase: required_single(&pkginfo, "pkgbase", ".PKGINFO")?,
        pkgver: required_single(&pkginfo, "pkgver", ".PKGINFO")?,
        arch: required_single(&pkginfo, "arch", ".PKGINFO")?,
    };
    crate::shared::aur_git::validate_package_name(&package.pkgname)
        .map_err(|error| format!("invalid .PKGINFO pkgname: {error}"))?;
    crate::shared::aur_git::validate_package_name(&package.pkgbase)
        .map_err(|error| format!("invalid .PKGINFO pkgbase: {error}"))?;

    let build_pkgname = required_single(&buildinfo, "pkgname", ".BUILDINFO")?;
    let build_pkgbase = required_single(&buildinfo, "pkgbase", ".BUILDINFO")?;
    let build_pkgver = required_single(&buildinfo, "pkgver", ".BUILDINFO")?;
    let build_arch = required_single(&buildinfo, "pkgarch", ".BUILDINFO")?;
    if build_pkgname != package.pkgname
        || build_pkgbase != package.pkgbase
        || build_pkgver != package.pkgver
        || build_arch != package.arch
    {
        return Err(format!(
            ".PKGINFO and .BUILDINFO package identities disagree: {:?} versus {build_pkgname}-{build_pkgver}-{build_arch} (base {build_pkgbase})",
            package
        ));
    }
    if let Some(expected) = expected_pkgbase
        && expected != package.pkgbase
    {
        return Err(format!(
            "expected package base {expected:?}, but artifact identifies base {:?}",
            package.pkgbase
        ));
    }

    let expected_file_name = format!(
        "{}-{}-{}{}",
        package.pkgname, package.pkgver, package.arch, package_suffix
    );
    if file_name != expected_file_name {
        return Err(format!(
            "artifact filename {file_name:?} disagrees with metadata; expected {expected_file_name:?}"
        ));
    }
    Ok(package)
}

fn parse_assignments(content: &[u8], label: &str) -> Result<HashMap<String, Vec<String>>, String> {
    let text = std::str::from_utf8(content).map_err(|_| format!("{label} is not valid UTF-8"))?;
    let mut assignments: HashMap<String, Vec<String>> = HashMap::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{label} line {} is not a key assignment", index + 1))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty()
            || value.is_empty()
            || key.chars().any(char::is_control)
            || value.chars().any(char::is_control)
        {
            return Err(format!("{label} line {} is malformed", index + 1));
        }
        assignments
            .entry(key.to_string())
            .or_default()
            .push(value.to_string());
    }
    Ok(assignments)
}

fn required_single(
    assignments: &HashMap<String, Vec<String>>,
    key: &str,
    label: &str,
) -> Result<String, String> {
    let values = assignments
        .get(key)
        .ok_or_else(|| format!("{label} is missing required {key}"))?;
    if values.len() != 1 {
        return Err(format!("{label} contains duplicate {key} assignments"));
    }
    Ok(values[0].clone())
}

fn add_mode_and_path_findings(
    findings: &mut Vec<ArtifactFinding>,
    path: &str,
    kind: ArchiveEntryKind,
    mode: u32,
) -> Result<(), String> {
    if kind == ArchiveEntryKind::File && mode & 0o4000 != 0 {
        push_path_finding(
            findings,
            "A-SETUID-FILE",
            ArtifactSeverity::Block,
            "Regular file is installed with the setuid bit",
            path,
        )?;
    }
    if kind == ArchiveEntryKind::File && mode & 0o2000 != 0 {
        push_path_finding(
            findings,
            "A-SETGID-FILE",
            ArtifactSeverity::Block,
            "Regular file is installed with the setgid bit",
            path,
        )?;
    }
    if kind == ArchiveEntryKind::File && mode & 0o002 != 0 {
        push_path_finding(
            findings,
            "A-WORLD-WRITABLE-FILE",
            ArtifactSeverity::Block,
            "Regular file is world-writable",
            path,
        )?;
    }
    if kind == ArchiveEntryKind::Directory && mode & 0o002 != 0 && mode & 0o1000 == 0 {
        push_path_finding(
            findings,
            "A-WORLD-WRITABLE-DIR",
            ArtifactSeverity::Block,
            "Directory is world-writable without the sticky bit",
            path,
        )?;
    }
    if kind == ArchiveEntryKind::Directory {
        return Ok(());
    }

    let block = if path == "etc/ld.so.preload" {
        Some((
            "A-LD-PRELOAD",
            "Package supplies the dynamic-loader preload file",
        ))
    } else if path == "etc/sudoers" || path.starts_with("etc/sudoers.d/") {
        Some(("A-SUDOERS", "Package supplies sudo authorization policy"))
    } else if matches!(
        path,
        "etc/passwd" | "etc/shadow" | "etc/group" | "etc/gshadow"
    ) {
        Some((
            "A-ACCOUNT-DATABASE",
            "Package supplies a system account database",
        ))
    } else {
        None
    };
    if let Some((id, description)) = block {
        push_path_finding(findings, id, ArtifactSeverity::Block, description, path)?;
    }

    let warning = if path.starts_with("usr/share/libalpm/hooks/")
        || path.starts_with("etc/pacman.d/hooks/")
    {
        Some((
            "A-PACMAN-HOOK",
            "Package installs a pacman transaction hook",
        ))
    } else if path.starts_with("usr/lib/systemd/system/")
        || path.starts_with("etc/systemd/system/")
        || path.starts_with("usr/lib/systemd/user/")
        || path.starts_with("etc/systemd/user/")
    {
        Some(("A-SYSTEMD-UNIT", "Package installs a systemd unit"))
    } else if path.starts_with("usr/lib/udev/rules.d/") || path.starts_with("etc/udev/rules.d/") {
        Some(("A-UDEV-RULE", "Package installs a udev rule"))
    } else if path.starts_with("usr/share/polkit-1/") || path.starts_with("etc/polkit-1/") {
        Some(("A-POLKIT-POLICY", "Package installs polkit policy"))
    } else if path.starts_with("usr/lib/tmpfiles.d/") || path.starts_with("etc/tmpfiles.d/") {
        Some(("A-TMPFILES", "Package installs a tmpfiles rule"))
    } else if path.starts_with("usr/lib/sysusers.d/") || path.starts_with("etc/sysusers.d/") {
        Some(("A-SYSUSERS", "Package installs a sysusers rule"))
    } else if path.starts_with("usr/lib/modules-load.d/")
        || path.starts_with("etc/modules-load.d/")
        || path.starts_with("usr/lib/modprobe.d/")
        || path.starts_with("etc/modprobe.d/")
        || path.starts_with("usr/lib/modules/")
    {
        Some((
            "A-KERNEL-MODULE",
            "Package supplies kernel module configuration or payload",
        ))
    } else if path.starts_with("etc/cron.d/")
        || path.starts_with("etc/cron.daily/")
        || path.starts_with("etc/cron.hourly/")
        || path.starts_with("etc/cron.weekly/")
        || path.starts_with("etc/cron.monthly/")
    {
        Some(("A-CRON", "Package installs a scheduled cron task"))
    } else if path.starts_with("etc/pam.d/") || path.starts_with("usr/lib/security/") {
        Some((
            "A-PAM",
            "Package supplies PAM authentication configuration or modules",
        ))
    } else if path == "etc/nsswitch.conf" || path.starts_with("usr/lib/libnss_") {
        Some((
            "A-NSS",
            "Package supplies name-service configuration or modules",
        ))
    } else if path.starts_with("etc/ld.so.conf.d/") {
        Some((
            "A-DYNAMIC-LINKER-CONFIG",
            "Package installs dynamic-linker search configuration",
        ))
    } else if path.starts_with("etc/profile.d/")
        || path.starts_with("etc/xdg/autostart/")
        || path.starts_with("etc/X11/xinit/xinitrc.d/")
    {
        Some((
            "A-SESSION-AUTOSTART",
            "Package installs session startup configuration",
        ))
    } else if path.starts_with("etc/ssh/sshd_config.d/") || path == "etc/ssh/sshd_config" {
        Some(("A-SSHD-CONFIG", "Package supplies SSH daemon configuration"))
    } else {
        None
    };
    if let Some((id, description)) = warning {
        push_path_finding(findings, id, ArtifactSeverity::Warning, description, path)?;
    }
    Ok(())
}

fn push_path_finding(
    findings: &mut Vec<ArtifactFinding>,
    id: &str,
    severity: ArtifactSeverity,
    description: &str,
    path: &str,
) -> Result<(), String> {
    push_finding(
        findings,
        ArtifactFinding {
            id: id.to_string(),
            severity,
            description: description.to_string(),
            path: Some(path.to_string()),
        },
    )
}

fn push_finding(
    findings: &mut Vec<ArtifactFinding>,
    finding: ArtifactFinding,
) -> Result<(), String> {
    if findings.len() >= MAX_FINDINGS {
        return Err(format!(
            "artifact exceeds the {MAX_FINDINGS} security-finding limit"
        ));
    }
    findings.push(finding);
    Ok(())
}

pub fn write_text(report: &ArtifactReport, mut writer: impl Write) -> io::Result<()> {
    writeln!(writer, "Artifact: {}", report.artifact)?;
    writeln!(
        writer,
        "Package:  {} {} ({}, base {})",
        report.package.pkgname, report.package.pkgver, report.package.arch, report.package.pkgbase
    )?;
    writeln!(writer, "SHA-256:  {}", report.sha256)?;
    writeln!(
        writer,
        "Archive:  {} entries, {} logical bytes, {} compressed bytes",
        report.entries, report.logical_bytes, report.compressed_bytes
    )?;
    writeln!(writer, "Result:   {}", report.disposition)?;
    for finding in &report.findings {
        if let Some(path) = &finding.path {
            writeln!(
                writer,
                "  [{}] {}: {} ({})",
                finding.severity, finding.id, finding.description, path
            )?;
        } else {
            writeln!(
                writer,
                "  [{}] {}: {}",
                finding.severity, finding.id, finding.description
            )?;
        }
    }
    if let Some(scan) = &report.install_scan {
        writeln!(
            writer,
            "  Install script scan: {} (trust {}/100)",
            scan.tier, scan.score
        )?;
        for signal in &scan.signals {
            writeln!(writer, "    {}: {}", signal.id, signal.description)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_paths_are_normalized_fail_closed() {
        assert_eq!(
            normalize_archive_path(b"usr/bin/demo").unwrap(),
            "usr/bin/demo"
        );
        for invalid in [
            &b""[..],
            &b"/etc/passwd"[..],
            &b"usr/../etc/passwd"[..],
            &b"./usr/bin/demo"[..],
            &b"usr/./bin/demo"[..],
            &b"usr/bin/."[..],
            &b"usr//bin/demo"[..],
            &b"usr/bin/evil\nname"[..],
            &b"usr\\bin\\demo"[..],
            &b"usr/bin/\xff"[..],
        ] {
            assert!(
                normalize_archive_path(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn aggregate_path_limit_accepts_boundary_and_rejects_one_more_byte() {
        let mut total = MAX_TOTAL_PATH_BYTES - 3;
        add_path_bytes(&mut total, 3).unwrap();
        assert_eq!(total, MAX_TOTAL_PATH_BYTES);
        assert!(add_path_bytes(&mut total, 1).is_err());
    }

    #[test]
    fn symlink_targets_may_move_within_but_not_escape_the_install_root() {
        assert!(validate_symlink_target("usr/bin/demo", b"../lib/demo").is_ok());
        assert!(validate_symlink_target("usr/bin/demo", b"../../lib/demo").is_ok());
        assert!(validate_symlink_target("usr/bin/demo", b"../../../etc/passwd").is_err());
        assert!(validate_symlink_target("usr/bin/demo", b"/usr/lib/demo").is_ok());
        assert!(validate_symlink_target("usr/bin/demo", b"/../etc/passwd").is_err());
    }

    #[test]
    fn privileged_modes_and_paths_are_classified_without_near_misses() {
        let mut findings = Vec::new();
        add_mode_and_path_findings(
            &mut findings,
            "usr/bin/demo",
            ArchiveEntryKind::File,
            0o4755,
        )
        .unwrap();
        add_mode_and_path_findings(
            &mut findings,
            "usr/lib/systemd/system/demo.service",
            ArchiveEntryKind::File,
            0o644,
        )
        .unwrap();
        add_mode_and_path_findings(
            &mut findings,
            "usr/share/doc/systemd/system/demo.service",
            ArchiveEntryKind::File,
            0o644,
        )
        .unwrap();

        assert!(findings.iter().any(|finding| {
            finding.id == "A-SETUID-FILE" && finding.severity == ArtifactSeverity::Block
        }));
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "A-SYSTEMD-UNIT")
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.id == "A-SYSTEMD-UNIT")
                .count(),
            1
        );
    }

    #[test]
    fn split_package_identity_checks_the_package_base_separately() {
        let pkginfo = b"pkgname = demo-cli\npkgbase = demo\npkgver = 1.0-1\narch = any\n";
        let buildinfo = b"pkgname = demo-cli\npkgbase = demo\npkgver = 1.0-1\npkgarch = any\n";
        let identity = parse_and_validate_identity(
            pkginfo,
            buildinfo,
            "demo-cli-1.0-1-any.pkg.tar.zst",
            ".pkg.tar.zst",
            Some("demo"),
        )
        .unwrap();
        assert_eq!(identity.pkgname, "demo-cli");
        assert_eq!(identity.pkgbase, "demo");

        assert!(
            parse_and_validate_identity(
                pkginfo,
                buildinfo,
                "demo-cli-1.0-1-any.pkg.tar.zst",
                ".pkg.tar.zst",
                Some("other"),
            )
            .is_err()
        );
    }
}
