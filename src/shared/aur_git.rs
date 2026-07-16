use crate::shared::models::GitCommit;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const AUR_GIT_BASE: &str = "https://aur.archlinux.org";
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const VERIFIED_REMOTE_REF: &str = "refs/remotes/bewaur/verified-master";

/// Validate an AUR package base before it is used as a cache path or URL
/// component. Keeping this check shared prevents cache-management commands from
/// accepting paths that clone operations would reject.
pub fn validate_package_name(package_base: &str) -> Result<(), String> {
    if package_base.is_empty()
        || package_base.starts_with(['-', '.'])
        || !package_base
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '@'))
        || package_base.contains("..")
    {
        return Err(format!("invalid package name: {package_base}"));
    }
    Ok(())
}

/// Clone or update the AUR git repo for a package. Returns the local path.
pub fn ensure_repo(package_base: &str, cache_dir: &str) -> Result<PathBuf, String> {
    ensure_repo_from_base(package_base, Path::new(cache_dir), AUR_GIT_BASE)
}

fn ensure_repo_from_base(
    package_base: &str,
    cache_dir: &Path,
    git_base: &str,
) -> Result<PathBuf, String> {
    validate_package_name(package_base)?;

    fs::create_dir_all(cache_dir).map_err(|error| {
        format!(
            "failed to create Git cache {}: {error}",
            cache_dir.display()
        )
    })?;
    let cache_metadata = fs::symlink_metadata(cache_dir).map_err(|error| {
        format!(
            "failed to inspect Git cache {}: {error}",
            cache_dir.display()
        )
    })?;
    if cache_metadata.file_type().is_symlink() || !cache_metadata.is_dir() {
        return Err(format!(
            "Git cache root is not a real directory: {}",
            cache_dir.display()
        ));
    }
    let canonical_cache = cache_dir.canonicalize().map_err(|error| {
        format!(
            "failed to resolve Git cache {}: {error}",
            cache_dir.display()
        )
    })?;
    let repo_path = cache_dir.join(package_base);
    let url = format!("{}/{}.git", git_base.trim_end_matches('/'), package_base);

    match fs::symlink_metadata(&repo_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "cached AUR repository is not a real directory: {}",
                    repo_path.display()
                ));
            }
            let canonical_repo = repo_path.canonicalize().map_err(|error| {
                format!(
                    "failed to resolve cached AUR repository {}: {error}",
                    repo_path.display()
                )
            })?;
            if canonical_repo.parent() != Some(canonical_cache.as_path()) {
                return Err(format!(
                    "cached AUR repository escaped the Git cache: {}",
                    repo_path.display()
                ));
            }
            validate_git_directory(&repo_path)?;
            require_clean_worktree(&repo_path)?;
            fetch_verified_master(&repo_path, &url)?;
            run_git_checked(
                safe_git_command(&repo_path).args(["reset", "--hard", VERIFIED_REMOTE_REF]),
                "git reset to fetched AUR master",
            )?;
            verify_fetched_head(&repo_path)?;
            require_clean_worktree(&repo_path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let destination = repo_path.to_str().ok_or_else(|| {
                format!("Git cache path is not valid UTF-8: {}", repo_path.display())
            })?;
            run_git_checked(
                safe_git_base_command().args([
                    "clone",
                    "--depth=50",
                    "--no-tags",
                    "--branch",
                    "master",
                    &url,
                    destination,
                ]),
                "git clone",
            )?;
            validate_git_directory(&repo_path)?;
            require_clean_worktree(&repo_path)?;
        }
        Err(error) => {
            return Err(format!(
                "failed to inspect cached AUR repository {}: {error}",
                repo_path.display()
            ));
        }
    }

    Ok(repo_path)
}

fn safe_git_base_command() -> Command {
    let mut command = Command::new("git");
    command
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn safe_git_command(repo_path: &Path) -> Command {
    let mut command = safe_git_base_command();
    command.current_dir(repo_path);
    command
}

fn validate_git_directory(repo_path: &Path) -> Result<(), String> {
    let git_path = repo_path.join(".git");
    let metadata = fs::symlink_metadata(&git_path).map_err(|error| {
        format!(
            "cached AUR repository has no readable .git directory at {}: {error}",
            git_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "cached AUR .git entry is not a real directory: {}",
            git_path.display()
        ));
    }
    Ok(())
}

fn fetch_verified_master(repo_path: &Path, url: &str) -> Result<(), String> {
    let refspec = format!("+refs/heads/master:{VERIFIED_REMOTE_REF}");
    run_git_checked(
        safe_git_command(repo_path).args([
            "fetch",
            "--force",
            "--no-tags",
            "--depth=50",
            url,
            &refspec,
        ]),
        "git fetch AUR master",
    )?;
    Ok(())
}

fn require_clean_worktree(repo_path: &Path) -> Result<(), String> {
    let output = run_git_checked(
        safe_git_command(repo_path).args(["status", "--porcelain=v1", "--untracked-files=all"]),
        "git status",
    )?;
    if !output.stdout.is_empty() {
        let status = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "cached AUR repository has modified or untracked files; refusing to scan it: {}",
            status.trim()
        ));
    }
    Ok(())
}

fn verify_fetched_head(repo_path: &Path) -> Result<(), String> {
    let head = run_git_checked(
        safe_git_command(repo_path).args(["rev-parse", "--verify", "HEAD"]),
        "git rev-parse HEAD",
    )?;
    let fetched = run_git_checked(
        safe_git_command(repo_path).args(["rev-parse", "--verify", VERIFIED_REMOTE_REF]),
        "git rev-parse fetched AUR master",
    )?;
    if head.stdout != fetched.stdout {
        return Err("cached AUR HEAD does not match the fetched master commit".to_string());
    }
    Ok(())
}

fn run_git_checked(cmd: &mut Command, operation: &str) -> Result<Output, String> {
    let output = run_with_timeout(cmd)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{operation} failed with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    Ok(output)
}

/// Run a command with a timeout. Kills the process if it exceeds GIT_TIMEOUT.
fn run_with_timeout(cmd: &mut Command) -> Result<Output, String> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn git: {e}"))?;

    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| format!("git failed: {e}"));
            }
            Ok(None) => {
                if start.elapsed() > GIT_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "git operation timed out after {}s",
                        GIT_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(format!("failed to wait for git: {e}")),
        }
    }
}

/// Parse git log into structured commits.
pub fn read_git_log(repo_path: &std::path::Path, max_commits: usize) -> Vec<GitCommit> {
    let output = Command::new("git")
        .args([
            "log",
            &format!("-{max_commits}"),
            "--format=%H%n%an%n%at%n%s%n---END---",
        ])
        .current_dir(repo_path)
        .output();

    let Ok(output) = output else {
        return Vec::new();
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut commits = Vec::new();

    let mut lines = stdout.lines().peekable();
    while lines.peek().is_some() {
        // hash
        match lines.next() {
            Some(h) if !h.is_empty() => {}
            _ => break,
        };
        let author = lines.next().unwrap_or("").to_string();
        let timestamp: u64 = lines.next().unwrap_or("0").parse().unwrap_or(0);
        // message
        let _ = lines.next();

        // Skip the ---END--- delimiter
        while let Some(line) = lines.peek() {
            if *line == "---END---" {
                lines.next();
                break;
            }
            lines.next();
        }

        commits.push(GitCommit {
            author,
            timestamp,
            diff: None,
        });
    }

    commits
}

/// Read the PKGBUILD content at a specific git revision (e.g., "HEAD~1").
pub fn read_pkgbuild_at_revision(repo_path: &std::path::Path, revision: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["show", &format!("{revision}:PKGBUILD")])
        .current_dir(repo_path)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

/// Get the diff of the most recent commit.
pub fn get_latest_diff(repo_path: &std::path::Path) -> Option<String> {
    let output = Command::new("git")
        .args(["diff", "HEAD~1..HEAD"])
        .current_dir(repo_path)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestRepo {
        root: PathBuf,
        source: PathBuf,
        remote_root: PathBuf,
        remote_repo: PathBuf,
        cache: PathBuf,
    }

    impl TestRepo {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "bewaur-aur-git-test-{}-{}",
                std::process::id(),
                NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            let source = root.join("source");
            let remote_root = root.join("remote");
            let remote_repo = remote_root.join("demo.git");
            let cache = root.join("cache");
            fs::create_dir_all(&source).unwrap();
            fs::create_dir_all(&remote_root).unwrap();
            fs::create_dir_all(&cache).unwrap();

            git_ok(
                &remote_root,
                ["init", "--bare", "--initial-branch=master", "demo.git"],
            );
            git_ok(&source, ["init", "--initial-branch=master"]);
            git_ok(&source, ["config", "user.name", "Bewaur Test"]);
            git_ok(&source, ["config", "user.email", "bewaur@example.invalid"]);
            git_ok(
                &source,
                ["remote", "add", "origin", remote_repo.to_str().unwrap()],
            );

            let repo = Self {
                root,
                source,
                remote_root,
                remote_repo,
                cache,
            };
            repo.write_revision("pkgname=demo\npkgver=1\npkgrel=1\n", "initial");
            repo
        }

        fn write_revision(&self, pkgbuild: &str, message: &str) {
            fs::write(self.source.join("PKGBUILD"), pkgbuild).unwrap();
            fs::write(
                self.source.join(".SRCINFO"),
                "pkgbase = demo\n\tpkgver = 1\n\tpkgrel = 1\n\npkgname = demo\n",
            )
            .unwrap();
            git_ok(&self.source, ["add", "PKGBUILD", ".SRCINFO"]);
            git_ok(&self.source, ["commit", "-m", message]);
            git_ok(&self.source, ["push", "--set-upstream", "origin", "master"]);
        }

        fn ensure(&self) -> Result<PathBuf, String> {
            ensure_repo_from_base("demo", &self.cache, self.remote_root.to_str().unwrap())
        }
    }

    impl Drop for TestRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn git_ok<I, S>(directory: &Path, args: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let output = Command::new("git")
            .args(args)
            .current_dir(directory)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(ensure_repo("../../etc/shadow", "/tmp").is_err());
    }

    #[test]
    fn rejects_slash() {
        assert!(ensure_repo("foo/bar", "/tmp").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(ensure_repo("", "/tmp").is_err());
    }

    #[test]
    fn rejects_dot_and_hyphen_prefixed_names() {
        assert!(validate_package_name(".").is_err());
        assert!(validate_package_name(".hidden").is_err());
        assert!(validate_package_name("-option").is_err());
    }

    #[test]
    fn accepts_valid_package_name() {
        assert!(validate_package_name("yay").is_ok());
    }

    #[test]
    fn accepts_complex_valid_name() {
        assert!(validate_package_name("lib32-mesa+utils").is_ok());
    }

    #[test]
    fn refresh_uses_the_explicit_aur_master_and_verifies_head() {
        let repo = TestRepo::new();
        let cached = repo.ensure().unwrap();
        repo.write_revision("pkgname=demo\npkgver=2\npkgrel=1\n", "update");

        // A poisoned tracking configuration must not redirect the security
        // refresh away from the explicit AUR URL and master ref.
        git_ok(&cached, ["config", "remote.origin.url", "/does/not/exist"]);
        git_ok(&cached, ["config", "branch.master.remote", "attacker"]);

        repo.ensure().unwrap();
        assert!(
            fs::read_to_string(cached.join("PKGBUILD"))
                .unwrap()
                .contains("pkgver=2")
        );

        let head = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&cached)
            .output()
            .unwrap();
        let source_head = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&repo.source)
            .output()
            .unwrap();
        assert_eq!(head.stdout, source_head.stdout);
    }

    #[test]
    fn dirty_cached_repository_is_rejected() {
        let repo = TestRepo::new();
        let cached = repo.ensure().unwrap();
        fs::write(cached.join("PKGBUILD"), "pkgname=modified\n").unwrap();

        let error = repo.ensure().unwrap_err();
        assert!(error.contains("modified or untracked files"), "{error}");
    }

    #[test]
    fn failed_refresh_is_an_error_instead_of_using_stale_content() {
        let repo = TestRepo::new();
        let cached = repo.ensure().unwrap();
        let original = fs::read_to_string(cached.join("PKGBUILD")).unwrap();
        let offline = repo.remote_root.join("demo.offline");
        fs::rename(&repo.remote_repo, offline).unwrap();

        let error = repo.ensure().unwrap_err();
        assert!(error.contains("git fetch AUR master failed"), "{error}");
        assert_eq!(
            fs::read_to_string(cached.join("PKGBUILD")).unwrap(),
            original
        );
    }
}
