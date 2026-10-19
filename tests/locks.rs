use fckn_delete::locks::{find_lockers, kill};
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::os::windows::fs::OpenOptionsExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Kills and reaps the child on drop so a failing assertion never leaks a process.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Env var that makes `locker_query_helper` query the path it holds.
const QUERY_ENV: &str = "FCKN_LOCKS_QUERY_PATH";

/// Not a real test: when re-run by `finds_self_as_locker` in a child process it
/// prints the pids that lock the path in `QUERY_ENV`. Otherwise it is a no-op.
#[test]
fn locker_query_helper() {
    if let Some(path) = std::env::var_os(QUERY_ENV) {
        for l in find_lockers(&[path.into()]).unwrap() {
            println!("LOCKER_PID={}", l.pid);
        }
    }
}

// The Restart Manager never reports the calling process itself, so the query
// has to run in a different process (this same test binary) to see our lock.
#[test]
fn finds_self_as_locker() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("held.txt");
    let _held = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .share_mode(0)
        .open(&file)
        .unwrap();

    let out = Command::new(std::env::current_exe().unwrap())
        .args(["locker_query_helper", "--exact", "--nocapture"])
        .env(QUERY_ENV, &file)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let own = format!("LOCKER_PID={}", std::process::id());
    assert!(
        stdout.lines().any(|l| l.trim() == own),
        "expected {own} in child output:\n{stdout}"
    );
}

#[test]
fn unlocked_file_has_no_lockers() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("free.txt");
    std::fs::write(&file, b"x").unwrap();

    assert_eq!(find_lockers(&[file]).unwrap(), vec![]);
}

#[test]
fn kill_refuses_self() {
    let err = kill(std::process::id()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn kill_terminates_child_locker() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("child-held.txt");
    std::fs::write(&file, b"x").unwrap();

    let script = format!(
        "$f=[IO.File]::Open('{}','Open','Read','None'); Start-Sleep 60",
        file.display()
    );
    let mut child = ChildGuard(
        Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .spawn()
            .unwrap(),
    );
    let child_pid = child.0.id();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let lockers = find_lockers(std::slice::from_ref(&file)).unwrap();
        if lockers.iter().any(|l| l.pid == child_pid) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "child {child_pid} never appeared as locker; saw {lockers:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    kill(child_pid).unwrap();
    // `kill` must not return before the process released its handles.
    std::fs::remove_file(&file).unwrap();
    child.0.wait().unwrap();
}
