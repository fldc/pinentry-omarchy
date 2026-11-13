//! Opt-in tests: temporarily take keyboard focus on the current Wayland desktop.
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Session(Child);

fn executable() -> std::ffi::OsString {
    std::env::var_os("PINENTRY_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_pinentry-omarchy").into())
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn open(commands: &str, timeout: &str) -> Session {
    let mut child = Command::new(executable())
        .args(["--timeout", timeout])
        .env("QML_IMPORT_PATH", "/nonexistent-untrusted-qml-path")
        .env("QT_QPA_PLATFORM", "xcb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(), "{commands}\nBYE").unwrap();
    let mut session = Session(child);
    for _ in 0..80 {
        let layers = Command::new("hyprctl")
            .args(["layers", "-j"])
            .output()
            .unwrap();
        if String::from_utf8_lossy(&layers.stdout).contains("pinentry-omarchy") {
            std::thread::sleep(Duration::from_millis(200));
            return session;
        }
        assert!(
            session.0.try_wait().unwrap().is_none(),
            "Frontend exited without UI"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("No pinentry overlay appeared");
}

fn type_text(text: &str) {
    assert!(Command::new("wtype").arg(text).status().unwrap().success());
}

fn key(key: &str) {
    assert!(
        Command::new("wtype")
            .args(["-k", key])
            .status()
            .unwrap()
            .success()
    );
}

fn finish(mut session: Session) -> String {
    let mut output = String::new();
    session
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert!(session.0.wait().unwrap().success());
    output
}

#[test]
#[ignore = "Takes desktop keyboard focus; run explicitly with --ignored --test-threads=1"]
fn desktop_round_trip() {
    let session = open(
        "SETTITLE Rust pinentry test\nSETDESC Dummy password only\nGETPIN",
        "8",
    );
    if let Some(path) = std::env::var_os("PINENTRY_TEST_SCREENSHOT") {
        assert!(
            Command::new("/usr/bin/grim")
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
    }
    type_text("rust-dummy-123");
    key("Return");
    assert!(finish(session).contains("D rust-dummy-123\nOK\n"));

    let session = open("GETPIN", "8");
    key("Escape");
    let output = finish(session);
    assert!(output.contains("ERR 83886179"));
    assert!(!output.contains("D "));

    let session = open("CONFIRM", "8");
    key("Return");
    assert!(finish(session).contains("OK\nOK closing"));

    let session = open("SETREPEAT Repeat password\nGETPIN", "8");
    type_text("rust-dummy");
    key("Return");
    type_text("wrong");
    key("Return");
    std::thread::sleep(Duration::from_millis(200));
    type_text("rust-dummy");
    key("Return");
    assert!(finish(session).contains("D rust-dummy\nS PIN_REPEATED\nOK\n"));

    let session = open("GETPIN", "2");
    assert!(finish(session).contains("ERR 83886179"));

    let session = open("GETPIN", "8");
    type_text("erase-on-focus-loss");
    let takeover_dir = tempfile::tempdir().unwrap();
    let takeover_qml = takeover_dir.path().join("shell.qml");
    std::fs::write(
        &takeover_qml,
        r#"
import QtQuick
import Quickshell
import Quickshell.Wayland
ShellRoot {
  PanelWindow {
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    exclusionMode: ExclusionMode.Ignore
    WlrLayershell.namespace: "pinentry-focus-test"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
  }
}
"#,
    )
    .unwrap();
    let started = std::time::Instant::now();
    let takeover = Session(
        Command::new("/usr/bin/quickshell")
            .arg("-p")
            .arg(&takeover_qml)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let output = finish(session);
    drop(takeover);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "Focus loss must cancel before interaction timeout"
    );
    assert!(output.contains("ERR 83886179"));
    assert!(!output.contains("D "));

    // Refusing to lock memory must fail, not show a weaker fallback prompt.
    let mut command = Command::new(executable());
    command
        .args(["--timeout", "2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    // SAFETY: this child-only hook calls setrlimit with a valid local struct.
    unsafe {
        command.pre_exec(|| {
            if libc::setrlimit(
                libc::RLIMIT_MEMLOCK,
                &libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                },
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    writeln!(child.stdin.as_mut().unwrap(), "GETPIN\nBYE").unwrap();
    let output = finish(Session(child));
    assert!(output.contains("ERR 83886081"));
    assert!(!output.contains("D "));

    // rbw closes command stdin after GETPIN and passes --timeout 0.
    let mut session = open("SETTITLE rbw\nGETPIN", "0");
    drop(session.0.stdin.take());
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        session.0.try_wait().unwrap().is_none(),
        "timeout 0 must not mean one second"
    );
    type_text("rbw-compatible");
    key("Return");
    assert!(finish(session).contains("D rbw-compatible\nOK"));

    let mut session = open("GETPIN", "0");
    let parent = session.0.id();
    let children = Command::new("ps")
        .args(["--ppid", &parent.to_string(), "-o", "pid="])
        .output()
        .unwrap();
    let ui: u32 = String::from_utf8(children.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .expect("UI child")
        .parse()
        .unwrap();
    for pid in [parent, ui] {
        assert!(
            std::fs::File::open(format!("/proc/{pid}/mem")).is_err(),
            "Same-user memory reading must be denied"
        );
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
        let locked: usize = status
            .lines()
            .find_map(|line| line.strip_prefix("VmLck:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(locked >= 4, "Secret pages must actually be locked");
    }
    // Closing the caller's stdout reader must dismiss an unlimited-time prompt.
    drop(session.0.stdout.take());
    for _ in 0..40 {
        if session.0.try_wait().unwrap().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("Disconnected caller left a password prompt running");
}

#[test]
fn termination_while_waiting_for_input() {
    // Exercise the Omarchy signal handler even on headless CI runners. No
    // dialog is requested, so a listening socket suffices to select the UI.
    let runtime = tempfile::tempdir().unwrap();
    let _display =
        std::os::unix::net::UnixListener::bind(runtime.path().join("wayland-test")).unwrap();
    let child = Command::new(executable())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("WAYLAND_DISPLAY", "wayland-test")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut session = Session(child);
    // The greeting confirms the signal handlers are installed before SIGTERM.
    let mut greeting = [0; b"OK pinentry-omarchy ready\n".len()];
    session
        .0
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut greeting)
        .unwrap();
    assert_eq!(&greeting, b"OK pinentry-omarchy ready\n");
    // SAFETY: kill sends SIGTERM to the child created by this test.
    assert_eq!(
        unsafe { libc::kill(session.0.id() as i32, libc::SIGTERM) },
        0
    );
    for _ in 0..30 {
        if let Some(status) = session.0.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("SIGTERM did not wake idle pinentry");
}
