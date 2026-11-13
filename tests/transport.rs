//! These regressions use protocol pipes and never open a desktop prompt.
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn stalled_session() -> Process {
    // Keep the Omarchy backend selected without requiring a real desktop.
    let runtime = tempfile::tempdir().unwrap();
    let _display =
        std::os::unix::net::UnixListener::bind(runtime.path().join("wayland-test")).unwrap();
    let mut commands = tempfile::tempfile().unwrap();
    commands.write_all(&b"NOP\n".repeat(20000)).unwrap();
    commands.seek(SeekFrom::Start(0)).unwrap();
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_pinentry-omarchy"))
            .env("XDG_RUNTIME_DIR", runtime.path())
            .env("WAYLAND_DISPLAY", "wayland-test")
            .stdin(commands)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    // A single pipe-sized read lets us observe that output has begun. The rest
    // of the responses exceed any normal pipe capacity, so the writer stalls.
    let fd = child.0.stdout.as_ref().unwrap().as_raw_fd();
    assert!(unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, 4096) } >= 4096);
    let mut greeting = [0; 26];
    child
        .0
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut greeting)
        .unwrap();
    assert!(greeting.starts_with(b"OK pinentry-omarchy ready\n"));
    child
}

fn wait_for_exit(process: &mut Process) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "Blocked protocol output did not exit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn full_stdout_pipe_is_cancellable() {
    let mut process = stalled_session();
    std::thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    assert_eq!(
        unsafe { libc::kill(process.0.id() as i32, libc::SIGTERM) },
        0
    );
    assert!(wait_for_exit(&mut process).success());
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn full_stdout_pipe_has_a_transport_deadline() {
    let mut process = stalled_session();
    let status = wait_for_exit(&mut process);
    assert!(
        !status.success(),
        "A stalled response must fail after its deadline"
    );
}
