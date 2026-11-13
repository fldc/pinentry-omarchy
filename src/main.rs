use pinentry_secure::assuan;
use pinentry_secure::metadata;
use pinentry_secure::secure::{MAX_SECRET, Secret, harden, verify_peer};
mod fallback;
mod output;
use output::DirectOutput;
use serde_json::{Map, Value, json};
use std::env;
use std::fs::{self, Permissions};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

const CANCEL: &str = "ERR 83886179 Operation cancelled";
const FAILURE: &str = "ERR 83886081 Pinentry UI failed";
const UNKNOWN: &str = "ERR 83886355 Unknown command";

struct Response {
    action: String,
    secret: Option<Secret>,
}

impl Response {
    fn cancelled() -> Self {
        Self {
            action: "cancel".into(),
            secret: None,
        }
    }
}

// Every exit path, including timeout or a signal, reaps this particular UI.
struct UiProcess(Child);

// A terminated pinentry must also wake while waiting for the next Assuan line.
struct SessionInput(Arc<AtomicBool>);

impl Read for SessionInput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.0.load(Ordering::Relaxed) {
                return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
            }
            let mut fd = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: fd points to one initialized pollfd for the duration of the call.
            let ready = unsafe { libc::poll(&mut fd, 1, 100) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready > 0 {
                // SAFETY: buffer is writable for buffer.len() bytes; stdin is borrowed, not closed.
                let length = unsafe {
                    libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len())
                };
                if length >= 0 {
                    return Ok(length as usize);
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

impl Drop for UiProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn decode(value: &str) -> io::Result<String> {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(a), Some(b)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                result.push((a * 16 + b) as u8);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).map_err(|_| invalid("Invalid UTF-8"))
}

fn write_data(output: &mut impl Write, value: &str) -> io::Result<()> {
    output.write_all(b"D ")?;
    let mut line_length = 2;
    // Escape directly to the caller, without allocating another secret string.
    for (offset, character) in value.char_indices() {
        let encoded = match character {
            '%' => b"%25".as_slice(),
            '\r' => b"%0D".as_slice(),
            '\n' => b"%0A".as_slice(),
            _ => &value.as_bytes()[offset..offset + character.len_utf8()],
        };
        // Assuan permits 1000 bytes including the prefix and CRLF. Keep
        // UTF-8 characters and percent escapes intact across data lines.
        if line_length + encoded.len() + 2 > assuan::MAX_LINE {
            output.write_all(b"\nD ")?;
            line_length = 2;
        }
        output.write_all(encoded)?;
        line_length += encoded.len();
    }
    output.write_all(b"\n")
}

fn dialog(request: &Value, timeout: Duration, stopped: &AtomicBool) -> io::Result<Response> {
    // Validate the total serialized size before any UI process is launched.
    let request_data = metadata::encode(request)?;
    let runtime =
        env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| invalid("XDG_RUNTIME_DIR required"))?;
    let metadata = fs::metadata(&runtime)?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(invalid("XDG_RUNTIME_DIR must be private and user-owned"));
    }
    let directory = tempfile::Builder::new()
        .prefix("pinentry-")
        .tempdir_in(runtime)?;
    fs::set_permissions(directory.path(), Permissions::from_mode(0o700))?;
    let path = directory.path().join("ui.sock");
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let executable = env::current_exe()?;
    let base = executable
        .parent()
        .ok_or_else(|| invalid("Missing executable directory"))?;
    // Cargo integration tests run target/debug; installed binaries use sibling qml/.
    let module_path = if executable == std::path::Path::new("/usr/bin/pinentry-omarchy") {
        std::path::PathBuf::from("/usr/lib/pinentry-omarchy/qml")
    } else if base
        .join("qml/Omarchy/Pinentry/libpinentrynative.so")
        .is_file()
    {
        base.join("qml")
    } else {
        let project = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        if base != project.join("target/debug") && base != project.join("target/release") {
            return Err(invalid("Native input module is missing"));
        }
        project.join("qml")
    };
    if !module_path
        .join("Omarchy/Pinentry/libpinentrynative.so")
        .is_file()
    {
        return Err(invalid("Build the native input module with bin/build"));
    }
    let startup_guard = module_path.join("Omarchy/Pinentry/libpinentrystartup.so");
    if !startup_guard.is_file() {
        return Err(invalid("Build the startup guard with bin/build"));
    }
    // Load package-owned code directly, never a writable runtime copy of QML.
    let qml = module_path
        .parent()
        .ok_or_else(|| invalid("Missing UI directory"))?
        .join("shell.qml");
    if !qml.is_file() {
        return Err(invalid("UI source is missing"));
    }
    if executable == std::path::Path::new("/usr/bin/pinentry-omarchy") {
        for code in [
            executable.as_path(),
            module_path.parent().expect("UI parent"),
            qml.as_path(),
            module_path.as_path(),
            module_path.join("Omarchy").as_path(),
            module_path.join("Omarchy/Pinentry").as_path(),
            module_path.join("Omarchy/Pinentry/qmldir").as_path(),
            module_path
                .join("Omarchy/Pinentry/libpinentrynative.so")
                .as_path(),
            startup_guard.as_path(),
        ] {
            let metadata = fs::metadata(code)?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(invalid(
                    "Installed UI code must be root-owned and not group/world writable",
                ));
            }
        }
    }
    let parent_pid = std::process::id();
    let mut command = Command::new("/usr/bin/quickshell");
    command.arg("-p").arg(qml).env_clear();
    for key in [
        "HOME",
        "XDG_RUNTIME_DIR",
        "WAYLAND_DISPLAY",
        "HYPRLAND_INSTANCE_SIGNATURE",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "XCURSOR_SIZE",
        "XCURSOR_THEME",
    ] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("PATH", "/usr/bin")
        .env("PINENTRY_OMARCHY_SOCKET", &path)
        .env("PINENTRY_OMARCHY_PARENT", parent_pid.to_string())
        .env("QML_IMPORT_PATH", module_path)
        // Only this explicitly selected, validated library may be preloaded.
        .env("LD_PRELOAD", startup_guard)
        .env("QML_DISABLE_DISK_CACHE", "1")
        .env("QT_QPA_PLATFORM", "wayland")
        .env("QT_IM_MODULE", "none")
        .env("QT_ACCESSIBILITY", "0")
        .env("QT_LINUX_ACCESSIBILITY_ALWAYS_ON", "0")
        .env("NO_AT_BRIDGE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the child hook only calls async-signal-safe Linux syscalls.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() as u32 != parent_pid {
                return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
            }
            Ok(())
        });
    }
    let mut child = UiProcess(command.spawn()?);
    let startup_deadline = Instant::now() + Duration::from_secs(10);
    // rbw explicitly sends --timeout 0, which means no interaction timeout.
    let deadline = if timeout.is_zero() {
        None
    } else {
        Some(Instant::now() + timeout)
    };
    let expired = || deadline.is_some_and(|deadline| Instant::now() >= deadline);
    let mut connection = loop {
        if stopped.load(Ordering::Relaxed) || expired() || caller_disconnected() {
            return Ok(Response::cancelled());
        }
        if Instant::now() >= startup_deadline {
            return Err(invalid("UI startup timed out"));
        }
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if child.0.try_wait()?.is_some() {
                    return Err(invalid("UI exited before connecting"));
                }
                // Wait for socket readiness rather than polling an idle desktop.
                let mut fd = libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: fd points to one initialized pollfd for this call.
                unsafe { libc::poll(&mut fd, 1, 100) };
            }
            Err(e) => return Err(e),
        }
    };
    verify_peer(&connection, uid, child.0.id())?;
    connection.set_write_timeout(Some(Duration::from_secs(2)))?;
    metadata::write(&mut connection, &request_data)?;
    connection.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut header = [0u8; 5];
    let mut received = 0;
    let mut secret = Secret::new()?;
    loop {
        if stopped.load(Ordering::Relaxed) || expired() || caller_disconnected() {
            return Ok(Response::cancelled());
        }
        let length = if received >= header.len() {
            u32::from_be_bytes(header[1..].try_into().expect("fixed header")) as usize
        } else {
            0
        };
        if length > MAX_SECRET || header[0] > 1 {
            return Err(invalid("Invalid response frame"));
        }
        if received >= header.len() + length {
            secret.finish_read(length)?;
            if header[0] == 0 && length != 0 {
                return Err(invalid("Invalid cancellation frame"));
            }
            connection.write_all(b"done\n")?;
            return Ok(Response {
                action: if header[0] == 1 { "accept" } else { "cancel" }.into(),
                secret: if header[0] == 1 { Some(secret) } else { None },
            });
        }
        let buffer = if received < header.len() {
            &mut header[received..]
        } else {
            &mut secret.storage_mut()[received - header.len()..length]
        };
        match connection.read(buffer) {
            Ok(0) => return Err(invalid("UI disconnected")),
            Ok(length) => received += length,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
}

fn caller_disconnected() -> bool {
    let mut fd = libc::pollfd {
        fd: libc::STDOUT_FILENO,
        events: 0,
        revents: 0,
    };
    // SAFETY: fd points to one initialized pollfd; no secret data is read.
    unsafe { libc::poll(&mut fd, 1, 0) };
    fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
}

fn request(state: &Map<String, Value>, mode: &str, one_button: bool) -> Value {
    let mut request = state.clone();
    request.insert("mode".into(), json!(mode));
    request.insert("oneButton".into(), json!(one_button));
    Value::Object(request)
}

fn serve(
    mut input: impl BufRead,
    mut output: impl Write,
    mut timeout: Duration,
    mut ask: impl FnMut(&Value, Duration) -> io::Result<Response>,
) -> io::Result<()> {
    let mut state = Map::new();
    writeln!(output, "OK pinentry-omarchy ready")?;
    output.flush()?;
    loop {
        let mut line = String::new();
        if input.by_ref().take(65537).read_line(&mut line)? == 0 {
            break;
        }
        if line.len() > 65536 {
            writeln!(output, "{FAILURE}")?;
            output.flush()?;
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (command, argument) = line.split_once(' ').unwrap_or((line, ""));
        let argument = match decode(argument) {
            Ok(value) => value,
            Err(_) => {
                writeln!(output, "{FAILURE}")?;
                output.flush()?;
                continue;
            }
        };
        match command.to_ascii_uppercase().as_str() {
            "BYE" => {
                writeln!(output, "OK closing connection")?;
                output.flush()?;
                break;
            }
            "RESET" => {
                state.clear();
                writeln!(output, "OK")?;
            }
            "OPTION" => {
                if let Some(value) = argument.strip_prefix("timeout=") {
                    if let Ok(seconds) = value.parse::<u32>() {
                        timeout = Duration::from_secs(u64::from(seconds));
                        writeln!(output, "OK")?;
                    } else {
                        writeln!(output, "{FAILURE}")?;
                    }
                } else if matches!(
                    argument.split('=').next().unwrap_or(""),
                    "ttyname"
                        | "ttytype"
                        | "ttyalert"
                        | "lc-ctype"
                        | "lc-messages"
                        | "display"
                        | "owner"
                        | "parent-wid"
                        | "grab"
                        | "no-grab"
                ) {
                    writeln!(output, "OK")?;
                } else {
                    writeln!(output, "ERR 83886254 Unknown option")?;
                }
            }
            command @ ("SETTITLE" | "SETDESC" | "SETPROMPT" | "SETERROR" | "SETOK"
            | "SETCANCEL" | "SETNOTOK" | "SETREPEAT" | "SETREPEATERROR"
            | "SETREPEATOK") => {
                let key = command[3..].to_ascii_lowercase();
                let previous = state.insert(key.clone(), Value::String(argument));
                // Reserve the largest mode and boolean encodings too. A failed
                // SET leaves the previous accepted state intact.
                if metadata::encode(&request(&state, "message", false)).is_err() {
                    if let Some(previous) = previous {
                        state.insert(key, previous);
                    } else {
                        state.remove(&key);
                    }
                    writeln!(output, "ERR 83886081 UI request too large")?;
                } else {
                    writeln!(output, "OK")?;
                }
            }
            command @ ("GETPIN" | "CONFIRM" | "MESSAGE") => {
                let request = request(
                    &state,
                    &command.to_ascii_lowercase(),
                    argument.split_whitespace().any(|a| a == "--one-button"),
                );
                match metadata::encode(&request).and_then(|_| ask(&request, timeout)) {
                    Ok(response) if response.action == "accept" => {
                        if command == "GETPIN" {
                            if let Some(secret) = response.secret.as_ref() {
                                // Defense in depth: no accepted password may
                                // depend on rbw reading multiple data lines.
                                if assuan::encoded_len(secret.bytes()) > assuan::MAX_DATA {
                                    writeln!(output, "{FAILURE}")?;
                                } else {
                                    write_data(&mut output, secret.text())?;
                                    if state.contains_key("repeat") {
                                        writeln!(output, "S PIN_REPEATED")?;
                                    }
                                    writeln!(output, "OK")?;
                                }
                            } else {
                                writeln!(output, "{FAILURE}")?;
                            }
                        } else {
                            writeln!(output, "OK")?;
                        }
                    }
                    Ok(_) => writeln!(output, "{CANCEL}")?,
                    Err(_) => writeln!(output, "{FAILURE}")?,
                }
                state.remove("error");
            }
            "GETINFO" => {
                let value = match argument.as_str() {
                    "pid" => Some(std::process::id().to_string()),
                    "version" => Some(env!("CARGO_PKG_VERSION").into()),
                    "flavor" => Some("quickshell".into()),
                    _ => None,
                };
                if let Some(value) = value {
                    write_data(&mut output, &value)?;
                    writeln!(output, "OK")?;
                } else {
                    writeln!(output, "{UNKNOWN}")?;
                }
            }
            "NOP" => writeln!(output, "OK")?,
            _ => writeln!(output, "{UNKNOWN}")?,
        }
        output.flush()?;
    }
    Ok(())
}

fn main() -> io::Result<()> {
    harden()?;
    // Select before DirectOutput changes stdout flags or the protocol begins.
    fallback::select()?;
    let stopped = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stopped))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stopped))?;
    // SAFETY: stdout remains open for this borrow; DirectOutput restores flags.
    let stdout = unsafe { BorrowedFd::borrow_raw(libc::STDOUT_FILENO) };
    let mut output = DirectOutput::new(stdout, &stopped)?;
    let mut preview = false;
    let mut timeout = Duration::from_secs(120);
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--preview" => preview = true,
            "--timeout" | "-o" => {
                let seconds = arguments
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
                    .ok_or_else(|| invalid("Invalid timeout"))?;
                timeout = Duration::from_secs(u64::from(seconds));
            }
            "--version" => {
                writeln!(output, "pinentry-omarchy {}", env!("CARGO_PKG_VERSION"))?;
                return Ok(());
            }
            "--help" | "-h" => {
                writeln!(output, "pinentry-omarchy [--preview] [--timeout SECONDS]")?;
                return Ok(());
            }
            // Pinentry callers may pass display/tty options; UI uses the session environment.
            _ => {}
        }
    }
    let result = if preview {
        dialog(&json!({"mode":"getpin", "title":"Pinentry preview", "desc":"Preview only — do not enter a real password.", "prompt":"Master password:"}), timeout, &stopped).map(|_| ())
    } else {
        serve(
            io::BufReader::new(SessionInput(Arc::clone(&stopped))),
            output,
            timeout,
            |request, timeout| dialog(request, timeout, &stopped),
        )
    };
    match result {
        Err(_) if stopped.load(Ordering::Relaxed) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(commands: &str, secret: Option<&str>) -> (String, Vec<Value>) {
        let mut output = Vec::new();
        let mut requests = Vec::new();
        serve(
            commands.as_bytes(),
            &mut output,
            Duration::from_secs(120),
            |request, _| {
                requests.push(request.clone());
                Ok(Response {
                    action: if secret.is_some() { "accept" } else { "cancel" }.into(),
                    secret: secret.and_then(|text| {
                        let mut value = Secret::new().unwrap();
                        if value.insert(text) {
                            Some(value)
                        } else {
                            None
                        }
                    }),
                })
            },
        )
        .unwrap();
        (String::from_utf8(output).unwrap(), requests)
    }

    #[test]
    fn unicode_and_assuan_escaping() {
        let (output, requests) = run(
            "SETDESC Hello%0Aworld+literal\nGETPIN\nBYE\n",
            Some("räksmörgås%\r\n"),
        );
        assert_eq!(requests[0]["desc"], "Hello\nworld+literal");
        assert!(output.contains("D räksmörgås%25%0D%0A\nOK\n"));
    }

    #[test]
    fn cancellation_never_returns_data() {
        let (output, _) = run("GETPIN\n", None);
        assert!(output.contains(CANCEL));
        assert!(!output.contains("D "));
    }

    #[test]
    fn reset_clears_state() {
        let (_, requests) = run("SETERROR Wrong\nSETREPEAT Again\nRESET\nGETPIN\n", None);
        assert!(requests[0].get("error").is_none());
        assert!(requests[0].get("repeat").is_none());
    }

    #[test]
    fn repeat_status_and_stale_error() {
        let (output, requests) = run(
            "SETREPEAT Again\nSETERROR Wrong\nGETPIN\nGETPIN\n",
            Some("dummy"),
        );
        assert!(output.contains("S PIN_REPEATED\n"));
        assert!(requests[1].get("error").is_none());
    }

    #[test]
    fn confirmation_has_no_secret() {
        let (output, requests) = run("CONFIRM --one-button\n", Some("not-for-output"));
        assert_eq!(requests[0]["oneButton"], true);
        assert!(!output.contains("not-for-output"));
    }

    #[test]
    fn unsupported_commands_fail() {
        assert!(run("BOGUS\n", None).0.contains(UNKNOWN));
    }

    #[test]
    fn nul_secret_fails_closed() {
        let (output, _) = run("GETPIN\n", Some("bad\0value"));
        assert!(output.contains(FAILURE));
        assert!(!output.contains("D "));
    }

    #[test]
    fn empty_secret_is_valid() {
        assert!(run("GETPIN\n", Some("")).0.contains("D \nOK\n"));
    }

    #[test]
    fn malformed_utf8_fails_closed() {
        assert!(run("SETDESC %FF\n", None).0.contains(FAILURE));
    }

    #[test]
    fn long_assuan_data_round_trips_with_bounded_lines() {
        for secret in [
            "x".repeat(MAX_SECRET),
            "%\r\né".repeat(MAX_SECRET / 5),
            format!("{}é%", "x".repeat(995)),
        ] {
            let mut output = Vec::new();
            write_data(&mut output, &secret).unwrap();
            let output = String::from_utf8(output).unwrap();
            let mut decoded = String::new();
            for line in output.lines() {
                assert!(line.len() + 2 <= 1000);
                decoded.push_str(&decode(line.strip_prefix("D ").unwrap()).unwrap());
            }
            assert_eq!(decoded, secret);
        }
    }

    #[test]
    fn passwords_requiring_multiple_data_lines_fail_before_delivery() {
        for secret in [
            "x".repeat(assuan::MAX_DATA + 1),
            "%".repeat(assuan::MAX_DATA / 3 + 1),
        ] {
            let (output, _) = run("GETPIN\n", Some(&secret));
            assert!(output.contains(FAILURE));
            assert!(!output.contains("D "));
        }
        let secret = "%".repeat(assuan::MAX_DATA / 3);
        let (output, _) = run("GETPIN\n", Some(&secret));
        assert_eq!(
            output.lines().filter(|line| line.starts_with("D ")).count(),
            1
        );
        assert!(output.ends_with("OK\n"));
    }

    #[test]
    fn oversized_metadata_setters_fail_without_poisoning_accepted_state() {
        let commands = format!(
            "SETDESC original\nSETDESC {}\nSETTITLE {}\nSETPROMPT {}\nGETPIN\n",
            "\0".repeat(12000),
            "x".repeat(33000),
            "y".repeat(33000)
        );
        let (output, requests) = run(&commands, None);
        assert_eq!(output.matches("UI request too large").count(), 2);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["desc"], "original");
        assert_eq!(requests[0]["title"], "x".repeat(33000));
        assert!(requests[0].get("prompt").is_none());
        assert!(metadata::encode(&requests[0]).is_ok());
    }
}
