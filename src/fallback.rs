//! Choose a frontend before emitting or consuming any Assuan protocol data.
use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

fn display_available(runtime: Option<&OsStr>, display: Option<&OsStr>) -> io::Result<bool> {
    let Some(display) = display.filter(|value| !value.is_empty()) else {
        return Ok(false);
    };
    let display = Path::new(display);
    let socket = if display.is_absolute() {
        display.to_path_buf()
    } else if let Some(runtime) = runtime.filter(|value| !value.is_empty()) {
        Path::new(runtime).join(display)
    } else {
        return Ok(false);
    };
    match connect_display(&socket) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn connect_display(path: &Path) -> io::Result<()> {
    // A full compositor connection queue must not block backend selection.
    // SAFETY: socket takes integer constants and returns a new owned descriptor.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is newly opened and has no other owner.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: an all-zero sockaddr_un is valid to initialize before filling it.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid Wayland socket path",
        ));
    }
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as libc::c_char;
    }
    // SAFETY: address is initialized, correctly sized and lives through connect.
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        // These indicate a listening socket with a busy connection queue.
        Some(libc::EAGAIN | libc::EINPROGRESS) => Ok(()),
        _ => Err(error),
    }
}

pub fn select() -> io::Result<()> {
    // Preview and informational commands must never become a terminal prompt.
    if std::env::args_os().skip(1).any(|arg| {
        matches!(
            arg.to_str(),
            Some("--preview" | "--help" | "-h" | "--version")
        )
    }) {
        return Ok(());
    }
    if !display_available(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        std::env::var_os("WAYLAND_DISPLAY").as_deref(),
    )? {
        eprintln!("No Wayland display available, falling back to curses");
        // Replace this process: curses owns the original pipes, terminal,
        // timeout, signals and password. Never relay secrets through a proxy.
        return Err(Command::new("/usr/bin/pinentry-curses")
            .args(std::env::args_os().skip(1))
            .exec());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn missing_and_stale_displays_use_curses() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Some(directory.path().as_os_str());
        assert!(!display_available(runtime, None).unwrap());
        assert!(!display_available(runtime, Some(OsStr::new(""))).unwrap());
        assert!(!display_available(None, Some(OsStr::new("wayland-1"))).unwrap());
        assert!(!display_available(runtime, Some(OsStr::new("wayland-1"))).unwrap());
        let listener = UnixListener::bind(directory.path().join("wayland-1")).unwrap();
        drop(listener);
        assert!(!display_available(runtime, Some(OsStr::new("wayland-1"))).unwrap());
    }

    #[test]
    fn reachable_relative_and_absolute_displays_keep_ui() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("wayland-1");
        let _listener = UnixListener::bind(&socket).unwrap();
        assert!(
            display_available(
                Some(directory.path().as_os_str()),
                Some(OsStr::new("wayland-1"))
            )
            .unwrap()
        );
        assert!(display_available(None, Some(socket.as_os_str())).unwrap());
    }
}
