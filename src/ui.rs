//! Small C ABI for Qt: no function exports the password to QML or C++.
use crate::metadata;
use crate::secure::{Secret, harden, verify_peer};
use std::ffi::{CString, c_char};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct Session {
    socket: UnixStream,
    metadata: CString,
    fields: [Secret; 2],
    password: bool,
    repeat: bool,
    submitted: bool,
    rejected: [bool; 2],
}

fn open() -> io::Result<Session> {
    // LD_PRELOAD failures are not fatal to the loader. Refuse input unless the
    // selected startup guard actually ran, rather than relying on its presence.
    let startup_ready =
        unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"pinentry_startup_ready".as_ptr()) };
    if startup_ready.is_null() {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    // SAFETY: this symbol is supplied by our trusted native/startup.c with this
    // C signature. The preloaded library stays loaded for the process lifetime.
    let startup_ready: unsafe extern "C" fn() -> libc::c_int =
        unsafe { std::mem::transmute(startup_ready) };
    if unsafe { startup_ready() } != 1 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    harden()?;
    let path = std::env::var_os("PINENTRY_OMARCHY_SOCKET").ok_or(io::ErrorKind::NotFound)?;
    let pid = std::env::var("PINENTRY_OMARCHY_PARENT")
        .ok()
        .and_then(|p| p.parse().ok())
        .ok_or(io::ErrorKind::InvalidInput)?;
    let mut socket = UnixStream::connect(path)?;
    // SAFETY: geteuid has no preconditions.
    verify_peer(&socket, unsafe { libc::geteuid() }, pid)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let data = metadata::read(&mut socket)?;
    let metadata: serde_json::Value = serde_json::from_slice(&data)?;
    let password = metadata["mode"] == "getpin";
    let repeat = metadata.get("repeat").is_some();
    Ok(Session {
        socket,
        metadata: CString::new(data).map_err(|_| io::ErrorKind::InvalidData)?,
        fields: [Secret::new()?, Secret::new()?],
        password,
        repeat,
        submitted: false,
        rejected: [false; 2],
    })
}

// Qt owns this handle on its GUI thread. Every unsafe boundary is kept here;
// callers must supply a live handle and only free it once.
#[unsafe(no_mangle)]
pub extern "C" fn pe_open() -> *mut Session {
    match open() {
        Ok(session) => Box::into_raw(Box::new(session)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_close(session: *mut Session) {
    if !session.is_null() {
        // SAFETY: Qt transfers sole ownership of a live pe_open handle back here.
        unsafe {
            drop(Box::from_raw(session));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_metadata(session: *const Session) -> *const c_char {
    // SAFETY: Qt keeps the handle alive while copying non-secret metadata.
    unsafe { (*session).metadata.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_insert(
    session: *mut Session,
    field: usize,
    data: *const u8,
    length: usize,
) -> bool {
    if field > 1 {
        return false;
    }
    // SAFETY: Qt exclusively borrows its live session on the GUI thread.
    let session = unsafe { &mut *session };
    if session.submitted || session.rejected[field] {
        return false;
    }
    let accepted = length <= crate::secure::MAX_SECRET && {
        // SAFETY: Qt lends a live UTF-8 buffer for the indicated length.
        let bytes = unsafe { std::slice::from_raw_parts(data, length) };
        std::str::from_utf8(bytes).is_ok_and(|text| session.fields[field].insert(text))
    };
    session.rejected[field] = !accepted;
    accepted
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_edit(session: *mut Session, field: usize, operation: i32) {
    if field <= 1 {
        // SAFETY: Qt exclusively borrows its live session on the GUI thread.
        let session = unsafe { &mut *session };
        if !session.submitted {
            session.fields[field].edit(operation);
            // Require an explicit clear/re-entry so rejected suffixes can never
            // silently turn into an accepted prefix, even after cursor edits.
            if operation == 6 {
                session.rejected[field] = false;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_rejected(session: *const Session, field: usize) -> bool {
    // SAFETY: Qt borrows its live handle on the GUI thread.
    field <= 1 && unsafe { (*session).rejected[field] }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_count(session: *const Session, field: usize, cursor: bool) -> usize {
    if field > 1 {
        return 0;
    }
    // SAFETY: Qt borrows its live handle on the GUI thread.
    let secret = unsafe { &(*session).fields[field] };
    if cursor {
        secret.cursor_count()
    } else {
        secret.count()
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_submit(session: *mut Session, accept: bool) -> i32 {
    // SAFETY: Qt exclusively borrows its live session on the GUI thread.
    let session = unsafe { &mut *session };
    if session.submitted {
        return -1;
    }
    if accept
        && session.password
        && (session.rejected[0] || (session.repeat && session.rejected[1]))
    {
        return -2;
    }
    if accept
        && session.password
        && session.repeat
        && !session.fields[0].matches(&session.fields[1])
    {
        session.fields[1].clear();
        return 0;
    }
    session.submitted = true;
    let secret = if accept && session.password {
        session.fields[0].bytes()
    } else {
        &[]
    };
    // A bounded binary frame avoids JSON/JavaScript/Qt secret serialization.
    let result = (|| -> io::Result<()> {
        session.socket.write_all(&[u8::from(accept)])?;
        session
            .socket
            .write_all(&(secret.len() as u32).to_be_bytes())?;
        session.socket.write_all(secret)?;
        Ok(())
    })();
    for field in &mut session.fields {
        field.clear();
    }
    session.rejected = [false; 2];
    if result.is_err() {
        return -1;
    }
    let mut acknowledgment = [0; 5];
    if session.socket.read_exact(&mut acknowledgment).is_ok() && acknowledgment == *b"done\n" {
        1
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::MAX_SECRET;

    fn session(repeat: bool) -> (Session, UnixStream) {
        let (socket, peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        (
            Session {
                socket,
                metadata: CString::new("{}").unwrap(),
                fields: [Secret::new().unwrap(), Secret::new().unwrap()],
                password: true,
                repeat,
                submitted: false,
                rejected: [false; 2],
            },
            peer,
        )
    }

    fn insert(session: &mut Session, field: usize, text: &str) -> bool {
        // SAFETY: this test exclusively lends a live session and text buffer.
        unsafe { pe_insert(session, field, text.as_ptr(), text.len()) }
    }

    #[test]
    fn multibyte_overflow_blocks_submission_until_explicit_clear() {
        let (mut session, mut peer) = session(false);
        assert!(insert(&mut session, 0, &"é".repeat(MAX_SECRET / 2)));
        assert!(!insert(&mut session, 0, "x"));
        assert!(unsafe { pe_rejected(&session, 0) });
        assert_eq!(unsafe { pe_submit(&mut session, true) }, -2);
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        unsafe { pe_edit(&mut session, 0, 0) }; // Deleting does not bless a truncated prefix.
        assert!(!insert(&mut session, 0, "x"));
        assert_eq!(unsafe { pe_submit(&mut session, true) }, -2);
        unsafe { pe_edit(&mut session, 0, 6) };
        assert!(!unsafe { pe_rejected(&session, 0) });
        assert!(insert(&mut session, 0, "re-entered"));
        peer.write_all(b"done\n").unwrap();
        assert_eq!(unsafe { pe_submit(&mut session, true) }, 1);
        let mut frame = [0; 15];
        peer.read_exact(&mut frame).unwrap();
        assert_eq!(&frame[..5], &[1, 0, 0, 0, 10]);
        assert_eq!(&frame[5..], b"re-entered");
        assert!(session.fields[0].bytes().is_empty());
    }

    #[test]
    fn matching_truncated_prefixes_never_pass_repeat() {
        let (mut session, mut peer) = session(true);
        for field in 0..2 {
            assert!(insert(&mut session, field, &"x".repeat(MAX_SECRET)));
        }
        assert!(!insert(&mut session, 0, "a"));
        assert!(!insert(&mut session, 1, "b"));
        assert!(session.fields[0].matches(&session.fields[1]));
        assert_eq!(unsafe { pe_submit(&mut session, true) }, -2);
        // Cancellation remains available even with rejected input.
        peer.write_all(b"done\n").unwrap();
        assert_eq!(unsafe { pe_submit(&mut session, false) }, 1);
        let mut frame = [1; 5];
        peer.read_exact(&mut frame).unwrap();
        assert_eq!(frame, [0; 5]);
        assert!(session.fields.iter().all(|field| field.bytes().is_empty()));
    }

    #[test]
    fn oversized_single_event_and_invalid_utf8_are_latched() {
        let (mut session, _peer) = session(false);
        assert!(!insert(&mut session, 0, &"x".repeat(MAX_SECRET + 1)));
        assert_eq!(unsafe { pe_submit(&mut session, true) }, -2);
        unsafe { pe_edit(&mut session, 0, 6) };
        assert!(!unsafe { pe_insert(&mut session, 0, [0xff].as_ptr(), 1) });
        assert_eq!(unsafe { pe_submit(&mut session, true) }, -2);
    }

    #[test]
    fn missing_startup_guard_refuses_input() {
        assert_eq!(
            open().err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
