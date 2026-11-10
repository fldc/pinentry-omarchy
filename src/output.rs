//! Unbuffered, cancellable output: passwords never enter a heap output buffer.
use std::io::{self, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub struct DirectOutput<'a> {
    fd: BorrowedFd<'a>,
    stopped: &'a AtomicBool,
    original_flags: libc::c_int,
    started: Option<Instant>,
    timeout: Duration,
}

impl<'a> DirectOutput<'a> {
    pub fn new(fd: BorrowedFd<'a>, stopped: &'a AtomicBool) -> io::Result<Self> {
        // SAFETY: fd is borrowed for this object's lifetime; fcntl takes integers.
        let original_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if original_flags < 0
            || unsafe {
                libc::fcntl(
                    fd.as_raw_fd(),
                    libc::F_SETFL,
                    original_flags | libc::O_NONBLOCK,
                )
            } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            stopped,
            original_flags,
            started: None,
            timeout: Duration::from_secs(2),
        })
    }
}

impl Write for DirectOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let started = *self.started.get_or_insert_with(Instant::now);
        loop {
            if self.stopped.load(Ordering::Relaxed) {
                return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
            }
            let remaining = self.timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            // SAFETY: the borrowed descriptor and input slice are live. Nonblocking
            // pipe/socket writes cannot trap us inside write when the reader stalls.
            let result =
                unsafe { libc::write(self.fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
            if result >= 0 {
                return Ok(result as usize);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {}
                _ => return Err(error),
            }
            let mut fd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let millis = remaining.as_millis().clamp(1, 100) as i32;
            // SAFETY: fd points to one live pollfd.
            if unsafe { libc::poll(&mut fd, 1, millis) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // A response has one overall deadline, including every escaped byte and
        // data line. A reader making tiny progress cannot keep a secret forever.
        self.started = None;
        Ok(())
    }
}

impl Drop for DirectOutput<'_> {
    fn drop(&mut self) {
        // SAFETY: the descriptor is still borrowed. Restore the caller's flags.
        unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, self.original_flags) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn stalled_output_times_out_and_restores_flags() {
        let (writer, _reader) = UnixStream::pair().unwrap();
        let stopped = AtomicBool::new(false);
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        let mut output = DirectOutput::new(writer.as_fd(), &stopped).unwrap();
        output.timeout = Duration::from_millis(40);
        let start = Instant::now();
        let error = output.write_all(&vec![0; 4 * 1024 * 1024]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(output);
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
            flags
        );
    }

    #[test]
    fn response_deadline_spans_writes_and_resets_after_flush() {
        let (writer, _reader) = UnixStream::pair().unwrap();
        let stopped = AtomicBool::new(false);
        let mut output = DirectOutput::new(writer.as_fd(), &stopped).unwrap();
        output.timeout = Duration::from_millis(20);
        output.write_all(b"D ").unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(
            output.write(b"x").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        output.flush().unwrap();
        output.write_all(b"OK\n").unwrap();
        stopped.store(true, Ordering::Relaxed);
        assert_eq!(
            output.write(b"x").unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
