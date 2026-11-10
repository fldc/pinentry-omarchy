use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::ptr::NonNull;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const MAX_SECRET: usize = 4096;

// A dedicated allocation avoids heap reallocations and shared-page munlock bugs.
pub struct Secret {
    memory: NonNull<u8>,
    length: usize,
    cursor: usize,
}

impl Secret {
    pub fn new() -> io::Result<Self> {
        // SAFETY: anonymous, private mapping; no file descriptor is involved.
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                MAX_SECRET,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if memory == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: memory is a live mapping of MAX_SECRET bytes.
        let protected = unsafe {
            libc::mlock(memory, MAX_SECRET) == 0
                && libc::madvise(memory, MAX_SECRET, libc::MADV_DONTDUMP) == 0
                && libc::madvise(memory, MAX_SECRET, libc::MADV_WIPEONFORK) == 0
        };
        if !protected {
            let error = io::Error::last_os_error();
            // SAFETY: this mapping has not escaped and is still live.
            unsafe {
                libc::munmap(memory, MAX_SECRET);
            }
            return Err(error);
        }
        Ok(Self {
            memory: NonNull::new(memory.cast()).expect("mmap returned null"),
            length: 0,
            cursor: 0,
        })
    }

    fn storage(&self) -> &[u8] {
        // SAFETY: allocation stays live for self, and mutation requires &mut self.
        unsafe { std::slice::from_raw_parts(self.memory.as_ptr(), MAX_SECRET) }
    }

    pub fn storage_mut(&mut self) -> &mut [u8] {
        // SAFETY: self exclusively owns this live allocation.
        unsafe { std::slice::from_raw_parts_mut(self.memory.as_ptr(), MAX_SECRET) }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.storage()[..self.length]
    }
    pub fn text(&self) -> &str {
        std::str::from_utf8(self.bytes()).expect("validated secret")
    }
    pub fn count(&self) -> usize {
        self.text().chars().count()
    }
    pub fn cursor_count(&self) -> usize {
        self.text()[..self.cursor].chars().count()
    }

    pub fn finish_read(&mut self, length: usize) -> io::Result<()> {
        if length > MAX_SECRET {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let data = &self.storage()[..length];
        if data.contains(&0) || std::str::from_utf8(data).is_err() {
            self.clear();
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.length = length;
        self.cursor = length;
        Ok(())
    }

    pub fn insert(&mut self, text: &str) -> bool {
        if text.contains('\0') || self.length + text.len() > MAX_SECRET {
            return false;
        }
        let cursor = self.cursor;
        let length = self.length;
        self.storage_mut()
            .copy_within(cursor..length, cursor + text.len());
        self.storage_mut()[cursor..cursor + text.len()].copy_from_slice(text.as_bytes());
        self.length += text.len();
        self.cursor += text.len();
        true
    }

    fn previous(&self) -> usize {
        self.text()[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(i, _)| i)
    }

    fn next(&self) -> usize {
        self.cursor
            + self.text()[self.cursor..]
                .chars()
                .next()
                .map_or(0, char::len_utf8)
    }

    pub fn edit(&mut self, operation: i32) {
        let range = match operation {
            0 => Some((self.previous(), self.cursor)), // Backspace.
            1 => Some((self.cursor, self.next())),     // Delete.
            2 => {
                self.cursor = self.previous();
                None
            }
            3 => {
                self.cursor = self.next();
                None
            }
            4 => {
                self.cursor = 0;
                None
            }
            5 => {
                self.cursor = self.length;
                None
            }
            6 => {
                self.clear();
                None
            }
            _ => None,
        };
        if let Some((start, end)) = range {
            let old_length = self.length;
            self.storage_mut().copy_within(end..old_length, start);
            self.length -= end - start;
            self.cursor = start;
            let length = self.length;
            self.storage_mut()[length..old_length].zeroize();
        }
    }

    pub fn clear(&mut self) {
        self.storage_mut().zeroize();
        self.length = 0;
        self.cursor = 0;
    }

    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.storage().ct_eq(other.storage()) & self.length.ct_eq(&other.length))
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.clear();
        // SAFETY: self still exclusively owns this live, locked mapping.
        unsafe {
            libc::munlock(self.memory.as_ptr().cast(), MAX_SECRET);
            libc::munmap(self.memory.as_ptr().cast(), MAX_SECRET);
        }
    }
}

pub fn harden() -> io::Result<()> {
    // SAFETY: these process-local options take integers and a valid rlimit pointer.
    let result = unsafe {
        libc::setrlimit(
            libc::RLIMIT_CORE,
            &libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            },
        ) == 0
            && libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
            && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
    };
    if result {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn verify_peer(stream: &UnixStream, uid: u32, pid: u32) -> io::Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: both output pointers refer to live buffers with the indicated size.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if credentials.uid != uid || credentials.pid as u32 != pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unexpected socket peer",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_preserves_unicode_and_wipes_deleted_tail() {
        let mut secret = Secret::new().unwrap();
        assert!(secret.insert("räksmörgås"));
        secret.edit(4);
        secret.edit(3);
        secret.edit(1);
        assert_eq!(secret.text(), "rksmörgås");
        secret.edit(5);
        secret.edit(0);
        assert_eq!(secret.text(), "rksmörgå");
        assert!(secret.storage()[secret.length..].iter().all(|b| *b == 0));
        secret.clear();
        assert!(secret.storage().iter().all(|b| *b == 0));
    }

    #[test]
    fn maximum_size_and_repeat_are_enforced() {
        let mut a = Secret::new().unwrap();
        let mut b = Secret::new().unwrap();
        assert!(a.insert(&"x".repeat(MAX_SECRET)));
        assert!(!a.insert("x"));
        assert!(!a.insert("\0"));
        assert!(!a.matches(&b));
        assert!(b.insert(&"x".repeat(MAX_SECRET)));
        assert!(a.matches(&b));
    }

    #[test]
    fn socket_authentication_rejects_other_pid() {
        let (a, _) = UnixStream::pair().unwrap();
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        verify_peer(&a, uid, std::process::id()).unwrap();
        assert!(verify_peer(&a, uid, std::process::id() + 1).is_err());
    }

    #[test]
    fn kernel_marks_secret_memory_locked_nondumpable_and_wiped_on_fork() {
        let secret = Secret::new().unwrap();
        let address = secret.memory.as_ptr() as usize;
        let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut found = false;
        for line in maps.lines() {
            if let Some((start, rest)) = line.split_once('-')
                && let (Ok(start), Some(end)) = (
                    usize::from_str_radix(start, 16),
                    rest.split_whitespace().next(),
                )
                && let Ok(end) = usize::from_str_radix(end, 16)
            {
                found = address >= start && address < end;
            }
            if found && line.starts_with("VmFlags:") {
                for flag in ["lo", "dd", "wf"] {
                    assert!(
                        line.split_whitespace().any(|value| value == flag),
                        "Missing kernel memory protection: {flag}"
                    );
                }
                return;
            }
        }
        panic!("Secret mapping not found");
    }
}
