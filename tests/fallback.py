#!/usr/bin/env python3
"""Exercise real curses delegation with dummy input; never touches rbw or the desktop."""
import fcntl
import os
import pathlib
import pty
import select
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else str(
    pathlib.Path("target/debug/pinentry-omarchy").resolve()
)


class Fallback(unittest.TestCase):
    def prompt(self, display=None, stale=False, cancel=False, timeout=False):
        with tempfile.TemporaryDirectory() as runtime:
            if stale:
                listener = socket.socket(socket.AF_UNIX)
                listener.bind(runtime + "/wayland-test")
                listener.close()
            env = os.environ.copy()
            for key in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE"):
                env.pop(key, None)
            env.update(XDG_RUNTIME_DIR=runtime, TERM="xterm-256color", LC_ALL="C.UTF-8")
            if display is not None:
                env["WAYLAND_DISPLAY"] = display
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            original = termios.tcgetattr(slave)

            def setup():
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

            process = subprocess.Popen(
                [BINARY, "--timeout", "1" if timeout else "0", "--ttyname", os.ttyname(slave)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, preexec_fn=setup,
            )
            try:
                # Match rbw: close command stdin immediately after GETPIN.
                process.stdin.write(b"SETPROMPT Dummy password:\nGETPIN\n")
                process.stdin.close()
                screen = b""
                sent = False
                end = time.monotonic() + 6
                while process.poll() is None and time.monotonic() < end:
                    ready, _, _ = select.select([master], [], [], 0.05)
                    if ready:
                        screen += os.read(master, 8192)
                    if b"Dummy password:" in screen and not sent:
                        self.assertFalse(termios.tcgetattr(slave)[3] & termios.ECHO)
                        if not timeout:
                            os.write(master, b"\t\t\r" if cancel else "dummy-räksmörgås%\r".encode())
                        sent = True
                self.assertIsNotNone(process.poll(), "terminal prompt did not exit")
                output = process.stdout.read()
                self.assertTrue(sent, "curses did not use the supplied terminal")
                self.assertNotIn(b"pinentry-omarchy ready", output)
                self.assertIn(b"falling back to curses", process.stderr.read())
                self.assertEqual(termios.tcgetattr(slave), original)
                if cancel or timeout:
                    self.assertIn(b"ERR ", output)
                    self.assertNotIn(b"D ", output)
                else:
                    self.assertIn("D dummy-räksmörgås%25\n".encode(), output)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                for stream in (process.stdout, process.stderr):
                    stream.close()
                os.close(master)
                os.close(slave)

    def test_headless_entry(self):
        self.prompt()

    def test_missing_display_entry(self):
        self.prompt(display="wayland-missing")

    def test_stale_display_entry(self):
        self.prompt(display="wayland-test", stale=True)

    def test_cancellation(self):
        self.prompt(cancel=True)

    def test_timeout(self):
        self.prompt(timeout=True)

    def test_version_stays_omarchy(self):
        env = os.environ.copy()
        env.pop("WAYLAND_DISPLAY", None)
        result = subprocess.run([BINARY, "--version"], env=env, capture_output=True, check=True)
        self.assertTrue(result.stdout.startswith(b"pinentry-omarchy "))
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
