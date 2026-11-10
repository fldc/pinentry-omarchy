#!/usr/bin/env python3
"""Opt-in desktop integration against rbw 1.15's encrypted local-cache format.

All credentials and entries are generated dummy data. No real account, network
login, clipboard, or existing rbw profile is used. Requires python-cryptography.
Reference: https://docs.rs/crate/rbw/1.15.0/source/src/
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


PROJECT = Path(__file__).resolve().parent.parent
PASSWORD = "dummy%räk-123"
ENTRY = "pinentry-dummy-entry"
ENTRY_PASSWORD = "dummy-entry-password"


def encrypt(keys, plaintext):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(keys[:32]), modes.CBC(iv)).encryptor()
    encrypted = cipher.update(padded) + cipher.finalize()
    mac = hmac.digest(keys[32:], iv + encrypted, "sha256")
    return "2." + "|".join(base64.b64encode(part).decode() for part in (iv, encrypted, mac))


def descendants(pid):
    children = set()
    # rbw spawns pinentry on a Tokio worker; children are listed per thread.
    for task in Path(f"/proc/{pid}/task").glob("*/children"):
        try:
            children.update(int(value) for value in task.read_text().split())
        except FileNotFoundError:
            pass
    return set(children).union(*(descendants(child) for child in children))


def layers():
    monitors = json.loads(subprocess.check_output(["hyprctl", "layers", "-j"]))
    return {layer["pid"] for monitor in monitors.values()
            for level in monitor["levels"].values() for layer in level
            if layer["namespace"] == "pinentry-omarchy"}


class Vault:
    def __init__(self, root):
        self.profile = "pinentry-test-" + uuid.uuid4().hex[:10]
        self.name = "rbw-" + self.profile
        self.runtime = Path(os.environ["XDG_RUNTIME_DIR"]) / self.name
        self.environment = os.environ | {
            "RBW_PROFILE": self.profile,
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "XDG_DATA_HOME": str(root / "data"),
        }
        email = "pinentry-test@example.invalid"
        server = "http://127.0.0.1:9"
        self.config_path = root / "config" / self.name / "config.json"
        self.config = {"email": email, "base_url": server, "identity_url": server,
                       "notifications_url": server, "sync_interval": 0, "lock_timeout": 120,
                       "pinentry": os.environ.get("PINENTRY_TEST_BINARY", str(PROJECT / "pinentry-omarchy"))}
        self.config_path.parent.mkdir(parents=True, mode=0o700)
        self.save_config()
        master = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), email.encode(), 10000)
        identity = b"".join(HKDFExpand(hashes.SHA256(), 32, info).derive(master) for info in (b"enc", b"mac"))
        keys = os.urandom(64)
        database = {"access_token": "dummy", "refresh_token": "dummy", "kdf": "0",
                    "iterations": 10000, "protected_key": encrypt(identity, keys),
                    "protected_private_key": encrypt(keys, b"unused dummy private key"),
                    "protected_org_keys": {}, "entries": [{
                        "id": str(uuid.uuid4()), "org_id": None, "folder": None, "folder_id": None,
                        "name": encrypt(keys, ENTRY.encode()), "data": {"Login": {
                            "username": encrypt(keys, b"dummy-user"),
                            "password": encrypt(keys, ENTRY_PASSWORD.encode()), "totp": None, "uris": []}},
                        "fields": [], "notes": None, "history": [], "key": None,
                        "master_password_reprompt": 0}]}
        cache = root / "cache" / self.name
        cache.mkdir(parents=True, mode=0o700)
        (cache / (quote(server, safe="") + ":" + email + ".json")).write_text(json.dumps(database))
        self.agent = subprocess.Popen(["rbw-agent", "--no-daemonize"], env=self.environment,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pending = None
        for _ in range(100):
            if (self.runtime / "socket").exists():
                break
            assert self.agent.poll() is None, "Isolated rbw-agent failed to start"
            time.sleep(.05)
        else:
            raise AssertionError("Isolated rbw-agent did not create its socket")

    def save_config(self):
        self.config_path.write_text(json.dumps(self.config))

    def run(self, *arguments, success=True):
        result = subprocess.run(["rbw", *arguments], env=self.environment,
                                capture_output=True, text=True, timeout=10)
        assert (result.returncode == 0) == success, (arguments, result.stderr)
        return result

    def start(self, *arguments):
        self.pending = subprocess.Popen(["rbw", *arguments], env=self.environment,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def prompt(self, previous=None):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.pending.poll() is not None:
                _, error = self.pending.communicate()
                raise AssertionError("rbw exited before its password prompt: " + error)
            own_layers = layers() & descendants(self.agent.pid)
            if own_layers and previous not in own_layers:
                time.sleep(.15)
                return own_layers
            time.sleep(.05)
        raise AssertionError("No password prompt from the isolated rbw agent")

    def input(self, prompt, text=None, key="Return"):
        # Bound desktop injection to short dummy values and verify the specific
        # agent's UI is still present immediately before each input operation.
        assert self.pending.poll() is None and prompt <= layers()
        if text is not None:
            assert len(text) <= 32
            subprocess.run(["wtype", text], check=True)
        assert self.pending.poll() is None and prompt <= layers()
        subprocess.run(["wtype", "-k", key], check=True)

    def finish(self, success=True):
        output, error = self.pending.communicate(timeout=10)
        assert (self.pending.returncode == 0) == success, error
        self.pending = None
        return output, error

    def close(self):
        # Only processes descended from this isolated agent can be cleaned up.
        for pid in descendants(self.agent.pid):
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
        if self.pending is not None and self.pending.poll() is None:
            self.pending.kill()
            self.pending.wait()
        stop = subprocess.Popen(["rbw", "stop-agent"], env=self.environment,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            # Reap our foreground agent while rbw's stop command waits for its
            # PID to disappear; a zombie would otherwise keep that command busy.
            self.agent.wait(timeout=5)
            stop.wait(timeout=5)
        finally:
            for process in (self.agent, stop):
                if process.poll() is None:
                    process.kill()
                process.wait()
            shutil.rmtree(self.runtime, ignore_errors=True)


def main():
    with tempfile.TemporaryDirectory(prefix="pinentry-rbw-") as directory:
        vault = Vault(Path(directory))
        try:
            vault.run("unlocked", success=False)
            vault.start("unlock")
            vault.input(vault.prompt(), key="Escape")
            _, error = vault.finish(success=False)
            assert "cancel" in error.lower()
            vault.run("unlocked", success=False)
            print("PASS: cancelled unlock leaves the vault locked", flush=True)

            vault.start("unlock")
            first = vault.prompt()
            vault.input(first, "wrong-dummy")
            second = vault.prompt(previous=next(iter(first)))
            vault.input(second, PASSWORD)
            vault.finish()
            vault.run("unlocked")
            vault.run("unlock")  # Already unlocked: no prompt is needed.
            assert vault.run("list").stdout.strip() == ENTRY
            assert vault.run("get", ENTRY).stdout.strip() == ENTRY_PASSWORD
            print("PASS: wrong-password retry, unlock, list and get", flush=True)

            vault.run("lock")
            vault.run("unlocked", success=False)
            vault.start("get", ENTRY)
            vault.input(vault.prompt(), PASSWORD)
            output, _ = vault.finish()
            assert output.strip() == ENTRY_PASSWORD
            vault.run("lock")
            vault.run("unlocked", success=False)
            print("PASS: lock and automatic unlock when retrieving an entry", flush=True)
        finally:
            vault.close()
    print("Isolated rbw desktop integration passed")


if __name__ == "__main__":
    main()
