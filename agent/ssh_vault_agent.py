#!/usr/bin/env python3
import argparse
import base64
import errno
import fcntl
import getpass
import glob
import hashlib
import os
import secrets
import select
import shutil
import socket
import struct
import subprocess
import sys
import termios
import threading
import time

SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENTC_SIGN_REQUEST = 13
SSH2_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_FAILURE = 5

USB_VENDOR_ID = "303a"
USB_PRODUCT_NAME = "Zeru Vault"
DEFAULT_SERIAL_PORT = "auto"
TIOCEXCL = 0x540C
TIOCMBIS = 0x5416
TIOCM_DTR = 0x002
SIGN_TIMEOUT_S = 100.0
MAX_AGENT_MESSAGE = 256 * 1024

SSH_CONFIG_BEGIN = "# >>> zeru-vault (managed by ssh_vault_agent.py) >>>"
SSH_CONFIG_END = "# <<< zeru-vault <<<"
SSH_CONFIG_MARKERS = (
    (SSH_CONFIG_BEGIN, SSH_CONFIG_END),
    ("# --- BEGIN ZERU VAULT ---", "# --- END ZERU VAULT ---"),
)


class DeviceNotFound(Exception):
    pass


def _read_sysfs(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _usb_device_dir(tty_name: str):
    node = os.path.realpath(f"/sys/class/tty/{tty_name}/device")
    for _ in range(4):
        if os.path.exists(os.path.join(node, "idVendor")):
            return node
        node = os.path.dirname(node)
    return None


def find_vault_ports() -> list:
    ports = []
    for tty in sorted(glob.glob("/sys/class/tty/ttyACM*")):
        name = os.path.basename(tty)
        usb = _usb_device_dir(name)
        if not usb:
            continue
        if (_read_sysfs(os.path.join(usb, "idVendor")).lower() == USB_VENDOR_ID
                and _read_sysfs(os.path.join(usb, "product")) == USB_PRODUCT_NAME):
            ports.append(f"/dev/{name}")
    if not ports:
        ports = [os.path.realpath(p) for p in sorted(glob.glob("/dev/serial/by-id/*Zeru_Security_Zeru_Vault*"))]
    return ports


def detect_serial_port(preferred: str = "auto") -> str:
    if preferred and preferred != "auto":
        if not os.path.exists(preferred):
            raise DeviceNotFound(f"Serial port {preferred} does not exist")
        return preferred
    ports = find_vault_ports()
    if not ports:
        raise DeviceNotFound("Zeru Vault not found (USB 303a, product 'Zeru Vault'). Is it plugged in?")
    return ports[0]


def default_socket_path() -> str:
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir and os.path.isdir(runtime_dir):
        return os.path.join(runtime_dir, "zeru-vault.sock")
    uid_dir = f"/run/user/{os.getuid()}"
    if os.path.isdir(uid_dir):
        return os.path.join(uid_dir, "zeru-vault.sock")
    raise RuntimeError("No private runtime directory (XDG_RUNTIME_DIR); pass --socket explicitly")


def ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def read_ssh_string(buf: bytes, offset: int):
    if len(buf) < offset + 4:
        raise ValueError("Buffer too short for string length")
    length = struct.unpack(">I", buf[offset:offset + 4])[0]
    offset += 4
    if len(buf) < offset + length:
        raise ValueError("Buffer too short for string payload")
    return buf[offset:offset + length], offset + length


def ed25519_blob(pubkey: bytes) -> bytes:
    return ssh_string(b"ssh-ed25519") + ssh_string(pubkey)


def fingerprint(pubkey: bytes) -> str:
    digest = hashlib.sha256(ed25519_blob(pubkey)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def desktop_notify(title: str, body: str):
    if not shutil.which("notify-send"):
        return
    try:
        subprocess.Popen(
            ["notify-send", "--app-name=Zeru Vault", "--icon=security-high", "--expire-time=8000", title, body],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass


class VaultDevice:
    def __init__(self, port: str = DEFAULT_SERIAL_PORT):
        self.port = port
        self.fd = None
        self.lock = threading.Lock()

    def _open(self):
        port = detect_serial_port(self.port)
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            fcntl.ioctl(fd, TIOCEXCL)
            attrs = termios.tcgetattr(fd)
            attrs[0] = 0
            attrs[1] = 0
            attrs[2] &= ~termios.CSIZE
            attrs[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL
            attrs[3] = 0
            attrs[4] = termios.B115200
            attrs[5] = termios.B115200
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            fcntl.ioctl(fd, TIOCMBIS, struct.pack("I", TIOCM_DTR))
        except OSError:
            os.close(fd)
            raise
        self.fd = fd
        info = self._transact("INFO", 2.0)
        if not info.startswith("INFO zeru-vault "):
            self.close()
            raise DeviceNotFound(f"{port} did not identify as Zeru Vault (got: {info!r})")

    def close(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def _transact(self, cmd: str, timeout: float) -> str:
        req_id = secrets.token_hex(4)
        termios.tcflush(self.fd, termios.TCIFLUSH)
        line = f"{req_id} {cmd}\n".encode("ascii")
        for off in range(0, len(line), 64):
            os.write(self.fd, line[off:off + 64])
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r, _, _ = select.select([self.fd], [], [], 0.2)
            if not r:
                continue
            chunk = os.read(self.fd, 512)
            if not chunk:
                raise OSError("Serial port EOF")
            buf += chunk
            while b"\n" in buf:
                raw_line, buf = buf.split(b"\n", 1)
                parts = raw_line.strip().decode("ascii", errors="replace").split(" ", 1)
                if len(parts) == 2 and parts[0] == req_id:
                    return parts[1]
        return "ERR TIMEOUT"

    def send_command(self, cmd: str, timeout: float = 5.0) -> str:
        with self.lock:
            for attempt in range(2):
                try:
                    if self.fd is None:
                        self._open()
                    return self._transact(cmd, timeout)
                except DeviceNotFound as exc:
                    return f"ERR NO_DEVICE ({exc})"
                except OSError as exc:
                    self.close()
                    if exc.errno == errno.EBUSY:
                        return "ERR BUSY (serial port in use by another program)"
                    if attempt == 0:
                        time.sleep(0.25)
                        continue
                    return f"ERR DISCONNECTED ({exc})"
                finally:
                    self.close()
            return "ERR FAILED"

    def info(self) -> str:
        return self.send_command("INFO", timeout=2.0)

    def get_status(self) -> str:
        return self.send_command("STATUS", timeout=2.0)

    def get_active_pubkey(self):
        res = self.send_command("GET_ACTIVE_PUBKEY", timeout=2.0)
        parts = res.split()
        if len(parts) == 3 and parts[0] == "PUBKEY":
            try:
                raw_pub = bytes.fromhex(parts[1])
            except ValueError:
                return None, None, res
            if len(raw_pub) == 32:
                return parts[2], raw_pub, res
        return None, None, res

    def sign(self, challenge: bytes):
        res = self.send_command(f"SIGN {challenge.hex()}", timeout=SIGN_TIMEOUT_S)
        parts = res.split()
        if len(parts) == 2 and parts[0] == "SIG":
            try:
                sig = bytes.fromhex(parts[1])
            except ValueError:
                sig = b""
            if len(sig) == 64:
                return sig, res
        return None, res


class SshVaultAgent:
    def __init__(self, port: str = DEFAULT_SERIAL_PORT, sock_path: str = None, notify: bool = True):
        self.sock_path = sock_path or default_socket_path()
        self.device = VaultDevice(port)
        self.notify = notify

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf

    def _identities(self) -> bytes:
        name, pubkey, _ = self.device.get_active_pubkey()
        if pubkey is None:
            return struct.pack(">BI", SSH2_AGENT_IDENTITIES_ANSWER, 0)
        comment = f"{name}@zeru-vault".encode("utf-8")
        return (struct.pack(">BI", SSH2_AGENT_IDENTITIES_ANSWER, 1)
                + ssh_string(ed25519_blob(pubkey)) + ssh_string(comment))

    def _sign(self, body: bytes) -> bytes:
        failure = struct.pack(">B", SSH_AGENT_FAILURE)
        req_blob, off = read_ssh_string(body, 0)
        data_to_sign, off = read_ssh_string(body, off)
        if len(body) != off + 4:
            raise ValueError("Invalid sign request length")
        flags = struct.unpack(">I", body[off:off + 4])[0]
        if flags != 0:
            raise ValueError(f"Unsupported sign flags: {flags}")

        name, active_pub, _ = self.device.get_active_pubkey()
        if not active_pub or req_blob != ed25519_blob(active_pub):
            return failure

        if self.notify:
            locked = self.device.get_status() == "STATUS LOCKED"
            desktop_notify("Zeru Vault: SSH login",
                           f"{'Unlock the device, then select' if locked else 'Select'} 'Approve login' and press both buttons ({name}).")
        sig, res = self.device.sign(data_to_sign)
        if not sig:
            print(f"[!] Device refused to sign: {res}", file=sys.stderr, flush=True)
            if self.notify and "REJECTED" not in res:
                desktop_notify("Zeru Vault: login not signed", res)
            return failure
        return struct.pack(">B", SSH2_AGENT_SIGN_RESPONSE) + ssh_string(ssh_string(b"ssh-ed25519") + ssh_string(sig))

    def handle_client(self, client_sock: socket.socket):
        try:
            client_sock.settimeout(SIGN_TIMEOUT_S + 10)
            creds = client_sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, peer_uid, _ = struct.unpack("3i", creds)
            if peer_uid != os.getuid():
                return

            while True:
                hdr = self._recv_exact(client_sock, 4)
                if len(hdr) < 4:
                    break
                length = struct.unpack(">I", hdr)[0]
                if length == 0 or length > MAX_AGENT_MESSAGE:
                    break
                payload = self._recv_exact(client_sock, length)
                if len(payload) < length:
                    break

                msg_type, body = payload[0], payload[1:]
                if msg_type == SSH2_AGENTC_REQUEST_IDENTITIES:
                    resp = self._identities()
                elif msg_type == SSH2_AGENTC_SIGN_REQUEST:
                    try:
                        resp = self._sign(body)
                    except ValueError as exc:
                        print(f"[!] Rejected malformed sign request: {exc}", file=sys.stderr, flush=True)
                        resp = struct.pack(">B", SSH_AGENT_FAILURE)
                else:
                    resp = struct.pack(">B", SSH_AGENT_FAILURE)
                client_sock.sendall(ssh_string(resp))
        except (OSError, socket.timeout) as exc:
            print(f"[!] Client connection error: {exc}", file=sys.stderr, flush=True)
        finally:
            client_sock.close()

    def run(self):
        sock_dir = os.path.dirname(self.sock_path) or "."
        st = os.stat(sock_dir)
        if st.st_uid != os.getuid() or st.st_mode & 0o022:
            raise RuntimeError(f"Socket directory {sock_dir} must be owned by you and not group/world writable")
        if os.path.lexists(self.sock_path):
            if os.path.islink(self.sock_path):
                raise RuntimeError(f"Socket path {self.sock_path} is a symlink; aborting.")
            os.remove(self.sock_path)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)
        try:
            server.bind(self.sock_path)
        finally:
            os.umask(old_umask)
        server.listen(8)

        print(f"[+] zeru-vault agent listening on: {self.sock_path}", flush=True)
        try:
            while True:
                client, _ = server.accept()
                threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[-] Stopping agent.")
        finally:
            server.close()
            if os.path.lexists(self.sock_path):
                os.remove(self.sock_path)


def cmd_pubkey(port: str):
    name, pubkey, res = VaultDevice(port).get_active_pubkey()
    if not pubkey:
        print(f"[-] Could not read the active key: {res}", file=sys.stderr)
        sys.exit(1)
    print(f"ssh-ed25519 {base64.b64encode(ed25519_blob(pubkey)).decode('ascii')} {name}@zeru-vault")


def cmd_status(port: str, sock_path: str):
    dev = VaultDevice(port)
    try:
        path = detect_serial_port(port)
    except DeviceNotFound as exc:
        print(f"[-] {exc}")
        sys.exit(1)
    info = dev.info()
    print(f"[*] Device        : {path}")
    print(f"[*] Firmware      : {info}")
    if info.startswith("INFO") and "hw=0" in info:
        print("[!] Vault is NOT bound to the chip (eFuse HMAC). Unlock it once with firmware >= 2.0 to bind.")
    print(f"[*] State         : {dev.get_status()}")
    name, pubkey, res = dev.get_active_pubkey()
    print(f"[*] Active key    : {f'{name}  {fingerprint(pubkey)}' if pubkey else res}")
    alive = os.path.exists(sock_path)
    print(f"[*] Agent socket  : {sock_path} ({'present' if alive else 'missing'})")
    ssh_config = os.path.expanduser("~/.ssh/config")
    configured = False
    if os.path.exists(ssh_config):
        with open(ssh_config, "r", encoding="utf-8") as f:
            configured = SSH_CONFIG_BEGIN in f.read()
    print(f"[*] ~/.ssh/config : {'IdentityAgent configured' if configured else 'not configured'}")


def build_test_challenge(pubkey: bytes, user: bytes, hostbound: bool) -> bytes:
    method = b"publickey-hostbound-v00@openssh.com" if hostbound else b"publickey"
    challenge = (
        ssh_string(secrets.token_bytes(32))
        + struct.pack(">B", 50)
        + ssh_string(user)
        + ssh_string(b"ssh-connection")
        + ssh_string(method)
        + struct.pack(">B", 1)
        + ssh_string(b"ssh-ed25519")
        + ssh_string(ed25519_blob(pubkey))
    )
    if hostbound:
        challenge += ssh_string(ed25519_blob(secrets.token_bytes(32)))
    return challenge


def cmd_test(port: str, hostbound: bool):
    dev = VaultDevice(port)
    name, pubkey, res = dev.get_active_pubkey()
    if not pubkey:
        print(f"[-] Could not read the active key: {res}", file=sys.stderr)
        sys.exit(1)

    user = getpass.getuser().encode("ascii", errors="replace")
    print(f"[+] Active key          : {name}")
    print(f"[+] SHA256 fingerprint  : {fingerprint(pubkey)}")
    print(f"[+] OpenSSH public key  : ssh-ed25519 {base64.b64encode(ed25519_blob(pubkey)).decode('ascii')} {name}@zeru-vault")
    print()
    print(f"[*] Sending {'hostbound ' if hostbound else ''}SSH userauth request (user '{user.decode()}') to the device...")
    print("[*] Unlock if asked, then select 'Approve login' (Up) and press both buttons.")

    challenge = build_test_challenge(pubkey, user, hostbound)
    t0 = time.monotonic()
    sig, res = dev.sign(challenge)
    dt = time.monotonic() - t0
    if not sig:
        print(f"[-] Not signed: {res}")
        sys.exit(1)

    print(f"[+] Ed25519 signature received in {dt:.2f}s: {sig.hex()[:48]}...")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        print("[*] Install python3-cryptography to verify the signature locally.")
        return
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, challenge)
    except Exception as exc:
        print(f"[-] ERROR: Invalid signature: {exc}", file=sys.stderr)
        sys.exit(1)
    print("[+] Signature verified against the public key.")


def _strip_managed_block(text: str, sock_path: str) -> str:
    lines = text.splitlines(keepends=True)
    out = []
    end_marker = None
    for line in lines:
        stripped = line.strip()
        if end_marker is None:
            for begin, end in SSH_CONFIG_MARKERS:
                if stripped == begin:
                    end_marker = end
                    break
            else:
                out.append(line)
            continue
        if stripped == end_marker:
            end_marker = None
    text = "".join(out).lstrip("\n")
    legacy = f"Host *\n    IdentityAgent {sock_path}\n"
    if text.startswith(legacy):
        text = text[len(legacy):].lstrip("\n")
    return text


def _write_private(path: str, content: str):
    tmp = f"{path}.zeru-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)


def configure_ssh(sock_path: str, enable: bool):
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    ssh_config = os.path.join(ssh_dir, "config")
    existing = ""
    if os.path.exists(ssh_config):
        with open(ssh_config, "r", encoding="utf-8") as f:
            existing = f.read()
        backup = f"{ssh_config}.zeru-vault.bak"
        if not os.path.exists(backup):
            shutil.copy2(ssh_config, backup)
            print(f"[+] Backed up {ssh_config} -> {backup}")

    cleaned = _strip_managed_block(existing, sock_path)
    if enable:
        block = (
            f"{SSH_CONFIG_BEGIN}\n"
            "# Default for hosts without their own IdentityAgent. Host blocks above take precedence.\n"
            "Host *\n"
            f"    IdentityAgent {sock_path}\n"
            f"{SSH_CONFIG_END}\n"
        )
        cleaned = (cleaned.rstrip("\n") + "\n\n" if cleaned.strip() else "") + block
    if cleaned != existing:
        _write_private(ssh_config, cleaned)


def cmd_install_service(sock_path: str, port: str):
    script_path = os.path.abspath(__file__)
    systemd_dir = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(systemd_dir, exist_ok=True)
    service_file = os.path.join(systemd_dir, "zeru-vault.service")
    port_arg = f' --port "{port}"' if port != DEFAULT_SERIAL_PORT else ""
    service_content = (
        "[Unit]\n"
        "Description=Zeru Vault hardware SSH agent\n"
        "Documentation=file://" + os.path.dirname(os.path.dirname(script_path)) + "/README.md\n\n"
        "[Service]\n"
        "Type=simple\n"
        f'ExecStart="{sys.executable}" -I "{script_path}" daemon --socket "{sock_path}"{port_arg}\n'
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "NoNewPrivileges=yes\n"
        "LockPersonality=yes\n"
        "RestrictRealtime=yes\n"
        "RestrictNamespaces=yes\n"
        "SystemCallArchitectures=native\n"
        "RestrictAddressFamilies=AF_UNIX\n"
        "UMask=0077\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    _write_private(service_file, service_content)
    configure_ssh(sock_path, enable=True)

    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "--user", "enable", "--now", "zeru-vault.service"], check=False)
    subprocess.run(["systemctl", "--user", "restart", "zeru-vault.service"], check=False)
    print(f"[+] Installed and started systemd user service: {service_file}")
    print(f"[+] ~/.ssh/config: default IdentityAgent -> {sock_path} (managed block at the end)")
    print("[i] Optional: 'make install-udev' keeps ModemManager away from the device.")


def cmd_uninstall_service(sock_path: str):
    service_file = os.path.expanduser("~/.config/systemd/user/zeru-vault.service")
    subprocess.run(["systemctl", "--user", "disable", "--now", "zeru-vault.service"], check=False)
    if os.path.exists(service_file):
        os.remove(service_file)
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    configure_ssh(sock_path, enable=False)
    print("[+] Removed the zeru-vault service and its ~/.ssh/config block.")


def main():
    parser = argparse.ArgumentParser(description="Zeru Vault SSH agent and tools")
    parser.add_argument(
        "command",
        choices=["daemon", "pubkey", "status", "test", "install-service", "uninstall-service", "detect"],
        default="daemon",
        nargs="?",
    )
    parser.add_argument("--port", default=DEFAULT_SERIAL_PORT, help="Serial port of Zeru Vault (default: auto)")
    parser.add_argument("--socket", default=None, help="UNIX socket path for SSH_AUTH_SOCK")
    parser.add_argument("--no-notify", action="store_true", help="Disable desktop notifications")
    parser.add_argument("--hostbound", action="store_true", help="test: send an OpenSSH hostbound request")
    args = parser.parse_args()
    sock_path = args.socket or default_socket_path()

    if args.command == "detect":
        try:
            print(detect_serial_port(args.port))
        except DeviceNotFound as exc:
            print(f"[-] {exc}", file=sys.stderr)
            sys.exit(1)
    elif args.command == "pubkey":
        cmd_pubkey(args.port)
    elif args.command == "status":
        cmd_status(args.port, sock_path)
    elif args.command == "test":
        cmd_test(args.port, args.hostbound)
    elif args.command == "install-service":
        cmd_install_service(sock_path, args.port)
    elif args.command == "uninstall-service":
        cmd_uninstall_service(sock_path)
    else:
        SshVaultAgent(port=args.port, sock_path=sock_path, notify=not args.no_notify).run()


if __name__ == "__main__":
    main()
