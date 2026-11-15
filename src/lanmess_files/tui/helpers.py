import re
import socket
import time

from ..config import PIN_MAX_LEN, PIN_MIN_LEN


def _now_ms():
    return int(time.time() * 1000)


def _check_pin_strength(pin):
    if not pin:
        return "PIN required."
    if len(pin) < PIN_MIN_LEN:
        return (
            f"PIN must be at least {PIN_MIN_LEN} characters."
        )
    if len(pin) > PIN_MAX_LEN:
        return f"PIN too long (max {PIN_MAX_LEN})."
    classes = 0
    if re.search(r"[a-z]", pin):
        classes += 1
    if re.search(r"[A-Z]", pin):
        classes += 1
    if re.search(r"[0-9]", pin):
        classes += 1
    if re.search(r"[^a-zA-Z0-9]", pin):
        classes += 1
    if classes < 3:
        return (
            "PIN must contain at least 3 of: "
            "lowercase, uppercase, digit, symbol."
        )
    if len(set(pin)) < 6:
        return "PIN uses too few distinct characters."
    return None


def _valid_port(s):
    if not isinstance(s, str):
        return False
    if not s.isdigit():
        return False
    n = int(s)
    return 1 <= n <= 65535


def _valid_ipv4(s):
    if not isinstance(s, str):
        return False
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if not (0 <= n <= 255):
            return False
    return True


def get_local_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass
    try:
        import subprocess

        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if "inet" in parts:
                    idx = parts.index("inet")
                    if idx + 1 < len(parts):
                        addr = parts[idx + 1].split("/")[0]
                        if (
                            not addr.startswith("127.")
                            and addr not in ips
                        ):
                            ips.append(addr)
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(
            hostname, None, socket.AF_INET
        ):
            addr = info[4][0]
            if addr not in ips and not addr.startswith("127."):
                ips.append(addr)
    except Exception:
        pass
    return ips or ["127.0.0.1"]