import re
import socket
import time
from collections import Counter

from ..config import PIN_MAX_LEN, PIN_MIN_LEN


def _now_ms():
    return int(time.time() * 1000)


def _check_pin_strength(pin):
    if not pin:
        return "PIN required."
    if len(pin) < PIN_MIN_LEN:
        return f"PIN must be at least {PIN_MIN_LEN} characters."
    if len(pin) > PIN_MAX_LEN:
        return f"PIN too long (max {PIN_MAX_LEN})."
    if not re.search(r"[a-z]", pin):
        return "PIN must contain a lowercase letter."
    if not re.search(r"[A-Z]", pin):
        return "PIN must contain an uppercase letter."
    if not re.search(r"[0-9]", pin):
        return "PIN must contain a digit."
    if not re.search(r"[^a-zA-Z0-9]", pin):
        return "PIN must contain a symbol."
    if len(set(pin)) < 8:
        return "PIN must contain at least 8 distinct characters."
    for i in range(len(pin) - 3):
        if pin[i] == pin[i + 1] == pin[i + 2] == pin[i + 3]:
            return "PIN has four identical characters in a row."
    for sub_len in range(3, len(pin) // 3 + 1):
        counts = Counter(
            pin[i:i + sub_len]
            for i in range(len(pin) - sub_len + 1)
        )
        if any(c >= 3 for c in counts.values()):
            return "PIN contains a repeated pattern."
    for sub_len in range(4, len(pin) // 2 + 1):
        counts = Counter(
            pin[i:i + sub_len]
            for i in range(len(pin) - sub_len + 1)
        )
        if any(c >= 2 for c in counts.values()):
            return "PIN contains a repeated pattern."
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
