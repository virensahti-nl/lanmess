import os
import shutil
import subprocess
import sys


def _has(cmd):
    return shutil.which(cmd) is not None


def _run(cmd, env=None, timeout=5):
    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env=env,
        )
        return True
    except Exception:
        return False


def _bell():
    try:
        sys.stdout.write("\x07")
        sys.stdout.flush()
        return True
    except Exception:
        return False


def _sanitize(text, max_len):
    if not isinstance(text, str):
        text = str(text) if text is not None else ""
    text = text.replace("\x00", "")
    text = text.replace("\r", " ").replace("\n", " ")
    text = text.strip()
    if len(text) > max_len:
        text = text[: max_len - 3].rstrip() + "..."
    return text


def _notify_windows(title, body):
    title = _sanitize(title, 100) or "LANMess"
    body = _sanitize(body, 200)
    try:
        from winotify import Notification

        toast = Notification(
            app_id="LANMess",
            title=title,
            msg=body if body else "(no preview)",
            duration="short",
        )
        toast.show()
        return True
    except ImportError:
        pass
    except Exception:
        pass
    if _has("powershell"):
        try:
            ps_bt = (
                "if (Get-Module -ListAvailable -Name BurntToast) {"
                "  Import-Module BurntToast;"
                "  New-BurntToastNotification "
                "    -Text $env:LM_NOTIF_TITLE, $env:LM_NOTIF_BODY;"
                "  exit 0"
                "} else { exit 1 }"
            )
            env = {
                **os.environ,
                "LM_NOTIF_TITLE": title,
                "LM_NOTIF_BODY": body or "(no preview)",
            }
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_bt],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                env=env,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass
    if _has("powershell"):
        ps = (
            "[Windows.UI.Notifications.ToastNotificationManager, "
            "Windows.UI.Notifications, ContentType = WindowsRuntime] "
            "| Out-Null;"
            "$xml = [Windows.UI.Notifications.ToastNotificationManager]"
            "::GetTemplateContent([Windows.UI.Notifications."
            "ToastTemplateType]::ToastText02);"
            "$xml.GetElementsByTagName('text')[0].AppendChild("
            "$xml.CreateTextNode($env:LM_NOTIF_TITLE)) | Out-Null;"
            "$xml.GetElementsByTagName('text')[1].AppendChild("
            "$xml.CreateTextNode($env:LM_NOTIF_BODY)) | Out-Null;"
            "$t = [Windows.UI.Notifications.ToastNotification]"
            "::new($xml);"
            "[Windows.UI.Notifications.ToastNotificationManager]"
            "::CreateToastNotifier('LANMess').Show($t);"
        )
        env = {
            **os.environ,
            "LM_NOTIF_TITLE": title,
            "LM_NOTIF_BODY": body or "(no preview)",
        }
        if _run(
            ["powershell", "-NoProfile", "-Command", ps],
            env=env,
        ):
            return True
    return _bell()


def _notify_macos(title, body):
    title = _sanitize(title, 100) or "LANMess"
    body = _sanitize(body, 200)
    if _has("terminal-notifier"):
        if _run(
            [
                "terminal-notifier",
                "-title",
                title,
                "-message",
                body or "(no preview)",
                "-group",
                "lanmess",
            ]
        ):
            return True
    if _has("osascript"):
        env = {
            **os.environ,
            "LM_NOTIF_TITLE": title,
            "LM_NOTIF_BODY": body or "(no preview)",
        }
        script = (
            'display notification (system attribute "LM_NOTIF_BODY") '
            'with title (system attribute "LM_NOTIF_TITLE")'
        )
        if _run(["osascript", "-e", script], env=env):
            return True
    return _bell()


def _notify_linux(title, body):
    title = _sanitize(title, 100) or "LANMess"
    body = _sanitize(body, 200)
    if _has("termux-notification"):
        if _run(
            [
                "termux-notification",
                "--title",
                title,
                "--content",
                body or "(no preview)",
            ]
        ):
            return True
    if _has("notify-send"):
        if _run(
            [
                "notify-send",
                "-a",
                "LANMess",
                title,
                body or "(no preview)",
            ]
        ):
            return True
    return _bell()


def notify(title, body, enabled=True):
    if not enabled:
        return False
    try:
        if sys.platform.startswith("win"):
            return _notify_windows(title, body)
        if sys.platform == "darwin":
            return _notify_macos(title, body)
        return _notify_linux(title, body)
    except Exception:
        try:
            return _bell()
        except Exception:
            return False