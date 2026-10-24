"""
System clipboard manager with automated secure memory wiping / auto-clear timer.
"""

import hashlib
import os
import subprocess
import threading
import time
from typing import Callable, Optional
import pyperclip


class ClipboardManager:
    """
    Handles clipboard copying with secure automatic memory purging.
    After a configured interval (e.g. 30 seconds), overwrites the clipboard
    if it still holds the copied sensitive data.
    """

    def __init__(self, default_timeout_seconds: int = 30):
        self.default_timeout = default_timeout_seconds
        self._timer: Optional[threading.Timer] = None
        self._last_copied_hash: Optional[str] = None
        self._countdown_active: bool = False
        self._remaining_seconds: int = 0
        self._tick_callback: Optional[Callable[[int], None]] = None
        self._stop_countdown = threading.Event()

    def copy(
        self,
        text: str,
        timeout_seconds: Optional[int] = None,
        on_tick: Optional[Callable[[int], None]] = None,
        on_cleared: Optional[Callable[[], None]] = None,
    ) -> None:
        """
        Copies text to the system clipboard and starts an auto-clear timer.
        """
        # Cancel any active countdown
        self.cancel_clear()

        # Place onto clipboard
        self._write_clipboard(text)

        # Hash text to recognize if user copied something else in the meantime
        self._last_copied_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        timeout = timeout_seconds if timeout_seconds is not None else self.default_timeout
        if timeout <= 0:
            return  # Auto-clear disabled

        self._remaining_seconds = timeout
        self._stop_countdown.clear()

        def countdown_worker():
            for remaining in range(timeout, 0, -1):
                if self._stop_countdown.is_set():
                    return
                self._remaining_seconds = remaining
                if on_tick:
                    try:
                        on_tick(remaining)
                    except Exception:
                        pass
                time.sleep(1)

            if not self._stop_countdown.is_set():
                self._clear_if_unchanged()
                if on_cleared:
                    try:
                        on_cleared()
                    except Exception:
                        pass

        thread = threading.Thread(target=countdown_worker, daemon=True)
        thread.start()

    def cancel_clear(self) -> None:
        """Stops the active auto-clear countdown without clearing the clipboard."""
        self._stop_countdown.set()
        self._remaining_seconds = 0

    def clear_now(self) -> None:
        """Immediately purges the system clipboard."""
        self.cancel_clear()
        self._write_clipboard("")
        self._last_copied_hash = None

    def _write_clipboard(self, text: str) -> None:
        """Attempts native macOS pbcopy first, with pyperclip fallback."""
        try:
            if os.name == "posix" and os.path.exists("/usr/bin/pbcopy"):
                p = subprocess.Popen(["/usr/bin/pbcopy"], stdin=subprocess.PIPE, close_fds=True)
                p.communicate(input=text.encode("utf-8"))
                return
        except Exception:
            pass

        try:
            pyperclip.copy(text)
        except Exception:
            pass

    def _read_clipboard(self) -> str:
        """Reads current clipboard text."""
        try:
            if os.name == "posix" and os.path.exists("/usr/bin/pbpaste"):
                return subprocess.check_output(["/usr/bin/pbpaste"]).decode("utf-8")
        except Exception:
            pass

        try:
            return pyperclip.paste()
        except Exception:
            return ""

    def _clear_if_unchanged(self) -> None:
        """Wipes the clipboard only if it still matches the sensitive string."""
        if not self._last_copied_hash:
            return

        current_val = self._read_clipboard()
        current_hash = hashlib.sha256(current_val.encode("utf-8")).hexdigest()

        if current_hash == self._last_copied_hash:
            self._write_clipboard("")
            self._last_copied_hash = None
