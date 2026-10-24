"""
Application controller orchestrating view navigation, auto-lock timers,
inactivity tracking, and secure shutdown memory wiping.
"""

import os
import tkinter as tk
from tkinter import filedialog
import time
from typing import Optional
import customtkinter as ctk

from src.storage.vault import VaultManager
from src.ui.clipboard import ClipboardManager
from src.ui.styles import COLORS
from src.ui.views.login_view import LoginView
from src.ui.views.setup_view import SetupView
from src.ui.views.vault_view import VaultView


class PasswordManagerApp(ctk.CTk):
    """Primary application window and lifecycle manager."""

    def __init__(self, db_path: str = "vault.db"):
        super().__init__()

        # Window Configuration
        self.title("LocalVault — Secure Local-First Password Manager")
        self.geometry("1100x720")
        self.minsize(960, 600)
        self.configure(fg_color=COLORS["bg_dark"])
        self._set_app_icon()

        # Appearance mode: Dark by default
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Core Components
        self.db_path = db_path
        self.vault = VaultManager(self.db_path)
        self.clipboard = ClipboardManager(default_timeout_seconds=30)

        # Inactivity & Auto-Lock Tracking
        self.last_activity_time = time.time()
        self.auto_lock_timer_id: Optional[str] = None

        # Container Frame for Views
        self.current_view: Optional[ctk.CTkFrame] = None

        # Hook Window Close for memory wiping
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Bind user activity events to reset auto-lock
        self._bind_activity_events()

        # Route to appropriate initial view
        self.navigate_initial()

        # Start periodic inactivity checking loop
        self._check_inactivity_loop()

    def _set_app_icon(self):
        """Applies assets/icon.png as the window/dock icon."""
        icon_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..", "assets", "icon.png"
        )
        try:
            self._app_icon = tk.PhotoImage(file=icon_path)
            self.iconphoto(True, self._app_icon)
        except tk.TclError:
            pass

    def _bind_activity_events(self):
        """Monitors keystrokes and mouse motion to detect user presence."""
        for event in ("<Key>", "<Button>", "<Motion>", "<MouseWheel>"):
            self.bind_all(event, self._record_activity, add="+")

    def _record_activity(self, event=None):
        """Resets the inactivity timer upon user input."""
        self.last_activity_time = time.time()

    def navigate_initial(self):
        """Determines whether to show the Setup view or Login view."""
        if not self.vault.is_initialized():
            self.show_setup_view()
        else:
            self.show_login_view()

    def show_setup_view(self):
        """Displays master password initialization screen."""
        self._switch_view(SetupView(
            self,
            on_setup_success=self._on_setup_success,
            vault_manager=self.vault,
        ))

    def show_login_view(self):
        """Displays locked vault login screen."""
        self._switch_view(LoginView(
            self,
            on_unlock_success=self.show_vault_view,
            on_switch_vault=self._on_switch_vault,
            on_create_new=self._on_create_new_vault,
            vault_manager=self.vault,
        ))

    def show_vault_view(self):
        """Displays the unlocked vault credential explorer."""
        self.last_activity_time = time.time()
        self._switch_view(VaultView(
            self,
            vault_manager=self.vault,
            clipboard_mgr=self.clipboard,
            on_lock_requested=self.lock_vault,
        ))

    def lock_vault(self):
        """Explicitly locks the vault and purges memory."""
        self.vault.lock()
        self.clipboard.clear_now()
        self.show_login_view()

    def _switch_view(self, new_view: ctk.CTkFrame):
        if self.current_view:
            self.current_view.destroy()
        self.current_view = new_view
        self.current_view.pack(fill="both", expand=True)

    def _on_setup_success(self, new_vault_manager: VaultManager):
        self.vault = new_vault_manager
        self.show_vault_view()

    def _on_switch_vault(self):
        path = filedialog.askopenfilename(
            title="Open Existing Vault Database",
            filetypes=[("SQLite Vault Database", "*.db"), ("All Files", "*.*")],
        )
        if path:
            self.vault.lock()
            self.vault = VaultManager(path)
            self.navigate_initial()

    def _on_create_new_vault(self):
        path = filedialog.asksaveasfilename(
            title="Create New Vault Database",
            defaultextension=".db",
            filetypes=[("SQLite Vault Database", "*.db"), ("All Files", "*.*")],
            initialfile="new_vault.db",
        )
        if path:
            self.vault.lock()
            self.vault = VaultManager(path)
            self.show_setup_view()

    def _check_inactivity_loop(self):
        """Periodically checks inactivity timeout and auto-locks if expired."""
        if self.vault.is_unlocked:
            setting_str = self.vault.db.get_setting("auto_lock_minutes", "5")
            try:
                timeout_minutes = int(setting_str)
            except ValueError:
                timeout_minutes = 5

            if timeout_minutes > 0:
                timeout_seconds = timeout_minutes * 60
                elapsed = time.time() - self.last_activity_time
                remaining = max(0, int(timeout_seconds - elapsed))

                # Update live badge on VaultView if active
                if isinstance(self.current_view, VaultView):
                    mins, secs = divmod(remaining, 60)
                    self.current_view.autolock_badge.configure(
                        text=f"⏱️ Auto-lock: {mins:02d}:{secs:02d}"
                    )

                if elapsed >= timeout_seconds:
                    self.lock_vault()

        # Run loop every 1000ms
        self.after(1000, self._check_inactivity_loop)

    def _on_close(self):
        """Performs immediate secure zeroization of memory upon window exit."""
        try:
            self.vault.lock()
            self.clipboard.clear_now()
        except Exception:
            pass
        finally:
            self.destroy()
