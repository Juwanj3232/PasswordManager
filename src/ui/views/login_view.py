"""
Unlock / Login screen for the local password manager.
"""

import time
import customtkinter as ctk
from src.crypto.cipher import InvalidMasterPasswordError
from src.ui.styles import COLORS, FONT_FAMILY


class LoginView(ctk.CTkFrame):
    """View presenting the secure master password unlock screen."""

    def __init__(self, master, on_unlock_success, on_switch_vault, on_create_new, vault_manager):
        super().__init__(master, fg_color=COLORS["bg_dark"])
        self.on_unlock_success = on_unlock_success
        self.on_switch_vault = on_switch_vault
        self.on_create_new = on_create_new
        self.vault = vault_manager

        self.failed_attempts = 0
        self._init_ui()

    def _init_ui(self):
        # Center container card
        card = ctk.CTkFrame(
            self,
            fg_color=COLORS["card_dark"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border_dark"],
            width=460,
        )
        card.place(relx=0.5, rely=0.5, anchor="center")

        # Shield Icon & App Title
        icon_lbl = ctk.CTkLabel(card, text="🛡️", font=(FONT_FAMILY, 46))
        icon_lbl.pack(pady=(35, 5))

        title_lbl = ctk.CTkLabel(
            card,
            text="Local Vault Locked",
            font=(FONT_FAMILY, 22, "bold"),
            text_color=COLORS["text_dark"],
        )
        title_lbl.pack(pady=(0, 4))

        subtitle_lbl = ctk.CTkLabel(
            card,
            text="Enter your master password to decrypt your local vault.",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_muted_dark"],
        )
        subtitle_lbl.pack(pady=(0, 25))

        # Vault path info badge
        db_badge = ctk.CTkLabel(
            card,
            text=f"📁 {self.vault.db_path}",
            font=(FONT_FAMILY, 10),
            text_color=COLORS["text_muted_dark"],
        )
        db_badge.pack(pady=(0, 15))

        # Password Entry Container
        pwd_container = ctk.CTkFrame(card, fg_color="transparent")
        pwd_container.pack(fill="x", padx=40, pady=(0, 10))

        self.pwd_entry = ctk.CTkEntry(
            pwd_container,
            placeholder_text="Master Password",
            show="•",
            height=42,
            font=(FONT_FAMILY, 14),
            fg_color=COLORS["bg_dark"],
            border_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
        )
        self.pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.pwd_entry.bind("<Return>", lambda e: self._attempt_unlock())

        self.show_pwd = False
        self.eye_btn = ctk.CTkButton(
            pwd_container,
            text="👁",
            width=42,
            height=42,
            fg_color=COLORS["card_hover_dark"],
            hover_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
            command=self._toggle_show_pwd,
        )
        self.eye_btn.pack(side="right")

        # Error notification label
        self.error_lbl = ctk.CTkLabel(
            card,
            text="",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["danger"],
        )
        self.error_lbl.pack(pady=(0, 10))

        # Unlock Action Button
        self.unlock_btn = ctk.CTkButton(
            card,
            text="Unlock Vault",
            height=44,
            font=(FONT_FAMILY, 14, "bold"),
            fg_color=COLORS["primary"],
            hover_color=COLORS["primary_hover"],
            command=self._attempt_unlock,
        )
        self.unlock_btn.pack(fill="x", padx=40, pady=(0, 20))

        # Footer Actions
        footer = ctk.CTkFrame(card, fg_color="transparent")
        footer.pack(fill="x", padx=40, pady=(0, 25))

        switch_btn = ctk.CTkButton(
            footer,
            text="Open Another Vault...",
            font=(FONT_FAMILY, 11),
            fg_color="transparent",
            hover_color=COLORS["card_hover_dark"],
            text_color=COLORS["text_muted_dark"],
            command=self.on_switch_vault,
        )
        switch_btn.pack(side="left")

        new_btn = ctk.CTkButton(
            footer,
            text="Create New Vault",
            font=(FONT_FAMILY, 11),
            fg_color="transparent",
            hover_color=COLORS["card_hover_dark"],
            text_color=COLORS["primary_light"],
            command=self.on_create_new,
        )
        new_btn.pack(side="right")

        # Focus password input automatically
        self.pwd_entry.focus()

    def _toggle_show_pwd(self):
        self.show_pwd = not self.show_pwd
        self.pwd_entry.configure(show="" if self.show_pwd else "•")
        self.eye_btn.configure(text="🔒" if self.show_pwd else "👁")

    def _attempt_unlock(self):
        password = self.pwd_entry.get()
        if not password:
            self.error_lbl.configure(text="Please enter your master password.")
            return

        self.error_lbl.configure(text="")
        self.unlock_btn.configure(state="disabled", text="Decrypting Vault...")
        self.update_idletasks()

        # Apply progressive delay if multiple failures occurred (anti-bruteforce)
        if self.failed_attempts > 0:
            delay = min(self.failed_attempts * 0.5, 3.0)
            time.sleep(delay)

        try:
            success = self.vault.unlock(password)
            if success:
                self.pwd_entry.delete(0, "end")
                self.failed_attempts = 0
                self.on_unlock_success()
        except InvalidMasterPasswordError:
            self.failed_attempts += 1
            self.error_lbl.configure(
                text=f"Incorrect master password. (Attempt {self.failed_attempts})"
            )
            self.pwd_entry.delete(0, "end")
            self.pwd_entry.focus()
        except Exception as e:
            self.error_lbl.configure(text=f"Error unlocking vault: {e}")
        finally:
            self.unlock_btn.configure(state="normal", text="Unlock Vault")
