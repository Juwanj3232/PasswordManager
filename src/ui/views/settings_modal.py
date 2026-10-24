"""
Settings modal for auto-lock timers, clipboard timeouts, backup/restore, and master password change.
"""

from tkinter import filedialog, messagebox
import customtkinter as ctk

from src.crypto.cipher import InvalidMasterPasswordError
from src.storage.backup import (
    export_decrypted_json,
    export_encrypted_backup,
    import_encrypted_backup,
    import_json_entries,
)
from src.ui.styles import COLORS, FONT_FAMILY


class SettingsModal(ctk.CTkToplevel):
    """Configuration modal for security policies, master password rotation, and backups."""

    def __init__(self, parent, vault_manager, on_settings_changed, on_lock_request):
        super().__init__(parent)
        self.vault = vault_manager
        self.on_settings_changed = on_settings_changed
        self.on_lock_request = on_lock_request

        self.title("Settings & Security")
        self.geometry("560x680")
        self.resizable(False, False)
        self.configure(fg_color=COLORS["bg_dark"])

        self.transient(parent)
        self.grab_set()

        self._init_ui()

    def _init_ui(self):
        # Scrollable container for all setting sections
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=24, pady=20)

        # Title
        title_lbl = ctk.CTkLabel(
            scroll,
            text="⚙️ Settings & Security",
            font=(FONT_FAMILY, 20, "bold"),
            text_color=COLORS["text_dark"],
        )
        title_lbl.pack(anchor="w", pady=(0, 16))

        # ---------------- Section 1: Inactivity & Clipboard ----------------
        self._build_section_header(scroll, "🔒 Security Timeouts")
        sec_card = ctk.CTkFrame(
            scroll,
            fg_color=COLORS["card_dark"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border_dark"],
        )
        sec_card.pack(fill="x", pady=(0, 20))

        # Auto-lock setting
        lock_row = ctk.CTkFrame(sec_card, fg_color="transparent")
        lock_row.pack(fill="x", padx=16, pady=(16, 10))

        lock_lbl = ctk.CTkLabel(
            lock_row,
            text="Auto-Lock Inactivity Period",
            font=(FONT_FAMILY, 12, "bold"),
            text_color=COLORS["text_dark"],
        )
        lock_lbl.pack(side="left")

        current_autolock = self.vault.db.get_setting("auto_lock_minutes", "5")
        self.autolock_menu = ctk.CTkOptionMenu(
            lock_row,
            values=["1 minute", "5 minutes", "10 minutes", "15 minutes", "30 minutes", "Never"],
            command=self._on_autolock_changed,
            width=130,
        )
        self.autolock_menu.set(f"{current_autolock} minutes" if current_autolock != "0" else "Never")
        self.autolock_menu.pack(side="right")

        # Clipboard auto-clear setting
        clip_row = ctk.CTkFrame(sec_card, fg_color="transparent")
        clip_row.pack(fill="x", padx=16, pady=(0, 16))

        clip_lbl = ctk.CTkLabel(
            clip_row,
            text="Clipboard Auto-Clear Timeout",
            font=(FONT_FAMILY, 12, "bold"),
            text_color=COLORS["text_dark"],
        )
        clip_lbl.pack(side="left")

        current_clip = self.vault.db.get_setting("clipboard_clear_seconds", "30")
        self.clip_menu = ctk.CTkOptionMenu(
            clip_row,
            values=["10 seconds", "30 seconds", "60 seconds", "Never"],
            command=self._on_clip_changed,
            width=130,
        )
        self.clip_menu.set(f"{current_clip} seconds" if current_clip != "0" else "Never")
        self.clip_menu.pack(side="right")

        # ---------------- Section 2: Local Backup & Export ----------------
        self._build_section_header(scroll, "💾 Local Backup & Restore")
        backup_card = ctk.CTkFrame(
            scroll,
            fg_color=COLORS["card_dark"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border_dark"],
        )
        backup_card.pack(fill="x", pady=(0, 20))

        # Backup explanation
        b_info = ctk.CTkLabel(
            backup_card,
            text="Your vault database is completely self-contained. Backups remain\nencrypted with your Master Password and Argon2id + AES-256-GCM.",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_muted_dark"],
            justify="left",
        )
        b_info.pack(anchor="w", padx=16, pady=(14, 10))

        # Buttons row
        btn_grid = ctk.CTkFrame(backup_card, fg_color="transparent")
        btn_grid.pack(fill="x", padx=16, pady=(0, 14))

        exp_enc_btn = ctk.CTkButton(
            btn_grid,
            text="Export Encrypted Backup...",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["primary"],
            hover_color=COLORS["primary_hover"],
            command=self._export_encrypted,
        )
        exp_enc_btn.pack(side="left", fill="x", expand=True, padx=(0, 6))

        imp_enc_btn = ctk.CTkButton(
            btn_grid,
            text="Restore Encrypted Backup...",
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["card_hover_dark"],
            hover_color=COLORS["border_dark"],
            command=self._import_encrypted,
        )
        imp_enc_btn.pack(side="right", fill="x", expand=True)

        # JSON Export / Import buttons
        json_row = ctk.CTkFrame(backup_card, fg_color="transparent")
        json_row.pack(fill="x", padx=16, pady=(0, 16))

        exp_json_btn = ctk.CTkButton(
            json_row,
            text="Export Decrypted JSON",
            font=(FONT_FAMILY, 11),
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border_dark"],
            hover_color=COLORS["card_hover_dark"],
            text_color=COLORS["warning"],
            command=self._export_json,
        )
        exp_json_btn.pack(side="left", fill="x", expand=True, padx=(0, 6))

        imp_json_btn = ctk.CTkButton(
            json_row,
            text="Import Credentials from JSON",
            font=(FONT_FAMILY, 11),
            fg_color="transparent",
            border_width=1,
            border_color=COLORS["border_dark"],
            hover_color=COLORS["card_hover_dark"],
            text_color=COLORS["text_muted_dark"],
            command=self._import_json,
        )
        imp_json_btn.pack(side="right", fill="x", expand=True)

        # ---------------- Section 3: Change Master Password ----------------
        self._build_section_header(scroll, "🔑 Change Master Password")
        pwd_card = ctk.CTkFrame(
            scroll,
            fg_color=COLORS["card_dark"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border_dark"],
        )
        pwd_card.pack(fill="x", pady=(0, 20))

        # Current password
        self.old_pwd_entry = ctk.CTkEntry(
            pwd_card,
            placeholder_text="Current Master Password",
            show="•",
            height=36,
            fg_color=COLORS["bg_dark"],
            border_color=COLORS["border_dark"],
        )
        self.old_pwd_entry.pack(fill="x", padx=16, pady=(16, 8))

        # New password
        self.new_pwd_entry = ctk.CTkEntry(
            pwd_card,
            placeholder_text="New Master Password (min 8 chars)",
            show="•",
            height=36,
            fg_color=COLORS["bg_dark"],
            border_color=COLORS["border_dark"],
        )
        self.new_pwd_entry.pack(fill="x", padx=16, pady=(0, 8))

        # Confirm new password
        self.conf_pwd_entry = ctk.CTkEntry(
            pwd_card,
            placeholder_text="Confirm New Master Password",
            show="•",
            height=36,
            fg_color=COLORS["bg_dark"],
            border_color=COLORS["border_dark"],
        )
        self.conf_pwd_entry.pack(fill="x", padx=16, pady=(0, 10))

        self.pwd_status_lbl = ctk.CTkLabel(
            pwd_card, text="", font=(FONT_FAMILY, 11), text_color=COLORS["danger"]
        )
        self.pwd_status_lbl.pack(padx=16, pady=(0, 8))

        change_btn = ctk.CTkButton(
            pwd_card,
            text="Re-Encrypt Vault with New Password",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["primary"],
            hover_color=COLORS["primary_hover"],
            height=38,
            command=self._change_master_password,
        )
        change_btn.pack(fill="x", padx=16, pady=(0, 16))

        # ---------------- Section 4: Cryptography & System Info ----------------
        self._build_section_header(scroll, "🛡️ Security Architecture")
        info_card = ctk.CTkFrame(
            scroll,
            fg_color=COLORS["bg_dark"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border_dark"],
        )
        info_card.pack(fill="x", pady=(0, 10))

        info_text = (
            f"• Database: {self.vault.db_path}\n"
            f"• Key Derivation: Argon2id (Time=3, Memory=64MB, Parallelism=4)\n"
            f"• Authenticated Encryption: AES-256-GCM (12-byte random nonces)\n"
            f"• Subkey Hierarchy: HKDF-SHA256 domain separation\n"
            f"• Network Egress: 0% (Pure local execution, zero cloud synchronization)\n"
            f"• Memory Zeroization: in-place ctypes buffer wipes upon lock"
        )
        info_lbl = ctk.CTkLabel(
            info_card,
            text=info_text,
            font=(FONT_FAMILY, 10),
            text_color=COLORS["text_muted_dark"],
            justify="left",
            anchor="w",
        )
        info_lbl.pack(padx=16, pady=12, fill="x")

    def _build_section_header(self, parent, text: str):
        lbl = ctk.CTkLabel(
            parent,
            text=text,
            font=(FONT_FAMILY, 13, "bold"),
            text_color=COLORS["text_dark"],
            anchor="w",
        )
        lbl.pack(fill="x", pady=(0, 6))

    def _on_autolock_changed(self, choice: str):
        val = choice.split()[0] if choice != "Never" else "0"
        self.vault.db.set_setting("auto_lock_minutes", val)
        if self.on_settings_changed:
            self.on_settings_changed()

    def _on_clip_changed(self, choice: str):
        val = choice.split()[0] if choice != "Never" else "0"
        self.vault.db.set_setting("clipboard_clear_seconds", val)
        if self.on_settings_changed:
            self.on_settings_changed()

    def _export_encrypted(self):
        dest = filedialog.asksaveasfilename(
            title="Export Encrypted Vault Backup",
            defaultextension=".db",
            filetypes=[("SQLite Vault Database", "*.db"), ("All Files", "*.*")],
            initialfile="vault-backup.db",
        )
        if dest:
            try:
                export_encrypted_backup(self.vault.db_path, dest)
                messagebox.showinfo(
                    "Backup Complete",
                    f"Encrypted vault backup successfully saved to:\n{dest}\n\nThis file is encrypted with your Master Password.",
                )
            except Exception as e:
                messagebox.showerror("Export Failed", f"Could not create backup: {e}")

    def _import_encrypted(self):
        src = filedialog.askopenfilename(
            title="Select Encrypted Vault Backup to Restore",
            filetypes=[("SQLite Vault Database", "*.db"), ("All Files", "*.*")],
        )
        if not src:
            return

        confirm = messagebox.askyesno(
            "Confirm Vault Restore",
            "Restoring this backup will replace your current vault database.\n(A safety copy of your current file will be preserved).\n\nDo you wish to proceed?",
            icon="warning",
        )
        if confirm:
            try:
                import_encrypted_backup(src, self.vault.db_path)
                messagebox.showinfo(
                    "Restore Successful",
                    "The vault has been restored from backup. Please log in with the backup's master password.",
                )
                self.destroy()
                if self.on_lock_request:
                    self.on_lock_request()
            except Exception as e:
                messagebox.showerror("Restore Failed", f"Could not restore backup: {e}")

    def _export_json(self):
        confirm = messagebox.askyesno(
            "Export Decrypted Credentials?",
            "⚠️ SECURITY WARNING:\nThis will export your credentials as UNENCRYPTED plaintext JSON.\nAnyone with access to the exported file can read your passwords.\n\nAre you sure you want to continue?",
            icon="warning",
        )
        if not confirm:
            return

        dest = filedialog.asksaveasfilename(
            title="Export Decrypted JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            initialfile="vault-export.json",
        )
        if dest:
            try:
                count = export_decrypted_json(self.vault, dest)
                messagebox.showinfo(
                    "Export Complete",
                    f"Exported {count} credentials to:\n{dest}\n\nKeep this file secure and delete it after use!",
                )
            except Exception as e:
                messagebox.showerror("Export Failed", f"Failed to export JSON: {e}")

    def _import_json(self):
        src = filedialog.askopenfilename(
            title="Select JSON File to Import",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if not src:
            return

        try:
            count = import_json_entries(self.vault, src)
            messagebox.showinfo("Import Complete", f"Successfully imported {count} credentials into your vault.")
            if self.on_settings_changed:
                self.on_settings_changed()
        except Exception as e:
            messagebox.showerror("Import Failed", f"Failed to import JSON entries: {e}")

    def _change_master_password(self):
        old_pwd = self.old_pwd_entry.get()
        new_pwd = self.new_pwd_entry.get()
        conf_pwd = self.conf_pwd_entry.get()

        if not old_pwd:
            self.pwd_status_lbl.configure(text="Please enter your current master password.")
            return

        if len(new_pwd) < 8:
            self.pwd_status_lbl.configure(text="New master password must be at least 8 characters.")
            return

        if new_pwd != conf_pwd:
            self.pwd_status_lbl.configure(text="New passwords do not match.")
            return

        self.pwd_status_lbl.configure(text="Re-encrypting all vault entries...", text_color=COLORS["primary"])
        self.update_idletasks()

        try:
            self.vault.change_master_password(old_pwd, new_pwd)
            self.old_pwd_entry.delete(0, "end")
            self.new_pwd_entry.delete(0, "end")
            self.conf_pwd_entry.delete(0, "end")
            self.pwd_status_lbl.configure(
                text="✓ Master password changed and all entries re-encrypted!",
                text_color=COLORS["success"],
            )
            messagebox.showinfo("Success", "Master password updated. All records have been re-encrypted.")
        except InvalidMasterPasswordError:
            self.pwd_status_lbl.configure(text="Current master password was incorrect.", text_color=COLORS["danger"])
        except Exception as e:
            self.pwd_status_lbl.configure(text=f"Re-encryption failed: {e}", text_color=COLORS["danger"])
