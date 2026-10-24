"""
Initial setup screen for creating a new encrypted local vault with a master password.
"""

from tkinter import filedialog
import customtkinter as ctk
from src.crypto.generator import calculate_entropy
from src.ui.styles import COLORS, FONT_FAMILY


class SetupView(ctk.CTkFrame):
    """View guiding the user through initial master password creation."""

    def __init__(self, master, on_setup_success, vault_manager):
        super().__init__(master, fg_color=COLORS["bg_dark"])
        self.on_setup_success = on_setup_success
        self.vault = vault_manager
        self.custom_db_path = self.vault.db_path

        self._init_ui()

    def _init_ui(self):
        card = ctk.CTkFrame(
            self,
            fg_color=COLORS["card_dark"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border_dark"],
            width=500,
        )
        card.place(relx=0.5, rely=0.5, anchor="center")

        # Shield Icon & App Title
        icon_lbl = ctk.CTkLabel(card, text="🔐", font=(FONT_FAMILY, 46))
        icon_lbl.pack(pady=(30, 5))

        title_lbl = ctk.CTkLabel(
            card,
            text="Create New Local Vault",
            font=(FONT_FAMILY, 22, "bold"),
            text_color=COLORS["text_dark"],
        )
        title_lbl.pack(pady=(0, 4))

        subtitle_lbl = ctk.CTkLabel(
            card,
            text="Set a strong Master Password. All credentials will be encrypted\nlocally using Argon2id and AES-256-GCM on your disk.",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_muted_dark"],
            justify="center",
        )
        subtitle_lbl.pack(pady=(0, 20))

        # Vault Location Row
        loc_frame = ctk.CTkFrame(card, fg_color=COLORS["bg_dark"], corner_radius=8)
        loc_frame.pack(fill="x", padx=40, pady=(0, 15))

        self.loc_lbl = ctk.CTkLabel(
            loc_frame,
            text=f"Database: {self.custom_db_path}",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_muted_dark"],
            anchor="w",
        )
        self.loc_lbl.pack(side="left", padx=10, pady=8, fill="x", expand=True)

        browse_btn = ctk.CTkButton(
            loc_frame,
            text="Browse...",
            width=70,
            height=26,
            font=(FONT_FAMILY, 11),
            fg_color=COLORS["card_dark"],
            hover_color=COLORS["card_hover_dark"],
            command=self._browse_location,
        )
        browse_btn.pack(side="right", padx=6, pady=6)

        # Master Password Field
        pwd_label = ctk.CTkLabel(
            card, text="Master Password", font=(FONT_FAMILY, 12, "bold"), text_color=COLORS["text_dark"], anchor="w"
        )
        pwd_label.pack(fill="x", padx=40, pady=(0, 4))

        pwd_container = ctk.CTkFrame(card, fg_color="transparent")
        pwd_container.pack(fill="x", padx=40, pady=(0, 10))

        self.pwd_entry = ctk.CTkEntry(
            pwd_container,
            placeholder_text="Enter strong master password",
            show="•",
            height=40,
            font=(FONT_FAMILY, 13),
            fg_color=COLORS["bg_dark"],
            border_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
        )
        self.pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.pwd_entry.bind("<KeyRelease>", lambda e: self._update_strength_meter())

        self.show_pwd = False
        self.eye_btn = ctk.CTkButton(
            pwd_container,
            text="👁",
            width=40,
            height=40,
            fg_color=COLORS["card_hover_dark"],
            hover_color=COLORS["border_dark"],
            command=self._toggle_show_pwd,
        )
        self.eye_btn.pack(side="right")

        # Password Strength Bar & Label
        self.strength_bar = ctk.CTkProgressBar(card, height=6, corner_radius=3)
        self.strength_bar.set(0)
        self.strength_bar.pack(fill="x", padx=40, pady=(0, 4))

        self.strength_lbl = ctk.CTkLabel(
            card,
            text="Strength: Minimum 8 characters required",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_muted_dark"],
            anchor="w",
        )
        self.strength_lbl.pack(fill="x", padx=40, pady=(0, 12))

        # Confirm Password Field
        conf_label = ctk.CTkLabel(
            card, text="Confirm Master Password", font=(FONT_FAMILY, 12, "bold"), text_color=COLORS["text_dark"], anchor="w"
        )
        conf_label.pack(fill="x", padx=40, pady=(0, 4))

        self.conf_entry = ctk.CTkEntry(
            card,
            placeholder_text="Re-enter master password",
            show="•",
            height=40,
            font=(FONT_FAMILY, 13),
            fg_color=COLORS["bg_dark"],
            border_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
        )
        self.conf_entry.pack(fill="x", padx=40, pady=(0, 15))
        self.conf_entry.bind("<Return>", lambda e: self._attempt_setup())

        # Error notification label
        self.error_lbl = ctk.CTkLabel(
            card,
            text="",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["danger"],
        )
        self.error_lbl.pack(pady=(0, 10))

        # Warning / Security Note
        warning_frame = ctk.CTkFrame(card, fg_color=COLORS["bg_dark"], corner_radius=8)
        warning_frame.pack(fill="x", padx=40, pady=(0, 20))

        warning_lbl = ctk.CTkLabel(
            warning_frame,
            text="⚠️ IMPORTANT: There is NO cloud recovery or password reset.\nMake sure to remember or securely store your master password.",
            font=(FONT_FAMILY, 10),
            text_color=COLORS["warning"],
            justify="center",
        )
        warning_lbl.pack(padx=10, pady=8)

        # Create Vault Button
        self.create_btn = ctk.CTkButton(
            card,
            text="Initialize Encrypted Vault",
            height=44,
            font=(FONT_FAMILY, 14, "bold"),
            fg_color=COLORS["success"],
            hover_color=COLORS["success_hover"],
            command=self._attempt_setup,
        )
        self.create_btn.pack(fill="x", padx=40, pady=(0, 30))

        self.pwd_entry.focus()

    def _browse_location(self):
        chosen = filedialog.asksaveasfilename(
            title="Choose Vault File Location",
            defaultextension=".db",
            filetypes=[("SQLite Vault Database", "*.db"), ("All Files", "*.*")],
            initialfile="vault.db",
        )
        if chosen:
            self.custom_db_path = chosen
            self.loc_lbl.configure(text=f"Database: {chosen}")

    def _toggle_show_pwd(self):
        self.show_pwd = not self.show_pwd
        self.pwd_entry.configure(show="" if self.show_pwd else "•")
        self.conf_entry.configure(show="" if self.show_pwd else "•")
        self.eye_btn.configure(text="🔒" if self.show_pwd else "👁")

    def _update_strength_meter(self):
        pwd = self.pwd_entry.get()
        if not pwd:
            self.strength_bar.set(0)
            self.strength_lbl.configure(
                text="Strength: Minimum 8 characters required",
                text_color=COLORS["text_muted_dark"],
            )
            return

        analysis = calculate_entropy(pwd)
        score_ratio = analysis["score"] / 100.0
        self.strength_bar.set(score_ratio)
        self.strength_bar.configure(progress_color=analysis["color"])

        self.strength_lbl.configure(
            text=f"Strength: {analysis['rating']} ({analysis['bits']} bits entropy • Crack time: {analysis['crack_time']})",
            text_color=analysis["color"],
        )

    def _attempt_setup(self):
        password = self.pwd_entry.get()
        confirm = self.conf_entry.get()

        if len(password) < 8:
            self.error_lbl.configure(text="Master password must be at least 8 characters long.")
            return

        if password != confirm:
            self.error_lbl.configure(text="Passwords do not match. Please verify.")
            return

        self.error_lbl.configure(text="")
        self.create_btn.configure(state="disabled", text="Deriving Argon2id Keys...")
        self.update_idletasks()

        try:
            # If path changed, update database manager
            if self.custom_db_path != self.vault.db_path:
                from src.storage.vault import VaultManager
                self.vault = VaultManager(self.custom_db_path)

            self.vault.setup_vault(password)
            self.pwd_entry.delete(0, "end")
            self.conf_entry.delete(0, "end")
            self.on_setup_success(self.vault)
        except Exception as e:
            self.error_lbl.configure(text=f"Setup failed: {e}")
            self.create_btn.configure(state="normal", text="Initialize Encrypted Vault")
