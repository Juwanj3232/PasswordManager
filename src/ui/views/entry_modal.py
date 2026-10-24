"""
Modal dialog for adding and editing credential entries.
"""

from typing import Callable, Optional
import customtkinter as ctk

from src.storage.vault import VaultEntry
from src.ui.styles import CATEGORIES, COLORS, FONT_FAMILY
from src.ui.views.generator_modal import GeneratorModal


class EntryModal(ctk.CTkToplevel):
    """Popup modal dialog for creating or updating a vault credential."""

    def __init__(
        self,
        parent,
        clipboard_mgr,
        entry: Optional[VaultEntry] = None,
        on_save: Optional[Callable[[dict], None]] = None,
    ):
        super().__init__(parent)
        self.clipboard = clipboard_mgr
        self.entry = entry
        self.on_save = on_save

        self.title("Edit Credential" if entry else "Add New Credential")
        self.geometry("540x660")
        self.resizable(False, False)
        self.configure(fg_color=COLORS["bg_dark"])

        self.transient(parent)
        self.grab_set()

        self.show_pwd = False
        self._init_ui()

    def _init_ui(self):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=26, pady=20)

        # Header Title
        title_text = "✏️ Edit Credential" if self.entry else "➕ Add Credential"
        header_lbl = ctk.CTkLabel(
            container,
            text=title_text,
            font=(FONT_FAMILY, 18, "bold"),
            text_color=COLORS["text_dark"],
        )
        header_lbl.pack(anchor="w", pady=(0, 16))

        # Title Field
        self._build_label(container, "Title / Service *")
        self.title_entry = self._build_entry(container, placeholder="e.g. GitHub, AWS, Bank Account")
        if self.entry:
            self.title_entry.insert(0, self.entry.title)

        # Category and Favorite Row
        meta_row = ctk.CTkFrame(container, fg_color="transparent")
        meta_row.pack(fill="x", pady=(0, 10))

        cat_col = ctk.CTkFrame(meta_row, fg_color="transparent")
        cat_col.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self._build_label(cat_col, "Category")
        
        category_options = [c[0] for c in CATEGORIES if c[0] != "All"]
        self.category_menu = ctk.CTkOptionMenu(
            cat_col,
            values=category_options,
            fg_color=COLORS["card_dark"],
            button_color=COLORS["card_hover_dark"],
            height=36,
        )
        self.category_menu.set(self.entry.category if self.entry else "Logins")
        self.category_menu.pack(fill="x")

        fav_col = ctk.CTkFrame(meta_row, fg_color="transparent")
        fav_col.pack(side="right", padx=(10, 0), pady=(18, 0))
        self.fav_var = ctk.BooleanVar(value=self.entry.is_favorite if self.entry else False)
        self.fav_cb = ctk.CTkCheckBox(
            fav_col,
            text="⭐ Favorite",
            variable=self.fav_var,
            font=(FONT_FAMILY, 12),
        )
        self.fav_cb.pack()

        # Username / Email Field
        self._build_label(container, "Username / Email")
        user_row = ctk.CTkFrame(container, fg_color="transparent")
        user_row.pack(fill="x", pady=(0, 10))

        self.user_entry = ctk.CTkEntry(
            user_row,
            placeholder_text="e.g. john@example.com",
            height=36,
            font=(FONT_FAMILY, 13),
            fg_color=COLORS["card_dark"],
            border_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
        )
        self.user_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        if self.entry:
            self.user_entry.insert(0, self.entry.username)

        user_copy_btn = ctk.CTkButton(
            user_row,
            text="📋",
            width=36,
            height=36,
            fg_color=COLORS["card_dark"],
            hover_color=COLORS["card_hover_dark"],
            command=lambda: self.clipboard.copy(self.user_entry.get()),
        )
        user_copy_btn.pack(side="right")

        # Password Field with Actions
        self._build_label(container, "Password")
        pwd_row = ctk.CTkFrame(container, fg_color="transparent")
        pwd_row.pack(fill="x", pady=(0, 10))

        self.pwd_entry = ctk.CTkEntry(
            pwd_row,
            placeholder_text="Enter or generate password",
            show="•",
            height=36,
            font=(FONT_FAMILY, 13),
            fg_color=COLORS["card_dark"],
            border_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
        )
        self.pwd_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        if self.entry:
            self.pwd_entry.insert(0, self.entry.password)

        self.eye_btn = ctk.CTkButton(
            pwd_row,
            text="👁",
            width=36,
            height=36,
            fg_color=COLORS["card_dark"],
            hover_color=COLORS["card_hover_dark"],
            command=self._toggle_pwd,
        )
        self.eye_btn.pack(side="left", padx=(0, 6))

        gen_btn = ctk.CTkButton(
            pwd_row,
            text="🎲 Generate",
            width=85,
            height=36,
            fg_color=COLORS["card_hover_dark"],
            hover_color=COLORS["border_dark"],
            command=self._open_generator,
        )
        gen_btn.pack(side="right")

        # Website / URL Field
        self._build_label(container, "Website URL")
        self.url_entry = self._build_entry(container, placeholder="https://example.com")
        if self.entry:
            self.url_entry.insert(0, self.entry.url)

        # Notes Multi-line Field
        self._build_label(container, "Secure Notes")
        self.notes_text = ctk.CTkTextbox(
            container,
            height=85,
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["card_dark"],
            border_width=1,
            border_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
        )
        self.notes_text.pack(fill="x", pady=(0, 15))
        if self.entry and self.entry.notes:
            self.notes_text.insert("1.0", self.entry.notes)

        # Error notification
        self.error_lbl = ctk.CTkLabel(
            container, text="", font=(FONT_FAMILY, 11), text_color=COLORS["danger"]
        )
        self.error_lbl.pack(pady=(0, 8))

        # Bottom Action Buttons
        btn_row = ctk.CTkFrame(container, fg_color="transparent")
        btn_row.pack(fill="x", side="bottom")

        cancel_btn = ctk.CTkButton(
            btn_row,
            text="Cancel",
            font=(FONT_FAMILY, 13),
            fg_color=COLORS["card_dark"],
            hover_color=COLORS["card_hover_dark"],
            height=40,
            command=self.destroy,
        )
        cancel_btn.pack(side="left", fill="x", expand=True, padx=(0, 10))

        save_btn = ctk.CTkButton(
            btn_row,
            text="Save Credential",
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["primary"],
            hover_color=COLORS["primary_hover"],
            height=40,
            command=self._save,
        )
        save_btn.pack(side="right", fill="x", expand=True)

        self.title_entry.focus()

    def _build_label(self, parent, text: str):
        lbl = ctk.CTkLabel(
            parent,
            text=text,
            font=(FONT_FAMILY, 11, "bold"),
            text_color=COLORS["text_muted_dark"],
            anchor="w",
        )
        lbl.pack(fill="x", pady=(0, 3))
        return lbl

    def _build_entry(self, parent, placeholder: str):
        entry = ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            height=36,
            font=(FONT_FAMILY, 13),
            fg_color=COLORS["card_dark"],
            border_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
        )
        entry.pack(fill="x", pady=(0, 10))
        return entry

    def _toggle_pwd(self):
        self.show_pwd = not self.show_pwd
        self.pwd_entry.configure(show="" if self.show_pwd else "•")
        self.eye_btn.configure(text="🔒" if self.show_pwd else "👁")

    def _open_generator(self):
        def on_use(pwd: str):
            self.pwd_entry.delete(0, "end")
            self.pwd_entry.insert(0, pwd)
            if not self.show_pwd:
                self._toggle_pwd()

        GeneratorModal(self, self.clipboard, on_use_password=on_use)

    def _save(self):
        title = self.title_entry.get().strip()
        if not title:
            self.error_lbl.configure(text="Title is required.")
            return

        data = {
            "title": title,
            "category": self.category_menu.get(),
            "username": self.user_entry.get().strip(),
            "password": self.pwd_entry.get(),
            "url": self.url_entry.get().strip(),
            "notes": self.notes_text.get("1.0", "end-1c").strip(),
            "is_favorite": self.fav_var.get(),
        }

        if self.on_save:
            self.on_save(data)

        self.destroy()
