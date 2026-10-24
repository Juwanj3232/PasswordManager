"""
Main vault explorer view featuring category sidebar, search filtering,
credential list, and detail inspector with secure clipboard copying.
"""

from tkinter import messagebox
from typing import Callable, List, Optional
import webbrowser
import customtkinter as ctk

from src.storage.vault import VaultEntry, VaultManager
from src.ui.styles import CATEGORIES, COLORS, FONT_FAMILY, FONT_MONO
from src.ui.views.entry_modal import EntryModal
from src.ui.views.generator_modal import GeneratorModal
from src.ui.views.settings_modal import SettingsModal
from src.utils.helpers import extract_domain, format_iso_timestamp


class VaultView(ctk.CTkFrame):
    """Main authenticated vault desktop interface."""

    def __init__(
        self,
        master,
        vault_manager: VaultManager,
        clipboard_mgr,
        on_lock_requested: Callable[[], None],
    ):
        super().__init__(master, fg_color=COLORS["bg_dark"])
        self.vault = vault_manager
        self.clipboard = clipboard_mgr
        self.on_lock_requested = on_lock_requested

        self.selected_category = "All"
        self.favorites_only = False
        self.selected_entry: Optional[VaultEntry] = None
        self.cached_entries: List[VaultEntry] = []
        self.show_inspector_pwd = False

        self._init_ui()
        self.refresh_entries()

    def _init_ui(self):
        # Top Header Bar
        self.header = ctk.CTkFrame(
            self,
            height=60,
            fg_color=COLORS["card_dark"],
            corner_radius=0,
            border_width=1,
            border_color=COLORS["border_dark"],
        )
        self.header.pack(fill="x", side="top")

        # App Brand & Status
        brand_frame = ctk.CTkFrame(self.header, fg_color="transparent")
        brand_frame.pack(side="left", padx=16, pady=10)

        logo_lbl = ctk.CTkLabel(
            brand_frame,
            text="🔐 LocalVault",
            font=(FONT_FAMILY, 16, "bold"),
            text_color=COLORS["text_dark"],
        )
        logo_lbl.pack(side="left")

        status_pill = ctk.CTkLabel(
            brand_frame,
            text="● Unlocked",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["success"],
        )
        status_pill.pack(side="left", padx=(10, 0))

        # Center Status Badges (Auto-Lock & Clipboard timer)
        self.timer_frame = ctk.CTkFrame(self.header, fg_color="transparent")
        self.timer_frame.pack(side="left", padx=30, expand=True)

        self.autolock_badge = ctk.CTkLabel(
            self.timer_frame,
            text="⏱️ Auto-lock Active",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_muted_dark"],
        )
        self.autolock_badge.pack(side="left", padx=8)

        self.clip_badge = ctk.CTkLabel(
            self.timer_frame,
            text="",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=COLORS["warning"],
        )
        self.clip_badge.pack(side="left", padx=8)

        # Header Action Buttons
        actions_frame = ctk.CTkFrame(self.header, fg_color="transparent")
        actions_frame.pack(side="right", padx=16, pady=10)

        new_btn = ctk.CTkButton(
            actions_frame,
            text="➕ New Item",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["primary"],
            hover_color=COLORS["primary_hover"],
            height=34,
            command=self._open_new_entry_modal,
        )
        new_btn.pack(side="left", padx=(0, 8))

        gen_btn = ctk.CTkButton(
            actions_frame,
            text="🎲 Generator",
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["card_hover_dark"],
            hover_color=COLORS["border_dark"],
            height=34,
            command=lambda: GeneratorModal(self, self.clipboard),
        )
        gen_btn.pack(side="left", padx=(0, 8))

        settings_btn = ctk.CTkButton(
            actions_frame,
            text="⚙️ Settings",
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["card_hover_dark"],
            hover_color=COLORS["border_dark"],
            height=34,
            command=self._open_settings_modal,
        )
        settings_btn.pack(side="left", padx=(0, 8))

        lock_btn = ctk.CTkButton(
            actions_frame,
            text="🔒 Lock",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["danger"],
            hover_color=COLORS["danger_hover"],
            height=34,
            command=self.on_lock_requested,
        )
        lock_btn.pack(side="left")

        # Main Body Splitter
        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.pack(fill="both", expand=True)

        self._build_sidebar()
        self._build_item_list()
        self._build_detail_inspector()

    def _build_sidebar(self):
        """Constructs left category navigation sidebar."""
        self.sidebar = ctk.CTkFrame(
            self.body,
            width=210,
            fg_color=COLORS["card_dark"],
            corner_radius=0,
            border_width=1,
            border_color=COLORS["border_dark"],
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        cat_title = ctk.CTkLabel(
            self.sidebar,
            text="CATEGORIES",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=COLORS["text_muted_dark"],
        )
        cat_title.pack(anchor="w", padx=16, pady=(16, 8))

        self.cat_buttons = {}

        # All items button
        self._add_sidebar_item("All", "📂 All Items")

        # Favorites button
        self._add_sidebar_item("Favorites", "⭐ Favorites")

        # Separator line
        sep = ctk.CTkFrame(self.sidebar, height=1, fg_color=COLORS["border_dark"])
        sep.pack(fill="x", padx=16, pady=8)

        for cat_name, icon in CATEGORIES:
            if cat_name in ("All", "Favorites"):
                continue
            self._add_sidebar_item(cat_name, f"{icon} {cat_name}")

    def _add_sidebar_item(self, key: str, label: str):
        btn = ctk.CTkButton(
            self.sidebar,
            text=label,
            font=(FONT_FAMILY, 12),
            height=34,
            anchor="w",
            fg_color="transparent",
            hover_color=COLORS["card_hover_dark"],
            text_color=COLORS["text_dark"],
            command=lambda k=key: self._on_select_category(k),
        )
        btn.pack(fill="x", padx=8, pady=2)
        self.cat_buttons[key] = btn

    def _build_item_list(self):
        """Constructs the center item list and search bar."""
        self.list_container = ctk.CTkFrame(
            self.body,
            width=360,
            fg_color=COLORS["bg_dark"],
            corner_radius=0,
            border_width=1,
            border_color=COLORS["border_dark"],
        )
        self.list_container.pack(side="left", fill="both")
        self.list_container.pack_propagate(False)

        # Search box
        search_frame = ctk.CTkFrame(self.list_container, fg_color="transparent")
        search_frame.pack(fill="x", padx=12, pady=12)

        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="🔍 Search credentials...",
            font=(FONT_FAMILY, 12),
            height=36,
            fg_color=COLORS["card_dark"],
            border_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
        )
        self.search_entry.pack(fill="x")
        self.search_entry.bind("<KeyRelease>", lambda e: self._on_search())

        # Scrollable items frame
        self.items_scroll = ctk.CTkScrollableFrame(self.list_container, fg_color="transparent")
        self.items_scroll.pack(fill="both", expand=True, padx=4, pady=(0, 8))

    def _build_detail_inspector(self):
        """Constructs the right detail inspector pane."""
        self.inspector = ctk.CTkFrame(self.body, fg_color=COLORS["card_dark"], corner_radius=0)
        self.inspector.pack(side="right", fill="both", expand=True)

        self.inspector_content = ctk.CTkFrame(self.inspector, fg_color="transparent")
        self.inspector_content.pack(fill="both", expand=True, padx=24, pady=20)

        self._show_empty_inspector()

    def _show_empty_inspector(self):
        for widget in self.inspector_content.winfo_children():
            widget.destroy()

        empty_box = ctk.CTkFrame(self.inspector_content, fg_color="transparent")
        empty_box.place(relx=0.5, rely=0.5, anchor="center")

        icon_lbl = ctk.CTkLabel(empty_box, text="🔒", font=(FONT_FAMILY, 40))
        icon_lbl.pack(pady=(0, 10))

        title_lbl = ctk.CTkLabel(
            empty_box,
            text="No Credential Selected",
            font=(FONT_FAMILY, 16, "bold"),
            text_color=COLORS["text_muted_dark"],
        )
        title_lbl.pack()

        sub_lbl = ctk.CTkLabel(
            empty_box,
            text="Choose an entry from the list or add a new one.",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_muted_dark"],
        )
        sub_lbl.pack(pady=(4, 0))

    def refresh_entries(self):
        """Reloads entries from vault database and refreshes view."""
        if not self.vault.is_unlocked:
            return

        query = self.search_entry.get().strip() if hasattr(self, "search_entry") else ""
        category_filter = "All" if self.selected_category in ("All", "Favorites") else self.selected_category
        favorites_filter = (self.selected_category == "Favorites")

        self.cached_entries = self.vault.list_entries(
            search_query=query,
            category=category_filter,
            favorites_only=favorites_filter,
        )

        # Update category buttons active appearance
        for k, btn in self.cat_buttons.items():
            if k == self.selected_category:
                btn.configure(fg_color=COLORS["card_hover_dark"], text_color=COLORS["primary_light"])
            else:
                btn.configure(fg_color="transparent", text_color=COLORS["text_dark"])

        self._render_entries_list()

        # Update inspector if currently selected entry exists
        if self.selected_entry:
            updated = self.vault.get_entry(self.selected_entry.id)
            if updated:
                self.selected_entry = updated
                self._render_inspector_entry(updated)
            else:
                self.selected_entry = None
                self._show_empty_inspector()

    def _render_entries_list(self):
        for widget in self.items_scroll.winfo_children():
            widget.destroy()

        if not self.cached_entries:
            empty_lbl = ctk.CTkLabel(
                self.items_scroll,
                text="No credentials found.",
                font=(FONT_FAMILY, 12),
                text_color=COLORS["text_muted_dark"],
            )
            empty_lbl.pack(pady=40)
            return

        for entry in self.cached_entries:
            is_active = (self.selected_entry and self.selected_entry.id == entry.id)
            card_bg = COLORS["card_hover_dark"] if is_active else COLORS["card_dark"]

            card = ctk.CTkFrame(
                self.items_scroll,
                fg_color=card_bg,
                corner_radius=10,
                border_width=1,
                border_color=COLORS["primary"] if is_active else COLORS["border_dark"],
            )
            card.pack(fill="x", pady=4, padx=4)

            # Click handler on card
            card.bind("<Button-1>", lambda e, item=entry: self._select_entry(item))

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=10, pady=8)
            inner.bind("<Button-1>", lambda e, item=entry: self._select_entry(item))

            # Title & Favorite Star
            header_row = ctk.CTkFrame(inner, fg_color="transparent")
            header_row.pack(fill="x")
            header_row.bind("<Button-1>", lambda e, item=entry: self._select_entry(item))

            title_txt = f"⭐ {entry.title}" if entry.is_favorite else entry.title
            t_lbl = ctk.CTkLabel(
                header_row,
                text=title_txt,
                font=(FONT_FAMILY, 13, "bold"),
                text_color=COLORS["text_dark"],
                anchor="w",
            )
            t_lbl.pack(side="left", fill="x", expand=True)
            t_lbl.bind("<Button-1>", lambda e, item=entry: self._select_entry(item))

            cat_pill = ctk.CTkLabel(
                header_row,
                text=entry.category,
                font=(FONT_FAMILY, 10),
                text_color=COLORS["text_muted_dark"],
            )
            cat_pill.pack(side="right")

            # Username / Subtitle
            user_lbl = ctk.CTkLabel(
                inner,
                text=entry.username or "(No username)",
                font=(FONT_FAMILY, 11),
                text_color=COLORS["text_muted_dark"],
                anchor="w",
            )
            user_lbl.pack(fill="x", pady=(2, 0))
            user_lbl.bind("<Button-1>", lambda e, item=entry: self._select_entry(item))

            # Quick Copy Action Row
            act_row = ctk.CTkFrame(inner, fg_color="transparent")
            act_row.pack(fill="x", pady=(6, 0))

            cp_user_btn = ctk.CTkButton(
                act_row,
                text="Copy User",
                font=(FONT_FAMILY, 10),
                height=22,
                fg_color=COLORS["bg_dark"],
                hover_color=COLORS["border_dark"],
                command=lambda e=entry: self._copy_with_toast(e.username, "Username"),
            )
            cp_user_btn.pack(side="left", padx=(0, 4))

            cp_pwd_btn = ctk.CTkButton(
                act_row,
                text="Copy Pass",
                font=(FONT_FAMILY, 10),
                height=22,
                fg_color=COLORS["bg_dark"],
                hover_color=COLORS["border_dark"],
                command=lambda e=entry: self._copy_with_toast(e.password, "Password"),
            )
            cp_pwd_btn.pack(side="left")

    def _select_entry(self, entry: VaultEntry):
        self.selected_entry = entry
        self.show_inspector_pwd = False
        self._render_entries_list()
        self._render_inspector_entry(entry)

    def _render_inspector_entry(self, entry: VaultEntry):
        for widget in self.inspector_content.winfo_children():
            widget.destroy()

        scroll = ctk.CTkScrollableFrame(self.inspector_content, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # Header with Title and Category
        header_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 16))

        t_lbl = ctk.CTkLabel(
            header_frame,
            text=entry.title,
            font=(FONT_FAMILY, 22, "bold"),
            text_color=COLORS["text_dark"],
            anchor="w",
        )
        t_lbl.pack(side="left", fill="x", expand=True)

        cat_badge = ctk.CTkLabel(
            header_frame,
            text=f"📂 {entry.category}",
            font=(FONT_FAMILY, 11),
            fg_color=COLORS["bg_dark"],
            corner_radius=6,
            padx=10,
            pady=4,
            text_color=COLORS["primary_light"],
        )
        cat_badge.pack(side="right")

        # Action Buttons (Edit & Delete)
        action_bar = ctk.CTkFrame(scroll, fg_color="transparent")
        action_bar.pack(fill="x", pady=(0, 16))

        edit_btn = ctk.CTkButton(
            action_bar,
            text="✏️ Edit",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["card_hover_dark"],
            hover_color=COLORS["border_dark"],
            height=32,
            command=lambda: self._open_edit_entry_modal(entry),
        )
        edit_btn.pack(side="left", padx=(0, 8))

        del_btn = ctk.CTkButton(
            action_bar,
            text="🗑️ Delete",
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["card_hover_dark"],
            hover_color=COLORS["danger_hover"],
            text_color=COLORS["danger"],
            height=32,
            command=lambda: self._confirm_delete(entry),
        )
        del_btn.pack(side="left")

        # Username Card
        self._build_field_card(
            scroll,
            label="Username / Email",
            value=entry.username or "—",
            copy_value=entry.username,
        )

        # Password Card
        self._build_password_card(scroll, entry.password)

        # Website / URL Card
        if entry.url:
            self._build_url_card(scroll, entry.url)

        # Notes Card
        if entry.notes:
            self._build_notes_card(scroll, entry.notes)

        # Timestamps footer
        time_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        time_frame.pack(fill="x", pady=(16, 0))

        created_text = f"Created: {format_iso_timestamp(entry.created_at)}"
        updated_text = f"Updated: {format_iso_timestamp(entry.updated_at)}"
        meta_lbl = ctk.CTkLabel(
            time_frame,
            text=f"{created_text}  •  {updated_text}",
            font=(FONT_FAMILY, 10),
            text_color=COLORS["text_muted_dark"],
            anchor="w",
        )
        meta_lbl.pack(fill="x")

    def _build_field_card(self, parent, label: str, value: str, copy_value: str = ""):
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg_dark"], corner_radius=10)
        card.pack(fill="x", pady=(0, 12))

        lbl = ctk.CTkLabel(
            card, text=label, font=(FONT_FAMILY, 11, "bold"), text_color=COLORS["text_muted_dark"], anchor="w"
        )
        lbl.pack(anchor="w", padx=14, pady=(10, 2))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 10))

        val_lbl = ctk.CTkLabel(
            row, text=value, font=(FONT_FAMILY, 13), text_color=COLORS["text_dark"], anchor="w"
        )
        val_lbl.pack(side="left", fill="x", expand=True)

        if copy_value:
            cp_btn = ctk.CTkButton(
                row,
                text="📋 Copy",
                font=(FONT_FAMILY, 11),
                width=65,
                height=26,
                fg_color=COLORS["card_dark"],
                hover_color=COLORS["card_hover_dark"],
                command=lambda: self._copy_with_toast(copy_value, label),
            )
            cp_btn.pack(side="right")

    def _build_password_card(self, parent, password: str):
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg_dark"], corner_radius=10)
        card.pack(fill="x", pady=(0, 12))

        lbl = ctk.CTkLabel(
            card, text="Password", font=(FONT_FAMILY, 11, "bold"), text_color=COLORS["text_muted_dark"], anchor="w"
        )
        lbl.pack(anchor="w", padx=14, pady=(10, 2))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 10))

        display_pwd = password if self.show_inspector_pwd else ("•" * len(password) if password else "—")
        self.inspector_pwd_lbl = ctk.CTkLabel(
            row,
            text=display_pwd,
            font=(FONT_MONO, 13, "bold"),
            text_color=COLORS["text_dark"],
            anchor="w",
        )
        self.inspector_pwd_lbl.pack(side="left", fill="x", expand=True)

        eye_btn = ctk.CTkButton(
            row,
            text="🔒" if self.show_inspector_pwd else "👁 Reveal",
            font=(FONT_FAMILY, 11),
            width=70,
            height=26,
            fg_color=COLORS["card_dark"],
            hover_color=COLORS["card_hover_dark"],
            command=lambda: self._toggle_inspector_pwd(password),
        )
        eye_btn.pack(side="right", padx=(6, 0))

        cp_btn = ctk.CTkButton(
            row,
            text="📋 Copy",
            font=(FONT_FAMILY, 11),
            width=65,
            height=26,
            fg_color=COLORS["primary"],
            hover_color=COLORS["primary_hover"],
            command=lambda: self._copy_with_toast(password, "Password"),
        )
        cp_btn.pack(side="right")

    def _toggle_inspector_pwd(self, password: str):
        self.show_inspector_pwd = not self.show_inspector_pwd
        self.refresh_entries()

    def _build_url_card(self, parent, url: str):
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg_dark"], corner_radius=10)
        card.pack(fill="x", pady=(0, 12))

        lbl = ctk.CTkLabel(
            card, text="Website URL", font=(FONT_FAMILY, 11, "bold"), text_color=COLORS["text_muted_dark"], anchor="w"
        )
        lbl.pack(anchor="w", padx=14, pady=(10, 2))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 10))

        domain = extract_domain(url)
        val_lbl = ctk.CTkLabel(
            row, text=f"🌐 {domain}", font=(FONT_FAMILY, 13), text_color=COLORS["primary_light"], anchor="w"
        )
        val_lbl.pack(side="left", fill="x", expand=True)

        open_btn = ctk.CTkButton(
            row,
            text="Open ↗",
            font=(FONT_FAMILY, 11),
            width=65,
            height=26,
            fg_color=COLORS["card_dark"],
            hover_color=COLORS["card_hover_dark"],
            command=lambda: webbrowser.open(url if url.startswith("http") else f"https://{url}"),
        )
        open_btn.pack(side="right", padx=(6, 0))

        cp_btn = ctk.CTkButton(
            row,
            text="📋 Copy",
            font=(FONT_FAMILY, 11),
            width=65,
            height=26,
            fg_color=COLORS["card_dark"],
            hover_color=COLORS["card_hover_dark"],
            command=lambda: self._copy_with_toast(url, "URL"),
        )
        cp_btn.pack(side="right")

    def _build_notes_card(self, parent, notes: str):
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg_dark"], corner_radius=10)
        card.pack(fill="x", pady=(0, 12))

        lbl = ctk.CTkLabel(
            card, text="Notes", font=(FONT_FAMILY, 11, "bold"), text_color=COLORS["text_muted_dark"], anchor="w"
        )
        lbl.pack(anchor="w", padx=14, pady=(10, 2))

        notes_box = ctk.CTkTextbox(
            card,
            font=(FONT_FAMILY, 12),
            height=90,
            fg_color="transparent",
            text_color=COLORS["text_dark"],
            wrap="word",
        )
        notes_box.insert("1.0", notes)
        notes_box.configure(state="disabled")
        notes_box.pack(fill="x", padx=14, pady=(0, 10))

    def _copy_with_toast(self, text: str, field_name: str):
        if not text:
            return

        # Read configured timeout
        timeout_setting = int(self.vault.db.get_setting("clipboard_clear_seconds", "30"))

        def on_tick(remaining: int):
            self.after(0, lambda: self.clip_badge.configure(
                text=f"📋 {field_name} copied! Auto-clears in {remaining}s"
            ))

        def on_cleared():
            self.after(0, lambda: self.clip_badge.configure(text=""))

        self.clipboard.copy(
            text,
            timeout_seconds=timeout_setting,
            on_tick=on_tick,
            on_cleared=on_cleared,
        )

    def _on_select_category(self, cat_key: str):
        self.selected_category = cat_key
        self.refresh_entries()

    def _on_search(self):
        self.refresh_entries()

    def _open_new_entry_modal(self):
        def on_save(data: dict):
            new_item = self.vault.add_entry(**data)
            self.selected_entry = new_item
            self.refresh_entries()

        EntryModal(self, self.clipboard, on_save=on_save)

    def _open_edit_entry_modal(self, entry: VaultEntry):
        def on_save(data: dict):
            updated = self.vault.update_entry(entry.id, **data)
            self.selected_entry = updated
            self.refresh_entries()

        EntryModal(self, self.clipboard, entry=entry, on_save=on_save)

    def _confirm_delete(self, entry: VaultEntry):
        confirm = messagebox.askyesno(
            "Delete Credential",
            f"Are you sure you want to permanently delete '{entry.title}'?\nThis cannot be undone.",
            icon="warning",
        )
        if confirm:
            self.vault.delete_entry(entry.id)
            self.selected_entry = None
            self.refresh_entries()
            self._show_empty_inspector()

    def _open_settings_modal(self):
        SettingsModal(
            self,
            self.vault,
            on_settings_changed=self.refresh_entries,
            on_lock_request=self.on_lock_requested,
        )
