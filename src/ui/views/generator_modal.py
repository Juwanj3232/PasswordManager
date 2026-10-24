"""
Password and Passphrase Generator modal window with entropy assessment.
"""

from typing import Callable, Optional
import customtkinter as ctk

from src.crypto.generator import (
    calculate_entropy,
    generate_passphrase,
    generate_password,
)
from src.ui.styles import COLORS, FONT_FAMILY, FONT_MONO


class GeneratorModal(ctk.CTkToplevel):
    """Standalone popup modal for generating cryptographically secure credentials."""

    def __init__(
        self,
        parent,
        clipboard_mgr,
        on_use_password: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(parent)
        self.clipboard = clipboard_mgr
        self.on_use_password = on_use_password

        self.title("Secure Password Generator")
        self.geometry("520x620")
        self.resizable(False, False)
        self.configure(fg_color=COLORS["bg_dark"])

        # Make modal window stay on top
        self.transient(parent)
        self.grab_set()

        self.mode_var = ctk.StringVar(value="password")
        self.length_var = ctk.IntVar(value=20)
        self.words_var = ctk.IntVar(value=5)
        self.upper_var = ctk.BooleanVar(value=True)
        self.lower_var = ctk.BooleanVar(value=True)
        self.digits_var = ctk.BooleanVar(value=True)
        self.symbols_var = ctk.BooleanVar(value=True)
        self.ambig_var = ctk.BooleanVar(value=False)
        self.cap_var = ctk.BooleanVar(value=True)
        self.num_var = ctk.BooleanVar(value=True)
        self.sep_var = ctk.StringVar(value="-")

        self.generated_text = ""

        self._init_ui()
        self._generate()

    def _init_ui(self):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=24, pady=20)

        # Header Title
        title_lbl = ctk.CTkLabel(
            container,
            text="🎲 Password Generator",
            font=(FONT_FAMILY, 18, "bold"),
            text_color=COLORS["text_dark"],
        )
        title_lbl.pack(anchor="w", pady=(0, 15))

        # Output Card
        output_card = ctk.CTkFrame(
            container,
            fg_color=COLORS["card_dark"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border_dark"],
        )
        output_card.pack(fill="x", pady=(0, 15))

        self.output_entry = ctk.CTkEntry(
            output_card,
            font=(FONT_MONO, 14, "bold"),
            height=46,
            fg_color=COLORS["bg_dark"],
            border_color=COLORS["border_dark"],
            text_color=COLORS["text_dark"],
            justify="center",
        )
        self.output_entry.pack(fill="x", padx=16, pady=(16, 10))

        # Entropy / Strength bar
        self.entropy_bar = ctk.CTkProgressBar(output_card, height=6, corner_radius=3)
        self.entropy_bar.pack(fill="x", padx=16, pady=(0, 4))

        self.entropy_lbl = ctk.CTkLabel(
            output_card,
            text="Entropy: calculating...",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_muted_dark"],
        )
        self.entropy_lbl.pack(padx=16, pady=(0, 12))

        # Action bar under card
        action_row = ctk.CTkFrame(container, fg_color="transparent")
        action_row.pack(fill="x", pady=(0, 15))

        regen_btn = ctk.CTkButton(
            action_row,
            text="🔄 Regenerate",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["card_dark"],
            hover_color=COLORS["card_hover_dark"],
            height=36,
            command=self._generate,
        )
        regen_btn.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.copy_btn = ctk.CTkButton(
            action_row,
            text="📋 Copy",
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["primary"],
            hover_color=COLORS["primary_hover"],
            height=36,
            command=self._copy_password,
        )
        self.copy_btn.pack(side="right", fill="x", expand=True)

        # Mode Selector
        self.mode_selector = ctk.CTkSegmentedButton(
            container,
            values=["Random Password", "Memorable Passphrase"],
            font=(FONT_FAMILY, 12),
            command=self._on_mode_change,
        )
        self.mode_selector.set("Random Password")
        self.mode_selector.pack(fill="x", pady=(0, 15))

        # Options Container
        self.options_frame = ctk.CTkFrame(
            container,
            fg_color=COLORS["card_dark"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border_dark"],
        )
        self.options_frame.pack(fill="both", expand=True, pady=(0, 15))

        self._render_password_options()

        # Bottom Apply Button
        if self.on_use_password:
            use_btn = ctk.CTkButton(
                container,
                text="Use This Password",
                font=(FONT_FAMILY, 13, "bold"),
                fg_color=COLORS["success"],
                hover_color=COLORS["success_hover"],
                height=40,
                command=self._use_password,
            )
            use_btn.pack(fill="x")

    def _render_password_options(self):
        for widget in self.options_frame.winfo_children():
            widget.destroy()

        pad_x = 20

        # Length Slider
        slider_row = ctk.CTkFrame(self.options_frame, fg_color="transparent")
        slider_row.pack(fill="x", padx=pad_x, pady=(16, 6))

        slider_lbl = ctk.CTkLabel(
            slider_row,
            text="Password Length:",
            font=(FONT_FAMILY, 12, "bold"),
            text_color=COLORS["text_dark"],
        )
        slider_lbl.pack(side="left")

        self.len_val_lbl = ctk.CTkLabel(
            slider_row,
            text=f"{self.length_var.get()} characters",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["primary_light"],
        )
        self.len_val_lbl.pack(side="right")

        self.len_slider = ctk.CTkSlider(
            self.options_frame,
            from_=8,
            to=64,
            number_of_steps=56,
            variable=self.length_var,
            command=self._on_length_slider,
        )
        self.len_slider.pack(fill="x", padx=pad_x, pady=(0, 15))

        # Toggles Grid
        toggles_frame = ctk.CTkFrame(self.options_frame, fg_color="transparent")
        toggles_frame.pack(fill="x", padx=pad_x, pady=(0, 10))

        cb1 = ctk.CTkCheckBox(
            toggles_frame,
            text="Uppercase (A-Z)",
            variable=self.upper_var,
            command=self._generate,
            font=(FONT_FAMILY, 12),
        )
        cb1.grid(row=0, column=0, sticky="w", pady=6)

        cb2 = ctk.CTkCheckBox(
            toggles_frame,
            text="Lowercase (a-z)",
            variable=self.lower_var,
            command=self._generate,
            font=(FONT_FAMILY, 12),
        )
        cb2.grid(row=0, column=1, sticky="w", pady=6, padx=(20, 0))

        cb3 = ctk.CTkCheckBox(
            toggles_frame,
            text="Numbers (0-9)",
            variable=self.digits_var,
            command=self._generate,
            font=(FONT_FAMILY, 12),
        )
        cb3.grid(row=1, column=0, sticky="w", pady=6)

        cb4 = ctk.CTkCheckBox(
            toggles_frame,
            text="Symbols (!@#$)",
            variable=self.symbols_var,
            command=self._generate,
            font=(FONT_FAMILY, 12),
        )
        cb4.grid(row=1, column=1, sticky="w", pady=6, padx=(20, 0))

        cb5 = ctk.CTkCheckBox(
            self.options_frame,
            text="Exclude Ambiguous Characters (0, O, 1, l, I)",
            variable=self.ambig_var,
            command=self._generate,
            font=(FONT_FAMILY, 12),
        )
        cb5.pack(anchor="w", padx=pad_x, pady=(6, 16))

    def _render_passphrase_options(self):
        for widget in self.options_frame.winfo_children():
            widget.destroy()

        pad_x = 20

        # Word count slider
        slider_row = ctk.CTkFrame(self.options_frame, fg_color="transparent")
        slider_row.pack(fill="x", padx=pad_x, pady=(16, 6))

        slider_lbl = ctk.CTkLabel(
            slider_row,
            text="Number of Words:",
            font=(FONT_FAMILY, 12, "bold"),
            text_color=COLORS["text_dark"],
        )
        slider_lbl.pack(side="left")

        self.words_val_lbl = ctk.CTkLabel(
            slider_row,
            text=f"{self.words_var.get()} words",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["primary_light"],
        )
        self.words_val_lbl.pack(side="right")

        self.words_slider = ctk.CTkSlider(
            self.options_frame,
            from_=3,
            to=8,
            number_of_steps=5,
            variable=self.words_var,
            command=self._on_words_slider,
        )
        self.words_slider.pack(fill="x", padx=pad_x, pady=(0, 15))

        # Separator row
        sep_row = ctk.CTkFrame(self.options_frame, fg_color="transparent")
        sep_row.pack(fill="x", padx=pad_x, pady=(0, 12))

        sep_lbl = ctk.CTkLabel(sep_row, text="Word Separator:", font=(FONT_FAMILY, 12), text_color=COLORS["text_dark"])
        sep_lbl.pack(side="left")

        sep_menu = ctk.CTkOptionMenu(
            sep_row,
            values=["- (Hyphen)", ". (Period)", "_ (Underscore)", "  (Space)"],
            command=self._on_sep_change,
            width=140,
        )
        sep_menu.set("- (Hyphen)")
        sep_menu.pack(side="right")

        # Checkboxes
        cb1 = ctk.CTkCheckBox(
            self.options_frame,
            text="Capitalize First Letters",
            variable=self.cap_var,
            command=self._generate,
            font=(FONT_FAMILY, 12),
        )
        cb1.pack(anchor="w", padx=pad_x, pady=6)

        cb2 = ctk.CTkCheckBox(
            self.options_frame,
            text="Include Random Numbers",
            variable=self.num_var,
            command=self._generate,
            font=(FONT_FAMILY, 12),
        )
        cb2.pack(anchor="w", padx=pad_x, pady=(6, 16))

    def _on_mode_change(self, choice: str):
        if choice == "Random Password":
            self.mode_var.set("password")
            self._render_password_options()
        else:
            self.mode_var.set("passphrase")
            self._render_passphrase_options()
        self._generate()

    def _on_length_slider(self, val):
        length = int(val)
        self.length_var.set(length)
        if hasattr(self, "len_val_lbl"):
            self.len_val_lbl.configure(text=f"{length} characters")
        self._generate()

    def _on_words_slider(self, val):
        words = int(val)
        self.words_var.set(words)
        if hasattr(self, "words_val_lbl"):
            self.words_val_lbl.configure(text=f"{words} words")
        self._generate()

    def _on_sep_change(self, choice: str):
        mapping = {
            "- (Hyphen)": "-",
            ". (Period)": ".",
            "_ (Underscore)": "_",
            "  (Space)": " ",
        }
        self.sep_var.set(mapping.get(choice, "-"))
        self._generate()

    def _generate(self):
        if self.mode_var.get() == "password":
            self.generated_text = generate_password(
                length=self.length_var.get(),
                use_upper=self.upper_var.get(),
                use_lower=self.lower_var.get(),
                use_digits=self.digits_var.get(),
                use_symbols=self.symbols_var.get(),
                exclude_ambiguous=self.ambig_var.get(),
            )
        else:
            self.generated_text = generate_passphrase(
                word_count=self.words_var.get(),
                separator=self.sep_var.get(),
                capitalize=self.cap_var.get(),
                include_number=self.num_var.get(),
            )

        self.output_entry.delete(0, "end")
        self.output_entry.insert(0, self.generated_text)

        # Update entropy
        analysis = calculate_entropy(self.generated_text)
        self.entropy_bar.set(analysis["score"] / 100.0)
        self.entropy_bar.configure(progress_color=analysis["color"])
        self.entropy_lbl.configure(
            text=f"Strength: {analysis['rating']} • {analysis['bits']} bits entropy • Crack time: {analysis['crack_time']}",
            text_color=analysis["color"],
        )

    def _copy_password(self):
        if not self.generated_text:
            return
        self.clipboard.copy(self.generated_text)
        self.copy_btn.configure(text="✓ Copied!", fg_color=COLORS["success"])
        self.after(1500, lambda: self.copy_btn.configure(text="📋 Copy", fg_color=COLORS["primary"]))

    def _use_password(self):
        if self.on_use_password and self.generated_text:
            self.on_use_password(self.generated_text)
            self.destroy()
