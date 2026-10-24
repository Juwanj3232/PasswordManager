"""
Design system, theme tokens, and typography constants for the desktop UI.
"""

# Color Palette (Tailwind-inspired Dark & Light Mode)
COLORS = {
    "bg_dark": "#0f172a",          # Slate 900
    "bg_light": "#f8fafc",         # Slate 50
    "card_dark": "#1e293b",        # Slate 800
    "card_light": "#ffffff",       # Pure white
    "card_hover_dark": "#2d3748",  # Slate 750
    "card_hover_light": "#f1f5f9", # Slate 100
    "border_dark": "#334155",      # Slate 700
    "border_light": "#e2e8f0",     # Slate 200
    "primary": "#3b82f6",          # Blue 500
    "primary_hover": "#2563eb",    # Blue 600
    "primary_light": "#60a5fa",    # Blue 400
    "success": "#10b981",          # Emerald 500
    "success_hover": "#059669",    # Emerald 600
    "warning": "#f59e0b",          # Amber 500
    "danger": "#ef4444",           # Red 500
    "danger_hover": "#dc2626",     # Red 600
    "text_dark": "#f8fafc",        # Slate 50
    "text_light": "#0f172a",       # Slate 900
    "text_muted_dark": "#94a3b8",  # Slate 400
    "text_muted_light": "#64748b", # Slate 500
    "favorite": "#fbbf24",         # Amber 400
}

FONT_FAMILY = "SF Pro Display"
FONT_MONO = "SF Mono"

CATEGORIES = [
    ("All", "📂"),
    ("Logins", "🔑"),
    ("Cards/Financial", "💳"),
    ("Secure Notes", "📝"),
    ("Work", "💼"),
    ("Personal", "👤"),
]
