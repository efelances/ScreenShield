"""Programmatic icon generation for ScreenShield desktop and PyInstaller builds."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


def build_shield_icon_image(size: int = 256) -> Image.Image:
    """Render the 3-color ScreenShield emblem (#245C46 / #F7F5F0 / #1C1B19)."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = max(2, size // 12)
    cx = size // 2
    top = pad
    bottom = size - pad
    shoulder_y = int(size * 0.24)
    mid_y = int(size * 0.56)

    shield_pts = [
        (cx, top),
        (size - pad, shoulder_y),
        (int(size * 0.86), mid_y),
        (cx, bottom),
        (int(size * 0.14), mid_y),
        (pad, shoulder_y),
    ]
    outline_w = max(2, size // 24)
    draw.polygon(shield_pts, fill=(36, 92, 70, 255), outline=(28, 27, 25, 255), width=outline_w)

    # Inner shield check mark in warm paper (#F7F5F0)
    stroke = max(2, size // 11)
    draw.line(
        [
            (int(size * 0.34), int(size * 0.50)),
            (int(size * 0.46), int(size * 0.63)),
            (int(size * 0.68), int(size * 0.37)),
        ],
        fill=(247, 245, 240, 255),
        width=stroke,
        joint="curve",
    )
    return img


def ensure_icon_file(path: Path) -> Path:
    """Write a multi-resolution Windows .ico file if missing."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    base = build_shield_icon_image(256)
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    base.save(path, format="ICO", sizes=sizes)
    return path
