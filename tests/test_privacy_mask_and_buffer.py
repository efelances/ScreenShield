"""Tests for SafetyRingBuffer, region redaction, and multi-language curtains."""

from __future__ import annotations

from PIL import Image

from screenshield.core.config import StaticZone
from screenshield.core.privacy_mask import (
    SafetyRingBuffer,
    apply_normalized_zones,
    apply_region_mask,
    make_heavy_frost_image,
    render_curtain,
)


def test_safety_ring_buffer_delay_and_flush():
    buf = SafetyRingBuffer(delay_ms=150)
    f1 = Image.new("RGB", (32, 32), (10, 20, 30))
    f2 = Image.new("RGB", (32, 32), (40, 50, 60))

    buf.push(f1, now=1.000)
    assert buf.pop_ready(now=1.100) is None
    assert buf.size == 1

    buf.push(f2, now=1.050)
    ready = buf.pop_ready(now=1.160)
    assert ready is f1
    assert buf.size == 1

    # Flush drops any pending transitional frames immediately
    dropped = buf.flush()
    assert dropped == 1
    assert buf.size == 0
    assert buf.pop_ready(now=2.000) is None


def test_apply_region_mask_and_zones():
    img = Image.new("RGB", (200, 100), (247, 245, 240))
    apply_region_mask(img, (10, 10, 90, 50), style="solid", label="Hidden")
    # Inside solid mask should be #1C1B19 (28, 27, 25)
    assert img.getpixel((50, 35)) == (28, 27, 25)
    # Outside mask stays untouched
    assert img.getpixel((180, 90)) == (247, 245, 240)

    zones = [
        StaticZone(label="Bottom", x=0.0, y=0.8, width=1.0, height=0.2, style="blur", enabled=True)
    ]
    apply_normalized_zones(img, zones)
    # Pixel in blurred zone darkened by tint
    r, g, b = img.getpixel((150, 90))
    assert (r, g, b) != (247, 245, 240)


def test_render_curtain_all_languages():
    for lang in ("tr", "en", "de", "es"):
        frame = render_curtain(640, 360, "panic", language=lang)  # type: ignore[arg-type]
        assert frame.size == (640, 360)
        assert frame.mode == "RGB"


def test_heavy_frost_destroys_sharp_text_contrast():
    # High-contrast alternating white/black stripes simulating sharp text lines
    src = Image.new("RGB", (400, 240), (255, 255, 255))
    for y in range(0, 240, 8):
        for x in range(400):
            if (y // 8) % 2 == 0:
                src.putpixel((x, y), (0, 0, 0))
    frosted = make_heavy_frost_image(src, out_size=(240, 140))
    assert frosted.size == (240, 140)
    # After 10x6 downsampling + GaussianBlur + dark veil, no pure white or sharp stripe contrast survives
    get_pixels = getattr(frosted, "get_flattened_data", frosted.getdata)
    pixels = list(get_pixels())
    max_channel = max(max(p) for p in pixels)
    min_channel = min(min(p) for p in pixels)
    assert max_channel < 160
    assert (max_channel - min_channel) < 40
