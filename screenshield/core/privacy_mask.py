"""Live blur, redaction, privacy curtain rendering, and 150ms safety ring buffer."""

from __future__ import annotations

import threading
import time
from collections import deque
from pathlib import Path
from typing import Literal

from PIL import Image, ImageDraw, ImageFilter, ImageFont

from screenshield.core.config import LanguageCode, MaskStyle, StaticZone


CurtainKind = Literal["idle", "panic", "sensitive_blocked", "waiting_window", "fail_closed"]

# Strictly 3-color ScreenShield palette (+ high contrast variant)
COLOR_BG = (28, 27, 25)       # #1C1B19
COLOR_PAPER = (247, 245, 240) # #F7F5F0
COLOR_ACCENT = (36, 92, 70)   # #245C46
COLOR_HC_ACCENT = (15, 81, 50)

CURTAIN_STRINGS: dict[LanguageCode, dict[CurtainKind, tuple[str, str]]] = {
    "tr": {
        "idle": ("GÜVENLİ PAYLAŞIM HAZIR", "Paylaşım Modu başlatıldığında yalnızca güvenli pencereler gösterilir."),
        "panic": ("PANİK PERDESİ AKTİF", "Ekran paylaşımı anında donduruldu. Açmak için kısayolu kullanın."),
        "sensitive_blocked": ("HASSAS İÇERİK ENGELLENDİ", "Koruma kuralı tetiklendi; tampon temizlendi ve gizli pencere engellendi."),
        "waiting_window": ("İZİNLİ PENCERE BEKLENİYOR", "Seçili pencereler kapalı veya simge durumunda. Sızıntı yok."),
        "fail_closed": ("GÜVENLİ BEKLEME (FAIL-CLOSED)", "Yakalama yenilenemedi; bilgi sızıntısını önlemek için ekran kilitlendi."),
    },
    "en": {
        "idle": ("SAFE SHARE READY", "Only allowlisted safe windows appear here when Share Mode is active."),
        "panic": ("PANIC SHIELD ACTIVE", "Live output is frozen immediately. Press your Panic hotkey to resume."),
        "sensitive_blocked": ("SENSITIVE CONTENT BLOCKED", "A privacy rule triggered; safety buffer flushed and view shielded."),
        "waiting_window": ("WAITING FOR ALLOWLISTED WINDOW", "Selected windows are minimized or closed. Zero-leak standby."),
        "fail_closed": ("FAIL-CLOSED STANDBY", "Capture could not refresh; output locked to prevent accidental leaks."),
    },
    "de": {
        "idle": ("SICHERER SPIEGEL BEREIT", "Im Freigabemodus erscheinen hier nur freigegebene sichere Fenster."),
        "panic": ("PANIKSCHUTZ AKTIV", "Die Live-Ausgabe wurde sofort gesperrt. Mit dem Panik-Shortcut fortsetzen."),
        "sensitive_blocked": ("SENSIBLER INHALT BLOCKIERT", "Datenschutzregel ausgelöst; Sicherheitspuffer geleert und Ansicht geschützt."),
        "waiting_window": ("WARTE AUF FREIGEGEBENES FENSTER", "Ausgewählte Fenster sind minimiert oder geschlossen. Kein Datenleck."),
        "fail_closed": ("FAIL-CLOSED-SCHUTZ", "Aufnahme konnte nicht aktualisiert werden; Ausgabe sicher gesperrt."),
    },
    "es": {
        "idle": ("ESPEJO SEGURO LISTO", "Al activar el modo compartir solo se mostrarán ventanas autorizadas."),
        "panic": ("ESCUDO DE PÁNICO ACTIVO", "La salida en vivo se bloqueó al instante. Usa el atajo para reanudar."),
        "sensitive_blocked": ("CONTENIDO SENSIBLE BLOQUEADO", "Se activó una regla de privacidad; búfer limpiado y vista protegida."),
        "waiting_window": ("ESPERANDO VENTANA AUTORIZADA", "Las ventanas elegidas están minimizadas o cerradas. Cero fugas."),
        "fail_closed": ("BLOQUEO PREVENTIVO (FAIL-CLOSED)", "No se pudo refrescar la captura; pantalla bloqueada por seguridad."),
    },
}


def _load_font(size: int, bold: bool = False) -> ImageFont.ImageFont | ImageFont.FreeTypeFont:
    candidates = (
        ["C:/Windows/Fonts/segoeuib.ttf", "C:/Windows/Fonts/arialbd.ttf"]
        if bold
        else ["C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/arial.ttf"]
    )
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size=size)
            except OSError:
                continue
    return ImageFont.load_default()


def make_heavy_frost_image(
    source: Image.Image, out_size: tuple[int, int] = (240, 140)
) -> Image.Image:
    """Create an opaque, completely unreadable frosted glass texture from a source image."""
    rgb = source if source.mode == "RGB" else source.convert("RGB")
    downsampled = rgb.resize((10, 6), Image.Resampling.BOX).filter(
        ImageFilter.GaussianBlur(radius=2)
    )
    frosted = downsampled.resize(out_size, Image.Resampling.BICUBIC)
    veil = Image.new("RGB", out_size, COLOR_BG)
    return Image.blend(frosted, veil, 0.48)


def apply_region_mask(
    image: Image.Image,
    box: tuple[int, int, int, int],
    style: MaskStyle = "blur",
    label: str | None = None,
) -> Image.Image:
    """Redact a pixel bounding box (left, top, right, bottom) on an RGB image in-place."""
    img_w, img_h = image.size
    left = max(0, min(img_w, int(box[0])))
    top = max(0, min(img_h, int(box[1])))
    right = max(0, min(img_w, int(box[2])))
    bottom = max(0, min(img_h, int(box[3])))
    if right - left < 2 or bottom - top < 2:
        return image

    region_w = right - left
    region_h = bottom - top

    if style == "blur":
        crop = image.crop((left, top, right, bottom))
        small_w = max(4, min(12, region_w // 32))
        small_h = max(4, min(8, region_h // 32))
        blurred = (
            crop.resize((small_w, small_h), Image.Resampling.BOX)
            .filter(ImageFilter.GaussianBlur(radius=2))
            .resize((region_w, region_h), Image.Resampling.BICUBIC)
        )
        tint = Image.new("RGB", (region_w, region_h), COLOR_BG)
        masked = Image.blend(blurred, tint, 0.48)
        image.paste(masked, (left, top))
    else:
        draw = ImageDraw.Draw(image)
        draw.rectangle((left, top, right, bottom), fill=COLOR_BG)

    draw = ImageDraw.Draw(image)
    draw.rectangle((left, top, right - 1, bottom - 1), outline=COLOR_ACCENT, width=2)

    if label and region_w >= 80 and region_h >= 28:
        font = _load_font(max(12, min(18, region_h // 4)), bold=True)
        draw.text((left + 10, top + 6), label, fill=COLOR_PAPER, font=font)

    return image


def apply_normalized_zones(image: Image.Image, zones: list[StaticZone]) -> Image.Image:
    """Apply all enabled normalized (0..1) static zones onto an RGB image."""
    if not zones:
        return image
    width, height = image.size
    for zone in zones:
        if not zone.enabled:
            continue
        left = int(round(zone.x * width))
        top = int(round(zone.y * height))
        right = int(round((zone.x + zone.width) * width))
        bottom = int(round((zone.y + zone.height) * height))
        apply_region_mask(image, (left, top, right, bottom), style=zone.style, label=zone.label)
    return image


def render_curtain(
    width: int,
    height: int,
    kind: CurtainKind,
    language: LanguageCode = "tr",
    detail: str = "",
    high_contrast: bool = False,
) -> Image.Image:
    """Render a zero-leak 3-color ScreenShield privacy curtain frame."""
    w = max(320, int(width))
    h = max(180, int(height))
    bg = (0, 0, 0) if high_contrast else COLOR_BG
    fg = (255, 255, 255) if high_contrast else COLOR_PAPER
    accent = COLOR_HC_ACCENT if high_contrast else COLOR_ACCENT

    img = Image.new("RGB", (w, h), bg)
    draw = ImageDraw.Draw(img)

    # Outer accent border
    draw.rectangle((16, 16, w - 17, h - 17), outline=accent, width=3)

    # Geometric shield emblem centered near top
    cx = w // 2
    cy = max(90, h // 2 - 58)
    sw = max(34, min(52, h // 12))
    sh = int(sw * 1.2)
    shield_pts = [
        (cx, cy - sh),
        (cx + sw, cy - int(sh * 0.55)),
        (cx + int(sw * 0.85), cy + int(sh * 0.35)),
        (cx, cy + sh),
        (cx - int(sw * 0.85), cy + int(sh * 0.35)),
        (cx - sw, cy - int(sh * 0.55)),
    ]
    draw.polygon(shield_pts, fill=accent, outline=fg)
    # Inner check / bar mark
    draw.line(
        [(cx - sw // 3, cy), (cx - sw // 10, cy + sh // 4), (cx + sw // 3, cy - sh // 4)],
        fill=fg,
        width=max(3, sw // 9),
    )

    strings = CURTAIN_STRINGS.get(language, CURTAIN_STRINGS["en"])
    title, subtitle = strings[kind]

    title_font = _load_font(max(20, min(32, w // 36)), bold=True)
    sub_font = _load_font(max(14, min(20, w // 56)), bold=False)

    title_box = draw.textbbox((0, 0), title, font=title_font)
    title_w = title_box[2] - title_box[0]
    draw.text((max(24, (w - title_w) // 2), cy + sh + 24), title, fill=fg, font=title_font)

    sub_text = subtitle if not detail else f"{subtitle} ({detail})"
    sub_box = draw.textbbox((0, 0), sub_text, font=sub_font)
    sub_w = sub_box[2] - sub_box[0]
    draw.text(
        (max(24, (w - sub_w) // 2), cy + sh + 66),
        sub_text,
        fill=fg,
        font=sub_font,
    )
    return img


class SafetyRingBuffer:
    """Timestamped delay buffer that drops all unshown frames on sensitive events."""

    def __init__(self, delay_ms: int = 150) -> None:
        self._delay_s = max(0.0, min(0.5, delay_ms / 1000.0))
        self._queue: deque[tuple[float, Image.Image]] = deque()
        self._lock = threading.Lock()

    @property
    def delay_ms(self) -> int:
        with self._lock:
            return int(round(self._delay_s * 1000))

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue)

    def set_delay_ms(self, delay_ms: int) -> None:
        with self._lock:
            self._delay_s = max(0.0, min(0.5, delay_ms / 1000.0))

    def push(self, frame: Image.Image, now: float | None = None) -> None:
        ts = time.monotonic() if now is None else now
        with self._lock:
            self._queue.append((ts, frame))
            while len(self._queue) > 45:
                self._queue.popleft()

    def pop_ready(self, now: float | None = None) -> Image.Image | None:
        ts = time.monotonic() if now is None else now
        with self._lock:
            if not self._queue:
                return None
            if self._delay_s <= 0.0:
                latest = self._queue[-1][1]
                self._queue.clear()
                return latest
            ready: Image.Image | None = None
            while self._queue and (ts - self._queue[0][0]) >= self._delay_s:
                _, ready = self._queue.popleft()
            return ready

    def flush(self) -> int:
        """Immediately discard all buffered frames so no transitional frame leaks."""
        with self._lock:
            dropped = len(self._queue)
            self._queue.clear()
            return dropped
