#!/usr/bin/env python3
"""Generates every launcher icon ReteGet ships: the legacy PNGs in src/android/res/drawable-*/ and
the adaptive icon's foreground and monochrome layers for API 26 and up.

The icon is the rete family's: a dark blue-grey rounded square with the name RETE across the top,
the same plate, colour and wordmark as ReteClock and ReteKey. Where ReteClock shows the time in
seven-segment digits, ReteGet shows what it does: an arrow pointing down into a tray, the usual
picture of a download.

Transparency, layer by layer:
  - legacy PNG: the plate is opaque, everything outside its rounded corners is fully transparent,
    and the edges are anti-aliased by drawing at 8x and downsampling;
  - adaptive foreground: only the white lettering and arrow, on a transparent layer; the plate is
    the background colour resource, so the launcher can mask it to any shape;
  - monochrome (Android 13 themed icons): the lettering and arrow are the OPAQUE part and nothing
    else is drawn. A themed launcher fills the background with the theme colour and paints the
    opaque pixels in the on-colour, so an opaque plate with a hole would come out inverted (what
    happened to ReteClock 0.26.0). The arrow and the tray stay separate shapes with a clear gap, so
    they do not merge into one blob when painted light on a colour.

Run this only when the design changes; the PNGs are committed, so a build needs no Python.

Usage: python3 tools/make-icons.py
"""

import os
import sys

from PIL import Image, ImageDraw, ImageFont

DENSITIES = {"ldpi": 36, "mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}

# An adaptive layer is 108dp, of which the middle 66dp survives any launcher mask.
ADAPTIVE_DENSITIES = {"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432}
SAFE_ZONE = 66.0 / 108.0

PLATE = (38, 50, 56, 255)  # #263238, the plate ReteClock and ReteKey are drawn on
LETTERING = (255, 255, 255, 255)
PLATE_RADIUS = 0.22

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
]
BOLD_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
] + FONT_CANDIDATES

WORDMARK = "RETE"
TRACKING = 0.14

# Same wordmark box as ReteClock; the picture takes the place of its time line.
WORD_BOX = (0.13, 0.18, 0.87, 0.38)
PICTURE_BOX = (0.10, 0.45, 0.90, 0.84)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "src", "android", "res")
SUPERSAMPLE = 8


def load_font(size, candidates):
    for path in candidates:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    raise SystemExit("no usable TTF font found; install the DejaVu fonts")


def tracked_width(draw, text, font, tracking):
    return sum(draw.textlength(c, font=font) for c in text) + tracking * font.size * (len(text) - 1)


def fit_tracked(draw, text, box, candidates, tracking):
    width, height = box[2] - box[0], box[3] - box[1]
    probe = load_font(100, candidates)
    left, top, right, bottom = draw.textbbox((0, 0), text, font=probe)
    scale = min(width / tracked_width(draw, text, probe, tracking), height / (bottom - top))
    return load_font(max(1, int(100 * scale)), candidates)


def draw_tracked(draw, text, font, box, tracking, fill):
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    x = box[0] + (box[2] - box[0] - tracked_width(draw, text, font, tracking)) / 2
    y = box[1] + (box[3] - box[1] - (bottom - top)) / 2 - top
    for c in text:
        draw.text((x, y), c, font=font, fill=fill)
        x += draw.textlength(c, font=font) + tracking * font.size


def draw_download(draw, box, fill, weight=1.0):
    """An arrow pointing down into an open tray, centred in box = (x, y, x2, y2).

    Two separate shapes: the arrow (shaft and head in one polygon) and the tray (a U of three
    bars). The gap between the arrow's tip and the tray floor is wider than a stroke, so the pair
    stays two shapes even when a launcher outlines or thickens the themed layer.
    """
    x, y, x2, y2 = box
    h = y2 - y
    cx = (x + x2) / 2
    stroke = h * 0.15 * weight

    # Arrow: shaft from the top down into a head whose tip stops above the tray.
    head_half = h * 0.30
    head_top = y + h * 0.36
    tip = y + h * 0.70
    shaft_half = stroke / 2
    draw.polygon([
        (cx - shaft_half, y),
        (cx + shaft_half, y),
        (cx + shaft_half, head_top),
        (cx + head_half, head_top),
        (cx, tip),
        (cx - head_half, head_top),
        (cx - shaft_half, head_top),
    ], fill=fill)

    # Tray: a floor with two short walls, open at the top.
    tray_half = h * 0.52
    floor_bottom = y2
    floor_top = y2 - stroke
    wall_top = y2 - h * 0.30
    draw.rectangle([cx - tray_half, floor_top, cx + tray_half, floor_bottom], fill=fill)
    draw.rectangle([cx - tray_half, wall_top, cx - tray_half + stroke, floor_bottom], fill=fill)
    draw.rectangle([cx + tray_half - stroke, wall_top, cx + tray_half, floor_bottom], fill=fill)


def draw_face(draw, origin, side, fill, bold=True):
    """RETE over the download picture, inside the square at origin with the given side.

    The themed layer uses the regular face and a slightly lighter picture: painted light on a
    colour (and outlined by some launchers) the same drawing reads heavier than ink on the plate.
    """
    def place(f):
        return (origin[0] + side * f[0], origin[1] + side * f[1],
                origin[0] + side * f[2], origin[1] + side * f[3])

    word_box = place(WORD_BOX)
    font = fit_tracked(draw, WORDMARK, word_box, BOLD_FONT_CANDIDATES if bold else FONT_CANDIDATES, TRACKING)
    draw_tracked(draw, WORDMARK, font, word_box, TRACKING, fill)
    draw_download(draw, place(PICTURE_BOX), fill, 1.0 if bold else 0.85)


def render(size):
    """Legacy launcher icon: the plate with the lettering, transparent outside the corners."""
    big = size * SUPERSAMPLE
    image = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle([0, 0, big - 1, big - 1], radius=big * PLATE_RADIUS, fill=PLATE)
    draw_face(draw, (0, 0), big, LETTERING)
    return image.resize((size, size), Image.LANCZOS)


def render_layer(size, fill, bold):
    big = size * SUPERSAMPLE
    side = big * SAFE_ZONE
    image = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw_face(ImageDraw.Draw(image), ((big - side) / 2, (big - side) / 2), side, fill, bold)
    return image.resize((size, size), Image.LANCZOS)


# A smaller check box than the stock 32dp one: 22dp, in the app's grey, with an orange ring when it
# has focus (D-pad) or is being pressed, like the compact buttons.
CHECK_DENSITIES = {"ldpi": 17, "mdpi": 22, "hdpi": 33, "xhdpi": 44, "xxhdpi": 66, "xxxhdpi": 88}
CHECK_BORDER = (120, 144, 156, 255)   # #78909C
CHECK_FOCUS = (255, 152, 0, 255)      # #FF9800
CHECK_FILL = (55, 71, 79, 255)        # #37474F when checked
CHECK_TICK = (255, 255, 255, 255)


def render_check(size, checked, focused):
    big = size * SUPERSAMPLE
    image = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    inset = big * 0.08
    stroke = big * (0.12 if focused else 0.09)
    box = [inset, inset, big - inset, big - inset]
    radius = big * 0.16
    border = CHECK_FOCUS if focused else CHECK_BORDER
    draw.rounded_rectangle(box, radius=radius, fill=border)
    inner = [box[0] + stroke, box[1] + stroke, box[2] - stroke, box[3] - stroke]
    draw.rounded_rectangle(inner, radius=max(1, radius - stroke),
                           fill=CHECK_FILL if checked else (255, 255, 255, 255))
    if checked:
        w = big * 0.11
        draw.line([(big * 0.27, big * 0.52), (big * 0.43, big * 0.68), (big * 0.74, big * 0.34)],
                  fill=CHECK_TICK, width=int(w), joint="curve")
    return image.resize((size, size), Image.LANCZOS)


# README pictures of the icon: the normal launcher icon, and the monochrome layer the way a themed
# Android 13 home screen paints it (theme colour on a round plate), since the raw layer is black on
# transparent and would vanish on GitHub's dark theme.
README_DIR = os.path.join(ROOT, "docs", "screenshots")
README_SIZE = 192
THEMED_PLATE = (214, 227, 255, 255)
THEMED_INK = (27, 46, 94, 255)


def render_themed_preview(size):
    mono = render_layer(size, (0, 0, 0, 255), False)
    plate = Image.new("RGBA", (size * SUPERSAMPLE, size * SUPERSAMPLE), (0, 0, 0, 0))
    ImageDraw.Draw(plate).ellipse([0, 0, plate.size[0] - 1, plate.size[1] - 1], fill=THEMED_PLATE)
    plate = plate.resize((size, size), Image.LANCZOS)
    ink = Image.new("RGBA", (size, size), THEMED_INK)
    plate.paste(ink, (0, 0), mono.split()[3])
    return plate


# F-Droid reads the store icon and the feature graphic from the fastlane tree.
FASTLANE = os.path.join(ROOT, "fastlane", "metadata", "android", "en-US", "images")
STORE_ICON_SIZE = 512
FEATURE_SIZE = (1024, 500)


def render_feature_graphic():
    """The icon on the left, the name and what it does on the right, on the plate colour."""
    w, h = FEATURE_SIZE
    big = SUPERSAMPLE // 2
    image = Image.new("RGBA", (w * big, h * big), PLATE)
    icon = render(int(h * 0.62)).resize((int(h * 0.62) * big, int(h * 0.62) * big), Image.LANCZOS)
    image.alpha_composite(icon, (int(w * 0.07) * big, int(h * 0.19) * big))
    draw = ImageDraw.Draw(image)
    title = load_font(int(h * 0.20) * big, BOLD_FONT_CANDIDATES)
    line = load_font(int(h * 0.075) * big, FONT_CANDIDATES)
    x = int(w * 0.44) * big
    draw.text((x, int(h * 0.24) * big), "ReteGet", font=title, fill=LETTERING)
    draw.text((x, int(h * 0.52) * big), "Downloads for old Android,", font=line, fill=LETTERING)
    draw.text((x, int(h * 0.62) * big), "with its own TLS 1.3", font=line, fill=LETTERING)
    return image.resize(FEATURE_SIZE, Image.LANCZOS)


def write(image, path):
    """Saves as an indexed PNG with per-entry alpha: the drawing has two colours plus their
    anti-aliased edges, so 64 palette entries keep the edges smooth at a third of the size."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    image = image.quantize(colors=64, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE)
    # Quantising averages alpha too; the plate and the lettering must stay fully opaque and the
    # background fully transparent, with partial alpha only on the anti-aliased edges.
    palette = image.getpalette("RGBA")
    for i in range(3, len(palette), 4):
        if palette[i] >= 248:
            palette[i] = 255
        elif palette[i] <= 7:
            palette[i] = 0
    image.putpalette(palette, "RGBA")
    image.save(path, "PNG", optimize=True)
    print("wrote", os.path.relpath(path, ROOT))


def main():
    for density, size in DENSITIES.items():
        write(render(size), os.path.join(RES, "drawable-" + density, "ic_launcher.png"))
    for density, size in ADAPTIVE_DENSITIES.items():
        d = os.path.join(RES, "drawable-" + density)
        write(render_layer(size, LETTERING, True), os.path.join(d, "ic_launcher_foreground.png"))
        write(render_layer(size, (0, 0, 0, 255), False), os.path.join(d, "ic_launcher_monochrome.png"))
    write(render(STORE_ICON_SIZE), os.path.join(FASTLANE, "icon.png"))
    write(render_feature_graphic(), os.path.join(FASTLANE, "featureGraphic.png"))
    write(render(README_SIZE), os.path.join(README_DIR, "icon.png"))
    write(render_themed_preview(README_SIZE), os.path.join(README_DIR, "icon-monochrome.png"))
    for density, size in CHECK_DENSITIES.items():
        d = os.path.join(RES, "drawable-" + density)
        for checked in (False, True):
            for focused in (False, True):
                name = "checkbox_%s%s.png" % ("on" if checked else "off", "_focus" if focused else "")
                write(render_check(size, checked, focused), os.path.join(d, name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
