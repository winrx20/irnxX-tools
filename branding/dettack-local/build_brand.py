#!/usr/bin/env python3
"""Rebuild the web brand assets from the source sprite.

    python3 scripts/build_brand.py

Reads  assets/brand/ghost-source-50x50.png
Writes assets/brand/ghost.png, assets/brand/ghost@4x.png,
       webui/ghost.png, webui/favicon.ico

The sprite is 1-bit pixel art (solid black body, white outline, transparent
background, no anti-aliasing), so every resample here is NEAREST. Using a
smoothing filter would grey the edges and destroy the look.
"""
from __future__ import annotations

import os
import sys

try:
    from PIL import Image
except ImportError:
    sys.exit("Pillow is required: python3 -m pip install Pillow")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "assets", "brand", "ghost-source-50x50.png")
ASSETS = os.path.join(ROOT, "assets", "brand")
WEBUI = os.path.join(ROOT, "webui")

#: Displayed size of the sidebar mark, in CSS pixels.
SIDEBAR_PX = 20
#: Ship the web copy at 2x for HiDPI screens.
WEB_SCALE = 5

#: A pixel is treated as transparent below this alpha. The upload stores junk
#: RGB under fully-transparent pixels, which makes some renderers fringe grey.
ALPHA_CUTOFF = 10


def load_clean(path: str) -> Image.Image:
    """Load the sprite, dropping colour data hidden under transparency."""
    im = Image.open(path).convert("RGBA")
    out = Image.new("RGBA", im.size, (0, 0, 0, 0))
    src, dst = im.load(), out.load()
    for y in range(im.size[1]):
        for x in range(im.size[0]):
            r, g, b, a = src[x, y]
            dst[x, y] = (0, 0, 0, 0) if a < ALPHA_CUTOFF else (r, g, b, 255)
    return out


def centre(im: Image.Image) -> Image.Image:
    """Crop to the visible art, then centre it on a transparent square."""
    art = im.crop(im.getbbox())
    side = max(art.size)
    sq = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    sq.paste(art, ((side - art.width) // 2, (side - art.height) // 2))
    return sq


def main() -> int:
    if not os.path.isfile(SRC):
        sys.exit(f"source sprite missing: {SRC}")

    os.makedirs(ASSETS, exist_ok=True)
    os.makedirs(WEBUI, exist_ok=True)

    master = centre(load_clean(SRC))
    print(f"master: {master.size[0]}x{master.size[1]}")

    master.save(os.path.join(ASSETS, "ghost.png"), optimize=True)
    master.resize((master.width * 4, master.height * 4), Image.NEAREST).save(
        os.path.join(ASSETS, "ghost@4x.png"), optimize=True
    )

    px = SIDEBAR_PX * WEB_SCALE
    web = master.resize((px, px), Image.NEAREST)
    web.save(os.path.join(WEBUI, "ghost.png"), optimize=True)
    print(f"webui/ghost.png: {px}x{px}")

    web.resize((64, 64), Image.NEAREST).save(
        os.path.join(WEBUI, "favicon.ico"),
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64)],
    )
    print("webui/favicon.ico: 16/32/48/64")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
