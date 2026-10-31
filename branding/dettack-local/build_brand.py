#!/usr/bin/env python3
"""Regenerate the derived ghost assets from the source sprite.

Works in either layout:

  * inside the Dettack Local project  -> assets/brand/ + webui/
  * inside this `branding/` folder    -> beside this script

    python3 build_brand.py

The sprite is 1-bit pixel art (solid black body, white outline, transparent
background, no anti-aliasing), so every resample is NEAREST. A smoothing filter
would grey the edges and destroy the look.
"""
from __future__ import annotations

import os
import sys

try:
    from PIL import Image
except ImportError:
    sys.exit("Pillow is required: python3 -m pip install Pillow")

HERE = os.path.dirname(os.path.abspath(__file__))

#: Displayed size of the sidebar mark, in CSS pixels.
SIDEBAR_PX = 20
#: Ship the web copy at this multiple of the display size (HiDPI).
WEB_SCALE = 5
#: Alpha below this counts as transparent. The upload stores junk RGB under
#: fully-transparent pixels, which fringes grey in some renderers.
ALPHA_CUTOFF = 10


def resolve_layout() -> tuple[str, str | None]:
    """Return (asset_dir, webui_dir_or_None) for whichever layout we are in."""
    if os.path.isdir(os.path.join(HERE, "..", "dettack_local")):
        root = os.path.dirname(HERE)
        return os.path.join(root, "assets", "brand"), os.path.join(root, "webui")
    return HERE, None


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
    asset_dir, webui_dir = resolve_layout()
    src = os.path.join(asset_dir, "ghost-source-50x50.png")
    if not os.path.isfile(src):
        sys.exit(f"source sprite missing: {src}")

    master = centre(load_clean(src))
    print(f"master: {master.width}x{master.height}")

    master.save(os.path.join(asset_dir, "ghost.png"), optimize=True)
    master.resize((master.width * 4, master.height * 4), Image.NEAREST).save(
        os.path.join(asset_dir, "ghost@4x.png"), optimize=True
    )
    print(f"{asset_dir}/ghost.png + ghost@4x.png")

    if webui_dir is None:
        print("no webui/ next to this script - skipping runtime copies")
        return 0

    os.makedirs(webui_dir, exist_ok=True)
    px = SIDEBAR_PX * WEB_SCALE
    web = master.resize((px, px), Image.NEAREST)
    web.save(os.path.join(webui_dir, "ghost.png"), optimize=True)
    print(f"{webui_dir}/ghost.png: {px}x{px}")

    web.resize((64, 64), Image.NEAREST).save(
        os.path.join(webui_dir, "favicon.ico"),
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64)],
    )
    print(f"{webui_dir}/favicon.ico: 16/32/48/64")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
