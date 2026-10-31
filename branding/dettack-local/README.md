# Dettack Local branding

Brand mark for **Dettack Local**, the offline attack-surface-management dashboard.
This folder is an asset drop only - **the `irnxsec` package in this repository does
not read these files** and is unaffected by them.

| file | size | purpose |
|---|---|---|
| `ghost-source-50x50.png` | 50x50 | the original upload, untouched |
| `ghost.png` | 47x47 | cleaned + centred master |
| `ghost@4x.png` | 188x188 | preview / large use |
| `build_brand.py` | - | regenerates every derived size |

The live application keeps its runtime copies in its own `webui/` folder
(`ghost.png` at 100x100 and `favicon.ico` at 16/32/48/64).

## Specification

* **Format:** 1-bit pixel art, PNG with alpha.
* **Palette:** `#000000` body, `#FFFFFF` outline/face, transparent background.
* **No anti-aliasing** - only those two visible colours plus transparency.
* **Native grid:** 47x47 after cropping to the visible art.

## Rendering rules

The sprite is **solid black**. It must be composited on a **light plate** -
the app paints it on the mint accent tile (`--accent` = `#00E5A0`). Placed
directly on a dark panel the body disappears and only the 1px white outline
remains, which is why the tile fill is part of the design and not decoration.

All scaling uses **nearest-neighbour**; `image-rendering: pixelated` is set on
the sidebar copy.

## Regenerating

```bash
python3 build_brand.py   # expects ghost-source-50x50.png beside it
```
