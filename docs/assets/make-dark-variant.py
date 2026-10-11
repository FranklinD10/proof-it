"""Derive the dark-theme logo from the transparent master.

Navy (the only dark colour in the logo) becomes near-white and the white prompt
glyphs become navy; the cyan and green are left unchanged.

    python3 docs/assets/make-dark-variant.py   # requires Pillow
"""

import colorsys
from pathlib import Path

from PIL import Image

HERE = Path(__file__).parent
LIGHT = (230, 237, 243)
NAVY = (11, 30, 58)

im = Image.open(HERE / "proof-it-logo.png").convert("RGBA")
px = im.load()
for y in range(im.size[1]):
    for x in range(im.size[0]):
        r, g, b, a = px[x, y]
        if a == 0:
            continue
        _, lightness, saturation = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
        if lightness < 0.32:
            px[x, y] = (*LIGHT, a)
        elif lightness > 0.8 and saturation < 0.35:
            px[x, y] = (*NAVY, a)
im.save(HERE / "proof-it-logo-dark.png", optimize=True)
