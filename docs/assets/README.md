# Brand assets

| File | Use |
|---|---|
| `proof-it-logo.png` | **Master** logo, transparent background (612×408). Shown in the README on light themes. Edit or replace this one. |
| `proof-it-logo-dark.png` | Dark-theme variant, generated from the master by `make-dark-variant.py` (navy becomes near-white, white glyphs become navy, cyan and green unchanged). |
| `proof-it-logo-1536-opaque.png` | High-resolution version on a white background (1536×1024), for print or GitHub's social preview. |

The README picks the right variant for the reader's theme with `<picture>`.

To change the logo, replace `proof-it-logo.png` (ideally a larger transparent
export: 612 px is enough for the README but soft on high-density screens), then
regenerate the dark variant:

```bash
python3 docs/assets/make-dark-variant.py   # requires Pillow
```

## Name and logo

The code is licensed under Apache-2.0, which grants no rights to the Proof-It
name or logo (Apache-2.0, section 6). You may use them to refer to this project,
but not as the name or logo of your own product, fork or service.
