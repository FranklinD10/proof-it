# Brand assets

| File | Use |
|---|---|
| `proof-it-logo.png` | **Master** logo (1536×1024, PNG). Edit or replace this one. |
| `proof-it-logo-768.png` | Web copy shown in the README (768×512, about 260 KB). Generated from the master. |

To change the logo, replace `proof-it-logo.png` and regenerate the web copy:

```bash
magick docs/assets/proof-it-logo.png -resize 768x -strip -define png:compression-level=9 docs/assets/proof-it-logo-768.png
```

## Name and logo

The code is licensed under Apache-2.0, which grants no rights to the Proof-It
name or logo (Apache-2.0, section 6). You may use them to refer to this project,
but not as the name or logo of your own product, fork or service.
