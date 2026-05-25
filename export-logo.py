#!/usr/bin/env python3
"""Convert aegis-logo.svg → aegis-logo.png at 512×512 (Discord-ready)."""
try:
    import cairosvg
    cairosvg.svg2png(url="aegis-logo.svg", write_to="aegis-logo.png",
                     output_width=512, output_height=512)
    print("Saved aegis-logo.png")
except ImportError:
    print("cairosvg not installed. Install it with:")
    print("  pip install cairosvg")
    print()
    print("Or convert with any of these alternatives:")
    print("  Inkscape:  inkscape aegis-logo.svg --export-png=aegis-logo.png -w 512 -h 512")
    print("  ImageMagick: convert -background none aegis-logo.svg -resize 512x512 aegis-logo.png")
    print("  Browser:   open aegis-logo.svg, screenshot, or File → Save as PNG")
