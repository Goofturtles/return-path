"""Crop the rendered sky to its cloud band, verify it tiles, and compress it.

    python tools/seamless.py

Nothing here blends or fades. The render is a full 360-degree equirectangular
panorama, so it is periodic horizontally by geometry - this only crops
vertically, proves the wrap, and converts to WebP.

Why crop and flip: seen from underneath, a cloud deck puts its dense band low
in frame - the sight-line to the horizon is long - with thin sky overhead. The
hero wants the opposite, cloud banked across the top thinning to clear sky
below, so we keep the band and turn it over. Both operations are vertical and
cannot disturb horizontal periodicity.
"""

import os
import sys
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
IMG = os.path.normpath(os.path.join(HERE, '..', 'img'))

# Fractions of image height. The last rows hold the deck's own bottom face,
# which reads as a hard bright line, so they are cut.
CROP_TOP, CROP_BOTTOM = 0.34, 0.955
QUALITY = 64
TOLERANCE = 2.5     # wrap error may be at most this many times the baseline


def seam_stats(arr):
    a = arr.astype(np.float64) / 255.0
    # Compare in premultiplied alpha: transparent pixels carry meaningless RGB.
    pm = np.concatenate([a[..., :3] * a[..., 3:4], a[..., 3:4]], axis=2)
    wrap = np.abs(pm[:, -1] - pm[:, 0]).mean()
    neighbour = np.abs(pm[:, 1:] - pm[:, :-1]).mean()
    return wrap, neighbour


failed = False
for name in ('near', 'mid', 'far'):
    src = os.path.join(IMG, 'cloud-%s.png' % name)
    if not os.path.exists(src):
        print('%-5s missing render, skipped' % name)
        continue

    arr = np.array(Image.open(src).convert('RGBA'))
    h = arr.shape[0]
    band = arr[int(h * CROP_TOP):int(h * CROP_BOTTOM)]
    band = band[::-1]                      # densest edge to the top

    wrap, neighbour = seam_stats(band)
    ratio = wrap / neighbour if neighbour else float('inf')

    if ratio > TOLERANCE:
        # Keep the PNG and leave the shipped WebP alone: a bad re-run must not
        # overwrite a good asset and delete the only source it could be redone
        # from.
        failed = True
        print('%-5s %dx%d  wrap %.5f  neighbour %.5f  ratio %.2fx  SEAM VISIBLE '
              '- kept %s, shipped asset untouched'
              % (name, band.shape[1], band.shape[0], wrap, neighbour, ratio,
                 os.path.basename(src)))
        continue

    dst = os.path.join(IMG, 'cloud-%s.webp' % name)
    Image.fromarray(band, 'RGBA').save(dst, 'WEBP', quality=QUALITY, method=6)
    kb = os.path.getsize(dst) / 1024.0
    print('%-5s %dx%d  wrap %.5f  neighbour %.5f  ratio %.2fx  %6.1f kB  seamless'
          % (name, band.shape[1], band.shape[0], wrap, neighbour, ratio, kb))
    os.remove(src)

print('done')
sys.exit(1 if failed else 0)
