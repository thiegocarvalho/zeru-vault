import glob
import os
import sys

from PIL import Image

src, dst = sys.argv[1], sys.argv[2]
os.makedirs(dst, exist_ok=True)
for path in sorted(glob.glob(os.path.join(src, "*.ppm"))):
    name = os.path.splitext(os.path.basename(path))[0]
    image = Image.open(path).convert("RGB").resize((640, 340), Image.NEAREST)
    image.save(os.path.join(dst, f"{name}.png"), optimize=True)
