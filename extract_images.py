import argparse
import base64
import hashlib
import io
import os
import re
import sys
from typing import Dict, Tuple, Optional


def try_import_pillow():
    try:
        from PIL import Image  # type: ignore
        return Image
    except Exception:
        return None


DATA_URI_RE = re.compile(
    r"data:image/(?P<type>[a-zA-Z0-9.+-]+);base64,(?P<b64>[A-Za-z0-9+/=]+)"
)


def ensure_outdir(path: str) -> None:
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)


def next_index_for_prefix(outdir: str, prefix: str, ext: str = ".jpg") -> int:
    max_idx = 0
    if not os.path.isdir(outdir):
        return 1
    for name in os.listdir(outdir):
        if not name.startswith(prefix):
            continue
        if not name.lower().endswith(ext):
            continue
        middle = name[len(prefix) : -len(ext)]
        if middle.isdigit():
            max_idx = max(max_idx, int(middle))
    return max_idx + 1


def save_as_jpeg_with_pillow(Image, bytes_data: bytes, outpath: str) -> None:
    with io.BytesIO(bytes_data) as bio:
        with Image.open(bio) as img:
            # Convert to RGB, handling alpha by flattening onto white background
            if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                background = Image.new("RGB", img.size, (255, 255, 255))
                try:
                    img = img.convert("RGBA")
                except Exception:
                    img = img.convert("RGB")
                background.paste(img, mask=img.split()[3] if img.mode == "RGBA" else None)
                background.save(outpath, format="JPEG", quality=85, optimize=True, progressive=True)
            else:
                rgb = img.convert("RGB")
                rgb.save(outpath, format="JPEG", quality=85, optimize=True, progressive=True)


def write_bytes(bytes_data: bytes, outpath: str) -> None:
    with open(outpath, "wb") as f:
        f.write(bytes_data)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract data URI images from a single HTML file and replace with file paths.")
    p.add_argument("--html", default="index.html", help="Path to the input HTML file (default: index.html)")
    p.add_argument("--outdir", default="images", help="Output directory for extracted images (default: images)")
    p.add_argument("--prefix", default="img_", help="Filename prefix for saved images (default: img_)")
    p.add_argument("--backup", default="index.backup.html", help="Backup file path for original HTML (default: index.backup.html)")
    p.add_argument("--force-jpg", action="store_true", default=True, help="Force convert to JPG when Pillow is available (default: True)")
    p.add_argument("--no-force-jpg", dest="force_jpg", action="store_false", help="Do not force JPG; keep original types")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not os.path.isfile(args.html):
        print(f"[ERROR] HTML 파일을 찾을 수 없습니다: {args.html}")
        return 1

    # Read HTML (large files supported)
    with open(args.html, "r", encoding="utf-8", errors="ignore") as f:
        html = f.read()

    # Create backup
    try:
        with open(args.backup, "w", encoding="utf-8", errors="ignore") as bf:
            bf.write(html)
    except Exception as e:
        print(f"[WARN] 백업 작성 실패: {e}")

    ensure_outdir(args.outdir)

    Image = try_import_pillow()
    if Image is None and args.force_jpg:
        print("[WARN] Pillow 미설치로 인해 JPG 변환을 보장할 수 없습니다. `pip install pillow` 권장")

    # Deduplicate by content hash (bytes)
    hash_to_filename: Dict[str, str] = {}

    # Start index after existing files to avoid collision
    current_index = next_index_for_prefix(args.outdir, args.prefix, ".jpg")

    saved_count = 0
    jpg_count = 0
    kept_original_ext_count = 0

    def replacer(m: re.Match) -> str:
        nonlocal current_index, saved_count, jpg_count, kept_original_ext_count
        img_type = m.group("type").lower()
        b64 = m.group("b64")
        try:
            data = base64.b64decode(b64, validate=False)
        except Exception:
            try:
                data = base64.b64decode(b64)
            except Exception:
                # If cannot decode, keep original
                return m.group(0)

        digest = hashlib.sha1(data).hexdigest()
        if digest in hash_to_filename:
            return hash_to_filename[digest]

        # Decide output path
        out_rel: Optional[str] = None

        # Prefer JPG when Pillow is available and force_jpg is True
        if Image is not None and args.force_jpg and img_type not in ("svg+xml",):
            filename = f"{args.prefix}{current_index:03d}.jpg"
            out_rel = os.path.join(args.outdir, filename).replace("\\", "/")
            out_abs = os.path.join(args.outdir, filename)
            try:
                save_as_jpeg_with_pillow(Image, data, out_abs)
                jpg_count += 1
                saved_count += 1
                current_index += 1
            except Exception:
                # Fallback to writing original bytes with original extension
                ext = ".jpg" if img_type in ("jpeg", "jpg") else (
                    ".png" if img_type == "png" else (
                        ".webp" if img_type == "webp" else (
                            ".gif" if img_type == "gif" else (
                                ".svg" if img_type == "svg+xml" else ".bin"
                            )
                        )
                    )
                )
                filename = f"{args.prefix}{current_index:03d}{ext}"
                out_rel = os.path.join(args.outdir, filename).replace("\\", "/")
                out_abs = os.path.join(args.outdir, filename)
                write_bytes(data, out_abs)
                kept_original_ext_count += 1
                saved_count += 1
                current_index += 1
        else:
            # No Pillow or not forcing JPG; keep original extension
            ext = ".jpg" if img_type in ("jpeg", "jpg") else (
                ".png" if img_type == "png" else (
                    ".webp" if img_type == "webp" else (
                        ".gif" if img_type == "gif" else (
                            ".svg" if img_type == "svg+xml" else ".bin"
                        )
                    )
                )
            )
            filename = f"{args.prefix}{current_index:03d}{ext}"
            out_rel = os.path.join(args.outdir, filename).replace("\\", "/")
            out_abs = os.path.join(args.outdir, filename)
            try:
                if Image is not None and args.force_jpg and ext != ".jpg" and img_type not in ("svg+xml",):
                    save_as_jpeg_with_pillow(Image, data, out_abs)
                    jpg_count += 1
                else:
                    write_bytes(data, out_abs)
                    if ext == ".jpg":
                        jpg_count += 1
                    else:
                        kept_original_ext_count += 1
                saved_count += 1
                current_index += 1
            except Exception:
                # On unexpected failure, keep original data URI
                return m.group(0)

        # Cache mapping for duplicates
        hash_to_filename[digest] = out_rel
        return out_rel

    new_html = DATA_URI_RE.sub(replacer, html)

    # Write modified HTML
    with open(args.html, "w", encoding="utf-8", errors="ignore") as f:
        f.write(new_html)

    # Report
    remaining = len(re.findall(r"data:image/", new_html))
    print(f"SAVED_TOTAL={saved_count}")
    print(f"SAVED_JPG={jpg_count}")
    print(f"SAVED_NONJPG={kept_original_ext_count}")
    print(f"DATA_URI_LEFT={remaining}")
    print(f"OUTDIR={args.outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


