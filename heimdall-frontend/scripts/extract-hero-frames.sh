#!/usr/bin/env bash
# Turns footage into the WebP frame sequence the optional Hero Scrub component plays on scroll (see public/video/README.md).
#   ./scripts/extract-hero-frames.sh footage.mp4 [frames-per-second] [width] [quality]
# Defaults: 20 fps, 1280 wide, quality 62.
set -euo pipefail
input="${1:?Usage: extract-hero-frames.sh footage.mp4 [fps] [width] [quality]}"
fps="${2:-20}"; width="${3:-1280}"; quality="${4:-62}"
out="$(cd "$(dirname "$0")/.." && pwd)/public/video/hero"
command -v ffmpeg >/dev/null || { echo "ffmpeg is required."; exit 1; }
[ -f "$input" ] || { echo "No such file: $input"; exit 1; }
mkdir -p "$out"
find "${out:?}" -maxdepth 1 \( -name '[0-9]*.webp' -o -name manifest.json \) -delete
ffmpeg -loglevel error -i "$input" -an -vf "fps=$fps,scale=$width:-2" -c:v libwebp -quality "$quality" "$out/%04d.webp"
count=$(find "$out" -name '[0-9]*.webp' | wc -l | tr -d ' ')
[ "$count" -gt 0 ] || { echo "No frames were produced."; exit 1; }
size=$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=s=x:p=0 -i "$input")
aspect=$(awk -F x '{printf "%.4f", $1/$2}' <<<"$size")
printf '{"frameCount": %s, "aspect": %s}\n' "$count" "$aspect" > "$out/manifest.json"
echo "Wrote $count frames, $(du -sh "$out" | cut -f1) in total, to $out"
