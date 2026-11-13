# Video assets

## heimdall-gate.mp4 and heimdall-gate.webp

The Home hero key art, cut from the original `herosection-heimdall.mp4` (1920x1080, 8 s). To regenerate from that file:

```bash
VF="delogo=x=836:y=476:w=184:h=34,crop=1336:1068:0:2,scale=1040:-2:flags=lanczos"
ffmpeg -i herosection-heimdall.mp4 -vf "$VF" -an -c:v libx264 -preset slow -crf 28 -pix_fmt yuv420p -movflags +faststart heimdall-gate.mp4
ffmpeg -ss 3 -i herosection-heimdall.mp4 -vf "$VF" -frames:v 1 -c:v libwebp -quality 76 heimdall-gate.webp
```

The crop removes third-party provider logos and a "Live analysis" panel with invented figures. `delogo` removes a misspelt subtitle under the wordmark. Small label text inside the footage is still machine-generated and slightly soft; new footage would fix that.

## Optional: scroll-scrubbed footage

`src/components/motion/HeroScrub.jsx` plays a WebP frame sequence on scroll. It is not mounted. To use it, run `./scripts/extract-hero-frames.sh your-footage.mp4`, which writes `public/video/hero/NNNN.webp` and `manifest.json`, then render `<HeroScrub />` in `src/pages/home/HomeStory.jsx`.
