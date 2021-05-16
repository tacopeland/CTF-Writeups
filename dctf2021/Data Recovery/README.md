# Data Recovery

In this challenge you are given an archive `recovered_data.zip` full of recovered files.

Running `file *` in the extracted directory gave me the following file types for each file:
```
accounting.xls:     data
alarm:              JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=0], baseline, precision 8, 639x629, components 3
a.out:              data
backup.db:          data
cat.webm:           WebM
code.dat:           GIF image data, version 89a, 446 x 526
compiled.exe:       data
config.cfg:         JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=0], progressive, precision 8, 1080x885, components 3
encrypted:          data
encrypted1:         ASCII text
fish.bmp:           ISO Media, MP4 Base Media v1 [ISO 14496-12:2003]
flag.txt:           PNG image data, 561 x 789, 8-bit colormap, non-interlaced
hint.txt:           GIF image data, version 89a, 498 x 440
how-to.png:         PNG image data, 561 x 789, 8-bit colormap, non-interlaced
important.docx:     data
kernel.bin:         data
logo.svg:           ISO Media, MP4 Base Media v1 [ISO 14496-12:2003]
logs.txt:           ISO Media, MP4 Base Media v1 [ISO 14496-12:2003]
macosx.app:         ISO Media, MP4 Base Media v1 [ISO 14496-12:2003]
main_base.db:       ISO Media, MP4 Base Media v1 [ISO 14496-12:2003]
sauce:              JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 678x590, components 3
secret_code.jpg:    ISO Media, MP4 v2 [ISO 14496-14]
secret.cpt:         ISO Media, MP4 v2 [ISO 14496-14]
security_route.zip: PNG image data, 128 x 128, 8-bit/color RGBA, non-interlaced
source.zip:         ISO Media, MP4 v1 [ISO 14496-1:ch13]
statistics.csv:     RIFF (little-endian) data, Web/P image, VP8 encoding, 640x476, Scaling: [none]x[none], YUV color, decoders should clamp
```

Just to make sure, I ran `mpv .` and `feh .` in the directory to view all the videos and pictures, and they were just memes.

So, then we were left with a few files that weren't accounted for:
```
accounting.xls
a.out
backup.db
compiled.exe
encrypted
encrypted1
important.docx
kernel.bin
```
There was also `main_base.db`, which was a video but didn't play.

The first thing that came to mind from these files was that `encrypted1` is in base64 format, which is the go-to format for ciphertext in crypto challenges. So, I loaded it up in [Cyberchef](https://gchq.github.io/CyberChef/). Putting it through the `From Base64` filter left us with random looking bits, so I just put in the `Magic` filter in intensive mode, which found that this ciphertext, when bruteforced by XORing with the byte `6a`, returns a zip file.

So I downloaded that zip file, extracted it, and was left with `very_important.txt`. Grepping for `dctf` left me with the flag.
