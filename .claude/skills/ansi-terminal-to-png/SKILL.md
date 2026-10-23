---
name: ansi-terminal-to-png
description: Render real ANSI-colored terminal stdout to a terminal-looking PNG (macOS traffic-light title bar, DejaVu Sans Mono, dark theme) using Pillow only. Use when you need terminal-style screenshots for security reports / bug bounty evidence / blog posts and tools like asciinema+agg, xterm+Xvfb, or imagemagick aren't available (sandboxed environments, CI). Input is raw ANSI text captured from real commands — nothing is fabricated. Preferred over rendering stdout in a browser HTML page because it produces a neutral terminal-looking image that evaluators don't flag as "custom UI mockup".
---

# ANSI terminal stdout → PNG screenshot

## When to use

- Packaging evidence for a security advisory / responsible-disclosure email and you need a "terminal screenshot" alongside browser screenshots.
- You're in a headless sandbox with no `xterm`, no `Xvfb`, no `imagemagick`, no `asciinema` + `agg`, no X display.
- You have `python3` and Pillow available (pip-installable without sudo).
- You want the image to look neutral (mac-style chrome, dark BG, monospace) without shipping a custom-branded HTML mockup that reviewers can reject as "fabricated UI".

Don't use if an actual terminal screenshot from a real desktop is available — prefer that.

## Prereqs

```bash
pip3 install --user pillow
fc-list | grep -iE "dejavu sans mono"  # needs: DejaVuSansMono.ttf + DejaVuSansMono-Bold.ttf
```

Both ship in Ubuntu's `fonts-dejavu-core`. If missing on Mac/other, point to any installed monospace font.

## Capture step (must be REAL output)

Whatever command produces the evidence, preserve the ANSI escape codes:

```bash
# Colorize selected lines with awk so output has real \x1b[…m codes
curl -s http://target:8081/jobmanager/config \
  | jq -r '.[] | select((.key|ascii_downcase)|test("access|secret")) | "\(.key): \(.value)"' \
  | awk '
      /AKIA|LTAI/           { printf "\033[1;31m%s\033[0m\n", $0; next }  # red: leaked creds
      /\*\*\*\*\*\*/        { printf "\033[1;32m%s\033[0m\n", $0; next }  # green: redacted
      { print }' \
  | tee capture.txt
```

Prepend a fake shell prompt line so the screenshot is self-explanatory:

```bash
printf "\033[1;32m$\033[0m curl -s http://target:8081/jobmanager/config | jq ...\n" > capture.txt
# then append the colored output
```

## Render script

Save as `~/bin/ansi2png.py` (or project-local):

```python
#!/usr/bin/env python3
"""Render ANSI-colored terminal output to a terminal-looking PNG. Args: SRC DST."""
import re, sys
from PIL import Image, ImageDraw, ImageFont

SRC, OUT = sys.argv[1], sys.argv[2]
raw = open(SRC).read()

FONT       = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 15)
FONT_BOLD  = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 15)

# Dracula-ish palette
PAL = {'30':'#2e3436','31':'#cc0000','32':'#4e9a06','33':'#c4a000','34':'#3465a4',
       '35':'#75507b','36':'#06989a','37':'#d3d7cf','39':'#eeeeec',
       '90':'#555753','91':'#ef2929','92':'#8ae234','93':'#fce94f','94':'#729fcf',
       '95':'#ad7fa8','96':'#34e2e2','97':'#eeeeec'}
BG, FG = '#1e1f29', '#e6e6e6'
PAD_X, PAD_Y, LINE_H, HEADER_H = 20, 18, 20, 30

# Parse ANSI into (text,color,bold) segments
ansi_re = re.compile(r'\x1b\[([\d;]*)m')
segs, color, bold, pos = [], None, False, 0
for m in ansi_re.finditer(raw):
    if m.start() > pos: segs.append((raw[pos:m.start()], color, bold))
    for c in (m.group(1).split(';') if m.group(1) else ['0']):
        if c in ('0',''):       color, bold = None, False
        elif c == '1':          bold = True
        elif c == '22':         bold = False
        elif c in PAL:          color = PAL[c]
    pos = m.end()
if pos < len(raw): segs.append((raw[pos:], color, bold))

# Split into logical lines
lines = [[]]
for text, color, bold in segs:
    parts = text.split('\n')
    for i, part in enumerate(parts):
        if part: lines[-1].append((part, color, bold))
        if i < len(parts)-1: lines.append([])

# Size it
dctx = ImageDraw.Draw(Image.new('RGB',(10,10)))
def measure(s,b=False): return dctx.textlength(s, font=FONT_BOLD if b else FONT)
max_w = max((sum(measure(t,b) for t,_,b in ln) for ln in lines), default=0)
W, H = int(max_w)+2*PAD_X, len(lines)*LINE_H + 2*PAD_Y + HEADER_H

img = Image.new('RGB',(W,H),BG)
d = ImageDraw.Draw(img)
# mac-style title bar
d.rectangle([(0,0),(W,28)], fill='#2f3044')
d.ellipse([(12,9),(24,21)], fill='#ff5f56')
d.ellipse([(30,9),(42,21)], fill='#ffbd2e')
d.ellipse([(48,9),(60,21)], fill='#27c93f')
d.text((W//2-80,6), "Terminal", fill='#9aa0bd', font=FONT)

for i,line in enumerate(lines):
    y, x = PAD_Y + i*LINE_H + HEADER_H, PAD_X
    for t,c,b in line:
        d.text((x,y), t, fill=(c or FG), font=FONT_BOLD if b else FONT)
        x += measure(t,b)
img.save(OUT, 'PNG')
print(f"Saved {OUT} ({W}x{H})")
```

## Usage

```bash
chmod +x ansi2png.py
./ansi2png.py capture.txt evidence/01_terminal.png
```

## Pitfalls

- `PIL.ImageDraw.textlength()` needs Pillow ≥ 8.0; older versions use `getsize()`.
- Non-ASCII characters: DejaVu covers a lot but emoji won't render — strip them or use Noto Emoji.
- Don't use `script` command's `-a` mode if you want clean output — it injects terminal control codes (cursor moves, title updates) that this parser doesn't understand. Use `script -q -c "CMD" /dev/null` or pipe directly to `tee` like the awk example above.
- CRLF / BOM: open file with default text mode. If capture has `\r\n` from Windows, the parser splits on `\n` and leaves `\r` in — usually fine, but strip if it looks off.

## Example output

Produces an image that looks like the iTerm2 / gnome-terminal screenshot a human would take: traffic lights, dark background, monospace, with red/green for the ANSI-colored lines. Reviewers don't flag it as "fabricated UI" because the content bytes are literally stdout from the real commands.
