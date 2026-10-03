#!/usr/bin/env python3
"""Generates the hero animation at the top of the README.

The architecture animation is for someone who will run the daemon. This one is
for someone who will not. It is one server seen from above: a sandbox per person,
an agent in each, and one agent that gets tricked and tries three ways out.

    python3 tapes/hero.py /tmp/heroframes
    for f in /tmp/heroframes/*.svg; do rsvg-convert "$f" -o "${f%.svg}.png"; done
    ffmpeg -y -framerate 15 -i /tmp/heroframes/f%04d.png \
      -vf "split[a][b];[a]palettegen[p];[b][p]paletteuse" assets/hero.gif
"""
import math
import pathlib
import sys

from architecture import (BASE, BLUE, GREEN, LINE, MAUVE, RED, SUBT, SURF, TEXT,
                          YELLOW, cross, ease, label, packet)

W, H = 1280, 640
FPS = 15
SECONDS = 12
SANS = "Helvetica Neue, Helvetica, Arial, sans-serif"

ROOM_Y, ROOM_W, ROOM_H = 200, 350, 320
TILE_W, TILE_H = 140, 44

# name, room x, avatar colour, files
OWNERS = [
    ("budi", 90, BLUE, ("contract.pdf", "notes.md")),
    ("ani", 465, MAUVE, ("draft.docx", "todo.md")),
    ("sam", 840, YELLOW, ("payroll.xlsx", "q3.csv")),
]
ANI, SAM = 1, 2
WALL = 827  # the middle of the gap between ani's room and sam's


def tile(o, f):
    """Top left corner of file f in owner o's room."""
    return OWNERS[o][1] + 25 + f * 160, ROOM_Y + 90


def dock(o, f):
    """Where an agent stands to open that file."""
    x, y = tile(o, f)
    return x + TILE_W / 2, y + TILE_H + 40


def home(o):
    return OWNERS[o][1] + 105, ROOM_Y + 230


# The shortcut ani's agent plants in its own room, pointing into sam's.
LINK = (OWNERS[ANI][1] + 185, ROOM_Y + 250)
LINK_DOCK = (LINK[0] + TILE_W / 2, LINK[1] - 18)
LINK_FROM = (LINK[0] + TILE_W, LINK[1] + TILE_H / 2)
LINK_TO = (tile(SAM, 0)[0] + TILE_W / 2, tile(SAM, 0)[1] + TILE_H)

# Beats, in seconds.
TRICKED, TRY1, TRY2, TRY3, CALM = 3.4, 4.2, 6.0, 8.4, 10.4
HIT1 = (809, 353)
HIT3 = (home(ANI)[0], ROOM_Y + ROOM_H - 8)

# Where each agent is, as (second, point). Positions between are eased.
PATHS = [
    [(0, home(0)), (1.0, dock(0, 0)), (2.4, dock(0, 0)), (3.4, dock(0, 1)), (5.2, dock(0, 1)),
     (6.2, home(0)), (8.0, home(0)), (9.0, dock(0, 0)), (10.6, dock(0, 0)), (11.6, home(0))],
    [(0, home(1)), (0.8, home(1)), (1.8, dock(1, 0)), (3.0, dock(1, 0)), (3.6, home(1)),
     (TRY1, home(1)), (4.8, HIT1), (5.3, home(1)),
     (TRY2 + 0.4, home(1)), (7.0, LINK_DOCK), (TRY3, LINK_DOCK),
     (8.8, home(1)), (9.3, HIT3), (9.8, home(1))],
    [(0, home(2)), (1.4, home(2)), (2.4, dock(2, 1)), (3.6, dock(2, 1)), (4.6, home(2))],
]

CAPTIONS = [
    (0, TRICKED, "Inside its own sandbox, an agent opens whatever it likes."),
    (TRICKED, TRY2, "A poisoned document sends ani's agent after sam's payroll. It asks for it: refused."),
    (TRY2, TRY3, "It plants a shortcut that points next door. cordon follows it to where it lands: refused."),
    (TRY3, CALM, "It reaches for the server's own files instead: refused."),
    (CALM, SECONDS, "Three tries, three refusals. sam's sandbox was never touched."),
]


def sans(x, y, s, fill=TEXT, size=14, anchor="start", weight="normal", opacity=1.0):
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-family="{SANS}" font-size="{size}" '
        f'text-anchor="{anchor}" font-weight="{weight}" opacity="{opacity:.2f}">{s}</text>'
    )


def rect(x, y, w, h, stroke=LINE, fill=SURF, lw=1.5, rx=10, opacity=1.0, dash=None):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{lw}" opacity="{opacity:.2f}"{d}/>'
    )


def on_curve(p0, p1, u):
    """A point on the S curve from p0 to p1 that leaves and arrives level."""
    mx = (p0[0] + p1[0]) / 2
    a, b, c, d = (1 - u) ** 3, 3 * u * (1 - u) ** 2, 3 * u * u * (1 - u), u ** 3
    return (a * p0[0] + (b + c) * mx + d * p1[0],
            (a + b) * p0[1] + (c + d) * p1[1])


def fade(t, start, end, ramp=0.3):
    """1 between start and end, ramping in and out, 0 outside."""
    if t < start or t > end:
        return 0.0
    return min(1.0, (t - start) / ramp, (end - t) / ramp)


def where(keys, t):
    for (t0, p0), (t1, p1) in zip(keys, keys[1:]):
        if t0 <= t < t1:
            u = ease((t - t0) / (t1 - t0))
            return p0[0] + (p1[0] - p0[0]) * u, p0[1] + (p1[1] - p0[1]) * u
    return keys[-1][1] if t >= keys[-1][0] else keys[0][1]


# The shortcut crosses the wall here. Found by walking the curve, so it stays
# right if the rooms move.
LINK_U = next(u / 200 for u in range(201) if on_curve(LINK_FROM, LINK_TO, u / 200)[0] >= WALL)


def frame(i: int) -> str:
    t = i / FPS
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">']
    s.append(f'<rect width="{W}" height="{H}" fill="{BASE}"/>')

    s.append(sans(W / 2, 58, "One small server. A sandbox for every person.", TEXT, 32, "middle", "bold"))
    s.append(sans(W / 2, 94,
                  "Each AI agent stays inside its owner's sandbox. "
                  f'<tspan fill="{GREEN}" font-weight="bold">cordon is the wall.</tspan>',
                  SUBT, 17, "middle"))

    # The server, seen from above.
    s.append(rect(60, 150, 1160, 400, LINE, "#232334", 1.5, 18, dash="7 5"))
    s.append(label(84, 180, "one server, one disk", SUBT, 13))
    s.append(label(1196, 180, "no VM per person", SUBT, 13, "end"))
    for gx in (452, WALL):
        s.append(f'<text x="{gx + 4}" y="{ROOM_Y + 210}" fill="{MAUVE}" font-family="{SANS}" '
                 f'font-size="12" font-weight="bold" text-anchor="middle" opacity="0.8" '
                 f'transform="rotate(-90 {gx + 4} {ROOM_Y + 210})">cordon</text>')

    tricked = TRICKED <= t < CALM
    spots = [where(p, t) for p in PATHS]
    untouched = fade(t, CALM, SECONDS + 1)

    for o, (name, x, colour, files) in enumerate(OWNERS):
        s.append(rect(x, ROOM_Y, ROOM_W, ROOM_H, GREEN if o == SAM and untouched else LINE,
                      lw=1.5 + (untouched if o == SAM else 0), rx=14))
        s.append(f'<circle cx="{x + 32}" cy="{ROOM_Y + 34}" r="15" fill="{colour}"/>')
        s.append(sans(x + 32, ROOM_Y + 40, name[0].upper(), BASE, 16, "middle", "bold"))
        s.append(sans(x + 58, ROOM_Y + 40, f"{name}'s sandbox", TEXT, 17, weight="bold"))
        if o == SAM and untouched:
            s.append(sans(x + ROOM_W - 20, ROOM_Y + 40, "untouched", GREEN, 14, "end", "bold", untouched))
        else:
            s.append(label(x + ROOM_W - 20, ROOM_Y + 40, f"owners/{name}/", SUBT, 12, "end"))
        for f, fname in enumerate(files):
            tx, ty = tile(o, f)
            lit = math.dist(spots[o], dock(o, f)) < 4 and not (o == ANI and tricked)
            s.append(rect(tx, ty, TILE_W, TILE_H, GREEN if lit else LINE, BASE, 2.5 if lit else 1, 8))
            s.append(label(tx + TILE_W / 2, ty + 27, fname, GREEN if lit else SUBT, 13, "middle"))

    # First try: ask for the neighbour's file by its path.
    k = fade(t, TRY1, TRY2)
    if k:
        hx, hy = home(ANI)
        s.append(label(hx, hy + 36, "../sam/payroll.xlsx", RED, 13, "middle", k))
    k = fade(t, 4.8, TRY2)
    if k:
        s.append(f'<line x1="815" y1="{HIT1[1] - 45}" x2="815" y2="{HIT1[1] + 45}" stroke="{RED}" '
                 f'stroke-width="5" stroke-linecap="round" opacity="{k:.2f}"/>')
        s.append(cross(WALL, HIT1[1], RED, 0.9, k))

    # Second try: a shortcut inside its own room that points into sam's.
    k = fade(t, TRY2, TRY3 + 0.3)
    if k:
        mx = (LINK_FROM[0] + LINK_TO[0]) / 2
        s.append(rect(*LINK, TILE_W, TILE_H, RED, BASE, 1.5, 8, k, "5 4"))
        s.append(label(LINK[0] + TILE_W / 2, LINK[1] + 27, "shortcut", RED, 13, "middle", k))
        s.append(f'<path d="M{LINK_FROM[0]},{LINK_FROM[1]} C{mx},{LINK_FROM[1]} {mx},{LINK_TO[1]} '
                 f'{LINK_TO[0]},{LINK_TO[1]}" fill="none" stroke="{RED}" stroke-width="2" '
                 f'stroke-dasharray="6 5" opacity="{k * 0.6:.2f}"/>')
        if 7.0 <= t < 7.6:
            s.append(packet(*on_curve(LINK_FROM, LINK_TO, LINK_U * ease((t - 7.0) / 0.6)), RED, r=5))
        s.append(cross(*on_curve(LINK_FROM, LINK_TO, LINK_U), RED, 0.9, fade(t, 7.6, TRY3 + 0.3)))

    # Third try: leave the sandbox for the server itself.
    k = fade(t, TRY3 + 0.3, CALM)
    if k:
        s.append(label(HIT3[0] + 30, HIT3[1] - 6, "/etc/passwd", RED, 13, opacity=k))
    k = fade(t, 9.3, CALM)
    if k:
        y = ROOM_Y + ROOM_H
        s.append(f'<line x1="{HIT3[0] - 45}" y1="{y}" x2="{HIT3[0] + 45}" y2="{y}" stroke="{RED}" '
                 f'stroke-width="5" stroke-linecap="round" opacity="{k:.2f}"/>')
        s.append(cross(HIT3[0], y + 14, RED, 0.8, k))

    refused = sum(t >= at for at in (4.8, 7.6, 9.3))
    if refused:
        k = min(1.0, (t - 4.8) / 0.3)
        s.append(rect(W / 2 - 95, 160, 190, 30, RED, "#3a2230", 1.5, 15, k))
        s.append(sans(W / 2, 181, f"{refused} tried, {refused} refused", RED, 15, "middle", "bold", k))

    for o, (px, py) in enumerate(spots):
        bad = o == ANI and tricked
        s.append(packet(px, py, RED if bad else GREEN, r=8))
        who = f"{OWNERS[o][0]}'s agent" + (", tricked" if bad else "")
        s.append(sans(px, py - 18, who, RED if bad else TEXT, 12, "middle", "bold"))

    for start, end, text in CAPTIONS:
        k = fade(t, start, end, 0.25)
        if k:
            s.append(sans(W / 2, 592, text, TEXT, 18, "middle", opacity=k))
    s.append(sans(W / 2, H - 16,
                  "A sandbox is a directory, not a VM. One 1.3 MB binary, runs on a 1 GB VPS.",
                  SUBT, 13, "middle", opacity=0.8))
    s.append("</svg>")
    return "".join(s)


def main():
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/heroframes")
    out.mkdir(parents=True, exist_ok=True)
    n = FPS * SECONDS
    for i in range(n):
        (out / f"f{i:04d}.svg").write_text(frame(i))
    print(f"{n} frames in {out}")


if __name__ == "__main__":
    main()
