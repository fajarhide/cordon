#!/usr/bin/env python3
"""Generates the architecture animation, one SVG frame at a time.

Rendered with rsvg-convert and assembled with ffmpeg. Hand-written frames
rather than a diagramming tool because the thing worth showing is motion: a
request taking one path and being stopped on another, which a static box
diagram cannot say.

Palette is Catppuccin Mocha, the same as the terminal recordings, so the
README does not look like three different projects.
"""
import math
import pathlib
import sys

W, H = 1180, 560
FPS = 20

BASE = "#1e1e2e"
SURF = "#2a2b3c"
LINE = "#45475a"
TEXT = "#cdd6f4"
SUBT = "#8389a5"
GREEN = "#a6e3a1"
RED = "#f38ba8"
BLUE = "#89b4fa"
MAUVE = "#cba6f7"
YELLOW = "#f9e2af"

MONO = "DejaVu Sans Mono, Menlo, monospace"

# Beat boundaries in frames.
B1, B2, B3 = 62, 136, 224


def ease(t: float) -> float:
    """Ease in and out, so a packet accelerates and settles instead of sliding."""
    t = max(0.0, min(1.0, t))
    return 0.5 - 0.5 * math.cos(math.pi * t)


def box(x, y, w, h, stroke, label, sub=None, lw=2, fill=SURF, label_fill=None, dim=1.0):
    out = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{lw}" opacity="{dim:.2f}"/>'
    ]
    cy = y + h / 2 + (0 if sub is None else -9)
    out.append(
        f'<text x="{x + w / 2}" y="{cy + 6}" fill="{label_fill or TEXT}" font-family="{MONO}" '
        f'font-size="16" text-anchor="middle" opacity="{dim:.2f}">{label}</text>'
    )
    if sub:
        out.append(
            f'<text x="{x + w / 2}" y="{cy + 28}" fill="{SUBT}" font-family="{MONO}" '
            f'font-size="12" text-anchor="middle" opacity="{dim:.2f}">{sub}</text>'
        )
    return "".join(out)


def label(x, y, s, fill=SUBT, size=13, anchor="start", opacity=1.0, weight="normal"):
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-family="{MONO}" font-size="{size}" '
        f'text-anchor="{anchor}" opacity="{opacity:.2f}" font-weight="{weight}">{s}</text>'
    )


def packet(x, y, colour, text=None, r=9, opacity=1.0):
    out = [
        f'<circle cx="{x}" cy="{y}" r="{r + 6}" fill="{colour}" opacity="{opacity * 0.18:.2f}"/>',
        f'<circle cx="{x}" cy="{y}" r="{r}" fill="{colour}" opacity="{opacity:.2f}"/>',
    ]
    if text:
        out.append(
            f'<text x="{x}" y="{y - 20}" fill="{colour}" font-family="{MONO}" font-size="13" '
            f'text-anchor="middle" opacity="{opacity:.2f}">{text}</text>'
        )
    return "".join(out)


def cross(x, y, colour, scale=1.0, opacity=1.0):
    d = 11 * scale
    return (
        f'<g opacity="{opacity:.2f}" stroke="{colour}" stroke-width="3.5" stroke-linecap="round">'
        f'<line x1="{x - d}" y1="{y - d}" x2="{x + d}" y2="{y + d}"/>'
        f'<line x1="{x + d}" y1="{y - d}" x2="{x - d}" y2="{y + d}"/></g>'
    )


def tick(x, y, colour, opacity=1.0):
    return (
        f'<g opacity="{opacity:.2f}" stroke="{colour}" stroke-width="3.5" fill="none" '
        f'stroke-linecap="round" stroke-linejoin="round">'
        f'<polyline points="{x - 10},{y} {x - 3},{y + 8} {x + 11},{y - 9}"/></g>'
    )


APP = (56, 232, 190, 96)
DAEMON = (330, 70, 400, 420)
GUARD = (362, 150, 336, 92)
PROC = (362, 290, 160, 86)
CTR = (538, 290, 160, 86)
BUDI = (830, 170, 290, 92)
ANI = (830, 330, 290, 92)


def frame(i: int) -> str:
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">']
    s.append(f'<rect width="{W}" height="{H}" fill="{BASE}"/>')

    # Which beat, and how far through it.
    if i < B1:
        beat, t = 1, i / B1
    elif i < B2:
        beat, t = 2, (i - B1) / (B2 - B1)
    else:
        beat, t = 3, (i - B2) / (B3 - B2)

    x, y, w, h = DAEMON
    s.append(
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="16" fill="#232334" '
        f'stroke="{LINE}" stroke-width="1.5" stroke-dasharray="7 5"/>'
    )
    s.append(label(x + 16, y + 26, "cordond", SUBT, 13))
    s.append(label(x + w - 16, y + 26, "one binary, no KVM", SUBT, 12, anchor="end"))

    s.append(box(*APP, BLUE, "your app", "agent runtime"))

    guard_hot = beat in (1, 2) and 0.30 < t < 0.70
    s.append(
        box(*GUARD, RED if beat == 2 and t > 0.42 else MAUVE, "the guard",
            "resolve on disk, then decide",
            lw=3 if guard_hot else 2)
    )

    job_running = beat == 3 and 0.30 < t < 0.86
    s.append(box(*PROC, LINE if job_running else LINE, "process", "rlimits + landlock",
                 dim=0.45 if job_running else 0.85))
    s.append(box(*CTR, GREEN if job_running else LINE, "container", "no network, ro root",
                 dim=1.0 if job_running else 0.85))

    budi_hot = (beat == 1 and t > 0.62) or (beat == 3 and t > 0.44)
    s.append(box(*BUDI, GREEN if budi_hot else LINE, "acme/legal/budi",
                 "this job's sandbox", lw=3 if budi_hot else 2))
    s.append(box(*ANI, RED if (beat == 2 and t > 0.42) else LINE, "acme/legal/ani",
                 "a sibling", dim=0.9))
    s.append(label(BUDI[0] + BUDI[2] / 2, 118, "sandboxes on disk", SUBT, 13, anchor="middle"))

    s.append(f'<line x1="246" y1="280" x2="356" y2="200" stroke="{LINE}" stroke-width="1.5" stroke-dasharray="5 5"/>')
    s.append(f'<line x1="698" y1="200" x2="824" y2="216" stroke="{LINE}" stroke-width="1.5" stroke-dasharray="5 5"/>')
    s.append(f'<line x1="698" y1="333" x2="824" y2="250" stroke="{LINE}" stroke-width="1.5" stroke-dasharray="5 5"/>')

    def along(p0, p1, u):
        return p0[0] + (p1[0] - p0[0]) * u, p0[1] + (p1[1] - p0[1]) * u

    cap = (246, 280)
    gin = (362, 196)
    gout = (698, 196)

    if beat == 1:
        s.append(label(56, 56, "A path the owner owns", TEXT, 17, weight="bold"))
        s.append(label(56, 80, 'resolve  acme/legal/budi  "notes.md"', GREEN, 14))
        if t < 0.46:
            u = ease(t / 0.46)
            px, py = along(cap, gin, u)
            s.append(packet(px, py, GREEN, "notes.md" if u > 0.25 else None))
        else:
            u = ease((t - 0.46) / 0.40) if t < 0.86 else 1.0
            px, py = along(gout, (870, 216), u)
            s.append(packet(px, py, GREEN))
            if t > 0.70:
                s.append(tick(BUDI[0] + BUDI[2] - 34, BUDI[1] + 46, GREEN,
                              min(1.0, (t - 0.70) / 0.14)))

    elif beat == 2:
        s.append(label(56, 56, "A path that leaves it", TEXT, 17, weight="bold"))
        s.append(label(56, 80, 'resolve  acme/legal/budi  "../ani/secret.md"', RED, 14))
        if t < 0.42:
            u = ease(t / 0.42)
            px, py = along(cap, gin, u)
            s.append(packet(px, py, RED, "../ani/secret.md" if u > 0.2 else None))
        else:
            # Stopped at the guard: it never reaches the rail on the far side.
            k = min(1.0, (t - 0.42) / 0.18)
            s.append(cross(362, 196, RED, 1.0, k))
            s.append(label(530, 268, "403  path_escapes_workspace", RED, 14, anchor="middle",
                           opacity=k))
            s.append(label(975, 452, "never reached", RED, 13, anchor="middle", opacity=k * 0.9))

    else:
        s.append(label(56, 56, "A job, and what it cannot do", TEXT, 17, weight="bold"))
        s.append(label(56, 80, "run  acme/legal/budi   sh -c  ...", BLUE, 14))
        if t < 0.30:
            u = ease(t / 0.30)
            px, py = along(cap, gin, u)
            s.append(packet(px, py, BLUE, "run" if u > 0.3 else None))
        elif t < 0.44:
            u = ease((t - 0.30) / 0.14)
            px, py = along((530, 242), (618, 288), u)
            s.append(packet(px, py, BLUE))
        else:
            # The sibling attempt is stopped by the kernel, not by a check.
            u = ease(min(1.0, (t - 0.44) / 0.22))
            px, py = along((698, 333), (870, 250), u)
            s.append(packet(px, py, GREEN))
            if t > 0.60:
                k = min(1.0, (t - 0.60) / 0.14)
                s.append(label(975, 152, "writes out/report.txt", GREEN, 13,
                               anchor="middle", opacity=k))
            if t > 0.66:
                k = min(1.0, (t - 0.66) / 0.16)
                s.append(f'<line x1="975" y1="272" x2="975" y2="320" stroke="{RED}" '
                         f'stroke-width="2" stroke-dasharray="5 4" opacity="{k:.2f}"/>')
                s.append(cross(975, 296, RED, 0.85, k))
                s.append(label(975, 452, "landlock: the job cannot see a sibling", RED, 13,
                               anchor="middle", opacity=k))
            if t > 0.78:
                # Output goes back as a token, never a path, so it travels all the way to the app.
                k = min(1.0, (t - 0.78) / 0.12)
                u = ease(min(1.0, (t - 0.78) / 0.20))
                bx = 900 - (900 - 150) * u
                s.append(packet(bx, 524, YELLOW, "art_… token", opacity=k))

    s.append(label(W / 2, H - 16,
                   "cordon  ·  a sandbox per owner  ·  github.com/fajarhide/cordon",
                   SUBT, 12, anchor="middle", opacity=0.75))
    s.append("</svg>")
    return "".join(s)


def main():
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/archframes")
    out.mkdir(parents=True, exist_ok=True)
    for i in range(B3):
        (out / f"f{i:04d}.svg").write_text(frame(i))
    print(f"{B3} frames in {out}")


if __name__ == "__main__":
    main()
