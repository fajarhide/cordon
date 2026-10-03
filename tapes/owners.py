#!/usr/bin/env python3
"""Generates the animation for "How an owner maps onto disk".

The ownership tree, one job in it, and six requests: three that are allowed
(its own file, then a file in each parent with inherit on) and three that are
refused (a sibling, another team, a symlink that lands next door).

    python3 tapes/owners.py /tmp/ownerframes
    for f in /tmp/ownerframes/*.svg; do rsvg-convert "$f" -o "${f%.svg}.png"; done
    ffmpeg -y -framerate 15 -i /tmp/ownerframes/f%04d.png \
      -vf "split[a][b];[a]palettegen[p];[b][p]paletteuse" assets/owners.gif
"""
import pathlib
import sys

from architecture import BASE, GREEN, LINE, RED, SUBT, SURF, TEXT, cross, ease, label, packet
from hero import fade, rect, sans

W, H = 1280, 640
FPS = 15
SECONDS = 14
NODE_W, NODE_H = 250, 74
LEG = 0.5  # seconds a request takes to cross one edge

# owner -> (centre, the file sitting directly in its sandbox)
NODES = {
    "acme": ((640, 235), "policy.md"),
    "acme/legal": ((400, 345), "template.docx"),
    "acme/finance": ((880, 345), "budget.xlsx"),
    "acme/legal/budi": ((250, 465), "draft.md"),
    "acme/legal/ani": ((550, 465), "secret.md"),
}
EDGES = [("acme", "acme/legal"), ("acme", "acme/finance"),
         ("acme/legal", "acme/legal/budi"), ("acme/legal", "acme/legal/ani")]
JOB = "acme/legal/budi"

# start second, the path the job asks for, the owners it passes through, and
# the code it is refused with. None means it is allowed.
REQUESTS = [
    (0.5, "draft.md", [JOB], None),
    (2.8, "../template.docx", [JOB, "acme/legal"], None),
    (4.4, "../../policy.md", [JOB, "acme/legal", "acme"], None),
    (6.4, "../ani/secret.md", [JOB, "acme/legal", "acme/legal/ani"],
     "403 path_escapes_workspace"),
    (8.4, "../../finance/budget.xlsx", [JOB, "acme/legal", "acme", "acme/finance"],
     "403 path_escapes_workspace"),
    (10.4, "peek", [JOB, "acme/legal/ani"], "403 path_escapes_workspace"),
]
SYMLINK = 5  # the request that is a symlink, drawn as a direct line next door

CAPTIONS = [
    (0, 2.6, "A job reads and writes inside its own sandbox."),
    (2.6, 6.2, "With inherit: true it also reads the files sitting directly in its parents."),
    (6.2, 12.2, "It cannot go sideways. A sibling, another team, a symlink that lands next door: refused."),
    (12.2, SECONDS, "Up for shared files. Never sideways."),
]


def travel(route, refused):
    """Seconds until a request stops: at its target, or half way down the last edge."""
    return max(0.3, LEG * (len(route) - 1) - (LEG / 2 if refused else 0))


def position(route, u):
    """Where a request is, u seconds after it left the job."""
    pts = [NODES[o][0] for o in route]
    i = min(int(u / LEG), len(pts) - 2)
    k = ease(min(1.0, (u - i * LEG) / LEG))
    (x0, y0), (x1, y1) = pts[i], pts[i + 1]
    return x0 + (x1 - x0) * k, y0 + (y1 - y0) * k


def frame(i: int) -> str:
    t = i / FPS
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">']
    s.append(f'<rect width="{W}" height="{H}" fill="{BASE}"/>')
    s.append(sans(W / 2, 56, "An owner is a path on disk", TEXT, 32, "middle", "bold"))
    s.append(sans(W / 2, 90,
                  "A job reaches its own sandbox, and up to its parents' shared files. "
                  f'<tspan fill="{GREEN}" font-weight="bold">Never sideways.</tspan>',
                  SUBT, 17, "middle"))

    # What has been decided so far. A verdict stays on screen once given.
    verdict = {}
    current = None
    for n, (start, path, route, code) in enumerate(REQUESTS):
        if t < start:
            continue
        current = n
        if t - start >= travel(route, code):
            verdict[route[-1]] = code

    s.append(rect(510, 132, 260, 36, LINE, "#232334", 1.5, 18))
    s.append(label(640, 155, "CORDON_ROOT/owners", SUBT, 13, "middle"))
    s.append(f'<line x1="640" y1="168" x2="640" y2="{235 - NODE_H / 2}" stroke="{LINE}" stroke-width="1.5"/>')
    for a, b in EDGES:
        (ax, ay), (bx, by) = NODES[a][0], NODES[b][0]
        s.append(f'<line x1="{ax}" y1="{ay + NODE_H / 2}" x2="{bx}" y2="{by - NODE_H / 2}" '
                 f'stroke="{LINE}" stroke-width="1.5"/>')

    for owner, ((cx, cy), fname) in NODES.items():
        colour = LINE
        if owner in verdict:
            colour = RED if verdict[owner] else GREEN
        x, y = cx - NODE_W / 2, cy - NODE_H / 2
        # A parent lends the file, not its sandbox, so only a refusal or the
        # job's own sandbox colours the whole box.
        edge = GREEN if owner == JOB else RED if colour == RED else LINE
        s.append(rect(x, y, NODE_W, NODE_H, edge, lw=1.5 if edge == LINE else 2.5, rx=12))
        s.append(label(cx, cy - 8, owner, TEXT, 15, "middle", weight="bold"))
        s.append(rect(cx - 80, cy + 4, 160, 24, colour, BASE, 1.5 if colour != LINE else 1, 6))
        s.append(label(cx, cy + 21, fname, SUBT if colour == LINE else colour, 12, "middle"))
    jx, jy = NODES[JOB][0]
    s.append(sans(jx, jy + NODE_H / 2 + 22, "the job runs here", GREEN, 14, "middle", "bold"))

    # The request in flight, and what the daemon said about it.
    if current is not None:
        start, path, route, code = REQUESTS[current]
        u = t - start
        done = u >= travel(route, code)
        if current == SYMLINK:
            (ax, ay), (bx, by) = NODES[route[0]][0], NODES[route[1]][0]
            x0, x1 = ax + NODE_W / 2, bx - NODE_W / 2
            s.append(f'<line x1="{x0}" y1="{ay}" x2="{x1}" y2="{by}" stroke="{RED}" '
                     f'stroke-width="2" stroke-dasharray="6 5"/>')
            if done:
                s.append(cross((x0 + x1) / 2, ay, RED, 0.9))
        elif len(route) > 1:
            px, py = position(route, min(u, travel(route, code)))
            if done and code:
                s.append(cross(px, py, RED, 0.9))
            elif not done:
                s.append(packet(px, py, TEXT, r=6))

        s.append(rect(770, 432, 450, 96, RED if done and code else GREEN if done else LINE,
                      "#232334", 2 if done else 1.5, 12))
        s.append(sans(790, 458, f"job owner {JOB}", SUBT, 13))
        s.append(sans(1200, 458, "inherit: true", SUBT, 13, "end"))
        what = "open peek, a symlink to ani's secret.md" if current == SYMLINK else f"open {path}"
        s.append(label(790, 486, what, TEXT, 15))
        if done:
            s.append(label(790, 512, code or "allowed", RED if code else GREEN, 14, weight="bold"))

    for start, end, text in CAPTIONS:
        k = fade(t, start, end, 0.25)
        if k:
            s.append(sans(W / 2, 590, text, TEXT, 18, "middle", opacity=k))
    s.append("</svg>")
    return "".join(s)


def main():
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/ownerframes")
    out.mkdir(parents=True, exist_ok=True)
    n = FPS * SECONDS
    for i in range(n):
        (out / f"f{i:04d}.svg").write_text(frame(i))
    print(f"{n} frames in {out}")


if __name__ == "__main__":
    main()
