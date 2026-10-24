"""Draw the night-sakura scene on the sign-in page as four SVG layers.

    python tools/make_sakura.py

writes into trustvault/static/img/:
    sakura-trunk.svg    trunk and branches (textured bark, red-orange rim glow)
    sakura-bloom-a.svg  about 60% of the blossom clumps
    sakura-bloom-b.svg  the rest, so the two can sway out of step
    sakura-ground.svg   grassy hill, glowing flowers and mushrooms, fallen
                        petals and mist; it does not move

Everything is generated (recursive branches, fixed random seed), so it is our
own artwork and comes out the same every run. The files are plain images (no
scripts, no <style>), so the Content-Security-Policy stays strict, and CSS can
move them without the browser redrawing them. The script prints the numbers
the CSS needs to line the layers up.
"""
import math
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "trustvault" / "static" / "img"
rng = random.Random(2026)

MAX_DEPTH = 8
BLOSSOM = ["#f6d5df", "#efbfcd", "#e6a6ba", "#da8ea7", "#cc7a96"]  # dusty pinks
SHADE = ["#7d3348", "#94405a", "#a9506c"]                          # undersides
MASS = ["#b8607e", "#c76f8c", "#a8546f"]                           # soft fill between clumps
HIGHLIGHT = "#fff3f6"
# Thin branches by thickness: darker inside the crown, glowing at the twigs.
TWIG = [(3, "#b2413a"), (1.6, "#c9554a"), (0, "#de6f6a")]

limbs = []     # thick limbs: filled tapered shapes
twigs = []     # (width, path) thin branches: strokes
clusters = []  # each a list of (tier, x, y, r, colour, opacity); tier 0 shade, 1 bloom, 2 highlight


def quad_point(p0, c, p1, t):
    return ((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * c[0] + t ** 2 * p1[0],
            (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * c[1] + t ** 2 * p1[1])


def tapered(p0, c, p1, w0, w1, steps=10):
    """A quadratic curve as a filled shape that narrows from w0 to w1."""
    left, right = [], []
    for i in range(steps + 1):
        t = i / steps
        px, py = quad_point(p0, c, p1, t)
        dx = 2 * (1 - t) * (c[0] - p0[0]) + 2 * t * (p1[0] - c[0])
        dy = 2 * (1 - t) * (c[1] - p0[1]) + 2 * t * (p1[1] - c[1])
        norm = math.hypot(dx, dy) or 1
        half = (w0 + (w1 - w0) * t) / 2
        left.append((px - dy / norm * half, py + dx / norm * half))
        right.append((px + dy / norm * half, py - dx / norm * half))
    return "M" + "L".join(f"{x:.1f} {y:.1f}" for x, y in left + right[::-1]) + "Z"


def branch(x, y, angle, length, width, depth):
    """One curved branch, then 2-3 thinner ones from its end.
    angle is in degrees from straight up (negative leans left)."""
    rad = math.radians(angle)
    end = (x + length * math.sin(rad), y - length * math.cos(rad))
    bend = rng.uniform(-0.25, 0.25) * length
    ctrl = ((x + end[0]) / 2 + bend * math.cos(rad), (y + end[1]) / 2 + bend * math.sin(rad))
    if width > 3.2:
        limbs.append(tapered((x, y), ctrl, end, width, width * 0.72))
    else:
        twigs.append((width, f"M{x:.0f} {y:.0f}Q{ctrl[0]:.0f} {ctrl[1]:.0f} {end[0]:.0f} {end[1]:.0f}"))

    if depth >= MAX_DEPTH or length < 10:
        blossom(*end, rng.randint(10, 15), 19)
        return
    if depth >= 4 and rng.random() < 0.6:
        blossom(*end, rng.randint(3, 6), 13)

    count = 2 if depth < 2 else rng.choice([2, 2, 3])
    for i in range(count):
        side = -1 if i == 0 else (1 if i == count - 1 else rng.choice([-0.3, 0.3]))
        new_angle = angle + side * rng.uniform(16, 34) + rng.uniform(-7, 7)
        # Upper branches spread outwards into the wide umbrella crown of a
        # cherry tree. Slight lean to the left, as if the wind blows right to left.
        if abs(new_angle) > 8:
            new_angle += math.copysign(depth * 2.4, new_angle)
        new_angle -= 1.5
        branch(*end, new_angle, length * rng.uniform(0.7, 0.82), width * 0.66, depth + 1)


def blossom(x, y, count, spread):
    """A clump of blossom: soft masses for fullness, darker shade underneath,
    pink on top, a few highlights."""
    clump = []
    for _ in range(2):
        clump.append((0, x + rng.gauss(0, spread * 0.4), y + rng.gauss(0, spread * 0.3),
                      rng.uniform(7, 13), rng.choice(MASS), 0.45))
    for _ in range(max(2, count // 3)):
        clump.append((0, x + rng.gauss(0, spread * 0.5), y + abs(rng.gauss(0, spread * 0.3)) + 4,
                      rng.uniform(3, 6), rng.choice(SHADE), 0.6))
    for _ in range(count):
        clump.append((1, x + rng.gauss(0, spread * 0.45), y + rng.gauss(0, spread * 0.32),
                      rng.uniform(1.4, 3.8), rng.choice(BLOSSOM), rng.choice([0.7, 0.85, 1])))
    for _ in range(rng.choice([0, 0, 1, 2])):
        clump.append((2, x + rng.gauss(0, spread * 0.3), y - abs(rng.gauss(0, spread * 0.25)),
                      rng.uniform(0.9, 1.6), HIGHLIGHT, 0.95))
    clusters.append(clump)


# ---- the tree ---------------------------------------------------------------
BASE_X, BASE_Y = 470, 880
FORK = (BASE_X - 6, BASE_Y - 230)
MID = (BASE_X + 16, BASE_Y - 118)
# The trunk: an S-curve in two tapered pieces, a second stem twisting round it,
# and a flared foot.
limbs.append(tapered((BASE_X, BASE_Y + 6), (BASE_X - 14, BASE_Y - 60), MID, 64, 38))
limbs.append(tapered(MID, (BASE_X + 34, BASE_Y - 178), FORK, 38, 24))
limbs.append(tapered((BASE_X - 18, BASE_Y + 2), (BASE_X + 40, BASE_Y - 90), (FORK[0] - 10, FORK[1] + 14), 16, 9))
limbs.append(tapered((BASE_X + 22, BASE_Y + 4), (BASE_X + 6, BASE_Y - 40), (BASE_X - 8, BASE_Y - 150), 12, 5))
branch(*FORK, -10, 150, 20, 1)
branch(*FORK, 26, 135, 17, 2)

# One viewBox for the tree layers, fitted round the crown.
xs = [c[1] for cl in clusters for c in cl]
ys = [c[2] for cl in clusters for c in cl]
PAD = 40
MIN_X, MAX_X = min(xs) - PAD, max(xs) + PAD
MIN_Y, MAX_Y = min(ys) - PAD, BASE_Y + 30
TREE_W, TREE_H = MAX_X - MIN_X, MAX_Y - MIN_Y


def svg(box, w, h, body, defs=""):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{box}" width="{w:.0f}" '
            f'height="{h:.0f}"><defs>{defs}</defs>{body}</svg>\n')


TREE_BOX = f"{MIN_X:.0f} {MIN_Y:.0f} {TREE_W:.0f} {TREE_H:.0f}"

GLOW = ('<filter id="glow" x="-20%" y="-20%" width="140%" height="140%">'
        '<feGaussianBlur stdDeviation="{s}" result="blur"/>'
        '<feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>')

# Bark: noise roughens the edges and adds vertical streaks; a blurred copy
# tinted red-orange behind it is the rim glow.
BARK_FILTER = (
    '<filter id="bark" x="-10%" y="-10%" width="120%" height="120%">'
    '<feTurbulence type="fractalNoise" baseFrequency="0.7 0.04" numOctaves="2" seed="3" result="n"/>'
    '<feDisplacementMap in="SourceGraphic" in2="n" scale="2.2" xChannelSelector="R" yChannelSelector="G" result="rough"/>'
    '<feColorMatrix in="n" type="matrix" values="0 0 0 0 .1  0 0 0 0 .02  0 0 0 0 .03  0 0 0 2 -1.05" result="streaks"/>'
    '<feComposite in="streaks" in2="rough" operator="in" result="texture"/>'
    '<feGaussianBlur in="rough" stdDeviation="6" result="blur"/>'
    '<feFlood flood-color="#ff5a3a" flood-opacity=".6"/>'
    '<feComposite in2="blur" operator="in" result="rim"/>'
    '<feMerge><feMergeNode in="rim"/><feMergeNode in="rough"/><feMergeNode in="texture"/></feMerge></filter>'
)
BARK_GRADIENT = (
    f'<linearGradient id="wood" gradientUnits="userSpaceOnUse" x1="0" y1="{BASE_Y}" x2="0" y2="{FORK[1] - 260}">'
    '<stop offset="0" stop-color="#3a0f12"/><stop offset=".45" stop-color="#7d2622"/>'
    '<stop offset="1" stop-color="#c2443a"/></linearGradient>'
)
twig_groups = ""
for i, (min_w, colour) in enumerate(TWIG):
    max_w = TWIG[i - 1][0] if i else 99
    paths = "".join(f'<path d="{d}" stroke-width="{w:.1f}"/>' for w, d in twigs if min_w <= w < max_w)
    twig_groups += f'<g stroke="{colour}">{paths}</g>'
limb_paths = "".join(f'<path d="{d}"/>' for d in limbs)
trunk = svg(
    TREE_BOX, TREE_W, TREE_H,
    f'<g fill="none" stroke-linecap="round" filter="url(#glow)">{twig_groups}</g>'
    f'<g fill="url(#wood)" filter="url(#bark)">{limb_paths}</g>',
    BARK_FILTER + BARK_GRADIENT + GLOW.format(s=2),
)
(OUT / "sakura-trunk.svg").write_text(trunk, encoding="utf-8")

# Blossoms: whole clumps go to one layer or the other, so each clump moves as
# one piece. Circles are grouped by tier, colour and opacity: shade is drawn
# first, highlights last, and each circle only needs its position and size.
layers = {"a": [], "b": []}
for clump in clusters:
    layers["a" if rng.random() < 0.6 else "b"].append(clump)
for name, group in layers.items():
    by_style = {}
    for clump in group:
        for tier, x, y, r, colour, opacity in clump:
            by_style.setdefault((tier, colour, opacity), []).append(
                f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r:.1f}"/>')
    dots = "".join(f'<g fill="{c}" opacity="{o}">{"".join(items)}</g>'
                   for (_, c, o), items in sorted(by_style.items()))
    (OUT / f"sakura-bloom-{name}.svg").write_text(
        svg(TREE_BOX, TREE_W, TREE_H, f'<g filter="url(#glow)">{dots}</g>', GLOW.format(s=2.6)),
        encoding="utf-8")

# ---- the ground -------------------------------------------------------------
# A wide strip: far to the left (behind the sign-in card, fading out) and a
# little to the right of the tree.
G_X0, G_X1 = BASE_X - 1500, BASE_X + 640
G_Y0, G_Y1 = BASE_Y - 70, MAX_Y
G_W, G_H = G_X1 - G_X0, G_Y1 - G_Y0


def hill_top(x):
    """Height of the hill: a low mound under the tree on a gentle slope."""
    mound = 24 * math.exp(-((x - BASE_X) / 300) ** 2)
    slope = (x - G_X0) / G_W * 14
    return BASE_Y + 2 - mound - slope + 3 * math.sin(x / 47) + 2 * math.sin(x / 13)


def lit(x):
    """How much of the tree's glow falls here: 1 at the trunk, 0 far away."""
    return math.exp(-((x - BASE_X) / 380) ** 2)


steps = 120
top = [(G_X0 + G_W * i / steps, hill_top(G_X0 + G_W * i / steps)) for i in range(steps + 1)]
hill = "M" + "L".join(f"{x:.0f} {y:.1f}" for x, y in top) + f"L{G_X1} {G_Y1}L{G_X0} {G_Y1}Z"

# Grass blades along the top of the hill, lit pink near the tree.
GRASS = ["#1c0a0f", "#3a1219", "#6e2430", "#b8475a"]
grass = {b: [] for b in range(len(GRASS))}
for _ in range(900):
    x = rng.uniform(G_X0, G_X1) if rng.random() < 0.55 else rng.gauss(BASE_X, 260)
    if not G_X0 < x < G_X1:
        continue
    y = hill_top(x) + rng.uniform(0, 8)
    h = rng.uniform(5, 18) * (0.6 + 0.6 * lit(x))
    lean = rng.uniform(-5, 3)
    bucket = max(0, min(3, int(lit(x) * 4 + rng.uniform(-0.4, 0.4))))
    grass[bucket].append(f"M{x:.0f} {y:.0f}q{lean / 2:.0f} {-h / 2:.0f} {lean:.0f} {-h:.0f}")
grass_svg = "".join(
    f'<path d="{"".join(paths)}" stroke="{GRASS[b]}" stroke-width="1.3" fill="none" stroke-linecap="round"/>'
    for b, paths in grass.items() if paths
)

fallen = "".join(
    f'<ellipse cx="{x:.0f}" cy="{hill_top(x) + rng.uniform(-1, 10):.0f}" rx="{rng.uniform(1.4, 3.2):.1f}" '
    f'ry="{rng.uniform(0.8, 1.6):.1f}" fill="{rng.choice(BLOSSOM)}" opacity="{0.35 + 0.6 * lit(x):.2f}"/>'
    for x in (rng.gauss(BASE_X - 40, 230) for _ in range(320)) if G_X0 < x < G_X1
)
# Tiny glowing flowers and mushrooms near the roots.
flowers = "".join(
    f'<circle cx="{x:.0f}" cy="{hill_top(x) - rng.uniform(2, 14):.0f}" r="{rng.uniform(0.9, 2.2):.1f}"/>'
    for x in (rng.gauss(BASE_X - 60, 260) for _ in range(110)) if G_X0 < x < G_X1
)
mushrooms = ""
for _ in range(11):
    x = BASE_X + rng.choice([-1, 1]) * rng.uniform(40, 260)
    y = hill_top(x) + 2
    h, w = rng.uniform(5, 11), rng.uniform(4, 8)
    mushrooms += (f'<rect x="{x - 1:.0f}" y="{y - h:.0f}" width="2" height="{h:.0f}" rx="1"/>'
                  f'<ellipse cx="{x:.0f}" cy="{y - h:.0f}" rx="{w:.1f}" ry="{w * 0.55:.1f}"/>')

ground_defs = (
    GLOW.format(s=2.2)
    + '<filter id="mist" x="-30%" y="-100%" width="160%" height="300%"><feGaussianBlur stdDeviation="14"/></filter>'
    + '<linearGradient id="earth" x1="0" y1="0" x2="0" y2="1">'
      '<stop offset="0" stop-color="#2a0e15"/><stop offset="1" stop-color="#07040a"/></linearGradient>'
    # A pool of pink light on the ground under the tree (a squashed circle).
    + f'<radialGradient id="pool" cx="{BASE_X}" cy="{BASE_Y}" r="380" gradientUnits="userSpaceOnUse" '
      f'gradientTransform="matrix(1 0 0 .22 0 {BASE_Y * 0.78:.0f})">'
      '<stop offset="0" stop-color="#ff7d8c" stop-opacity=".75"/>'
      '<stop offset=".5" stop-color="#c2405a" stop-opacity=".25"/>'
      '<stop offset="1" stop-color="#c2405a" stop-opacity="0"/></radialGradient>'
    # Fade the far-left end of the strip into the background.
    + f'<linearGradient id="fadeout" gradientUnits="userSpaceOnUse" x1="{G_X0}" y1="0" x2="{G_X0 + 900}" y2="0">'
      '<stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset="1" stop-color="#fff"/></linearGradient>'
    + f'<mask id="fade"><rect x="{G_X0}" y="{G_Y0}" width="{G_W}" height="{G_H}" fill="url(#fadeout)"/></mask>'
)
ground = svg(
    f"{G_X0} {G_Y0} {G_W} {G_H}", G_W, G_H,
    f'<g mask="url(#fade)">'
    f'<ellipse cx="{BASE_X - 60}" cy="{BASE_Y - 26}" rx="420" ry="34" fill="#ff8aa0" opacity=".16" filter="url(#mist)"/>'
    f'<path d="{hill}" fill="url(#earth)"/>'
    f'<path d="{hill}" fill="url(#pool)"/>'
    f'{grass_svg}{fallen}'
    f'<g filter="url(#glow)"><g fill="#ffe9ef" opacity=".9">{flowers}</g>'
    f'<g fill="#f7dbe3" opacity=".85">{mushrooms}</g></g>'
    f'<ellipse cx="{BASE_X}" cy="{BASE_Y - 4}" rx="140" ry="16" fill="#ff9aac" opacity=".22" filter="url(#mist)"/>'
    f'</g>',
    ground_defs,
)
(OUT / "sakura-ground.svg").write_text(ground, encoding="utf-8")


# ---- numbers for the CSS ----------------------------------------------------
def pct(value, start, size):
    return f"{100 * (value - start) / size:.1f}%"


print(f"tree aspect-ratio: {TREE_W / TREE_H:.3f}")
print(f"trunk pivot (transform-origin): {pct(BASE_X, MIN_X, TREE_W)} 100%")
print(f"blossom pivot: {pct(FORK[0], MIN_X, TREE_W)} {pct(FORK[1], MIN_Y, TREE_H)}")
print(f"ground box: left {pct(G_X0, MIN_X, TREE_W)}  width {100 * G_W / TREE_W:.1f}%  "
      f"top {pct(G_Y0, MIN_Y, TREE_H)}  height {100 * G_H / TREE_H:.1f}%")
print(f"{len(limbs)} limbs, {len(twigs)} twigs, {sum(len(c) for c in clusters)} blossom dots")
for f in sorted(OUT.glob("sakura-*.svg")):
    print(f"  {f.name}: {f.stat().st_size // 1024} KB")
