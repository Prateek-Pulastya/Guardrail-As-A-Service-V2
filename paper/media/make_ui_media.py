"""
Render media of the GuardRail playground's "how it was screened" animation.

The browser preview pane in this environment does not reliably composite frames
for screen capture, so instead of a screen recording this renders the same UI,
frame by frame, from REAL trace data pulled from the live /explain endpoint
(paper/media/traces.json). The layout, palette and staged reveal match
static/index.html.

Outputs into paper/media/:
  screening.gif          animated leetspeak block (staged reveal -> verdict)
  shot_*.png             final-state still for each scenario

Regenerate the trace data by POSTing to /explain, then:
    python paper/media/make_ui_media.py
"""

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
TRACES = json.loads((HERE / "traces.json").read_text(encoding="utf-8"))

W = 720
SCALE = 2  # supersample for crisp text, downscaled at save

# palette (from static/index.html :root)
BG = (13, 17, 23); BG2 = (22, 27, 34); BG3 = (33, 38, 45)
EDGE = (48, 54, 61); EDGE2 = (61, 68, 77)
FG = (230, 237, 243); MUTED = (145, 152, 161); DIM = (110, 118, 129)
BLUE = (68, 147, 248); GREEN = (63, 185, 80); RED = (248, 81, 73); AMBER = (210, 153, 34)
HL_BG = (74, 30, 30); HL_FG = (255, 196, 192)
AMBER_BG = (35, 28, 12)


def font(size, bold=False, mono=False):
    size *= SCALE
    names = (["consola.ttf"] if mono else
             (["segoeuib.ttf", "arialbd.ttf"] if bold else ["segoeui.ttf", "arial.ttf"]))
    for n in names:
        try:
            return ImageFont.truetype(n, size)
        except OSError:
            continue
    return ImageFont.load_default(size)


F_H1 = font(20, bold=True); F_BADGE = font(10, mono=True)
F_SUB = font(11); F_LAB = font(9, bold=True); F_STEPLAB = font(9)
F_MONO = font(11, mono=True); F_MONO_S = font(10, mono=True)
F_STATUS = font(16, bold=True); F_BY = font(9, mono=True)
F_WHY = font(10); F_NUM = font(9, bold=True, mono=True)
F_CARDH = font(9, bold=True); F_CARDV = font(13, mono=True); F_NOTE = font(8)


def px(v):
    return int(v * SCALE)


def rrect(d, box, fill, outline=None, width=1, radius=8):
    d.rounded_rectangle([px(box[0]), px(box[1]), px(box[2]), px(box[3])],
                        radius=px(radius), fill=fill, outline=outline,
                        width=px(width) if outline else 0)


def text(d, xy, s, fnt, fill):
    d.text((px(xy[0]), px(xy[1])), s, font=fnt, fill=fill)


def mark(d, cx, cy, r, kind, color):
    """Draw a crisp cross or check centered at (cx, cy); glyph fonts lack these."""
    w = max(SCALE, int(1.6 * SCALE))
    cx, cy, r = px(cx), px(cy), px(r)
    if kind == "cross":
        d.line([cx - r, cy - r, cx + r, cy + r], fill=color, width=w)
        d.line([cx - r, cy + r, cx + r, cy - r], fill=color, width=w)
    else:  # check
        d.line([cx - r, cy, cx - r * 0.3, cy + r], fill=color, width=w)
        d.line([cx - r * 0.3, cy + r, cx + r, cy - r], fill=color, width=w)


def wrap(d, s, fnt, max_w):
    words, lines, cur = s.split(" "), [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if d.textlength(trial, font=fnt) <= px(max_w):
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def mono_trunc(d, s, fnt, max_w):
    if d.textlength(s, font=fnt) <= px(max_w):
        return s
    while s and d.textlength(s + "…", font=fnt) > px(max_w):
        s = s[:-1]
    return s + "…"


def draw_frame(trace_obj, n_steps, show_verdict, height):
    """Render one frame. n_steps = how many trace steps are revealed."""
    img = Image.new("RGB", (px(W), px(height)), BG)
    d = ImageDraw.Draw(img)
    t = trace_obj["trace"]
    steps = t["steps"]
    blocked = t["blocked"]
    match_idx = (next((i for i, s in enumerate(steps)
                       if s["text"] == t["matched_text"]), -1) if blocked else -1)

    pad = 22
    # ── header
    text(d, (pad, 20), "GuardRail", F_H1, FG)
    bw = d.textlength("two-tier prompt-injection detection", font=F_BADGE) / SCALE + 18
    rrect(d, (pad + 118, 24, pad + 118 + bw, 42), None, EDGE, 1, radius=999)
    text(d, (pad + 127, 27), "two-tier prompt-injection detection", F_BADGE, MUTED)

    # ── prompt echo card
    y = 58
    rrect(d, (pad, y, W - pad, y + 60), BG2, EDGE, 1, radius=10)
    text(d, (pad + 14, y + 11), "PROMPT", F_LAB, MUTED)
    src = trace_obj.get("_source") or t.get("source", "user")
    tag = "  source: " + src
    tw = d.textlength(tag.strip(), font=F_BADGE) / SCALE + 16
    rrect(d, (W - pad - 14 - tw, y + 8, W - pad - 14, y + 26), BG3, EDGE2, 1, radius=6)
    text(d, (W - pad - 14 - tw + 8, y + 11), tag.strip(), F_BADGE, MUTED)
    raw = steps[0]["text"].replace("\n", " \\n ")
    text(d, (pad + 14, y + 32), mono_trunc(d, raw, F_MONO, W - 2 * pad - 28), F_MONO, FG)

    # ── trace panel
    ty = y + 78
    text(d, (pad + 2, ty), "HOW IT WAS SCREENED", F_LAB, MUTED)
    ty += 22
    for i in range(min(n_steps, len(steps))):
        s = steps[i]
        is_match = (i == match_idx)
        # number bubble
        bx = pad + 2
        bub = RED if is_match else BG3
        d.ellipse([px(bx), px(ty), px(bx + 20), px(ty + 20)],
                  fill=bub, outline=(RED if is_match else EDGE2), width=SCALE)
        if is_match:
            mark(d, bx + 10, ty + 10, 4, "cross", (255, 255, 255))
        else:
            num = str(i + 1)
            nw = d.textlength(num, font=F_NUM) / SCALE
            text(d, (bx + 10 - nw / 2, ty + 4), num, F_NUM, MUTED)
        # label + text
        text(d, (bx + 32, ty - 1), s["label"], F_STEPLAB, DIM)
        txt = s["text"].replace("\n", " \\n ")
        tx = bx + 32
        tyy = ty + 13
        if is_match and t["match_start"] is not None:
            a, b = t["match_start"], t["match_end"]
            pre, mid, post = txt[:a], txt[a:b], txt[b:]
            cx = tx
            for seg, hl in ((pre, False), (mid, True), (post, False)):
                if not seg:
                    continue
                seg = seg.replace("\n", " ")
                wpx = d.textlength(seg, font=F_MONO) / SCALE
                if hl:
                    d.rounded_rectangle([px(cx - 2), px(tyy - 1), px(cx + wpx + 2),
                                        px(tyy + 15)], radius=px(3), fill=HL_BG,
                                        outline=RED, width=SCALE)
                    text(d, (cx, tyy), seg, F_MONO, HL_FG)
                else:
                    text(d, (cx, tyy), seg, F_MONO, FG)
                cx += wpx + (4 if hl else 0)
        else:
            col = MUTED if (blocked and match_idx >= 0 and i > match_idx) else FG
            text(d, (tx, tyy), mono_trunc(d, txt, F_MONO, W - tx - pad - 6), F_MONO, col)
        ty += 34
        if i < min(n_steps, len(steps)) - 1:
            d.line([px(bx + 10), px(ty - 12), px(bx + 10), px(ty - 6)], fill=EDGE2, width=SCALE)

    # ── verdict
    if show_verdict:
        vy = ty + 4
        allowed = trace_obj["allowed"]
        accent = GREEN if allowed else RED
        band = (16, 26, 18) if allowed else (32, 17, 16)
        d.rectangle([px(pad), px(vy), px(W - pad), px(vy + 46)], fill=band)
        d.line([px(pad), px(vy), px(W - pad), px(vy)], fill=EDGE, width=SCALE)
        cy = vy + 15
        d.ellipse([px(pad + 6), px(cy), px(pad + 18), px(cy + 12)], fill=accent)
        text(d, (pad + 28, vy + 12), "ALLOWED" if allowed else "BLOCKED", F_STATUS, accent)
        by = ("blocked_by: " + trace_obj["blocked_by"]) if trace_obj["blocked_by"] else "cascade: allowed"
        byw = d.textlength(by, font=F_BY) / SCALE
        text(d, (W - pad - 14 - byw, vy + 16), by, F_BY, MUTED)
        vy += 54
        # why line
        if t["reason"]:
            lab = {"blocklist": "blocklist term", "regex": "structural pattern",
                   "data_instruction": "instruction-in-data pattern"}.get(t["match_type"], t["match_type"])
            reason = str(t["reason"])
            if len(reason) > 46:
                reason = reason[:45] + "…"
            text(d, (pad, vy), lab + " matched in the " + t["matched_in"] + " text:",
                 F_WHY, MUTED)
            vy += 16
            rw = d.textlength(reason, font=F_MONO_S) / SCALE
            rrect(d, (pad, vy - 1, pad + rw + 12, vy + 15), BG3, radius=5)
            text(d, (pad + 6, vy), reason, F_MONO_S, FG)
            vy += 24
        else:
            t2 = trace_obj["tier2_score"]
            msg = "No rule matched. Tier 1 let it through"
            if t2 is not None:
                msg += ", Tier 2 scored it %.3f." % t2
            for ln in wrap(d, msg, F_WHY, W - 2 * pad):
                text(d, (pad, vy), ln, F_WHY, MUTED)
                vy += 15
            vy += 6
        # monitor flag
        if trace_obj.get("tier2_monitor_flag"):
            fh = 40
            rrect(d, (pad, vy, W - pad, vy + fh), AMBER_BG, (90, 66, 20), 1, radius=8)
            msg = ("Tier 2 scored this %.3f (injection) but is monitor-only, so it was "
                   "allowed. As a blocker it flags 40%% of benign prompts." % trace_obj["tier2_score"])
            yy = vy + 8
            for ln in wrap(d, msg, F_NOTE, W - 2 * pad - 20):
                text(d, (pad + 11, yy), ln, F_NOTE, (227, 179, 65))
                yy += 12
            vy += fh + 8
        # tier cards
        cw = (W - 2 * pad - 12) / 2
        t1_fired = trace_obj["blocked_by"] == "tier1"
        t2 = trace_obj["tier2_score"]
        for ci, (title, dotcol, val, unit, note) in enumerate([
            ("Tier 1 · rules", RED if t1_fired else GREEN,
             ("cross" if t1_fired else "check"),
             "matched" if t1_fired else "passed", None),
            ("Tier 2 · classifier",
             (DIM if t2 is None else (AMBER if trace_obj.get("tier2_monitor_flag") else GREEN)),
             ("—" if t2 is None else "%.3f" % t2),
             ("" if t2 is None else "score"),
             ("not reached (Tier 1 decided)" if t2 is None
              else ("flagged, monitor-only" if trace_obj.get("tier2_monitor_flag")
                    else "below 0.75 threshold"))),
        ]):
            cx = pad + ci * (cw + 12)
            rrect(d, (cx, vy, cx + cw, vy + 58), BG, EDGE, 1, radius=8)
            d.ellipse([px(cx + 12), px(vy + 14), px(cx + 20), px(vy + 22)], fill=dotcol)
            text(d, (cx + 28, vy + 12), title, F_CARDH, MUTED)
            if val in ("cross", "check"):
                mark(d, cx + 18, vy + 36, 6, val, dotcol)
                text(d, (cx + 30, vy + 30), unit, F_NOTE, DIM)
            else:
                text(d, (cx + 12, vy + 28), val, F_CARDV, FG)
                vw = d.textlength(val, font=F_CARDV) / SCALE
                if unit:
                    text(d, (cx + 12 + vw + 5, vy + 33), unit, F_NOTE, DIM)
            if note:
                text(d, (cx + 12, vy + 46), note, F_NOTE, DIM)

    return img.resize((W, height), Image.LANCZOS)


def case_height(trace_obj, full=True):
    n = len(trace_obj["trace"]["steps"])
    h = 58 + 78 + 22 + n * 34 + 20
    if full:
        h += 54
        if trace_obj["trace"]["reason"]:
            h += 40
        else:
            h += 34
        if trace_obj.get("tier2_monitor_flag"):
            h += 48
        h += 66
    return int(h)


def main():
    by_title = {c["_title"]: c for c in TRACES}

    # ── GIF: leetspeak block, staged reveal
    leet = by_title["leetspeak attack"]
    leet["_source"] = "user"
    H = case_height(leet, full=True)
    frames, durations = [], []
    n = len(leet["trace"]["steps"])
    # steps appearing
    for k in range(1, n + 1):
        frames.append(draw_frame(leet, k, False, H))
        durations.append(430)
    # verdict
    frames.append(draw_frame(leet, n, True, H))
    durations.append(2400)
    # short hold on first frame at loop start
    frames.insert(0, draw_frame(leet, 1, False, H))
    durations.insert(0, 650)

    gif = HERE / "screening.gif"
    frames[0].save(gif, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print(f"wrote {gif}  ({gif.stat().st_size/1024:.0f} KB, {len(frames)} frames)")

    # ── stills: final state of each case
    slug = {"leetspeak attack": "leetspeak_block",
            "benign correction": "benign_monitor_flag",
            "unmarked injection (data)": "instruction_in_data_block",
            "benign question": "benign_allow"}
    for c in TRACES:
        c.setdefault("_source", c["trace"].get("source", "user"))
        H = case_height(c, full=True)
        img = draw_frame(c, len(c["trace"]["steps"]), True, H)
        out = HERE / ("shot_" + slug[c["_title"]] + ".png")
        img.save(out)
        print(f"wrote {out.name}  ({img.size[0]}x{img.size[1]})")


if __name__ == "__main__":
    main()
