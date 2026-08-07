#!/usr/bin/env python3
"""Generate calibration tracks for the automated offset finder.

Design goals (so the wizard never has to ASK for a BPM):
  * BPMs are exact divisors of SAMPLE_RATE*60 (= 2_646_000), so each beat is a
    whole number of samples — Rekordbox analyses them to the exact integer BPM
    and the on-deck tempo doesn't drift.
  * Each beat is a synthesized KICK DRUM (pitch-swept sine + a short noise
    transient), which Rekordbox's beat detector locks onto far more reliably
    than a bare sine click.
  * Unique BPM + unique duration + unique title (filename) per track = strong,
    unambiguous memory anchors.

No external tools needed — writes 16-bit mono WAV via the stdlib `wave` module.
Output: ./calibration/*.wav   (load track d on deck d)
"""

import math
import os
import random
import struct
import wave

SAMPLE_RATE = 44100
BEAT_UNIT = SAMPLE_RATE * 60  # 2_646_000; BPM must divide this for exact beats

# (title/filename stem, BPM, duration seconds). BPMs chosen to divide BEAT_UNIT.
TRACKS = [
    ("RKBXCAL_ONE_100", 100, 120),
    ("RKBXCAL_TWO_125", 125, 150),
    ("RKBXCAL_THREE_150", 150, 180),
    ("RKBXCAL_FOUR_175", 175, 210),
]

AMPLITUDE = 0.9


def kick(length: int) -> list:
    """One kick-drum hit: pitch-swept sine body + a short noise transient."""
    out = [0.0] * length
    phase = 0.0
    for i in range(length):
        t = i / SAMPLE_RATE
        # Pitch sweeps from ~160 Hz down to ~50 Hz (that "thump").
        freq = 50.0 + 110.0 * math.exp(-t / 0.018)
        phase += 2.0 * math.pi * freq / SAMPLE_RATE
        env = math.exp(-t / 0.05)
        s = env * math.sin(phase)
        # Attack transient (first ~1 ms of decaying noise) for a sharp onset.
        if i < 48:
            s += 0.6 * math.exp(-i / 10.0) * random.uniform(-1.0, 1.0)
        out[i] = s
    return out


def render(bpm: int, seconds: int) -> bytes:
    total = SAMPLE_RATE * seconds
    buf = bytearray(total * 2)
    assert BEAT_UNIT % bpm == 0, f"BPM {bpm} must divide {BEAT_UNIT}"
    spb = BEAT_UNIT // bpm  # samples per beat, exact integer
    hit = kick(int(0.20 * SAMPLE_RATE))

    beat = 0
    while True:
        start = beat * spb
        if start >= total:
            break
        for i, s in enumerate(hit):
            idx = start + i
            if idx >= total:
                break
            val = max(-32767, min(32767, int(s * AMPLITUDE * 32767)))
            struct.pack_into("<h", buf, idx * 2, val)
        beat += 1
    return bytes(buf)


def main() -> None:
    random.seed(1)  # reproducible transients
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "calibration"
    )
    os.makedirs(out_dir, exist_ok=True)
    for stem, bpm, seconds in TRACKS:
        path = os.path.join(out_dir, f"{stem}.wav")
        with wave.open(path, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(SAMPLE_RATE)
            w.writeframes(render(bpm, seconds))
        print(f"wrote {path}  ({bpm} BPM, {seconds}s, {BEAT_UNIT // bpm} samples/beat)")
    print("\nDone. Load track d on deck d and let Rekordbox analyse them.")


if __name__ == "__main__":
    main()
