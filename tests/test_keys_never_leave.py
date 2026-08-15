"""
Keys-never-leave guardrail.

A 2026-08-15 security audit found two real, confirmed instances of
secret material reaching a log on this air-gapped signing device:
seed.py logging repr(e) on an invalid mnemonic (the underlying
ValueError embeds the mistyped word), and decode_qr.py logging a
QR's full raw content before classifying whether it was seed
material. Both were fixed by hand; this test mechanizes the check
so a future regression of the same class fails CI instead of
needing another manual audit to catch it.

What it catches -- the dominant developer-mistake class:
  A logger.<level>(...) or print(...) call whose arguments mention a
  secret-named identifier (mnemonic / seed_bytes / seed_phrase /
  passphrase / seed_words / private_key / xprv). This is the
  "I added a debug log with the wrong variable" leak -- exactly how
  both real findings above happened.

What it does NOT catch -- documented gaps, not silent ones:
  - Destination(..., view_args=dict(...)) carrying a raw secret
    string rather than a wrapped Seed object. Destination.__repr__
    (views/view.py) renders view_args faithfully, and Controller
    logs every destination transition -- so a future call site that
    passes view_args=dict(mnemonic=raw_list) instead of
    view_args=dict(seed=seed_obj) would silently start writing
    plaintext to the log. This is real (the 2026-08-15 audit flagged
    it as "structurally fragile") but distinguishing "a Seed object
    happens to be named seed" from "a raw mnemonic string" by static
    analysis alone is not reliable enough to enforce without heavy
    false positives -- it needs eyes on the diff at review time, the
    same way the audit caught it.
  - repr(e)/str(e) on an exception whose OWN message embeds secret
    material (finding A's actual shape) -- this regex catches the
    logging call, not what the exception itself contains. A future
    "log the error, but the error's message happens to contain the
    mnemonic" bug would need the same manual read this audit did.
  - Indirect leaks: logger.info(seed) where seed is a Seed object
    with no __str__/__repr__ override today, but would leak
    silently if one were ever added. Covers the by-name case only.

The check is a heuristic, deliberately tuned for low false
positives -- it matches logging/print calls that literally mention a
secret-named token on the same line, not every line that mentions one.
"""
import os
import re


HERE = os.path.dirname(os.path.abspath(__file__))
SRC_ROOT = os.path.join(HERE, "..", "src", "seedsigner")

# Identifiers that name secret material this device must never log.
SECRET_NAMES = [
    "mnemonic",
    "seed_bytes",
    "seed_phrase",
    "seed_words",
    "passphrase",
    "private_key",
    "privkey",
    "xprv",
]
SECRET_GROUP = "(?:" + "|".join(SECRET_NAMES) + ")"

# logger.<level>( ... <secret> ... ) or print( ... <secret> ... ),
# bounded so the match can't span statements.
LOG_LEAK = re.compile(
    r"(?:logger\s*\.\s*(?:debug|info|warning|warn|error|exception|critical)|print)\s*\([^)]*?\b"
    + SECRET_GROUP
    + r"\b",
    re.IGNORECASE,
)

# Files/lines that are allowed to mention a secret name in a logging
# call because they deliberately log ONLY a type/length/boolean, never
# the value itself -- the exact pattern this audit's own fixes use.
# Matched by an inline marker comment so the allowlist lives next to
# the code it exempts, not in a list here that silently drifts.
ALLOW_MARKER = "keys-never-leave: safe, logs shape not value"


def iter_source_files():
    for dirpath, _dirnames, filenames in os.walk(SRC_ROOT):
        for name in filenames:
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def scan_file(path):
    findings = []
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    for i, line in enumerate(lines, start=1):
        if ALLOW_MARKER in line:
            continue
        if LOG_LEAK.search(line):
            findings.append((path, i, line.strip()))
    return findings


def test_no_source_file_logs_a_secret_named_value():
    findings = []
    for path in iter_source_files():
        findings.extend(scan_file(path))

    rel_findings = [
        (os.path.relpath(p, SRC_ROOT), line_no, text) for p, line_no, text in findings
    ]

    assert rel_findings == [], (
        "Keys-never-leave violation -- a logging or print call mentions a "
        "secret-named value (mnemonic / seed_bytes / seed_phrase / "
        "seed_words / passphrase / private_key / privkey / xprv) on the "
        "same line. This device never logs secret material -- log the "
        "type/length/boolean instead of the value, or mark the line safe "
        "with a trailing '# " + ALLOW_MARKER + "' comment if it genuinely "
        "only logs shape, not content.\n"
        + "\n".join(f"  - {p}:{n}: {t}" for p, n, t in rel_findings)
    )
