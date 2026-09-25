*[Lire en français](CONVENTIONS_FR.md)*

# BOB — Conventions

How this project does things, in one place: what a colour means, what a symbol
means, and the code patterns a check must follow.

Everything here was true when it was written, and most of it is now checked.
That distinction matters: this project has twice found a convention that lived
in three modules which happened to agree — the curses colour chart shared its
cyan between the cursor row and the banner for nine releases because nothing
compared them. A rule that can be checked mechanically has a guard named beside
it; a rule that cannot says so.

---

## 1. Colour — terminal output

Sixteen ANSI colours are defined in `bob/output.py`; fourteen carry meaning.
The table is the authority, and no module builds an escape sequence itself.

| Colour | Means |
|---|---|
| green | an OK finding, a score that rose |
| yellow | a warning, a score that fell, a target that cannot be verified |
| red | an alert |
| cyan | information, a recurrence marker |
| `dim` | secondary detail: CIS codes, hints, the prose around a command |
| **`violet_bold`** | **material to reproduce exactly** — a command to run, or a directive to write |
| `orange` | a `[ profile ]` heading in `--explain` |
| `blue_bold` | the border of a summary box |
| `bold` | a box title, a section heading |
| `yellow_bold` | a heading inside the fix screen |

**Violet is the one that carries information rather than mood.** It marks what
must be reproduced exactly — *do not paraphrase this, copy it* — whether that
is a command to run or a line to write into a config file. A flag *named* in
prose is neither: "the run was narrowed by `--check` / `--skip`" describes what
happened and offers nothing to transcribe. Colouring every `--flag` in the
locale would make violet stop signalling anything.

**Why it is not "a runnable command".** That was the first wording, and
`server signing = mandatory` in a `HOW TO FIX` block is not a command. Narrowing
violet to commands is neither reliable nor useful. Not reliable: 37 of those
lines are `sudo nano <file>  →  <directive>` — a command and a directive on one
line, which no per-line colour can separate — and classifying the rest took a
sixty-binary regex that still left 16% unsorted. A rule needing such a list is
a heuristic, and it drifts the first time a check uses a binary nobody listed.
Not useful: from the operator's side both say the same thing, and the prose
above already says whether to run it or write it — *"Edit /etc/samba/smb.conf →
In the `[global]` section set:"*.

One honest cost: a handful of lines pair a command with its expected output
(`ls -la <key_path>  →  -rw------- owner owner`), so the expected output is
violet too. It is still material to compare literally.

**A mention is not the canonical place to copy from.** *"Run `sudo fwupdmgr
update` to apply pending firmware updates"* is a sentence, and the same command
sits a line away as the finding's `cmd`, where it is violet. Colouring both
would make the colour ambient. Violet marks the one place to copy from — the
start of a line, or what follows the `→` / `ℹ` / `?` that introduces it.

A command spliced into a sentence goes through `output.command()`, and the
sentence itself is a locale template with a `{cmd}` placeholder — never a
string with the command baked in, which cannot be coloured without colouring
the prose.

**Asking whether colour is on has one answer.** `_c` holds empty strings when
colour is off, so `f"{_c.red}…{_c.reset}"` is already correct in both states.
Do not consult `_no_color` — that was a second way to ask the same question,
and `print_help` used it while everything else used the first.

*Guarded:* every declared colour is consumed · a command hint is a template ·
`output.command` paints violet · `print_dim` re-establishes dim after an
embedded reset.

---

## 2. Colour — curses screens

Nine pairs, defined once in `bob/tui/_palette.py`. **Do not call `init_pair`
outside that module** — a guard rejects it, and it exists because three screens
once initialised the same chart independently and agreed, which is how the
cursor row and the banner shared a background unnoticed.

| Pair | Role |
|---|---|
| `SELECTION` | the row under the cursor — black on orange |
| `ACCENT` | group headers, prompts |
| `NORMAL` | ordinary rows |
| `NOTICE` | per-screen: red for a warning list, cyan for `--explain`'s detail heading |
| `BANNER` | the top title bar — white on cyan |
| `PROFILE` | a `[ profile ]` heading |
| `FOOTER` | the bottom key banner — white on orange |
| `CONTEXT` | the line above it, for prompts and status — white on black |
| `VERBATIM` | material to reproduce exactly — violet, as in the text output |

**The two surfaces agree on meaning.** Orange marks the thing under attention
(the cursor row, the key banner); violet marks what must be reproduced exactly,
on both sides. `VERBATIM` was added in v0.16.4 because the convention stopped
at the curses boundary for no reason anyone had stated: the same lines that
were violet in `bob --explain` read as ordinary prose inside the wizard.

Inside a `HOW TO FIX` block, indentation is what marks the material — 664
indented lines against 527 numbered steps and 74 notes, consistent across all
explain keys. Painting a whole block violet was tried and emptied the colour of
meaning: two thirds of a block is prose.

Both orange and violet fall back to the nearest 8-colour approximation rather
than disappearing, and every pair degrades to an attribute (`A_REVERSE`,
`A_BOLD`, `A_UNDERLINE`) on a terminal without colour at all.

*Guarded:* no `init_pair` outside `_palette.py` · the cursor row and the banner
never share a background · a marked row reads red on every screen.

---

## 3. Symbols

| Symbol | Means |
|---|---|
| `✔` | an OK result, an applied fix |
| `✖` | an alert, a refusal, a fix that was not applied |
| `⚠` | a warning |
| `ℹ` | information — and, before a command, that it only *diagnoses* |
| `→` | before a command, that it *changes state* |
| `•` | an item in a list the operator must handle themselves |

`→` and `ℹ` before a command are the visible half of `cmd_type`: `fix` draws
`→`, `check` draws `ℹ`. That field also decides whether `--fix --apply` may run
the command at all, so the symbol and the behaviour come from one place.

---

## 4. Boxes and rules

Two styles, one rule:

* **double `╔═╗`** — a summary box: a top-level result. `print_titled_box`,
  `print_summary_box`, the fix screen's header.
* **single `┌─┐`** — a section header: structure within a run. `print_section`.

Modules that *parse* saved reports recognise both, which is not a style choice.

---

## 5. Text that reaches a terminal

`Finding.__post_init__` strips ANSI escapes and control characters from
`message`, `detail`, `note` and `cmd`. **Do not sanitise finding text
yourself** — that is the chokepoint, and it is why a process name from `ss`
cannot carry an escape sequence into a root-run audit's output.

Data that reaches the terminal *outside* a Finding — a hostname, a domain, a
container name — goes through `output.sanitize()` at the point it is read. There
are several such places and they are the fragile ones: a new one added without it
is a terminal-escape vector that no test would notice.

---

## 6. Width

Help output is capped at 100 **visible** columns. Escape sequences are zero
columns wide and must be stripped before measuring — `\x1b[1m…\x1b[0m` is eight
characters `len()` counts and a terminal does not.

---

## 7. Code conventions

### Snapshot / check pattern

Each check module strictly follows this pattern:

```python
@dataclass
class XxxSnapshot:
    # Raw data collected from the system
    field_a: str
    field_b: int

    @classmethod
    def from_system(cls) -> "XxxSnapshot":
        # Subprocess calls here — ONLY here
        data = _run("command", "arg")
        return cls(field_a=data, field_b=0)


def check_xxx(snapshot: XxxSnapshot, t=None) -> CheckResult:
    # Pure logic — NEVER any subprocess calls here
    _t = t if t is not None else _identity_t
    result = CheckResult()
    # ...
    return result
```

**Absolute rule:** `check_xxx()` never calls subprocess. All data collection is in `from_system()`.

**Since v0.14.1 — three rules that follow from the fault barrier:**

1. **Register the collector, not the snapshot.** `runner._sec` takes
   `XxxSnapshot.from_system` (a callable), never `XxxSnapshot.from_system()`
   (an already-built object). The collector is invoked *inside* the barrier,
   so a failure there degrades the section instead of aborting the audit — and
   a section excluded by `--check` / `--skip` / the profile costs nothing.
   Passing a pre-built snapshot silently moves the collection outside the
   barrier; `tests/test_v0141_robustness.py` fails the build if any call site
   does. (`hardening_snapshot` is the one documented exception — it also feeds
   `ChecksResult` for the `--json-full` sysctl block.)

2. **Read files through `bob._atomic.read_text_capped()`**, not `read_text()`.
   It refuses anything that is not a regular file (device, FIFO, directory) and
   caps the read, and it declares `errors="replace"` so a non-UTF-8 byte in a
   system file degrades instead of raising. A bare `read_text()` inside an
   `except OSError` block is rejected by an AST guard over the whole package.

3. **Do not sanitise finding text yourself.** `Finding.__post_init__()`
   strips ANSI escapes and control characters from `message` / `detail` /
   `note` (and from `cmd`, preserving newlines) at the single point every
   finding passes through. Interpolate system-derived values directly.

A check that raises is no longer fatal, but it is not free either: the section
is reported as a `<section>.unavailable` INFO finding and listed in the JSON
`degraded_sections`. Degrading gracefully inside the check is still better than
relying on the barrier.

### CheckResult

```python
result = CheckResult()

result.ok(message=_t("key"))                          # ✔ finding
result.warn(message=_t("key"), nature="improvement")  # ⚠ finding
result.alert(message=_t("key"), nature="action",      # ✖ finding
             cmd="sudo ufw ...")
result.info(message=_t("key"))                        # ℹ finding

result.add_deduction(
    reason=_t("key"),
    points=2,
    context="local",   # or "public"
)
```

### Finding natures

| Nature | Meaning | Summary block |
|---|---|---|
| `"action"` | Correction required | *Action required* |
| `"improvement"` | Possible improvement | *Possible improvements* |
| `"structural"` | Normal but notable configuration | *Normal configuration* |
| `None` | Purely informational | Not shown in summary |

### Translation function

Always pass `t` as a parameter with an identity fallback:

```python
def check_xxx(snapshot, t=None) -> CheckResult:
    _t = t if t is not None else _identity_t
```

This allows testing without initialising i18n:

```python
result = check_firewall(make_status())          # raw keys in messages
result = check_firewall(make_status(), t=my_t)  # custom translation
```

### Subprocess

Always via the `_run()` helper local to each module:

```python
def _run(*args: str) -> str:
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=10,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
```

Never let a subprocess exception propagate.

### Tests

Each check module has a corresponding test file. Tests:

- Make no system calls
- Build snapshots directly
- Test pure logic in `check_xxx()`
- Test parsing helpers separately

Typical structure:

```python
def make_snapshot(**overrides) -> XxxSnapshot:
    defaults = dict(field_a="default", field_b=0)
    defaults.update(overrides)
    return XxxSnapshot(**defaults)

def test_nominal_case():
    snap = make_snapshot(field_a="value")
    result = check_xxx(snap)
    assert "ok" in [f.level.value for f in result.findings]
```

---

## 8. Versioning

Versions are **SemVer** `MAJOR.MINOR.PATCH` with **no `v` prefix** — in code, in
git tags, and in everything BOB displays. The canonical version lives in
`bob/__init__.py` (`__version__`) and `pyproject.toml`; PyPI and SemVer both call
it `0.21.0`, so the banner, `--version`, the report/markdown header, the webhook
and the TUI title bar print `0.21.0`, never `v0.21.0`. Third-party tool versions
(ufw, firewalld) are shown the same way — bare.

A release is a git tag named for the version with **no prefix** (`0.21.0`, not
`v0.21.0`); the publish workflow triggers on it. The legacy `v*` form is kept in
the trigger only so the last v-tagged release (`v0.20.5`) still publishes — every
tag from v0.21.0 on carries no `v`. `tests/test_v0210_semver_no_v_prefix.py` pins
the display surfaces and `tests/test_doc_version_consistency.py` the badges.

**Is the `--version` text a stable contract?** No. The version *string* is a
display surface, not part of BOB's compatibility contract. It changed exactly
once — the `v` was dropped in 0.21.0 — and is now fixed as the bare SemVer core.
The stable CLI contract is: exit codes, the JSON schema (`schema_version` and its
keys), option names, and finding keys — those do not change without a MAJOR/MINOR
bump and a changelog note. A script that parsed `bob --version` and hard-coded the
`v` (or `sed 's/^v//'`) must read the bare form from 0.21.0 on; scripts that need a
machine-stable version should read `--format json` (`schema_version`) rather than
scrape human output. This is called out so the de-`v` is a one-time, documented
decision, not an open precedent for churning the version text.

---

© 2026 Cédric Clauzel
