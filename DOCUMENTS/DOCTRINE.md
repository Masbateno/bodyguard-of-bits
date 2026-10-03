<p align="center">
  <img src="https://raw.githubusercontent.com/Masbateno/bodyguard-of-bits/main/assets/logo_bob.png" alt="BOB — Bodyguard Of Bits" width="180">
</p>

*[Lire en français](DOCTRINE_FR.md)*

# BOB — Doctrine

This is the *why*. [`CONVENTIONS.md`](CONVENTIONS.md) is the *how* (colours, symbols,
the Snapshot/check pattern, localisation, SemVer); this document is the set of values
those conventions serve. When a design decision is unclear, it is resolved here, not
by taste. Two parts: what BOB **asserts** (the audit philosophy), and how the project
is **built and proven** (the engineering doctrine).

---

## Part I — What BOB asserts

### 1. Assert only the measurable

BOB states facts it has read, never facts it has inferred from silence. "SSH root
login is permitted" is said only when a parsed `sshd_config` says so — never because
a file was unreadable and a compiled-in default was assumed. Hide nothing, assume
nothing, claim nothing you did not measure. Every other principle below is a
consequence of this one.

### 2. unknown ≠ clean

The absence of a reading is not a pass. A verifier that is not installed, a config
that could not be read, a command that timed out — each produces an explicit
*"not verified"*, never a green verdict. BOB fails **closed**: when it cannot
establish safety, it says the question is open. Manufacturing "clean" out of
"could not look" is the single worst thing an auditor can do, because it is the one
error the operator cannot see.

### 3. The three sorting questions

Before adding or keeping any check, finding or deduction, answer:

1. **Is it measurable?** Can BOB read the fact directly, or is it inferring?
2. **Is it actionable?** Can the operator do something specific about it?
3. **Is it honest about uncertainty?** Does it distinguish "safe", "unsafe" and
   "could not tell" — or does it collapse the third into one of the first two?

A check that fails any of the three is reworked or dropped.

### 4. Non-dogmatic, profile-aware

BOB is a hardening audit, not a CIS box-ticking machine. A control that is right for
an internet-facing server is wrong for a laptop or a container, so findings are
gated on the active profile (`server` / `desktop` / `workstation` / `container`):
full-disk encryption is WARN on a bare-rooted desktop but INFO on a server whose
threat model is a locked rack; PAM account lockout is WARN on a server, INFO on a
desktop where the lockout-vs-DoS trade-off differs. BOB never penalises a
legitimate configuration just because a checklist names it.

### 5. Reported, not scored, when the signal is ambiguous

A fact can be real and still ambiguous. A packaged binary that differs from its
digest may be an intrusion or a local recompile; an un-blacklisted kernel module is
a hardening opportunity, not a vulnerability. These are emitted **INFO-only**: BOB
surfaces them and leaves the judgement to the operator, rather than inventing a
deduction it cannot defend. Deductions are reserved for facts with an unambiguous
direction.

### 6. Never over-affirm, never over-prescribe

Saying *more* than the measurement supports is as dishonest as hiding it. BOB does
not announce "no firewall" on a host whose nftables ruleset is filtering, and it
does not demand one specific tool (`ufw`) when `firewalld` or a plain netfilter
ruleset would do. The remediation it offers is the one that fits *this* host's
distribution — half a remedy (a Debian command handed to a Fedora operator) is no
remedy.

### 7. The score is an upper bound

The score reflects what BOB could **see**. When a check is blinded — a file it
cannot read, a section that fails — the score does not rise to fill the gap; the
uncertainty is carried into the result (`score_is_upper_bound`), and blinding a
check can *lower* the score, never raise it. A high score on a half-read system is
a lie BOB refuses to tell.

### 8. A reproducible, launch-independent verdict

Audit the system's *configured* state, not the ambient state of the shell BOB
happened to run in. Root's PATH is read from `login.defs` and sudoers, not from the
inherited `os.environ`; command output is parsed under `LC_ALL=C` so a verdict does
not hinge on the operator's locale. The same host in the same state yields the same
verdict, whoever launched it and how — a result that changes with the environment is
not a measurement of the host.

### 9. BOB does not change the system behind the operator's back

For anything risky or hard to reverse — PAM stacks, `fstab`, disk encryption,
a world-writable set-id root binary — BOB **describes** the fix and never applies
it. Native auto-apply (`--fix --apply`) is reserved for changes that are safe,
reversible and verifiable, and it never claims a success it did not confirm. A
compromise symptom is something to investigate before flipping a bit, not a bit to
flip.

### 10. BOB does not phone home

A security tool that exfiltrates is a contradiction. BOB runs with **no telemetry
and no outbound traffic** by default; the only network calls it ever makes are a
public-IP lookup and, if the operator configured one, a result webhook — both
suppressed by `--offline`, which is a hard global guarantee the air-gapped build
sandboxes rely on. What BOB reads about the host stays on the host, in the operator's
own report directory.

### 11. A noisy check is worse than no check

Every false positive spends the operator's trust, and trust is the only thing that
makes an audit worth running. A check that cries wolf on legitimate configurations
is removed or narrowed until its signal is clean — one aggregated finding rather
than twelve, the narrow unambiguous case rather than the broad noisy one.

### 12. Honest framing

BOB audits **hardening posture**, not threats. It does not model adversaries,
predict attacks or score "risk" in the actuarial sense. It reports what is
exposed, what is unverified and what is misconfigured against a hardening baseline,
and it says so in those terms.

---

## Part II — How the project is built and proven

### 13. A guard must test what it claims, and a mutation must prove it

Every behavioural guarantee is pinned by a test, and every test is pinned by a
**mutation**: a deliberate break of the code the test watches. If the mutation
survives, the test does not test what it claims — a green run proves nothing on its
own. Adding a guard means adding its mutation (`scripts/mutate.py`). A guard that
passes against a broken-but-masked code path (a filter shadowed by another filter,
a check that bypasses the real render) is rewritten until the mutation bites.

### 14. The probes lie; the field is the oracle

A reasoning about what a system *should* report is not evidence of what BOB *does*
report. Behaviour is proven on real machines — real distributions, real init
systems, real firewalls — with **polarity pairs** (forge the bad state → detect it
→ restore → confirm it clears), tool by tool, including hostile inputs (a FIFO
where a config file is expected must never hang the audit). A local bench under the
same conditions is worth as much as the instance; a synthetic unit test is not.

### 15. Measure before you fix, fix narrowly, replay

An `exit 0` is not proof of a fix. Detect broadly (find every instance of a class),
repair narrowly (change only what the evidence demands), then replay against the
condition that revealed it — in a container round-trip where possible: apply, re-audit,
watch the finding disappear. A static scan that lists 180 candidates and zero
priorities is worth less than a hostile bench that finds the two that matter.

### 16. Low gain × non-zero risk = STOP

A refactor that changes no verdict, closes no real gap and carries any risk is not
done. Conservatism is the default for a tool whose whole value is that its output
can be trusted. When a change's benefit is small and its blast radius is not, it
waits for a reason.

### 17. A bounded command, and a timeout that kills the group

Every subprocess runs under a finite timeout. A deliberately slow verifier
(`rpm -Va`) runs in its own process group so that when the deadline passes, the
**whole group** is killed — not just the parent, leaving orphaned work behind.
BOB never hangs an operator's cron.

### 18. Say what changed, honestly

A changelog never claims "no behaviour change" flatly when an output moves. It
names the invariants that held (score formula, JSON schema, CSV column order,
detection rules) *and* the outputs that changed, in the operator's terms. A
BREAKING change is labelled BREAKING even on a patch-shaped diff.

### 19. Judge advice; follow no oracle

External advice — from another AI, a reviewer, a benchmark — is weighed on its
merits, point by point, accepted or rejected with a stated reason. Nothing is
adopted because of its source. A checklist that names a control BOB already ships,
or recommends a check that would be noise, is declined and the reasoning kept.

### 20. The documentation is audited like the code

Every countable claim in the docs (key counts, section counts, locale totals) is
pinned by a guard, because a frozen number is a lie waiting to happen. Documentation
accuracy follows the same rule as the audit itself (principle 1): assert only the
measurable, and let a machine catch the drift.

### 21. References come from an authority, not from memory

A CIS or benchmark number BOB prints is generated from its upstream source
(ComplianceAsCode) by the rule's name, never hand-typed from recollection. Citing a
standard is itself a claim, and principle 1 applies to it: the reference must trace
back to something checkable, not to a plausible-looking number.

### 22. The last step before an irreversible one is a stop

Publishing to PyPI cannot be undone. Before any irreversible release step, BOB's
maintainer stops, verifies, and acts only on an explicit go. The release is proven
(full suite green, every mutation killed, `ruff` clean, version consistent
everywhere) *before* the tag, not after.

---

© 2026 Cédric Clauzel
