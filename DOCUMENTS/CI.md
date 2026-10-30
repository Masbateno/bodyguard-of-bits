*[Lire en français](CI_FR.md)*

# BOB — CI/CD, from a push to a package on PyPI

What runs on GitHub when code is pushed or a release is tagged, with which
rights, what is pinned and what is not. Written for 0.28.2, after an audit of
the whole chain on 30 October 2026: the repository settings read through the
GitHub API, the three workflows read line by line, the code of each action read
at the commit it is pinned to, the logs of the 0.28.1 publication read, and
[zizmor](https://docs.zizmor.sh/) 1.31.1 run offline as a cross-check. Each
change was measured before it was made — in podman on every image of the
matrix, in a throwaway environment for the build, as a draft release for the
release step.

## The three workflows

| Workflow | Runs on | Jobs | Token |
|---|---|---|---|
| `tests.yml` | every push and pull request | `lint` (ruff over `bob/`), `build-backend-pin` (the setuptools pin must bite), `mutation` (every guard must still fail when its defect returns), `pytest` on Python 3.10 – 3.14 | read |
| `integration.yml` | a push to `main`, a pull request to `main`, by hand | `smoke` in a container of each distribution below, `arm64` under QEMU | read |
| `publish.yml` | a tag `X.Y.Z` | `test` (3.10 – 3.14) and `ci-green` → `build` → `publish` (PyPI) → `github-release` | read; `ci-green` reads Actions, `publish` asks `id-token: write`, `github-release` asks `contents: write` |

- **Rights**: each workflow says `contents: read`; only the two jobs above ask
  for more. The repository default is read as well.
- **Timeouts**: every job has one, 10 to 45 minutes — well above the longest
  run measured (10 minutes, for the mutations).
- **Concurrency**: a newer push to the same ref cancels the older `tests` and
  `integration` runs; two publications never run at once and none is
  cancelled.
- **Token on disk**: no checkout leaves it in `.git/config`
  (`persist-credentials: false`).
- **Scripts**: no `${{ … }}` expression is expanded inside a `run:` script;
  values reach the shell through the environment.
- **Failures**: none is hidden — no `continue-on-error`, no `|| true`. The one
  `if: failure()` uploads the audit log of a failed job; the `set +e` blocks
  capture an exit code that is checked on the next line.
- **Cache**: none. No workflow declares one, and the QEMU action's image cache
  is turned off (`cache-image: false`).

## The publication

A release is published by pushing a tag. Nothing else can publish.

1. **Tests**, on the five Python versions — and **CI green on the tagged
   commit** (`ci-green`): the `Tests` and `Integration` workflows must have
   passed on this very commit, pushed to `main`, or nothing is built. A red run
   stops the publication; a run still going is waited for (up to an hour); a
   commit never pushed to `main` is refused. What counts as passed: for each
   workflow, identified by its file, the most recent run of the exact tagged
   SHA pushed to `main`, in the state of its latest attempt, is `completed` and
   `success`. The job holds `actions: read` only. Measured with the GitHub API:
   0.28.1's commit green, a commit whose tests failed refused, a commit only on
   a Dependabot branch refused, a run that failed then passed on its second
   attempt listed as passed.
2. **Build**, on Python 3.12:
   - pip is installed from a wheel pinned by its SHA-256 (26.2.2, the first
     pip that no longer trusts the eMudhra / emSign authorities), and the job
     refuses an older one;
   - the tag must be a bare `MAJOR.MINOR.PATCH` equal to the version in
     `pyproject.toml`, or nothing is built — **this** is the strict check of
     the tag;
   - the build tools come from `requirements-ci.txt`, each pinned by version
     and SHA-256 (`pip install --require-hashes`);
   - `python -m build` installs its backend in an isolated environment: that
     environment receives `requirements-build.txt` (setuptools pinned by
     SHA-256) through `PIP_CONSTRAINT`. The `build-backend-pin` job of
     `tests.yml` proves on every push that the constraint bites: the same
     build with the hashes replaced — and nothing else, which the job checks —
     must fail, and fail on the hash check.
3. **PyPI**, through Trusted Publishing (OIDC): no PyPI token exists.
   - The job runs in the `release` environment, which waits for the
     maintainer's approval (administrators cannot bypass it). Its tag filter,
     `[0-9]*.[0-9]*.[0-9]*`, is a glob, not a regular expression: it also lets
     `1x.2.3y` through. It is a coarse first gate; the strict one is step 2.
   - The upload action is pinned by commit, but what runs is the container it
     starts, `ghcr.io/pypa/gh-action-pypi-publish:<commit>`, which the action
     pulls **by tag** — read in the action's code at that commit, and in the
     0.28.1 log ("Unable to find image … locally", then the pull). That
     container holds the OIDC token. A step pulls it first **by digest** and
     gives it the name the action asks for, so the action finds it and pulls
     nothing; a test keeps that name equal to the commit the action is
     pinned to. The step fails if the local image is not that digest, and a
     step after the upload checks it again: had the action pulled the tag
     anew, the name would point elsewhere.
   - Each file gets a PEP 740 attestation naming this repository,
     `publish.yml` and the `release` environment (checked on 0.28.1). It says
     who built and published the file — not that the code is sound or that
     the tests were enough.
   - `skip-existing` is kept on purpose: if one of the two files was uploaded
     and the job failed on the other, a re-run completes the publication
     instead of failing on the file already there. PyPI never lets a file be
     replaced.
4. **GitHub Release**, by GitHub's own CLI on the runner
   (`gh release create … --verify-tag`), in place of a third-party action
   that held `contents: write`: the title is the bold lead of the
   `CHANGELOG.md` row, the notes the version's section of
   `DOCUMENTS/CHANGELOG_FULL.md`, the built files attached. Before the change
   the same command made a draft release with the 0.28.1 title, the 0.28.1
   notes byte for byte and both files (then deleted). Before it, a step
   compares the SHA-256 of each file to attach with the digests PyPI lists for
   the version (waiting up to ten minutes for PyPI to list it): the release
   carries the files PyPI has, or is not made — measured on 0.28.1, a byte
   appended to the sdist was refused. It runs after PyPI. If
   it fails, **never rebuild**: re-run the failed job — it downloads the same
   `dist` artifact the upload used (kept 90 days; its digest is checked on
   download, as the 0.28.1 log shows) — or attach the files downloaded from
   PyPI, whose SHA-256 PyPI lists.

Each action is pinned by commit, its version written beside it. On
30 October 2026 each pinned commit was checked against the tag of that version
in the action's own repository: all six matched — none is a commit from
elsewhere wearing a version's name. Dependabot proposes the updates, once a
release is a week old.

## Repository settings (read on 30 October 2026)

| Setting | Value |
|---|---|
| Default token rights | read; workflows cannot approve pull requests |
| Actions | pinning by commit required (`sha_pinning_required`) |
| Pull requests from forks | first-time contributors need approval to run workflows |
| `main` | no force-push, no deletion (ruleset) |
| Release tags (`X.Y.Z`, legacy `v*`) | never deleted, never moved (ruleset) |
| `release` environment | maintainer's approval, no administrator bypass, tag glob `[0-9]*.[0-9]*.[0-9]*` |
| Secrets | none stored |
| Secret scanning, push protection | on |
| Dependabot vulnerability alerts | on — they cover the tools pinned in `requirements-*.txt` |

## Pull requests and other people's code

- `tests.yml` and `integration.yml` run on `pull_request`, never
  `pull_request_target`: a pull request runs with a read-only token and no
  secret, on a runner GitHub throws away after the job. A first-time
  contributor's run waits for approval.
- Publishing needs a tag; a fork cannot push one here.
- The arm64 job runs privileged containers: only the QEMU image
  (`tonistiigi/binfmt`, pinned by digest) runs with `--privileged`, to
  register the emulator in the runner's kernel — read in the action's code.
  The code under test runs in a separate `docker run` without privileges.

## The distributions CI runs

Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04, Fedora 44, openSUSE Leap 16,
Alpine 3.24, Kali Rolling, and Debian 12 on arm64 under QEMU. In each, pip
26.2.2 is installed into a fresh venv by hash (the distribution's own pip can be
older — openSUSE Leap 16's was 26.1.2), setuptools is installed by hash, and BOB
is built against it into a wheel; then an offline audit and a plugin through the
sandbox. The job fails on an exit code above 3, a locale key printed raw, or a
Python traceback. The steps call the venv by its absolute path, never through
`GITHUB_PATH`: the runner builds a container step's `PATH` from the one the
image declares, and `opensuse/leap:16.0` declares none — with the venv added,
the next step could not find `sh` (found on the first 0.28.2 push).

The rule: only releases still supported — the LTS or stable line where the
distribution has one (Ubuntu, Debian, openSUSE Leap), the Tier 1 release where
it has none (Fedora, Alpine). Each image's end of support is recorded in
`tests/test_v0282_ci_hardening.py`; past that date the suite fails until the
image is replaced. Kali Rolling has no end date: it carries the date it was
last run through every step instead (30 October 2026), and the suite fails
six months after it until the review is done again. 0.28.2 replaced
Ubuntu 25.04 (ended 17 January 2026) and Fedora 41 (15 December 2025), and
added Alpine and openSUSE; each image was run through every step in podman
first, arm64 included.

## What is not covered

- **The images CI tests on** are taken by tag (`debian:13`, `alpine:3.24`…),
  not by digest. This is a choice, not an oversight: a tag follows each
  distribution's security updates, a digest would freeze them; the price is
  that two runs on different days may not use the same image. These are the
  9 findings zizmor still reports — static-analysis findings, not
  vulnerabilities. The QEMU image, which runs privileged, and the upload
  container, which holds the PyPI token, are pinned by digest.
- **The runner itself** — its image (`ubuntu-latest`), its Python, its system
  — is GitHub's; the pins fix the backend and the tools, not the whole
  environment.
- **The actions' own dependencies**: pinning an action by commit fixes its
  code; an image or a tool the action fetches at run time is fixed only where
  this repository does it (the QEMU image, the upload container).
- **Dependabot** proposes action updates, not updates of the pinned Python
  tools: those are regenerated with `scripts/gen_ci_requirements.py`, and a
  vulnerability in one of them raises an alert.
- **`main` has no required status check**: a commit reaches `main` before its
  CI runs (the project is kept on one branch). A *publication*, though, is
  held: `ci-green` refuses a tag whose commit is not green.
- **The repository settings** are not readable by the workflow token (they
  need administrator rights): they are checked by
  `scripts/check_repo_settings.py`, run with the maintainer's `gh` login
  before a push that leads to a release, not by CI.

## Keeping it so

- Regenerate the pinned tools: `python3 scripts/gen_ci_requirements.py`
  (writes `requirements-ci.txt` and `requirements-build.txt` from the
  versions listed in the script).
- An action update arrives as a Dependabot pull request; it keeps the pin by
  commit. For `pypa/gh-action-pypi-publish`, the test fails until the
  pre-pull step names the new commit; its digest is then read from ghcr.io
  for that tag (the test checks the commit, not the digest).
- Replace a distribution before its end of support, and record the new date
  in the test; run Kali through every step every six months and update its
  date.
- Before a push that leads to a release: `python3 scripts/check_repo_settings.py`
  (13 settings, read through the API; it says which one changed).

The guards: `tests/test_v0270_release_chain_pins.py`,
`tests/test_v0281_build_backend_pinned.py`,
`tests/test_v0282_ci_hardening.py`, `tests/test_v0280_ci_apt_step.py` — each
with mutations that bring its defect back.

---
© 2026 Cédric Clauzel
