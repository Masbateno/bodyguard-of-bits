"""`--install-completion` prints translated text, not bracketed locale keys.

Found while validating BOB on the Raspberry Pi Zero W: running
``sudo bob --install-completion`` printed::

    ✔ [completion.installed]
    ✔ [completion.symlink_created]
    ⚠  [completion.reload_title]

The ``[key]`` form is what ``i18n.t`` returns when i18n has not been
initialised. Every other action branch in ``__main__`` calls
``i18n.init(lang=config.lang)`` before printing; the ``--install-completion``
branch did not, so both its needs-root error and ``install_completion()``'s own
output fell back to raw keys — in either locale. The keys existed all along; the
init was missing.

This drives the non-root branch (patched ``geteuid`` so it is deterministic and
needs no root), which prints through the same uninitialised path.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest

from bob.__main__ import main


def _run(argv):
    import io
    from contextlib import redirect_stderr, redirect_stdout

    import bob.i18n as i18n

    # Reproduce a fresh process: i18n uninitialised. Otherwise a prior test
    # left it initialised, `t()` returns real text regardless, and the missing
    # init in the branch under test goes unnoticed (the bug only shows in a
    # cold process, which is how the operator hit it).
    i18n._initialized = False
    i18n._translations = {}
    with patch("bob.__main__.os.geteuid", return_value=1000):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(argv)
    return rc, out.getvalue() + err.getvalue()


def test_english_output_has_no_bracketed_keys():
    rc, text = _run(["--install-completion"])
    assert rc != 0                                   # non-root → error exit
    assert not re.search(r"\[completion\.[a-z_]+\]", text), text
    assert "requires root" in text                   # the real EN string


def test_french_output_has_no_bracketed_keys():
    rc, text = _run(["--install-completion", "--french"])
    assert rc != 0
    assert not re.search(r"\[completion\.[a-z_]+\]", text), text
    assert "droits root" in text                     # the real FR string


def test_the_message_names_the_pipx_path_cause():
    """The needs-root message is the one an operator actually needs: it says
    plainly why `sudo bob` fails (restricted PATH, no pipx binaries)."""
    _rc, text = _run(["--install-completion"])
    assert "PATH" in text and "pipx" in text
