"""v0.42.0 — a test that runs the CLI does not leave the screen silent behind it.

Measured while assembling 0.42.0: ``test_v0180``'s end-to-end ``--diff`` run
left ``bob.output._quiet`` True (and colours off), and three screen tests of
``test_v0270_port_scans`` captured an empty output when run after it — on the
0.41.0 tree too; the suite's file order had hidden it. ``conftest`` restores
the module's state around every test. The two tests below run in file order:
the first leaves the module quiet, the second must not inherit it.
"""

from __future__ import annotations


def test_a_test_that_silences_the_output():
    from bob import output
    output.init(quiet=True)
    assert output._quiet is True


def test_the_next_one_starts_with_it_restored(capsys):
    from bob import output
    assert output._quiet is False
    output._p("visible")
    assert "visible" in capsys.readouterr().out
