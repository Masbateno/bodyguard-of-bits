"""v0.25.1 — the Slack text and the --watch line say when the score is a ceiling.

Both printed `engine.score` bare while the terminal, the report and every
format rendered `≤ N/10`, so a Slack channel read "Score: 8/10" for a run that
could not read sshd_config.
"""

from types import SimpleNamespace

from bob.scoring import score_out_of_ten
from bob.webhook import build_slack_payload


def _engine(bounded=False, uncertain=False):
    return SimpleNamespace(score=8, score_is_upper_bound=bounded, score_is_uncertain=uncertain,
                           score_span=(6, 9), alert_count=0, warn_count=0, findings=[],
                           effective_level=SimpleNamespace(value="low"))


def test_the_three_states():
    assert score_out_of_ten(_engine()) == "8/10"
    assert score_out_of_ten(_engine(bounded=True)) == "≤ 8/10"
    assert score_out_of_ten(_engine(uncertain=True)).startswith("~ 8/10")


def test_slack_shows_the_ceiling():
    payload = build_slack_payload(_engine(bounded=True), SimpleNamespace(hostname="h"), "0.25.1")
    assert "≤ 8/10" in payload["attachments"][0]["text"]
