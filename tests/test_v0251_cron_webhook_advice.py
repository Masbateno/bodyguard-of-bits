"""v0.25.1 — the cron wizard's webhook advice reaches the job it is about.

A scheduled audit runs as root and reads /root/.config/bob/config.conf. Under
sudo, `bob --webhook=URL` saves the URL in the invoking user's configuration
(get_user_home follows SUDO_USER), so "set a webhook with bob --webhook=URL
(as root)" pointed the operator at a file the job never reads, and
"check it with bob --test-webhook" tested the user's URL, not root's.
"""

import json
from pathlib import Path

_LOC = Path(__file__).resolve().parent.parent / "bob" / "locales"


def _ic(lang):
    return json.loads((_LOC / f"{lang}.json").read_text(encoding="utf-8"))["install_cron"]


def test_the_advice_points_at_the_job_script_not_at_sudo_bob_webhook():
    for lang in ("en", "fr"):
        ic = _ic(lang)
        for key in ("mta_missing", "reports_nobody"):
            assert "--webhook URL" in ic[key] and "/usr/local/bin/bob-" in ic[key], (lang, key)
            assert "(as root)" not in ic[key] and "(en root)" not in ic[key], (lang, key)


def test_the_webhook_check_names_the_url_it_tests():
    for lang in ("en", "fr"):
        assert "--test-webhook --webhook=URL" in _ic(lang)["reports_webhook"], lang
