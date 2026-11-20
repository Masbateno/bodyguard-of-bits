"""
Unit tests for _manage_email_store() in bob.cron.

The function loops until the user quits (Enter / 'q').
Every test that performs an action must therefore end its input sequence
with "" so the loop exits cleanly after the action is verified.

Run with: python -m pytest tests/test_email_store_mgmt.py -v
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

from bob.cron import _manage_email_store
from bob.config import EmailStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store(tmp_path, addresses=None):
    """Create a real EmailStore backed by a temp file."""
    path = tmp_path / "emails"
    store = EmailStore(path=path)
    store._ensure_dir = lambda: None
    if addresses:
        for addr in addresses:
            store._emails.append(addr)
        store._save()
    return store


def _t(key, **kwargs):
    """Minimal translator stub."""
    messages = {
        "manage_cron.email_store_title":        "EMAIL ADDRESS BOOK",
        "manage_cron.email_store_empty":         "No email address saved yet.",
        "manage_cron.email_store_prompt":        "Number/range/all/a/Enter",
        "manage_cron.email_store_enter":         "New email address",
        "manage_cron.email_store_invalid_email": "Invalid email address",
        "manage_cron.email_store_added":         "Address added: {email}".format(**kwargs) if "email" in kwargs else "Address added",
        "manage_cron.email_store_removed":       "Address deleted: {email}".format(**kwargs) if "email" in kwargs else "Address deleted",
        "manage_cron.email_store_cleared":       "All addresses deleted ({count})".format(**kwargs) if "count" in kwargs else "All addresses deleted",
        "manage_cron.email_store_invalid_sel":   "Invalid selection",
        "manage_cron.invalid":                   "Unrecognised choice",
    }
    if key in messages:
        return messages[key]
    # v0.39.0 — the shared selection and confirmation texts, in English.
    from bob import i18n
    i18n.init("en")
    return i18n.t(key, **kwargs)


# ---------------------------------------------------------------------------
# TestEmailStoreQuit — Enter / q quit without changes
# ---------------------------------------------------------------------------

class TestEmailStoreQuit:
    def test_enter_quits(self, tmp_path):
        store = _make_store(tmp_path, ["a@example.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=[""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == ["a@example.com"]

    def test_q_quits(self, tmp_path):
        store = _make_store(tmp_path, ["a@example.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["q"]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == ["a@example.com"]

    def test_empty_store_shows_info(self, tmp_path, capsys):
        store = _make_store(tmp_path)
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=[""]):
            _manage_email_store(_t)
        out = capsys.readouterr().out
        assert "No email address saved" in out


# ---------------------------------------------------------------------------
# TestEmailStoreAdd — 'a' command
# ---------------------------------------------------------------------------

class TestEmailStoreAdd:
    def test_add_valid_email(self, tmp_path):
        store = _make_store(tmp_path)
        # "a" → enters address → loop redisplays → "" quits
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["a", "new@example.com", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert "new@example.com" in store.all()

    def test_add_invalid_email_rejected(self, tmp_path, capsys):
        store = _make_store(tmp_path)
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["a", "notanemail", ""]):
            _manage_email_store(_t)
        assert store.all() == []
        out = capsys.readouterr().out
        assert "Invalid email" in out

    def test_add_duplicate_ignored(self, tmp_path):
        store = _make_store(tmp_path, ["dup@example.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["a", "dup@example.com", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all().count("dup@example.com") == 1

    def test_add_shows_confirmation(self, tmp_path, capsys):
        store = _make_store(tmp_path)
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["a", "new@example.com", ""]):
            _manage_email_store(_t)
        out = capsys.readouterr().out
        assert "new@example.com" in out

    def test_loop_stays_open_after_add(self, tmp_path):
        """After adding, the menu redisplays and a second add is possible."""
        store = _make_store(tmp_path)
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["a", "first@x.com", "a", "second@x.com", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == ["first@x.com", "second@x.com"]


# ---------------------------------------------------------------------------
# TestEmailStoreDeleteAll — 'all' command
# ---------------------------------------------------------------------------

class TestEmailStoreDeleteAll:
    def test_all_deletes_every_address(self, tmp_path):
        store = _make_store(tmp_path, ["a@x.com", "b@x.com", "c@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["all", "y", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == []

    def test_all_shows_count(self, tmp_path, capsys):
        store = _make_store(tmp_path, ["a@x.com", "b@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["all", "y", ""]):
            _manage_email_store(_t)
        out = capsys.readouterr().out
        assert "2" in out

    def test_all_on_empty_store_shows_info(self, tmp_path, capsys):
        store = _make_store(tmp_path)
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["all", ""]):
            _manage_email_store(_t)
        out = capsys.readouterr().out
        assert "No email address saved" in out

    def test_loop_stays_open_after_all(self, tmp_path):
        """After 'all', the menu stays open — user can add a new address."""
        store = _make_store(tmp_path, ["old@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["all", "y", "a", "new@x.com", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == ["new@x.com"]


# ---------------------------------------------------------------------------
# TestEmailStoreDeleteSingle — single number
# ---------------------------------------------------------------------------

class TestEmailStoreDeleteSingle:
    def test_delete_first(self, tmp_path):
        store = _make_store(tmp_path, ["first@x.com", "second@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["1", "y", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == ["second@x.com"]

    def test_delete_last(self, tmp_path):
        store = _make_store(tmp_path, ["first@x.com", "second@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["2", "y", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == ["first@x.com"]

    def test_delete_out_of_range_rejected(self, tmp_path, capsys):
        store = _make_store(tmp_path, ["a@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["5", ""]):
            _manage_email_store(_t)
        assert store.all() == ["a@x.com"]
        out = capsys.readouterr().out
        assert "there is no 5 in the list" in out

    def test_delete_shows_confirmation(self, tmp_path, capsys):
        store = _make_store(tmp_path, ["del@x.com", "keep@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["1", "y", ""]):
            _manage_email_store(_t)
        out = capsys.readouterr().out
        assert "del@x.com" in out

    def test_loop_stays_open_after_delete(self, tmp_path):
        """After deleting one entry the menu stays open for further action."""
        store = _make_store(tmp_path, ["first@x.com", "second@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["1", "y", "1", "y", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        # Both deleted (second became #1 after the reload in second iteration)
        assert store.all() == []


# ---------------------------------------------------------------------------
# TestEmailStoreDeleteCommaList — e.g. '1,3'
# ---------------------------------------------------------------------------

class TestEmailStoreDeleteCommaList:
    def test_comma_list_deletes_correct_entries(self, tmp_path):
        store = _make_store(tmp_path, ["a@x.com", "b@x.com", "c@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["1,3", "y", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == ["b@x.com"]

    def test_comma_list_out_of_range_rejected(self, tmp_path, capsys):
        store = _make_store(tmp_path, ["a@x.com", "b@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["1,9", ""]):
            _manage_email_store(_t)
        assert len(store.all()) >= 1
        out = capsys.readouterr().out
        assert "there is no 9 in the list" in out


# ---------------------------------------------------------------------------
# TestEmailStoreDeleteRange — e.g. '1-3'
# ---------------------------------------------------------------------------

class TestEmailStoreDeleteRange:
    def test_range_deletes_correct_entries(self, tmp_path):
        store = _make_store(tmp_path, ["a@x.com", "b@x.com", "c@x.com", "d@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["2-3", "y", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == ["a@x.com", "d@x.com"]

    def test_a_range_takes_the_entries_there_are(self, tmp_path):
        """v0.39.0 (bob/selection.py) — a range reaching past the end takes the
        entries there are between its bounds; it was refused."""
        store = _make_store(tmp_path, ["a@x.com", "b@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["1-5", "y", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert store.all() == []

    def test_a_range_with_no_entry_is_refused(self, tmp_path, capsys):
        store = _make_store(tmp_path, ["a@x.com", "b@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["5-9", ""]):
            _manage_email_store(_t)
        assert store.all() == ["a@x.com", "b@x.com"]
        assert "nothing in the list between 5 and 9" in capsys.readouterr().out

    def test_a_refused_confirmation_deletes_nothing(self, tmp_path, capsys):
        """v0.39.0 — the plain-text address book deleted without asking."""
        store = _make_store(tmp_path, ["a@x.com", "b@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["all", "n", ""]):
            _manage_email_store(_t)
        assert store.all() == ["a@x.com", "b@x.com"]
        assert "nothing was changed" in capsys.readouterr().out

    def test_range_single_element(self, tmp_path):
        store = _make_store(tmp_path, ["a@x.com", "b@x.com", "c@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["2-2", "y", ""]), \
            patch("builtins.print"):
            _manage_email_store(_t)
        assert "b@x.com" not in store.all()
        assert "a@x.com" in store.all()
        assert "c@x.com" in store.all()


# ---------------------------------------------------------------------------
# TestEmailStoreInvalidInput — unrecognised patterns
# ---------------------------------------------------------------------------

class TestEmailStoreInvalidInput:
    def test_garbage_input_rejected(self, tmp_path, capsys):
        store = _make_store(tmp_path, ["a@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["xyz!!", ""]):
            _manage_email_store(_t)
        assert store.all() == ["a@x.com"]
        out = capsys.readouterr().out
        assert "is not a selection" in out

    def test_zero_index_rejected(self, tmp_path, capsys):
        store = _make_store(tmp_path, ["a@x.com"])
        with \
            patch("bob.config.EmailStore.load", return_value=store), \
            patch("builtins.input", side_effect=["0", ""]):
            _manage_email_store(_t)
        assert store.all() == ["a@x.com"]
        out = capsys.readouterr().out
        assert "there is no 0 in the list" in out
