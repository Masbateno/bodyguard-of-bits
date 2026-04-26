"""
Unit tests for bob.i18n module.

Run with: python -m pytest tests/test_i18n.py -v
"""

import pytest
from bob import i18n


@pytest.fixture(autouse=True)
def reset_i18n():
    """Reset i18n state between tests."""
    yield
    i18n._translations = {}
    i18n._lang = "en"
    i18n._initialized = False


class TestInit:
    def test_init_english(self):
        i18n.init("en")
        assert i18n.current_lang() == "en"
        assert i18n._initialized

    def test_init_french(self):
        i18n.init("fr")
        assert i18n.current_lang() == "fr"

    def test_init_unknown_lang_falls_back_to_english(self):
        i18n.init("de")
        # current_lang() reflects the actually loaded locale, not the requested one
        assert i18n.current_lang() == "en"
        assert i18n._initialized

    def test_init_twice_reloads(self):
        i18n.init("en")
        i18n.init("fr")
        assert i18n.current_lang() == "fr"


class TestTranslate:
    def test_simple_key_english(self):
        i18n.init("en")
        result = i18n.t("firewall.active")
        assert result == "UFW firewall is active"

    def test_simple_key_french(self):
        i18n.init("fr")
        result = i18n.t("firewall.active")
        assert result == "Le pare-feu UFW est actif"

    def test_nested_key(self):
        i18n.init("en")
        result = i18n.t("scoring.level.low")
        assert result == "LOW"

    def test_nested_key_french(self):
        i18n.init("fr")
        result = i18n.t("scoring.level.low")
        assert result == "FAIBLE"

    def test_missing_key_returns_bracketed_key(self):
        i18n.init("en")
        result = i18n.t("this.key.does.not.exist")
        assert result == "[this.key.does.not.exist]"

    def test_before_init_returns_bracketed_key(self):
        result = i18n.t("firewall.active")
        assert result == "[firewall.active]"

    def test_interpolation(self):
        i18n.init("en")
        result = i18n.t("services.state.inactive_disabled", label="Redis")
        assert "Redis" in result

    def test_interpolation_missing_placeholder_returns_raw(self):
        i18n.init("en")
        # Missing placeholder should not crash, return raw string
        result = i18n.t("services.state.inactive_disabled")
        assert isinstance(result, str)

    def test_section_key_returns_bracketed(self):
        """Requesting a dict node rather than a leaf should return bracketed key."""
        i18n.init("en")
        result = i18n.t("scoring.level")
        assert result == "[scoring.level]"

    def test_all_english_keys_are_strings(self):
        """Every leaf value in en.json must be a string."""
        i18n.init("en")
        _assert_all_leaves_are_strings(i18n._translations, "en")

    def test_all_french_keys_are_strings(self):
        """Every leaf value in fr.json must be a string."""
        i18n.init("fr")
        _assert_all_leaves_are_strings(i18n._translations, "fr")

    def test_french_has_same_keys_as_english(self):
        """French locale must define the same keys as English."""
        i18n.init("en")
        en_keys = _collect_keys(i18n._translations)

        i18n.init("fr")
        fr_keys = _collect_keys(i18n._translations)

        missing_in_fr = en_keys - fr_keys - {"_meta"}
        assert not missing_in_fr, (
            f"Keys present in en.json but missing in fr.json: {missing_in_fr}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_all_leaves_are_strings(data: dict, lang: str, path: str = "") -> None:
    for key, value in data.items():
        full_path = f"{path}.{key}" if path else key
        if key == "_meta":
            continue
        if isinstance(value, dict):
            _assert_all_leaves_are_strings(value, lang, full_path)
        else:
            assert isinstance(value, str), (
                f"[{lang}] Key '{full_path}' has non-string value: {value!r}"
            )


def _collect_keys(data: dict, prefix: str = "") -> set:
    keys = set()
    for key, value in data.items():
        full = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            keys |= _collect_keys(value, full)
        else:
            keys.add(full)
    return keys
