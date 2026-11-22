"""v0.42.0 — six texts said more than BOB measures (B-036).

Read in the developer's workstation audit under 0.40.0 (21 November 2026),
raised by the external review, judged against the doctrine (principle 6: never
over-claim). Each text now says what is measured; the guard keeps the strong
phrase from coming back, in both languages.
"""

from __future__ import annotations

import pytest

from bob import i18n

#: key → (words that must not come back, words of the measured claim), per language
CASES = {
    "ports.system_port": {
        "en": ("no risk", "recognised system service"),
        "fr": ("aucun danger", "service système reconnu")},
    "suid_audit.ok": {
        "en": ("known-safe", "reference list"),
        "fr": ("sûrs", "liste de référence")},
    "clamav.socket_open_shutdown_refused_detail": {
        "en": ("no account can turn the antivirus off", "SHUTDOWN command"),
        "fr": ("aucun compte ne peut couper l'antivirus", "commande SHUTDOWN")},
    "auditd.no_rules_detail": {
        "en": ("to cover the most critical paths", "not reads"),
        "fr": ("pour couvrir les chemins les plus critiques", "pas les lectures")},
    "samba.server_signing_auto_detail": {
        "en": ("to prevent NTLM relay attacks", "to this SMB server"),
        "fr": ("prévenir les attaques NTLM relay", "vers ce serveur SMB")},
    # v0.42.0, second review (ChatGPT on the 0.42.0 output) — judged and kept:
    "log_rotation.remote_syslog_none_detail": {
        "en": ("ensures logs are preserved", "provided the remote server is protected"),
        "fr": ("garantit leur conservation", "à condition que le serveur distant")},
    "file_integrity.not_installed_detail": {
        "en": ("will go undetected", "can go unnoticed"),
        "fr": ("passe inaperçu.", "peut passer inaperçue")},
    "service_risk.samba_windows_file_sharing.exposure": {
        "en": ("exclusively", "trusted networks"),
        "fr": ("exclusivement", "réseaux de confiance")},
    "updates.unattended_not_configured": {
        "en": ("require manual intervention", "no other automatic update mechanism BOB knows"),
        "fr": ("nécessitent une intervention manuelle", "aucun autre mécanisme")},
    "scoring.context.local": {
        "en": ("only", "No public address on the host"),
        "fr": ("uniquement", "Aucune adresse publique sur l'hôte")},
    "module_blacklist.candidates_detail": {
        "en": ("CIS Ubuntu 22.04", "CIS benchmarks"),
        "fr": ("CIS Ubuntu 22.04", "benchmarks CIS")},
    "service_risk.avahi_local_network_discovery.threat": {
        "en": ("devices and and", "service enumeration"),
        "fr": ("et d'services", "et de services")},
    # third review — only login.defs is read; the detail said more than the message
    "password_policy.no_expiry": {
        "en": ("Password expiry not enforced", "for new accounts"),
        "fr": ("Expiration des mots de passe non appliquée", "pour les nouveaux comptes")},
    "password_policy.no_expiry_detail": {
        "en": ("Passwords never expire.", "not read here"),
        "fr": ("n'expirent jamais", "pas lue ici")},
    "updates.unattended_not_configured_detail": {
        "en": ("so patches wait for someone to remember", "a tool it does not know"),
        "fr": ("attendent donc que quelqu'un y pense", "un outil qu'il ne connaît pas")},
    "mount_hardening.proc_hidepid_detail": {
        "en": ("systemd-logind) need it", "may need it"),
        "fr": ("systemd-logind) en ont besoin", "peuvent en avoir besoin")},
    "service_risk.telnet_server.threat": {
        "en": ("immediately", "encrypted"),
        "fr": ("immédiatement", "chiffré")},
}


@pytest.mark.parametrize("key", sorted(CASES))
@pytest.mark.parametrize("lang", ["en", "fr"])
def test_the_text_says_what_is_measured(key, lang):
    gone, said = CASES[key][lang]
    before = i18n.current_lang()
    i18n.init(lang)
    try:
        text = i18n.t(key, port="53/udp", service="DNS", suid_count=23, sgid_count=13)
    finally:
        i18n.init(before)
    assert gone not in text
    assert said in text
