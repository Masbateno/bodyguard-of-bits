"""v0.25.0 — what each finding says it established, after the changelog review.

- A raw-firewall port read "governed by the ruleset (inbound default: refuse)".
  Measured on a Fedora 43 VM: an nftables input chain with policy drop and
  `tcp dport 8080 accept` gave the same words as one without the accept, while
  8080 answered. BOB reads the default, not each rule — the message says so.
- The kubelet was asked from this host; reachability from the network is not
  tested.
- A container with every capability is what privileged: true grants and also
  what capabilities.add: [ALL] grants: the finding names the measurement.
- kube-system is not deducted because it usually holds the platform; the
  namespace alone proves nothing, so the finding asks for each pod to be checked.
"""

from __future__ import annotations

import pytest

from bob import i18n

_CASES = {
    "en": {
        "ports.uncovered_netfilter": "does not establish reachability",
        "ports.uncovered_bound_address_netfilter": "does not establish reachability",
        "kubernetes.kubelet_anonymous": "asked from this host",
        "kubernetes.kubelet_anonymous_read": "no command endpoint was shown to authorise them",
        "kubernetes.kubelet_readonly_port": "asked from this host",
        "kubernetes.privileged_pod": "every Linux capability",
        "kubernetes.system_pods_elevated": "check that each one listed is",
    },
    "fr": {
        "ports.uncovered_netfilter": "n'établit pas la joignabilité",
        "ports.uncovered_bound_address_netfilter": "n'établit pas la joignabilité",
        "kubernetes.kubelet_anonymous": "demandé depuis cet hôte",
        "kubernetes.kubelet_anonymous_read": "aucun point d'accès de commande n'a été montré comme les autorisant",
        "kubernetes.kubelet_readonly_port": "demandé depuis cet hôte",
        "kubernetes.privileged_pod": "toutes les capabilities Linux",
        "kubernetes.system_pods_elevated": "vérifiez que chaque pod listé en est un",
    },
}


@pytest.mark.parametrize("lang, key, needle", [(lang, k, n) for lang, kv in _CASES.items() for k, n in kv.items()])
def test_the_finding_names_what_was_established(lang, key, needle):
    i18n.init(lang)
    try:
        text = i18n.t(key, port="8080/tcp", address="10.0.0.5", count=1, pods="a/b")
    finally:
        i18n.init(lang="en")
    assert needle in text, text


@pytest.mark.parametrize("lang", ["en", "fr"])
def test_kube_system_is_not_called_the_platform_outright(lang):
    i18n.init(lang)
    try:
        text = i18n.t("kubernetes.system_pods_elevated", count=1, pods="kube-system/x")
    finally:
        i18n.init(lang="en")
    assert "the platform's own components, not deducted" not in text
    assert "les composants de la plateforme elle-même, non déduits" not in text
