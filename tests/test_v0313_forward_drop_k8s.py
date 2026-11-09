"""v0.31.3 — FORWARD at DROP on a Kubernetes node, measured.

`firewall_iptables.forward_accept` advises `sudo iptables -P FORWARD DROP`, and
its explanation told routing hosts (libvirt, Docker, KVM) to keep ACCEPT. A
Kubernetes node routes its pods' traffic, and whether the advice cut them off
was open since 0.31.0 (the MicroK8s node's pod network was broken before any
change). Measured on Ubuntu Server 26.04, MicroK8s 1.35.6 with calico (its rules
in the legacy tables), 8 November 2026 (~/.cache/bob-fieldtest/netnsbench/fwd0313/):
with the policy at ACCEPT, at DROP as BOB prints it (the nft table), at DROP in
the legacy table too, and 60 s later, a pod reached a pod's DNS, the DNS
service, the API service and the internet; BOB went from WARN −1 to OK. k3s was
measured the same way on the same host in 0.25.1. The explanation says so —
for those two, not for every CNI (third review of the 0.31.3 changelog).
"""

from __future__ import annotations

import json

import pytest


def _how(lang):
    with open(f"bob/locales/{lang}.json", encoding="utf-8") as fh:
        return json.load(fh)["explain"]["firewall_iptables"]["forward_accept"]["how"]


@pytest.mark.parametrize("lang, words", [
    ("en", "Being a Kubernetes node is not on its own a reason to keep ACCEPT: measured on MicroK8s 1.35.6 (calico) and on k3s"),
    ("fr", "Être un nœud Kubernetes ne suffit pas à justifier ACCEPT : mesuré sur MicroK8s 1.35.6 (calico) et sur k3s")],
    ids=["en", "fr"])
def test_the_explanation_says_a_kubernetes_node_keeps_its_pods_at_drop(lang, words):
    how = _how(lang)
    assert words in how
    # still after the routing-host advice it qualifies, and the DROP command stays first
    assert how.index(words) > how.index("FORWARD -n")
    assert how.lstrip().startswith(("1. Set FORWARD policy to DROP", "1. Mettre la policy FORWARD à DROP"))
