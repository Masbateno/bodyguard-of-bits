"""v0.27.0 — the DOCKER-USER example: what an already-open flow does, measured.

0.25.1 shipped `-I DOCKER-USER -i <ext> ! -s <trusted> -j DROP` with a RETURN
for RELATED,ESTABLISHED in front, and left "a connection already established
may go on" unmeasured; a review asked for `-i <ext>` on the RETURN too.
Measured in network namespaces (router, outside, container; 24 October 2026):
new connections met the same verdicts either way — untrusted refused, trusted
let in, the container's new egress let out, an operator's later DROP on
container egress to 9000 refusing new flows. The difference is one held flow:
without -i the RETURN took its packets and the operator's DROP never saw them
(counter 0); with -i <ext> the DROP cut it (counter 4).
"""

from __future__ import annotations

import pytest

from bob import i18n


@pytest.mark.parametrize("lang, measured, variant", [
    ("en", "one already established goes on until it closes — measured", "add -i <external-interface> to the RETURN for it to"),
    ("fr", "Une connexion déjà établie continue jusqu'à sa fermeture — mesuré", "ajoutez -i <interface-externe> au RETURN pour qu'il les coupe"),
])
def test_the_explain_says_what_was_measured(lang, measured, variant):
    i18n.init(lang)
    try:
        why = i18n.t("explain.docker.exposed_port.why")
        how = i18n.t("explain.docker.exposed_port.how")
    finally:
        i18n.init(lang="en")
    assert measured in why and "that last point" not in why and "ce point, l'IPv6" not in why
    assert variant in how
