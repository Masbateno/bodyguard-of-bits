*[Read in English](TESTING.md)*

# BOB — Plan de tests et historique de versions

Deux parties complémentaires :

- **Historique des tests unitaires** (table par version + sections détaillées) — chaque release liste les tests ajoutés, supprimés ou corrigés, avec la plateforme et le compteur de tests de l'époque. C'est la trace d'audit de la croissance de la suite, de v0.1.0 (4200 tests) à v0.6.0 (4583 tests). La croissance +45 net à travers v0.5.5 → v0.5.8 vient des régressions hardening de la campagne deep-audit. v0.6.0 est contract-preserving — les splits ssh.py + cron.py et le sunset UFW_AUDIT_SHARE ajoutent zéro delta test.
- **Plan de régression UFW manuel** (Catégories A–E en bas) — règles UFW délibérément dangereuses et le comportement BOB attendu pour chacune. Utilisé pour valider la détection + remédiation sur de vrais systèmes.

---

## Historique des tests unitaires

| Version | Tests | Notes |
|---------|-------|-------|
| v0.15.0 | 7156 | **Exactitude des verdicts — en cours (branche `v0.15.x`).** Tests différentiels contre l'analyseur qui fait autorité (`sshd -T`, `ssh -G`, `cvtsudoers -f json`) au lieu d'attentes écrites à la main. Une classe de défaut domine : les motifs écrits sur la forme *propre* d'une ligne cessaient de correspondre dès qu'un opérateur ajoutait un commentaire final — une règle UFW `allow from anywhere` commentée n'était pas détectée, et `NOPASSWD: ALL # temporaire` était rétrogradé de WARN −2 à un INFO sans score. Chaque correctif est testé par mutation : le défaut est réinjecté et la garde doit échouer. |
| v0.14.1 | 6719 | **Premier patch v0.14.x — sémantique `privileged` + trois campagnes de stress test (30-08-2026).** **Sémantique :** `container_security.privileged` valait `cap_bnd & (1 << CAP_SYS_ADMIN)` — littéralement « CAP_SYS_ADMIN présente » — donc `--cap-add SYS_ADMIN` était rapporté PRIVILÉGIÉ sous le titre *« jeu complet de capabilities »*. Mesuré sur podman : 2149844475 contre **2199023255551** = `(1 << 41) - 1`. C'est désormais le bounding set complet lu depuis `/proc/sys/kernel/cap_last_cap` (borné), plus la clé additive `container_security.cap_sys_admin`. **Campagne 1 — résilience :** `runner._sec` n'avait aucune gestion d'exception, donc un seul check en échec coûtait l'audit ENTIER (exit 3, zéro octet sur stdout) — reproduit avec un octet latin-1 dans un champ GECOS d'`/etc/passwd`. Les sections dégradent maintenant sur place (finding INFO `<section>.unavailable` + nouveau champ JSON `degraded_sections`) ; codes de sortie délibérément inchangés. A nécessité la conversion de 29 sites de snapshot `_sec` impatients en fabriques paresseuses (`--check=ssh` 2,60 s → 1,91 s). `UnicodeDecodeError` échappait à 33 gardes `except OSError` ; `load_history` mourait sur une ligne JSON valide non-objet ; `--lang` acceptait un chemin absolu ; les rapports n'avaient pas `O_NOFOLLOW` ; injection de formules CSV ; garde tiret manquante sur `--profile`/`--check`/`--skip`. **Campagne 2 — les correctifs eux-mêmes :** la barrière pouvait être mise en échec depuis son propre handler (rendu hors du try interne) ; les écritures de rapport n'avaient aucune gestion d'erreur (un tmpfs plein de 64 Ko coûtait tout l'audit) ; `--ignore` faisait taire le score mais pas le terminal (`display_result` parcourt le `CheckResult` brut) ; des séquences d'échappement issues de valeurs système atteignaient le terminal (un *nom de fichier* de script cron portant `\033]0;…\007` réécrivait le titre de la fenêtre) — assaini désormais dans `add_finding`, point unique pour tous les formats ; lectures non bornées sur fichiers non réguliers (plugin lié à `/dev/zero` → OOM ; `--diff=<fifo>` → **blocage indéfini**) fermées par `_atomic.read_text_capped()` ; Ctrl-C affichait un traceback. **Campagne 3 — ce que l'outil dit :** le profil actif n'apparaissait que dans le terminal (désormais champ `profile` en JSON/webhook + en-têtes Markdown/HTML ; CSV délibérément intact) ; `-p NOM` persiste silencieusement comme défaut (non documenté depuis v0.12.1) ; les deux READMEs documentaient `-d` comme « sortie en français ». **Vérifié sain :** 12 000 combinaisons d'argv, 46 sections sous userns restreint, concurrence à 8, tout l'espace de clés i18n (966 littérales + 637 expansions à l'exécution dans les deux locales), invariants de score sur 6 000 états de moteur aléatoires, schéma JSON sur 16 charges utiles, dry-run `--fix` (0 appel subprocess), déterminisme, signaux, un log UFW de 34 Mo. **6590 → 6719 (+129** : 17 privileged + 64 + 32 robustesse + 16 surfaces de contrat). 0 régression. 20 mutations injectées, 20 gardes confirmés les tuer. |
| v0.14.0 | 6590 | **Première release v0.14.x — bundle BREAKING de corrections de contrat (29-08-2026).** **🔴 Le profil d'audit n'atteignait jamais 12 des 14 chemins de résultat** : il incombait à l'appelant d'invoquer `apply_profile()` avant `engine.apply()`, et seuls `_sec` et le chemin plugin le faisaient — 8 overrides livrés dans `desktop.conf`/`workstation.conf` étaient donc inertes, et un hôte LAN avec Samba derrière une règle UFW retournait exit 1 en permanence, rendant inatteignable l'`exit 0` documenté. `ScoreEngine` reçoit désormais `profile=` et applique les overrides dans `apply()`, le point de passage unique. BREAKING sur desktop/workstation (`warning_count` 4 → 2 mesuré en live) ; `server` intact. **La couleur était émise inconditionnellement (BREAKING)** : `bob > fichier` écrivait des codes ANSI ; `supports_color()` existait et n'était appelée nulle part. Câblée avec `--no-color` → `NO_COLOR` → `FORCE_COLOR` → `isatty()`. **Formulation de `--help`** pour les variables de couleur. **Plus** B904/B905, 8 jours de semaine faux dans le packaging, et la table des codes de sortie du README racine (bandes de score inventées → le vrai contrat). **6547 → 6590 (+43**, mutation-testés ; les gardes du profil sont comportementaux et non structurels — l'ancien design était « correct » à chaque site qui y pensait, ce qui explique que la suite passait aussi avant le fix). |
| v0.13.4 | 6545 | **Passe d'exactitude documentaire — corrections factuelles uniquement (28-08-2026).** Audit machine de tout le corpus documentaire. La section sécurité FR était **factuellement inversée** depuis 7 releases mineures ; 5 options CLI étaient indécouvrables ; 29 liens cassés ou fuités. Plus 3 gardes (liens, parité EN/FR par section, surface CLI). **6533 → 6545 (+12).** |
| v0.13.3 | 6533 | **Premier patch de durcissement v0.13.x après la croissance de périmètre de la branche (28-08-2026, additif, sans changement de score).** Hygiène de journalisation (`NullHandler` + `BOB_DEBUG`), performance des runs filtrés (−52 % sur `--check`), un garde de dérive des compteurs documentaires, et une barrière ruff de correction (E9/F/B, rien d'ignoré). **6511 → 6533 (+22).** |
| v0.13.2 | 6511 | **Patch same-day cohérence/sécurité des commandes de finding (21-06-2026, additif, sans changement de score).** Passe de cohérence sémantique par sub-agent sur ~144 commandes (déclenchée par un user remarquant `apt purge` sous « Vérifier : »). **docker `userns_not_configured` 🔴** : la remédiation `tee /etc/docker/daemon.json` écrasait tout le fichier (perte de données) — désormais création-si-absent uniquement (`test -f … \|\| {…}`, sans texte humain), le detail avertit de sauvegarder + fusionner (EN+FR). **kernel `kernels_obsolete`** : `apt purge` destructif déplacé de `cmd_type="check"` (Vérifier ℹ) vers `"fix"` (Que faire →). **kernel `kernels_update_available`** : `cmd_type="action"` invalide → `"fix"`. **garde-fou** : `add_finding` lève sur cmd_type hors `("fix","check")`. L'audit a confirmé que ce sont les seuls bugs de présentation (toutes les autres check-cmds sont des lectures, toutes les fix-cmds des actions, parité de sens EN/FR OK). **6504 → 6511 (+7** : 6 `test_v0132_cmd_semantics.py` + 1 `test_kernel_modules.py`). 0 régression. Validé live EN+FR. v0.12.x reste EOL ; v0.13.x seule ligne supportée. |
| v0.13.1 | 6504 | **Premier patch hardening v0.13.x — checks de contexte runtime additifs (21-06-2026, INFO-only, non-BREAKING, sans changement de score).** Poursuit le virage runtime in-branch ; les dents (scoring conteneur/nftables) gardées pour le bundle BREAKING planifié v0.14.0. **Unités socket systemd orphelines** (`socket_units`) : signale une `.socket` encore active alors que son `.service` backing est cassé — absent (masqué/introuvable) ou crashé (`ActiveState=failed`) — ou la socket elle-même en `failed` ; orpheline si l'un de plusieurs triggers est cassé ; un service backing simplement inactive est sain ; marque les binds non-loopback ; les internes systemd à `Triggers` vide jamais flaguées. **Contexte cloud côté hôte** (`cloud_context`) : supprimée hors cloud ; détection conservatrice (fournisseur DMI, ou cloud-init corroboré par IMDS on-link — une VM homelab à simple cloud-init n'est pas signalée) ; remonte IMDS joignable on-link (rappel IMDSv2) + user-data lisible par tous — strictement côté hôte, aucune API/identifiant cloud. **Robustesse ddns + ssh** : un chemin sous un répertoire non-parcourable (`/root` durci, userns) levait `PermissionError` — dans ddns ça avortait l'audit (`_config_present()` dégrade en « absent ») ; le field test live a révélé la même classe dans `ssh/_snapshot.py` (`~/.ssh` sous un home non-parcourable fuitait la chaîne d'erreur), maintenant gardé aussi. Sections 36 → 38. **6461 → 6504 (+43** : 21 `test_socket_units.py` + 18 `test_cloud_context.py` + 3 `test_ddns.py` + 1 `test_ssh.py`). 0 régression. Validé live EN+FR (socket négatif+positif ; cloud négatif live + positif forgé ; ddns EACCES via répertoire mode-000). v0.12.x reste EOL ; v0.13.x seule ligne supportée. |
| v0.13.0 | 6461 | **Première release v0.13.x — extension de scope : deux nouveaux checks INFO-only (20-06-2026).** Première vraie croissance de couverture après le long cycle de durcissement interne ; les deux additifs, non-BREAKING, sans déduction. **`systemd-analyze security`** (`systemd_hardening`) : remonte le score d'exposition systemd des services en cours (parsé depuis `--json=short`) — résumé par prédicat (UNSAFE/EXPOSED/OK) + services les moins durcis + pointeur `systemd-analyze security <unit>` ; aucune déduction (non-durci par défaut = normal). **Posture conteneur** (`container_security`) : ne tourne que dans un conteneur (supprimée sur un hôte via `skip_if`) ; lit CapBnd → détection privilégié/CAP_SYS_ADMIN, seccomp, userns (uid_map), rootfs en écriture depuis `/proc` ; INFO-only (WARN conteneur privilégié = fast-follow). systemd field-testé live EN+FR ; conteneur validé contre de vraies données noyau `/proc` dans des user namespaces `unshare` (privilégié + non-privilégié + branche userns-supprime-warning-root, EN+FR). Sections 35 → 36. **6442 → 6461 (+19**: 7 + 12). 0 régression. **v0.12.x déclarée EOL** (politique ligne-minor-récente) ; v0.8.x–v0.11.x également EOL ; v0.13.x seule ligne supportée. v0.7.x / v0.6.x restent EOL. |
| v0.12.2 | 6442 | **Cleanup hardening de clôture — deep-audit tool entier + sweep angles inexplorés (12-06-2026). Clôt la branche v0.12.x.** Verdict audit : 0 critique / 0 important. Vérifié propre : `_atomic`, `webhook` (scheme+redaction+timeout), subprocess (pas de shell=True, LC_ALL=C, garde symlink), parsers (anchored, pas de ReDoS), i18n 1975/1975, pas de drift, parser profils (extends borné 8). Deux fixes : **M-1** `_DOMAIN_SECTIONS` contenait les préfixes `virt`/`logs` au lieu des sections réelles `virtualization`/`ufw_logging` (inatteignable — always-on — mais inexact ; remappé + garde de drift). **Défense-en-profondeur nom cron** : nom slugué pour le chemin mais écrit brut dans le commentaire `# name:` du cron root ; `input()` est line-based donc PAS une injection exploitable, mais les control chars sont maintenant strippés (cohérent avec `_validate_custom_cron` strict). **6437 → 6442 (+5**). 0 régression. v0.7.x reste EOL ; v0.6.x reste EOL. |
| v0.12.1 | 6437 | **Premier patch hardening v0.12.x — complétude affichage domaines + fixes audit naive/advanced (12-06-2026, additif/non-BREAKING).** Afficher les 7 domaines même inactifs, étiquetés avec la raison précise (`non installé` / `non évalué (profil <X>)` / `non évalué (--check/--skip)` / `aucune action requise`) ; jamais comptés dans la moyenne (préserve scores + F1 + garde v0.4.5). `disk` n'est jamais "non installé" à tort. Exposé en texte + JSON + Markdown + HTML, EN+FR. Puis un audit naive + 4 tours advanced a corrigé : **A** mislabel `--check`/`--skip` → raison `filtered` via `_section_enabled` ; **B** `--profile=typo` persistait le nom invalide → seuls profils valides sauvés ; **C** `--profile` inconnu signalé avant le root-gate ; **E** `--english`, `--output=html`, `--output=json-full`, casse-insensible `--check`/`--skip`/`--explain`/`--output` ; **ADV-1** `domain_scores[d]` JSON gagne `active`+`reason` (machine reproduit le headline) — additif schema v3 ; **ADV-G2** `history.jsonl` healé à 0600 ; **ADV-B1** breakdown domaines ajouté en Markdown + HTML. Audit aussi vérifié propre : déterminisme, maths scoring (cap domaine × F1 × posture), concurrence, `LC_ALL=C`, `--ignore`, `--no-color`. **6401 → 6437 (+36**). 0 régression. Field test bilingue live propre. v0.7.x reste EOL ; v0.6.x reste EOL. |
| v0.12.0 | 6401 | **Première release v0.12.x — bundle UX BREAKING planifié F1/F2/F4/F6/F9 (11-06-2026).** Les cinq findings du test bilingue live de v0.11.x qui changent un contrat, un code de sortie, ou le score. **F1** (BREAKING, score) : le score de tête = moyenne des domaines actifs, donc une déduction firmware (brut 9) moyennait `(6×10+9)/7=9.86 → 10/10` alors que le résumé disait "Action requise". Désormais "10/10 = audit sans défaut" — dès que `raw_score < MAX_SCORE` le score de tête plafonne à 9 ; `--breakdown` montre moyenne → cap (nouvelle `domain_average_precap` + clé `breakdown.f1_cap`) ; le `score` JSON reflète le cap. **F2** (présentation) : le symbole par item du résumé reflète la sévérité (`⚠`/`✖`) pour matcher le corps (était hardcodé par section de nature) ; l'en-tête groupe toujours par nature. **F4** (BREAKING, sortie) : `--explain <inconnu>` sort maintenant 3 et non 0 (`run_explain`→bool) ; ajoute une suggestion difflib "vouliez-vous dire" (clé `explain.ui.did_you_mean`). **F6** : validation `--check`/`--skip` déplacée avant le root-gate, donc un mauvais token est rapporté sans demander sudo (garde AST statique sur l'ordre). **F9** (BREAKING, schéma v2→v3) : compteurs int `alerts`/`warnings` renommés `alert_count`/`warning_count` (symétrie avec `info_count`) ; un renommage de clé bump `schema_version` "2"→"3" selon la règle documentée + précédent clean-cut (`SUPPORTED={"3"}`) ; le webhook garde `alerts`/`warnings` (contrat plat séparé). Fix d'isolation : les tests de barre de score watch forcent le monochrome (`output.init(no_color=True)`) au lieu d'un global fuité. Audit pre-ship sub-agent : 0 critique / 0 important → SHIP. **6381 → 6401 (+20** : 6 F1 + 3 F2 + 6 F4 + 2 F6 + 3 F9). 0 régression. v0.7.x reste EOL ; v0.6.x reste EOL. |
| v0.11.2 | 6381 | **Second patch de durcissement v0.11.x — complétude i18n F8 + F8b (11-06-2026).** Ferme les deux dernières lacunes de l'audit français relevées par un test bilingue approfondi en live de la v0.11.1. **F8** : les 60 lignes de référence « Best practice — … » rédigées par BOB dans `bob/data/cis_refs.json` (entrées `code:null`) n'existaient qu'en anglais → chacune reçoit un `ref_fr` français ; `get_cis_ref()` devient sensible à la locale (`i18n.current_lang()` paresseux). Les 114 entrées codées CIS conservent leurs titres canoniques en anglais, par conception. **F8b** : deux commentaires `# …` en ligne dans des suggestions `cmd=` (`ipv6.py`, `log_rotation.py`) étaient codés en dur en anglais (même classe que le correctif disk.py de v0.11.1, qui était incomplet) → passés en clés de locale. Nouveau garde anti-dérive interdisant un `  # <texte>` codé en dur dans les littéraux `cmd=`. Deux observations du test approfondi vérifiées comme **non-bugs** et laissées telles quelles : l'en-tête `ignore:` résiduel de `--unignore` (préservation délibérée du commentaire I-1) et l'alignement de la boîte (toutes les lignes font 80 caractères ; le décalage visuel vient de la largeur d'affichage des emoji). **6369 → 6381 (+12** : tous dans `test_v0112_i18n_refs_and_cmd_comments.py` — 9 F8 + 3 F8b). 0 régression. v0.7.x et v0.6.x restent EOL. |
| v0.11.1 | 6369 | **Premier patch de durcissement v0.11.x — deux mineurs d'audit profond + trois finitions issues d'un audit UX (11-06-2026).** 20e passe d'audit profond : 0 critique + 0 important + 2 mineurs (construction des `cmd`, écriture atomique, échappement HTML et contrats de clés littérales tous propres). **M-1** : `bob/i18n.py::t()` n'attrapait que le `KeyError` de `str.format()` — un template de locale malformé (accolade non fermée → `ValueError`, `{0}` positionnel → `IndexError`) faisait planter l'audit dans cette langue. `t()` dégrade désormais sur `(KeyError, IndexError, ValueError)` ; `try_t()` reçoit la garde IndexError/ValueError (en préservant la propagation intentionnelle du KeyError). Nouveau linter de locale `TestTemplateWellFormed` qui rejette les templates malformés en CI. **M-2** : `--test-webhook` honore désormais `--offline` (le chemin d'audit le faisait déjà) — `bob --test-webhook --offline` saute proprement le POST (avis sur stderr, EXIT_OK) au lieu de sortir sur le réseau ; nouvelle clé `cli.test_webhook.offline_skipped` (EN+FR). **Plus trois finitions sans risque issues d'un audit fonctionnel / de qualité perçue (UX)** (le sous-ensemble sans changement de contrat ; modèle de score F1 / présentation F2 / code de sortie F4 / garde root F6 → v0.12.0) : **F3** l'analyse des noms d'appareils fwupd laissait fuir des débris de connecteurs (`?`, `??UEFI dbx:`) quand l'arbre dégradait en `?` sous `LC_ALL=C` — fwupd tourne maintenant sous `C.UTF-8` (`_C_UTF8_LOCALE_ENV`) avec une garde de parseur rejetant les noms ne commençant pas par un alphanumérique ; **F5** l'indice affiché pour une clé d'explication inconnue réclamait à tort sudo (`--explain list` n'en a pas besoin), retiré en EN+FR ; **F7** les règles UFW orphelines sans protocole affichent désormais `57621/tcp+udp` et non un `57621` nu (la commande de suppression garde le port nu). **Plus une passe d'exactitude documentaire** (DOC-A…G) : `--json-v1` (retiré en v0.9.0) supprimé des docs utilisateur ; le profil `workstation` réconcilié comme profil de plein droit et ajouté à `--help` ; compteurs EXPLAIN_KEYS → 169/45, « 43 checks » → 34 sections ; `UFW_AUDIT_SHARE` → `BOB_SHARE` ; dates des pages de man → 11-06. **6336 → 6369 (+33** : 9 i18n/webhook + 2 linter de locale + 9 `test_v0111_ux_audit_fixes.py` + 6 `test_v0111_doc_accuracy.py` anti-dérive). 0 régression. v0.7.x et v0.6.x restent EOL. |
| v0.11.0 | 6336 | **Première release v0.11.x — bundle BREAKING : hygiène + correction de design (10-06-2026).** Ouvre la branche v0.11.x. Deux items BREAKING ; F-1 (checks parallèles) reste différé indéfiniment (aucun signal de performance). **M-3 portée `Host` SSH** : `_check_client_config` est désormais sensible à la portée — un `ForwardX11 yes` / `ForwardAgent yes` limité à un bloc `Host` non global émet un INFO sans déduction (`ssh.x11.forwarding.client_scoped` + `ssh.client_forward_agent_scoped`, avec un placeholder `{host}` EN+FR) ; en portée globale, WARN + déduction sont conservés ; `StrictHostKeyChecking no` et `UserKnownHostsFile /dev/null` restent ALERTE quelle que soit la portée. Une ligne multi-motifs contenant un `*` nu (`Host gitlab *`) compte comme globale (`scoped = "*" not in entry.host.split()`, durci par l'audit pré-livraison). BREAKING : un forwarding limité à une portée ne déduit plus. **KILL D-4 Rank 2-8** : `SUBCHECK_RENAMES_V100` passe de 14 à 1 entrée (seul le Rank 1 est conservé) ; les 13 entrées retirées étaient inertes (motifs canoniques qu'aucun code n'émettait ; les clés monolithiques vivantes sont couvertes par correspondance exacte). Sans changement de comportement. **Garde CI** `tests/test_v0110_legacy_key_drift_guard.py` : balayage AST interdisant tout littéral de production référençant une clé renommée (généralise le garde statique de v0.10.2). **Matrice de posture** `tests/test_v0110_posture_matrix.py` : matrice exhaustive à 8 cellules UFW × iptables × score de domaine + isolation des branches + résolution des priorités (solde la dette de branche masquante qui avait caché le I-1 de v0.10.2). SNAPSHOT.md rafraîchi de v0.10.0 à v0.10.2. Audit sub-agent pré-livraison : 1 important (évasion via `Host` multi-motifs) corrigé avant le tag, 2 mineurs différés. **6268 → 6336 (+68** : 15 matrice de posture + 4 garde de dérive + 37 épinglage du KILL D-4 + 12 portée `Host` SSH). 0 régression. v0.7.x et v0.6.x restent EOL. |
| v0.10.2 | 6268 | **Second patch de durcissement v0.10.x (10-06-2026) — correctif I-1 issu de l'audit de durcissement approfondi post-v0.10.1.** La passe sub-agent du même jour sur la surface post-v0.10.1 a rendu 4 constats (1 important + 3 mineurs) ; le filtre du workflow conservateur « gain × risque = STOP » n'a retenu que I-1. **Le bug** : `bob/scoring.py::set_posture_from_engine` cherchait des findings portant la clé legacy v0.7.x / v0.8.x `iptables_nft.input_accept` pour basculer le drapeau de posture `iptables_input_accept`. Le préfixe a été renommé `firewall_iptables.*` en v0.9.0 D-1, si bien que la comparaison de littéraux ne correspondait plus à rien. **L'escalade de posture propre à iptables était silencieusement morte depuis la v0.9.0** (3 versions majeures). Masquée par la branche `firewall_inactive` sur les hôtes où UFW est arrêté, mais un hôte UFW actif + iptables INPUT ACCEPT régressait de HIGH à LOW. **Correctif** : mettre le littéral à `firewall_iptables.input_accept` pour coller à la clé canonique v0.9.0+ émise par `bob/checks/iptables_nftables.py:174`. La source unique (depuis v0.7.3 M-10) couvre à la fois `bob/__main__.py::audit` et `bob/watch.py:109`. **Tests** (`tests/test_v0102_posture_iptables_key.py`, NOUVEAU, 7 tests) : `TestPostureIptablesKey` (4 — la clé canonique déclenche / la legacy non / cohérence / indépendance de `firewall_inactive`) + `TestNoLegacyKeyInLiveCheck` (2 gardes statiques — scoring.py + balayage complet de `bob/` avec liste d'exception pour le shim de migration v0.9.2) + 1 paramétrage épinglant le contrat `EXPLAIN_KEYS`. 6261 → 6268 (+7). 0 régression. **Workflow conservateur** : M-1 (les blocs `Host` dupliqués déduisent trois fois, 4 directives préexistantes, aucun signal depuis 5+ majeures), M-2 (remontée cosmétique), M-3 (sémantique de portée `Host`, vraie fuite de contrat v0.10.1 via une incohérence du texte d'explication, candidat v0.11.x) différés. v0.7.x et v0.6.x restent EOL. |
| v0.10.1 | 6261 | **Premier patch de durcissement v0.10.x (10-06-2026) — split D-4 Rank 1 de `ssh.x11_forwarding` + NOUVELLE détection ForwardX11 côté client.** Workflow conservateur : un seul split D-4 retenu, celui dont le gain de sécurité est mesurable (il ajoute une détection jusque-là absente) ; les 7 autres rangs et F-1 restent différés jusqu'à signal utilisateur, conformément à la règle « gain × risque = STOP ». **Côté serveur** : `ssh.x11_forwarding` renommé `ssh.x11.forwarding.server` dans `bob/checks/ssh/_directives.py` (ligne `_BadDirective` de `x11forwarding`). **Côté client (NOUVEAU)** : `_check_client_config` reçoit une branche `elif k == "forwardx11" and v == "yes"` émettant `ssh.x11.forwarding.client` avec warn + détail + commande de remédiation complets. Avant la v0.10.1, BOB n'avait **aucune** détection côté client. **Rétrocompatibilité** : les entrées `ignore.yml` antérieures portant `ssh.x11_forwarding` couvrent les deux nouvelles sous-clés via le shim `SUBCHECK_RENAMES_V100` de v0.10.0 (glob fnmatch `ssh.x11.forwarding.*`) ; `bob --explain ssh.x11_forwarding` résout vers le contenu serveur via `EXPLAIN_KEY_ALIASES` (premier alias vivant après que le retrait D-3 de v0.9.0 eut vidé le dictionnaire). Migration des locales (EN + FR) + 6 nouvelles feuilles `explain.*` avec la formulation du risque côté client. EXPLAIN_KEYS 168 → 169 (+1). Références CIS : le serveur garde CIS:5.2.6, le client reçoit une référence « Best practice ». La regex `canonical_pattern` est étendue par une exception `_SSH_X11_FORWARDING_RE` couvrant la forme à 4 segments. 6242 → 6261 tests (+19 : 10 dédiés dans `tests/test_v0101_ssh_x11_client.py` répartis sur `TestServerSideRename` / `TestClientSideDetection` / `TestBackCompat` + 9 ailleurs, issus des mises à jour de constantes, regex, freeze, format, test_ssh et test_profiles). 0 régression. v0.7.x et v0.6.x restent EOL. |
| v0.10.0 | 6242 | **Première release v0.10.x (09-06-2026) — release de préparation** ouvrant la fenêtre du bundle BREAKING suivant. Livre la fondation du shim de migration des sous-checks D-4 (`bob/_v100_subcheck_renames.py::SUBCHECK_RENAMES_V100` + `matches_legacy_ignore` + `any_legacy_ignore_matches`) ainsi que le câblage de rétrocompatibilité `ignore.yml` dans `ScoreEngine.apply` (les entrées legacy v0.9.x continuent de supprimer les findings via une correspondance glob `fnmatch` contre `SUBCHECK_RENAMES_V100`, une fois que v0.10.1+ livrera les splits réels). Les deux audits sub-agent (candidats aux splits D-4 et sûreté vis-à-vis des threads pour F-1) ont tourné le 08-06-2026 avec citations `fichier:ligne` concrètes, listes de candidats classées et estimations d'effort : D-4 ≈ 20 h sur 8 splits classés (Rank 1 ssh.x11 serveur/client, Rank 2 unification de la famille DSA, Rank 3 auditd manquants par bucket, Rank 4 wildcard samba par partage, Rank 5 journald volatile vs storage_unknown, Rank 6 algorithmes de doublons firewall_rules, Rank 7 wildcard kernel_modules par nom, Rank 8 wildcard SSH crypto faible par algorithme), F-1 ≈ 6-8 h de refonte runner.py en 3 phases (Option B) + 4 nouveaux fichiers de tests de déterminisme. **Splits D-4 et implémentation F-1 différés à v0.10.1+** sous forme de patchs de durcissement. SNAPSHOT.md rafraîchi de v0.7.4 à v0.9.2 + paragraphe de préparation v0.10.0. 6242 → 6242 tests (aucun delta — la fondation du shim ne change rien au comportement visible sur les entrées `ignore.yml` existantes tant que v0.10.1 n'a pas livré le premier split). 0 régression. v0.7.x et v0.6.x restent EOL. |
| v0.9.2 | 6242 | **Ferme les deux lacunes i18n / UX documentées dans le CHANGELOG de v0.9.1 comme « différées à v0.10.0+ »**, toutes deux révélées par la campagne de tests terrain cross-distro de v0.9.0. **i18n de `BaselineLoadError`** (`bob/compare.py`) : les 4 sites de `raise` utilisaient des messages anglais codés en dur, même sur un système FR. Câble 4 nouvelles clés de locale `compare.baseline_load.{not_found, invalid_json, v1_schema, bad_shape}` (EN + FR) via le helper `bob._i18n_safe.t_or_hardcoded`. **Shim de migration de baseline entre versions** (`bob/_v090_renames.py::remap_finding_key`) : une baseline écrite par v0.7.x / v0.8.x portait des clés de finding avec les préfixes renommés en v0.9.0 D-1 (`iptables_nft.*`, `cron_audit.*`, …) ; l'audit v0.9.0+ émet les préfixes canoniques (`firewall_iptables.*`, `cron.*`, …), si bien que le diff faisait apparaître le même problème physique à la fois comme *résolu* ET comme *nouveau*. Le shim remappe legacy → canonique au chargement de la baseline, couvrant les 7 renommages D-1. Idempotent sur une entrée déjà canonique — sans effet sur les baselines v0.9.0+. **Extraction de la carte partagée** : `SECTION_RENAMES_V090` extraite de `bob/runner.py` vers `bob/_v090_renames.py` pour que `bob/compare.py` puisse la consommer sans import circulaire. `bob/runner.py` conserve l'ancien nom `_RENAMED_SECTIONS_V090` comme ré-export de rétrocompatibilité (identité d'objet vérifiée par `test_v092_baseline_i18n_and_shim.py::TestV090RenamesSharedModule`). 6212 → 6242 tests (+30 sur 4 classes : rétrocompatibilité de la carte partagée + contrat à 7 entrées ; `remap_finding_key` 8 legacy + 6 canoniques + 4 cas limites ; shim de `load_baseline` v0.7.x / v0.8.x + passe-plat v0.9.x + garde pré-v1.22 ; rendu FR de `BaselineLoadError` + présence des clés de locale). 0 régression. **v0.7.x reste EOL** (déclaré en v0.8.1) ; **v0.6.x reste EOL** (déclaré en v0.7.2). |
| v0.9.1 | 6212 | **Hotfix de l'UX du message F-3 de v0.9.0**. Le chemin de retrait de `--json-v1` appelait `i18n.t()` depuis `parse_args()`, qui s'exécute AVANT `i18n.init()` : l'utilisateur voyait donc `Error: [cli.error.json_v1_retired]` (repli entre crochets) au lieu d'un message actionnable. Reproduit 5 fois sur 5 distributions × 2 locales pendant la campagne de tests terrain cross-distro de v0.9.0 (Mint desktop, Debian 13, Kali Rolling, Mint serveur FR, Ubuntu 26.04 FR). Correctif : anglais brut en ligne dans le `raise CLIError` (conforme à la convention des 18 autres `raise CLIError` de `bob/cli.py`). Clés de locale mortes `cli.error.json_v1_retired` supprimées (EN + FR). Gardes de régression (`tests/test_v091_cli_i18n_safety.py`, +2 tests) : un balayage AST interdit tout futur appel `i18n.t()` dans `parse_args` ; un garde direct épingle le contenu du message actionnable (il doit contenir « v0.9.0 » et l'un de « json-v1 » / « schema », et ne doit PAS être un repli entre crochets). 6210 → 6212 tests. 0 régression. **v0.9.0 N'A PAS été yankée** — F-3 n'affecte que les utilisateurs passant explicitement l'option retirée `--json-v1` ; le chemin d'audit nominal n'est pas concerné. **Deux lacunes i18n documentées mais différées** à v0.10.0+ : (1) les messages de `BaselineLoadError` codés en dur en anglais (postérieurs à l'init, donc localisables) ; (2) le bruit de diff entre versions sur les clés de finding renommées par D-1 (`iptables_nft.*` → `firewall_iptables.*` fait apparaître les mêmes problèmes physiques comme résolus et comme nouveaux). Deux verrues UX cosmétiques sans aucun signal utilisateur. |
| v0.9.0 | 6210 | **Première release v0.9.x — bundle BREAKING clôturant le nettoyage architectural différé de v0.7.0 → v0.8.x.** **D-1 BREAKING** : 7 renommages de sections avec chemin d'erreur de migration ferme (`cron_audit` → `cron`, `docker_audit` → `docker_hardening`, `services_state` → `services_health`, `ports_analysis` → `ports`, `rules` → `firewall_rules`, `iptables_nft` → `firewall_iptables`, `firewall_stack` → `firewall_drivers`). Les titres d'en-tête de section sont inchangés ; la surface BREAKING est uniquement le nom de jeton visible par les scripts. Préfixes de clés de findings, espaces de noms de locale, EXPLAIN_KEYS, références CIS, overrides de profils, complétion bash et ~167 préfixes de tests : tous migrés. **F-3 BREAKING** : `--json-v1` retiré. Le schéma v2 est le seul format supporté ; `SUPPORTED_SCHEMA_VERSIONS = {"2"}` ; `_build_v1` + `_populate_v1_full_blocks` (~170 lignes) supprimés ; `tests/test_json_schema.py` retiré entièrement. **TD-1 BREAKING** : trappe `BOB_SANDBOX_LEGACY=1` retirée ; les plugins sont toujours sandboxés. 2 gardes de retrait vérifient que les helpers ne réapparaissent pas. **Nettoyage D-3** : `EXPLAIN_KEY_ALIASES` retiré, avec correction de la dérive côté source (alignement entre le nom émis par `services_state.py` et le nom de l'entrée EXPLAIN_KEYS) ; la machinerie `_warn_alias_deprecation` de v0.8.2 est supprimée. **D-2 interne** : `_SECTIONS: tuple[_Section(name, always_on), ...]` devient la source unique de vérité ; les anciens `_ALL_SECTIONS` / `_ALWAYS_ON_SECTIONS` sont des vues dérivées (rétrocompatibilité préservée). **F-2 NOUVEAU** : comparaison cross-machine `--diff [CHEMIN]`. Nouveau champ `AuditBaseline.hostname` capturé via `socket.gethostname` ; `load_baseline(path, strict=True)` lève `BaselineLoadError` sur un fichier absent, cassé ou en schéma v1, au lieu de renvoyer silencieusement None. Le `--diff` nu conserve le comportement v0.8.x sur baseline locale. Débloque : auditer l'hôte A → sauvegarder → `scp` vers B → `sudo bob --diff hostA.json` sur B. **Correction de bug** : cas `cur="="` de la complétion bash (`bob --check=<TAB><TAB>` sans sudo ne renvoyait aucun candidat) — pendant du retour arrière sur le dispatcher sudo de v0.8.2. Correction sémantique du validateur, effet de bord de D-1 : l'avertissement « sans effet » de `--skip=firewall` est restauré depuis que `firewall_iptables` et consorts ont rejoint `_ALL_SECTIONS` (la correspondance exacte always-on précède désormais la correspondance de préfixe filtrable). 6246 → 6210 tests (net −36 : −53 tests de baseline v1 et de dépréciation v0.8.2 retirés ; +17 nouveaux tests F-2). 0 régression. **v0.7.x reste EOL** (déclaré en v0.8.1) ; **v0.6.x reste EOL** (déclaré en v0.7.2). Les utilisateurs dont les scripts emploient `--check=<legacy>`, `--json-v1` ou `BOB_SANDBOX_LEGACY=1` doivent migrer. |
| v0.8.4 | 6246 | **Dernière release v0.8.x — lot de nettoyage avant le bundle BREAKING v0.9.0.** **Retrait de code mort** (`bob/checks/_run.py`) : `is_unit_enabled(name, timeout)` avait été ajouté en v0.5.0 (Phase 1 #7) comme miroir symétrique d'`is_unit_active`, et documenté dans la liste de surveillance de release comme « aucun consommateur immédiat — à réexaminer à chaque release v0.5.x ». Sept mois et quatre versions mineures plus tard : zéro consommateur dans `bob/` comme dans `tests/`, et `services.py::_detect_single_unit_state` continue d'utiliser son propre appel `_run` comme prévu. Supprimé. Les entrées de CHANGELOG historiques sont conservées comme archives exactes. **Nouveau tutoriel** (`DOCUMENTS/TUTORIAL{,_FR}.md`, 269 lignes × 2 locales) : parcours de bout en bout pour un premier utilisateur — installation → premier audit → correctifs → profils → ignore → cron et webhook → diff/historique/watch → formats machine → scénarios courants. Référencé depuis la section « Voir aussi » des `README{,_FR}.md`, en première entrée. L'item `tutorial` différé depuis le backlog v0.9.0 a été avancé en v0.8.4 parce qu'il est purement documentaire, sans aucune surface de code. **Clôtures de roadmap** : la liste de surveillance de release ouverte en v0.5.0 est close (les deux entrées sont tranchées — `is_unit_enabled` SUPPRIMÉ, `width=62` CONSERVÉ hors surveillance après sept mois de stabilité). La feuille de route de la fonctionnalité « diff du breakdown de comparaison » est abandonnée — ouverte en v0.3.0 (08-05-2026), zéro signal utilisateur sur 5 versions majeures. Règle retenue : 5 majeures de dormance sans signal = abandon plutôt que conservation indéfinie. 6246 → 6246 tests (aucun delta — le helper supprimé n'avait aucune couverture de test à retirer). 0 régression. **Suite** : bundle BREAKING v0.9.0 (D-1 + D-2 + D-4 + retrait de BOB_SANDBOX_LEGACY + checks parallèles + `--diff baseline.json` cross-machine). La branche v0.8.x est close ; d'éventuels patchs v0.8.x ne sortiront que pour des régressions de sécurité. |
| v0.8.3 | 6246 | **HOTFIX — le chemin d'audit de v0.8.2 plantait avec `UnboundLocalError` à chaque invocation autre que `--test-webhook`.** Cause racine : le handler `--test-webhook` de v0.8.2 faisait un `from bob.config import UserConfig` *à l'intérieur* de `main()`, masquant ainsi la liaison de niveau module pour tout le corps de la fonction et faisant planter le chemin d'audit avec `UnboundLocalError: cannot access local variable 'UserConfig' where it is not associated with a value`. Le même motif de masquage existait pour `os` et `traceback` dans le gestionnaire `except` de plus haut niveau. Correctif : suppression des imports locaux redondants de `UserConfig` et `os` ; promotion de `traceback` en import de portée module. **Garde de régression** (`tests/test_v083_main_scope_guard.py`, +2 tests) : un `ast.walk` statique sur le corps de `main()` vérifie qu'aucun `from`/`import` local ne relie un nom déjà importé au niveau module. Le garde d'intégration smoke-plugin-on-CI a bien attrapé le plantage en conditions réelles, mais seulement après que v0.8.2 fut déjà publiée sur PyPI — les tests unitaires ne l'avaient pas vu parce qu'ils exercent soit `--test-webhook` (qui passe par l'import local et lie donc le nom), soit un mock de `UserConfig.load` (résolu via le décorateur de mock). 6244 → 6246 tests. 0 régression. **v0.8.2 est cassée sur PyPI — les utilisateurs doivent faire `pipx upgrade bodyguard-of-bits` sans attendre.** |
| v0.8.2 | ~6244 | Patch en lot conservateur — 6 items visibles par l'utilisateur ou côté confort de développement, aucun BREAKING. **Complétion bash v0.8.2** : synchronisation de `_SECTIONS` et `_EXPLAIN_KEYS` avec l'exécution, ajout des complétions de valeurs pour `--unignore=CLÉ` / `--ignore=CLÉ` / `--explain CLÉ`, ajout de `--json-v1` et `--test-webhook` aux options longues. Plus 21 tests de garde de synchronisation et fonctionnels (`test_v082_bash_completion.py`). **Consolidation i18n** : le nouveau `bob/_i18n_safe.py` expose `make_fallback_t(labels)` et `t_or_hardcoded(key, fallback)`, et remplace 4 `_fallback_t` réimplémentés à la main plus 1 `_t_or_hardcoded` dans config/webhook/markdown_output/html_output/__main__ (source unique de vérité, sémantique « formater ou conserver le template » cohérente). **Commande de test `--test-webhook`** : POST d'une charge utile minimale étiquetée `bob_smoke_test` vers l'URL de webhook configurée, puis sortie ; réutilise toutes les gardes de validation d'URL de `send_webhook` + 4 nouvelles clés de locale EN+FR. **Descriptions de `--check=list`** : 44 sections × 2 langues = 88 descriptions techniques d'une ligne sous le nouvel espace de noms `sections.descriptions.*`. **Avertissement de dépréciation D-3** à la résolution d'`EXPLAIN_KEY_ALIASES` : un `logger.warning` unique pointant vers le nom canonique et le calendrier de retrait en v0.9.0 ; cantonné au logger pour ne pas polluer les sorties lisibles par machine. **Linter de locale** (`scripts/lint_locales.py`) : outil de développement vérifiant la parité stricte des clés EN/FR (1941 × 2, 0 dérive), la parité des jeux de placeholders, le contrat d'espaces en fin de ligne (I-2 passe 7) et la cohérence des longueurs. **D-1 / D-2 / D-4 + retrait de BOB_SANDBOX_LEGACY + checks parallèles + `--diff <baseline.json>` + tutoriel** différés à v0.9.0 comme nettoyage architectural du bundle BREAKING. 6198 → 6244 tests. 0 régression. |
| v0.8.1 | ~6198 | Maintenance mineure + cycle d'audit de durcissement approfondi. Ferme **26 paliers de lacunes** sur 3 passes d'audit sub-agent (6/7/8) et un balayage initial dérive / cadrage / lacunes fonctionnelles silencieuses. **Cycle initial (12 paliers)** : T6 couverture des sévérités par profil (desktop +24 / workstation +28 overrides) ; T10 exceptions i18n dans webhook/config/__main__ (14 nouvelles clés de locale EN+FR + motif de dictionnaire de repli issu de v0.7.2 M-4) ; **retrait BREAKING de l'alias workstation** (l'alias de v0.1.0 qui redirigeait silencieusement `bob -p workstation` vers desktop est retiré — workstation.conf devient un profil de plein droit à contexte professionnel, qui maintient backup/auditd/mac_policy en WARN tout en relâchant l'ergonomie d'usage personnel) ; T11 parité du champ `Finding.detail` en CSV et JSON v1/v2 ; T26 dispatch d'explication pour `services.exposed.<id>` via la locale `service_risk.*` existante (38 services explicables automatiquement) ; T27 parité `detail` + `note` dans la charge utile webhook (générique + Slack en ligne) ; T31/T37 rattrapage du champ `nature` sur 90 sites warn/alert (`bob --fix --apply`, filtré par `f.nature == "action"`, était silencieusement aveugle à 88 % des findings actionnables) ; T32 validation des fautes de frappe dans les profils, avec `logger.warning` sur les clés d'override inconnues ; T39 nettoyage de `service_risk.ollama_llm_server` orphelin ; T57 chemin CLI `--unignore` + helper `remove_ignore_key` + 2 clés de locale + entrée de page de man ; T60 le helper `_t_or_hardcoded` câble les préfixes `cli.error.*` dans le `catch-all` de `main()` et le chemin d'erreur de `parse_args` ; T74 masquage des identifiants dans les URL de webhook (`redact_url_credentials` retire `user:pass@` avant tout affichage sur stdout, dans le `.log` ou dans une `WebhookError`). **Passe d'audit 6 (5 constats)** : I-1 préservation des commentaires d'ignore.yml (parcours des lignes au lieu d'une réécriture canonique) ; M-1 la regex de T32 accepte les clés contenant des chiffres (`fail2ban.ssh_jail_active`, `ipv6.ufw_disabled_no_listeners`) ainsi que le préfixe permissif `file_perms.*` ; M-2 ensemble énuméré canonique de `services.exposure` et rejet des `services.exposure.<svc_id>` fantaisistes ; M-3 consolidation de la transformation `service_label_to_subkey` dans `bob/registry.py` (source unique de vérité, ferme une dérive à trois voies) ; M-4 `--unignore` documenté dans man/bob.1 + garde d'exclusion mutuelle avec `--ignore`. **Passe d'audit 7 (3 constats)** : I-1 la regex de `remove_ignore_key` s'aligne sur la grammaire du chargeur (espaces multiples et tabulation désormais supprimables) ; **I-2 dérive de typographie française du deux-points sur les préfixes T10/T60** — l'espace précédant le deux-points est maintenant intégré aux valeurs de locale, donc plus de double deux-points du type `« Avertissement : échec du webhook: … »` ; M-1 réécriture de la description de `--show-ignored` dans man/bob.1. **Passe d'audit 8 (5 constats)** : I-1 unification de `_KEY_LINE_RE` (abandon de l'ancre `\s*$` pour que le chargeur voie les entrées suivies d'un commentaire en ligne ; la regex sœur de la passe 7 était du code mort masqué par une garde défensive) ; I-2 les 3 préfixes `Warning:` codés en dur de `runner.py` sont passés en i18n via `cli.error.warning_prefix` et `cli.runner.*` (6 nouvelles clés de locale EN+FR) ; M-1 retrait du fantôme `--webhook-secret` de `_VALUE_TAKING_OPTS` ; M-2 restriction des variantes `_ufw_inactive` à `(no_rule, loopback_no_rule)` ; M-3 test épinglant le contrat d'espaces en fin de valeur de `t()` (protège I-2 de la passe 7). **Plus** : le `_ensure_i18n_initialised_for_tests` en autouse de `tests/conftest.py` reproduit l'invariant de production. ~190 tests dédiés à v0.8.1 sur 8 fichiers. 5521 → 6198 tests. 0 régression. |
| v0.8.0 | ~6008 | Majeure mineure — lot de dérive + actions de cadrage + audit des lacunes fonctionnelles silencieuses. Clôt le cycle v0.7.x (4 patchs de durcissement v0.7.1→v0.7.4) et ouvre v0.8.x. **Lot de dérive (11 items)** resynchronisant toutes les surfaces doc/packaging en retard : rattrapage du CHANGELOG FR v0.7.0→v0.7.4 (5 entrées), pages de man bumpées, badges bumpés, debian/changelog et %changelog rpm rattrapés, TESTING.md rattrapé, section Install des README.md et README_FR.md synchronisée avec le parcours en 4 sous-étapes de README_TECH, nouveau `tests/test_runner.py` en smoke sur l'orchestrateur `_sec()`, nouveau 5e garde CI `tests/test_doc_version_consistency.py` (7 surfaces documentaires contre pyproject), `__version__ = "1.14.0"` orphelin retiré de `bob/checks/__init__.py`, `BOB_DEBUG` documenté dans `SECURITY.md`. **Actions de cadrage** : A1 = la boîte de résumé s'ouvre sur une ligne « Hypothèses : profil=X | contexte=Y | posture=Z » (display.py) ; A2 = nouvel encart « Ce que BOB est / n'est pas » dans README{,_FR} et SECURITY{,_FR}. **Audit des lacunes fonctionnelles silencieuses (8 paliers)** — **T1** +51 entrées `--explain` pour des findings WARN/ALERT jusque-là non couverts, ouvrant 15 nouveaux préfixes (`backup, ddns, docker, fail2ban, firewall_stack, iptables_nft, log_rotation, logs, mac_policy, network_context, ntp, ports, rootkit, services, smtp`) ; référence EXPLAIN_KEYS 117/30 → **168/45**. **T1bis** ajout du champ `_BadDirective.cmd_template` ; 8 directives SSH livrent désormais un `cmd=` (PermitEmptyPasswords/X11Forwarding/IgnoreRhosts/HostbasedAuthentication/PermitUserEnvironment/StrictModes/AllowTcpForwarding/PubkeyAuthentication). **T2** services.json 32 → **38** avec Tailscale/Caddy/AdGuard Home/Vaultwarden/Ollama/Authelia. **T3** rattrapage de `warn_with_deduction` : `services.state.installed_inactive_critical` +1 pt, `services.state.active_disabled` +1 pt, `firewall.policy_unknown` +2 pts, `virt.snap_network` plafonné à 2 pts cumulés. **T4** 5 rattrapages de locale `service_risk.*` (SMTP/NFS/Jenkins/OpenVPN/Squid). **T7** renommage de clé de profil `hardening.auto_updates_missing` → `updates.unattended_not_configured` (la clé réellement émise). **T9** parité de format Markdown et HTML pour `Finding.detail` et `Finding.note` (auparavant limités au terminal, au JSON et au texte). **Différés à v0.8.1** : T6 audit de couverture des sévérités par profil, T10 i18n de 27 messages d'exception anglais codés en dur. Le contrat D-1..D-4 reste ouvert pour la suite de v0.8.x. +487 tests sur l'ensemble du lot. 5521 → ~6008 tests. 0 régression. |
| v0.7.4 | 5521 | Quatrième patch de durcissement v0.7.x — seconde passe d'audit approfondi après v0.7.3. Lot agressif (6 importants + 8 mineurs livrés, aucun report). **I-1** fuites de sortie sous `--quiet` verrouillées sur 4 sites d'affichage (`exposed_ports` Docker / `display_geoip_notice` / `display_ports_overview` / `display_log_results`). **I-2** i18n des libellés d'interface `--explain` (18 nouvelles clés `explain.ui.*`). **I-3** i18n des flux CLI de `__main__` (`--check=list` / `--ignore` / `--reset-baseline` / `--diff` sans baseline). **I-4** symétrie du schéma webhook : `config.py::set_webhook_url` devient insensible à la casse (miroir de v0.7.3 I-5). **I-5** retrait de `services.py::_PRIVATE_ADDR` → délégation aux helpers de sysinfo (restaure l'invariant de v0.5.6). **I-6** alignement du champ CSV `risk` sur le JSON v1 (format de sortie BREAKING). **M-2** UX de la valeur manquante en CLI (frozenset `_VALUE_TAKING_OPTS`). **M-3** piège du deux-points final dans le PYTHONPATH de cron. **M-4** i18n des WARN du sandbox + `key=` (9 nouvelles clés `plugin.sandbox.*`, `--ignore` fonctionne). **M-5** dictionnaire `labels=` pour `report.py::write_header` (motif de v0.7.3 M-5). **M-7** json_output utilise le cache `engine.domain_scores`. **M-8** `set_posture_from_engine` rejette les sous-classes booléennes d'int. +19 tests (1 parité CSV/JSON v1, 1 symétrie de schéma webhook, 4 affichage sous quiet, 9 UX de valeur manquante en CLI, 1 PYTHONPATH cron, 3 épinglages de set_posture). 5502 → 5521 tests. 0 régression. |
| v0.7.3 | 5502 | Troisième patch de durcissement v0.7.x — passe d'audit approfondi complète (sub-agent + 14 correctifs + 5 écartés à raison). **I-1** locale FR « finding » → « découverte ». **I-2** `completion.py` ne validait pas SUDO_USER (KeyError sur une valeur malformée) → protégé par regex + `try/except`. **I-3** colonne CSV `section` → `nature` (format de sortie BREAKING). **I-4** 3 `input()` nus → `safe_input()` dans manage_logs. **I-5** schéma d'URL webhook insensible à la casse (RFC 3986). **I-6** convergence de l'idiome de garde de niveau entre markdown et html. **M-2** forme séparée par une espace `--lang VALEUR` acceptée. **M-3** `bob -e ""` : clé vide rejetée. **M-4** durcissement d'argv (`-w` / `--ignore` / `--output-dir`). **M-5** i18n des libellés de champs de `report.py` (OK/Avertissement/Alerte/Score/Risque/Contexte). **M-6** correction du double échappement des caractères d'URL dans `_inline_format`. **M-10** extraction du helper `set_posture_from_engine`. **M-11** suppression défensive des CRLF dans `send_html_email`. **M-12** libellé de risque traduit dans html_output (badges FR). +12 tests (1 renommage CSV, 3 insensibilité à la casse du schéma webhook, 6 durcissement d'argv CLI, 2 traduction du niveau de risque HTML). 5490 → 5502 tests. 0 régression. |
| v0.7.2 | 5490 | Second patch de durcissement v0.7.x — ferme les 6 mineurs différés par v0.7.1 et formalise la fin de vie de v0.6.x. **M-4** extraction i18n des exports Markdown et HTML (24 + 22 nouvelles clés de locale, avec repli anglais optionnel via `t=None`). **M-6** sysinfo accepte une IP publique IPv6 (`ipaddress.ip_address()` remplace la regex limitée à IPv4). **M-7** collision de fichier temporaire dans `_atomic.py` en écriture concurrente (`tempfile.mkstemp`). **M-8** `SCHEMA_*_KEYS` câblés comme invariants réellement vérifiés. **M-9** texte d'aide de `--json-full --json-v1`. **M-10** dédoublonnage des chemins de détection de posture dans `display.py` (helper `_compute_posture_annotation`). v0.6.x officiellement déclarée EOL dans `SECURITY.md` et `SECURITY_FR.md`. +11 tests (4 épinglages SCHEMA, 3 i18n Markdown, 4 i18n HTML). 5479 → 5490 tests. 0 régression. |
| v0.7.1 | 5479 | Premier patch de durcissement v0.7.x — suivi le jour même de la v0.7.0 finale. 4 importants + 3 mineurs livrés. **I-1** dérive de contrat du mode watch : `bob --watch` créait un `ScoreEngine()` neuf à chaque itération mais n'appelait jamais `set_posture()` ni ne posait `ignore_keys`. **I-2** dérive de signature de `MarkdownReport.write_summary` (le kwarg `posture_annotation` est ajouté au Protocol et à l'implémentation). **I-3** rupture de format du champ `risk` en JSON v1 — la v0.7.0 était silencieusement passée d'`engine.level` à `engine.effective_level` ; retour en arrière pour préserver le contrat de mise en forme v0.6.x. **I-5** URL de webhook en clair acceptée — `http://` est désormais rejeté par défaut ; dérogation via `BOB_WEBHOOK_ALLOW_INSECURE=1`. **M-1** `from typing import Any` inutilisé. **M-2** `_atomic.py` fsync(fd) + fsync(dir_fd). **M-5** `--ignore=CLÉ` valide la clé contre le motif canonique d'EXPLAIN_KEYS avant écriture. +13 tests (5 validation d'ignore, 1 espion sur fsync, 2 rejet http du webhook, 3 parité MarkdownReport, 2 propagation en mode watch). 5466 → 5479 tests. 0 régression. |
| v0.7.0 | 5466 | Bump majeur — ouvre la branche stable v0.7.x. Regroupe le cycle de bêtas b1+b2+b3+b4 en trois phases thématiques. **Phase 1 (T1 Fondation)** : Python 3.14 ajouté à la matrice CI ; nouveaux `ScoreEngine.set_posture()`, propriété `effective_level` et bloc `posture_escalation` ; nouvelle clé EXPLAIN `risk.escalated_posture`. **Phase 2 (T2 Schéma v2)** : `build_json_data(..., schema_version="2")` devient le défaut ; `--json-v1` préserve exactement la mise en forme v0.6.x ; référence EXPLAIN_KEYS = 117 clés / 30 préfixes / 100 % de conformité. **Phase 3 (T3 bac à sable des plugins)** : nouveau `bob/_sandbox.py` (~900 LoC) — isolation de processus via `mp spawn`, timeout mural de 5 s + RLIMIT_AS=256 Mio + RLIMIT_CPU=10 s, liste blanche d'imports, `__builtins__` restreints, wrapper `open()` refusant les écritures et la lecture de chemins sensibles, retrait extensif d'attributs `os` (84 attributs), aller-retour en dict JSON-safe à travers `mp.Queue`. Modèle de menace recadré honnêtement dans SECURITY.md — un bac à sable Python in-process n'est **pas** une frontière de sécurité (PEP 416) ; le profil AppArmor est la vraie frontière. 4 gardes d'ingénierie de release ajoutés en cours de route : integration-first, smoke-after-commit, version-consistency, smoke-plugin-on-CI. +75 tests sur l'ensemble du cycle (15 bêtas + épinglages de durcissement du bac à sable + version-consistency + smoke-plugin). 5391 → 5466 tests. 0 régression. v0.6.x EOL. |
| v0.6.2 | 4600 | **Hotfix de packaging critique.** Toutes les wheels depuis la v0.6.0 étaient dépourvues des sous-paquets `bob/checks/ssh/` et `bob/cron/` — les deux splits introduits par la v0.6.0. Les utilisateurs ayant fait `pipx upgrade` se heurtaient à un `ModuleNotFoundError` à chaque invocation. Cause racine : `pyproject.toml [tool.setuptools.packages.find].include` était une liste littérale `["bob", "bob.checks", "bob.tui"]` héritée d'un audit de packaging v0.4.x. Les splits de v0.6.0 ont ajouté `bob.checks.ssh` et `bob.cron`, mais la liste n'a pas été mise à jour. Pourquoi personne ne l'a vu : les tests unitaires et le smoke de pré-livraison tournaient depuis l'arbre source (la résolution de `sys.path` contourne la configuration de packaging) ; la CI utilisait `pip install -e .` (le mode editable contourne entièrement la découverte par `find_packages`). Correctif : `include = ["bob*"]`, un glob qui découvre automatiquement tout sous-paquet `bob.*` présent et futur. CI durcie : les jobs d'`integration.yml` utilisent désormais `pip install .` (non-editable, ce qui construit et installe une vraie wheel), plus une nouvelle étape de smoke explicite important chaque module ajouté en v0.6.x (`bob.checks.ssh`, `bob.cron`, `bob._atomic`, `bob._tty.safe_input`), de sorte qu'un module absent de la wheel se manifeste dès l'installation en CI. Aucun changement de code hormis la configuration de packaging (1 ligne) et le garde de workflow (~15 lignes). **4600 tests inchangés.** Contrat JSON, EXPLAIN_KEYS, format de sortie : tous préservés. Utilisateurs en v0.6.0 / v0.6.1 : faire `pipx upgrade bodyguard-of-bits` vers la v0.6.2 pour réparer l'installation cassée. |
| v0.6.1 | 4600 | Première release hardening sur la branche v0.6.x. Sub-agent d'audit profond a remonté 14 findings (0 critique + 6 important + 8 mineur) ; 6 important + 4 mineur shippés. **Consolidation contrat atomic-write** : extraction `bob/_atomic.py::atomic_write(path, content, *, mode=)` source unique ; migration 5 implémentations hand-rolled + fix 4 sites non-atomiques (`bob/cron/_install.py`, `bob/tui/cron.py` paths d'install, `bob/ignore.py`, `bob/history.py` first-write). **Contrat EOF complet** : nouveau `bob/_tty.safe_input()` + `prompt_wizard()` catche maintenant EOFError ; 11 sites `input()` brut migrés. **I-3** `_validate_cron_field` borne les step values (`*/200` pour minute 0-59 était accepté). **I-4** `shlex.quote()` appliqué sur 8 sites `cmd=` avec paths user-contrôlés. **I-5** `history.jsonl` mode `0o600` au first-write. Mineurs : M-2/M-3/M-6/M-8 (4 mineurs déférés à judgment-call). +17 tests régression à travers `tests/test_atomic_v061.py` (12 : TestAtomicWritePublicAPI, TestCronLegacyAliasStillWorks, TestHistoryFileMode, TestIgnoreAtomic, TestSafeInput) et `tests/test_cron.py::TestStepBoundedToFieldRange` (5). 4583 → 4600 tests. Contrat JSON préservé. Sortie wire inchangée (seul `--watch=N` error string diffère). Deux contrats uniformément enforced (atomic-write + gestion EOF). |
| v0.6.0 | 4583 | **Bump majeur** ouvrant la branche v0.6.x. Deux splits architecturaux (`bob/checks/ssh.py` 1296L → package `bob/checks/ssh/` 4 modules ; `bob/cron.py` 1204L → package `bob/cron/` 4 modules) délibérément déférés tout au long du cycle v0.5.x, les deux contract-preserving via re-exports `__init__.py`. Plus le sunset env var legacy `UFW_AUDIT_SHARE` honoré (annoncé "REMOVED in v0.6.0" en v0.5.4). Trois updates triviaux d'infrastructure test : `tests/test_template_vars_migration.py` et `tests/test_domain_scores_mapping_complete.py` switchés de `glob` à `rglob` pour que les AST scanners pickup les nouveaux sous-modules de check-package ; `tests/test_cron.py::TestApplyCronScheduleAtomic` target patch shifté de `bob.cron._atomic_write` (re-export package) à `bob.cron._io._atomic_write` (où `apply_cron_schedule` appelle effectivement). 4583 tests inchangés (0 ajouté, 0 retiré — splits + sunset sont wire-équivalents). Le plus gros module post-split est `ssh/_subchecks.py` à 529L, bien sous le soft ceiling 1000-LoC du projet. Toutes les API publiques v0.5.x préservées via re-exports. Contrat JSON, EXPLAIN_KEYS, keybindings, fallback no-curses, exit codes — tous préservés. Ferme le roadmap architectural déféré depuis v0.5.x. |
| v0.5.8 | 4583 | Cleanup des 5 mineurs cosmétiques explicitement déférés par v0.5.7 (M-2, M-5, M-6, M-7, M-8). **M-2** cursor-shift de `manage_logs.py` après delete traque maintenant `deleted_before_cursor` séparément donc le cursor ne shift que par les deletions à-ou-avant la position active (pré-fix `cursor -= deleted` shiftait par le total même quand la plupart des items supprimés étaient après le cursor). **M-5** tuple unpack local du wizard schedule `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` promu en `_Schedule(IntEnum)` module-level avec noms explicites `DAILY`/`WEEKDAYS`/`MONTHDAYS`/`CUSTOM` — IntEnum préserve la sémantique `choice == _Schedule.X` donc wire-équivalent. **M-6** sentinelle `summary_start: int \| None = None` de `_extract_summary_view` remplace le check truthy `summary_start = 0` — gère le edge case unreachable-en-pratique où SEP62 est à la ligne 0. **M-7** nouveau helper `_is_finding_continuation(line)` stoppe le grouping 4-space-indent aux markers de finding (`[ALERT]`/`[WARN]`/`[OK]`/`[INFO]`) et aux délimiteurs de section (`┌`/`└`/`│`/`━`/`╔`/`╠`/`╚`/`║`) — défense contre le grouping over-greedy de contenu indenté ultérieur. **M-8** `from datetime import datetime` remonté au niveau module dans `bob/cron.py` et `bob/tui/cron.py`, 3 imports locaux retirés (aussi retiré 2 `import os` / `from pathlib import Path` locaux redondants dans `_run_install_cron_plain`). +12 tests régression à travers `tests/test_cron.py` (TestScheduleIntEnum, TestDatetimeImportLifted) et `tests/test_manage_logs.py` (TestCursorShiftAfterDelete, TestSummaryStartSentinel, TestIsFindingContinuation). Release single-commit. Contrat JSON préservé. Sortie wire inchangée. **Ferme la campagne deep-audit v0.5.x — branche intégralement auditée (25 modules deep + ~25 spot-checkés, 0 finding critique en suspens).** Prochaine version mineure (v0.6.0) réservée pour #13 (split ssh.py) et #14 (split cron.py). |
| v0.5.7 | 4571 | Passe de hardening ciblée sur TUI curses (`bob/manage_logs.py` 999 LoC + `bob/tui/cron.py` 920 LoC = ~1920 LoC) — bucket explicitement déféré par les audits v0.5.5 / v0.5.6. 11 findings du sub-agent focalisé : 0 critique, 3 important (I-1 `_curses_readline` acceptait les codes keypad curses `KEY_*` via `chr(ch_i)` insérant glyphes Grecs dans les buffers d'entrée TUI — UX-corrompant seulement grâce à validation downstream ; I-2 trois sites `input()` bruts dans `manage_logs.py` ne catchaient pas `EOFError` — Ctrl-D dumpait une traceback Python ; I-3 `apply_cron_schedule` utilisait `os.open(O_TRUNC) + write` brut au lieu de `_atomic_write` — coupure de courant entre truncate et write viderait silencieusement le fichier cron et dropperait l'entrée, asymétrique avec `apply_cron_email` qui utilisait déjà l'écriture atomique), 3 mineurs (M-1 status `deleted_one` flashait mauvais nom de fichier sous échecs unlink sélectifs, M-3 dead-code elif body simplifié, M-4 `from bob.cron import` dupliqué consolidé). +11 tests régression à travers `tests/test_cron.py` (TestApplyCronScheduleAtomic, TestIsPrintableInputChar) et `tests/test_manage_logs.py` (TestEOFErrorOnPromptPath, TestEOFErrorOnMoveConfirm, TestEOFErrorOnDeleteAllConfirm, TestDeletedOneCorrectName). Release single-commit. Contrat JSON préservé. Deltas UX-visibles seulement : sortie Ctrl-D propre (pas de traceback), touches fléchées/fonction n'impriment plus de glyphes Grecs dans les prompts TUI. 5 mineurs cosmétiques (M-2, M-5, M-6, M-7, M-8) explicitement déférés à v0.5.8. Après v0.5.7, campagne deep-audit v0.5.x fermée (25 modules audités + ~25 spot-checkés). |
| v0.5.6 | 4560 | Passe de hardening ciblée sur `bob/checks/logs.py` (662 LoC parser UFW logs) — module explicitement déféré par l'audit v0.5.5 à cause densité regex. 10 findings sub-agent focalisé : 0 critique, 2 important (I-1 regex `_PRIVATE_IP` incohérente avec sysinfo — manquait CGNAT 100.64/10 + IPv6 link-local fe80::/10 + faux positifs sur strings `fc`/`fd` ; I-2 year-rollover droppait silencieusement événements syslog 1s en avance de l'horloge), 8 mineurs (M-1 variante IPv6 `[UFW BLOCK6]` silencieusement ignorée, M-2 regex `_count_available_days` restreinte mois anglais, M-3 ordre paths GeoIP City-avant-Country, M-4 consistance symlink `geoip2_status`, M-5 `_GEO_CACHE` borné 2048 éviction FIFO, M-6 arithmétique binaire `tell()`/`seek()`, M-7 `subprocess.TimeoutExpired` redondant retiré, M-8 `proto.upper()` au parse-time). +15 tests régression dans `tests/test_logs.py` (4 nouvelles classes : `TestPrivateIPDispatch`, `TestParseTimestampYearRollover`, `TestBlockPrefixMatcher`, `TestProtoNormalisation`). Single-module pass, single commit. Contrat JSON préservé. Sortie wire : deltas étroits seulement sur hosts émettant `[UFW BLOCK6]` (maintenant comptés) ou avec syslog locale non-anglais (maintenant `days_available` exact). |
| v0.5.5 | 4545 | Passe de hardening — post-v0.5.4 audit par un sub-agent général-purpose profond. **4 bugs réels** (C-1 bug mode `apply_cron_email` cassant les audits programmés, C-2/C-3 cmds `password_policy` non-fixables par `--fix --apply` à cause de `&&`/flèche Unicode, C-4 drift `EXPLAIN_KEYS` pour `services_state`), **4 security smells** (I-1 `recurrence.json`+`ignore.yml` écrits world-readable au lieu de 0o600, I-2 déductions post-`finalize()` bypassant les caps silencieusement, I-3 `_safe_url` ne re-escapait pas le contexte attribut HTML autorisant XSS dans rapports email, I-4 `_PRIVATE_IPV4_RE` brittle + cassure widening stdlib Python 3.12+), **11 cleanups mineurs** (M-1 dedup regex email, M-2 `_NullReport` → canonique `bob.report.NullReport`, M-3 3 clés locale mortes, M-4 check fail2ban asymétrique `corr.fully_blind`, M-7 extract helper `_has_actionable_findings`, M-8/M-9 commentaires clarifiants, M-10 ancre regex cron plus stricte, M-11 split cmd `&&` `services_state.service_inactive`). +7 tests régression couvrant chaque classe de fix. Commit cosmétique M-6 migre typing `Optional[X]` / `List[X]` sur 18 modules. **Diff net : 23 fichiers code, +312 / -112 = +200 LoC.** Changement wire visible sur hosts sans pwquality : finding password_policy se déplace de "À corriger" à "Améliorations possibles" (nature='action' → 'improvement'). Score global inchangé. |
| v0.5.4 | 4538 | Refactor v0.5.x Phase 5 sur 5 (finale) — **#6 helper `prompt_wizard()`** dans `bob/_tty.py` + 10 sites migrés dans `bob/cron.py` (wizards install + edit) + **#9 sunset `UFW_AUDIT_SHARE`** (`logger.info` → `logger.warning` avec message explicite "REMOVED en v0.6.0") + **#15b mapping `_PREFIX_TO_DOMAIN` explicite** (`fail2ban` → ssh, `virt` → hardening, `docker_audit` → hardening) + **cache APT option C** (nouvelle feature métier : ligne INFO `updates.apt_cache_age` permanente quand aucune mise à jour security/regular en attente et cache sous le seuil obsolète, ferme le gap d'observabilité remonté par le test terrain VM Ubuntu v0.5.3). **Zero delta de tests** — Phase 5 est contract-preserving comme les Phases 2-4. 3 entrées de test retirées de `_CATCH_ALL_BY_DESIGN` dans `tests/test_domain_scores_mapping_complete.py` (reflet de la migration de prefixes #15b), mais aucun test ajouté ou supprimé. Le test scan AST `#15a` continue de pin chaque prefixe de clé émis. **#13 (split ssh.py, 1324 LoC) et #14 (split cron.py, 1223 LoC) déférés à v0.6.0** selon le principe conservative-refactor. Diff net : 12 fichiers code modifiés, +118 / −69 = +49 LoC. Ferme l'audit v0.5.x (13/15 findings shippés + 1 feature métier + 2 déférés avec justification). |
| v0.5.3 | 4538 | Refactor v0.5.x Phase 4 — **#5 table dispatch `_LEVEL_DISPATCH`** dans `display_result` (cascade 4-branches OK/WARN/ALERT/INFO → boucle déclarative pilotée par dataclass `_LevelTraits`) + **#12 split `print_audit_summary`** en 3 helpers module-level (`_summary_header_lines`, `_summary_findings_lines`, `_summary_breakdown_lines`) + `_add_finding_lines` remonté d'inner closure à module-level + **#8 retrait `CheckResult.log_data`** (dict escape hatch → tuple return `check_logs(...) -> (CheckResult, LogReportData | None)` avec dataclass frozen `LogReportData`). **Zero delta de tests** — refactor purement structurel, sortie wire bit-identique à v0.5.2. 3 tests renommés (`test_log_data_*` → `test_report_data_*`) et réécrits pour accès attribut dataclass au lieu d'accès dict-clé ; ~20 sites tests utilisent `result, _ = check_logs(...)` tuple unpack. Side-fix lors de #12 : `report.write_summary(score=score, risk_level=level_str, network_context=ctx_str, ...)` référait des locals devenues dead après l'extraction du header ; remplacées par expressions directes sur `engine.score` / `t(f"scoring.level.{engine.level.value}")` — attrapé par les tests `TestScoreTrend` (8 failures → 0 après fix). Diff net : display.py +23 LoC, logs.py +19 LoC, runner.py 0, scoring.py −1, tests +3 = **+40 LoC total**. |
| v0.5.2 | 4538 | Refactor v0.5.x Phase 3 — **#4 table directive SSH** (8 directives uniformes migrées vers table `_BAD_DIRECTIVES`) + **#3 extension runner._sec** avec callbacks `skip_if=` / `post_display=` (4 blocs inline migrés). **Zero delta de tests** — refactor purement structurel. La dataclass `_BadDirective` + table + helper `_apply_bad_directive()` produit des findings et déductions bit-identiques aux if-blocks impératifs précédents. L'extension `_sec` est keyword-only (call sites existants inaffectés). `test_ssh.py` (122 tests) a passé avant et après la migration. Diff net : ssh.py +56 LoC (table verbose), runner.py −29 LoC. **#13 (split ssh.py) déféré Phase 5** — ssh.py reste à 1324 LoC (cible <1000 non atteinte). |
| v0.5.1 | 4538 | Refactor v0.5.x Phase 2 — gros gain LoC. Nouveaux helpers `CheckResult.warn_with_deduction()` + `.alert_with_deduction()` collapsent 120 sites paired `warn`+`add_deduction` dans 27 fichiers check. **Zéro delta de tests** — chaque appel helper invoque en interne la séquence existante `warn`/`alert` + `add_deduction`, produisant des sorties `Finding` + `Deduction` bit-identiques. Les 4538 tests pinnent la sortie wire (messages findings, raisons déductions, template_vars, préfixes clés, refs CIS) — tous préservés. Chacune des 6 vagues de migration (fichiers 1-site → 2-site → 3-site → 4-6 site → hardening → ssh.py) a passé `pytest tests/` avant de continuer. Diff net : 37 fichiers modifiés, +483/−1002 = −519 lignes. |
| v0.5.0 | 4538 | Refactor v0.5.x Phase 1 (+39 tests) — **+4** dans le nouveau `tests/test_domain_scores_mapping_complete.py` (scan AST de `bob/checks/*.py` pour les préfixes de clés non-mappés, protège le catch-all `_PREFIX_TO_DOMAIN` du drift silencieux). **+35** dans `tests/test_cron.py` couvrant 5 helpers purs jusque-là non testés : `TestValidateCronField` (13), `TestValidateCustomCron` (7), `TestBuildScriptContent` (7), `TestApplyCronSchedule` (3), `TestApplyCronEmail` (5 — incl. parité legacy `NOTIFY_EMAIL=`). **Bug latent corrigé** : `apply_cron_schedule()` référençait `_os.open` (non défini au niveau module) — l'extraction de déduplication v0.4.8 avait raté le renommage ; les nouveaux tests ont remonté le NameError au premier run. Tests dans `test_fail2ban.py` et `test_ntp.py` adaptés pour patcher `is_unit_active` en parallèle de `_run` (refactor #7). |
| v0.4.8 | 4499 | Release de hardening — passe sub-agent code-review n°4 (4 important + 5 mineur + 3 suggestion findings) + audit approfondi pyproject.toml (6 fixes). **−1 test (4500 → 4499) :** suppression de `test_default_method_is_none` dans `test_secure_boot.py` après retrait du champ mort `method: str` de `SecureBootSnapshot`. Les autres retraits de champs morts (`ssh.config_source_files`, `firewall.ipv4_rules_count`/`ipv6_rules_count`, `samba.min_protocol`, `clamav.db_path`/`last_scan_log_path`) ont vu leurs tests associés mis à jour pour retirer les kwargs devenus invalides. Aucun nouveau comportement, nettoyage contract-preserving. |
| v0.4.7 | 4500 | Release de maintenance — audit cross-doc (24 corrections / 8 fichiers) + harmonisation jauges UI + refonte bash completion (fix critique de la complétion de valeurs `--xxx=<TAB>` via convention args positionnels) + automatisation CI de la Release GitHub. Aucun nouveau test ; 3 tests dans `test_breakdown.py::TestBar` adaptés pour stripper les codes ANSI avant comparaison (les barres sont maintenant des strings colorés, plus juste `█░░░░░░░░░` brut). |
| v0.4.6 | 4500 | Correctifs passe terrain v0.4.5 (+11) : `TestParseInstalledKernels` (+5 — filtrage statuts `ii`/`rc`/`pn`/`un`/`iU`, `hi` hold gardé, format legacy+préfixé mixte) · `TestActiveDomainsIncludesOK` (+6 dans test_domain_scores — OK promeut, INFO non, scénario remédiation Debian 13 complet attendu à global=9 au lieu de 8). CI multi-distro ajoutée (purement additive, non comptée comme tests unitaires). |
| v0.4.5 | 4489 | Hardening de l'infrastructure de tests (0 nouveau test, pur refactor de `tests/test_locale_coverage.py`) : scan regex → parsing AST (`ast.walk` + `ast.Call` + `ast.Name`). Élimine les faux positifs sur docstrings, la fragilité multi-lignes des call sites, et les edge cases d'appels d'attribut `obj._t(...)`. Allowlist `_KEY_EXCLUSIONS` supprimée. Mêmes 9 tests, même contrat externe. |
| v0.4.4 | 4489 | Hardening terrain cross-distro (+21) : couverture du bug critique `updates.py` (sémantique `-s dist-upgrade`, détection cache obsolète, cross-check vs `apt list --upgradable`) ; clé AppArmor 0-profil ; skip SMART all-virtuel ; ports DDNS inline ; nouveau `test_locale_coverage.py` en forme regex initiale (attrape la classe de régression `[xxx.yyy]`). |
| v0.4.3 | 4468 | Rattrapage doc + passe hardening post-audit (+16) : régression firewall EXPLAIN_KEYS, couverture dead-attr HardeningSnapshot `--json-full`, `strptime("%b…")` indépendant locale (ssl_certs + logs), faux positif `_is_covered_by_ufw` IP, validateur range cron hors bornes, markdown email non échappé HTML. |
| v0.4.2 | 4452 | Phase 3 distro-ready (discipline packaging) + passe de hardening pré-release — 2 critiques + 5 importants + 4 mineurs corrigés depuis audit agent. +3 tests dans nouveau `test_template_vars_migration.py` |
| v0.4.1 | 4449 | Phase 2 distro-ready (+19) : extraction `bob/tui/cron` (0 nouveau test — couvert par l'existant) · intégration `--offline` (+3 dans `test_webhook.py`) · `test_formatter.py` (14 nouveaux — reconstruction indépendante de la locale + 4 edge cases post-revue) · `test_json_schema.py` (+2 — exposition champ `template_vars`) |
| v0.4.0 | 4430 | Phase 1 distro-ready (+82) : `TestDetectSystemLang` (12) · `TestExplainKeyAliases` + `TestExplainKeyFreezePolicy` (6) · `test_json_schema.py` (17 — incl. strict-set + defense-in-depth contre dérive des constantes) · `test_services_schema.py` (43 — incl. `$defs`, regex port stricte 1–65535, contraintes métier, wrapper plugin-file, `minItems: 1` sur services-list) · 4 intégration locale CLI |
| v0.3.6 | 4348 | Aucun nouveau test — passe code review (`Path.home()` sudo-aware, ULA IPv6, SSH `local`, imports/locales morts) |
| v0.3.5 | 4348 | Aucun nouveau test — refactoring pur (`runner.py` closure `_sec`, `ssh.py` helper `_check_weak_algo`) |
| v0.3.4 | 4348 | Aucun nouveau test — hotfix uniquement (`user_config` NameError sur whitelist SUID) |
| v0.3.3 | 4348 | +7 nouveaux, −6 retirés (TestWasCapped → TestCappedIndices) : `TestCappedIndices` dans test_domain_scores |
| v0.3.2 | 4347 | +21 nouveaux (whitelist utilisateur), −2 retirés (code mort DC-1) : `TestFromSystemUserWhitelist` · `TestGetSuidWhitelist` · `TestGlobMatching` dans test_suid_audit |
| v0.3.1 | 4328 | +6 nouveaux tests : `TestWasCapped` dans test_domain_scores · drapeau `was_capped` · propriétés mises en cache du moteur |
| v0.3.0 | 4322 | +48 nouveaux tests : affichage de `--breakdown` · scénarios de scoring de référence · 16 dans test_breakdown · 32 dans test_golden_scenarios · 1 renommé dans test_min_level |
| v0.2.4 | 4274 | +12 nouveaux tests : UX des noyaux Debian `-unsigned` · sentinelle `deduction_total` à None · 2 dans test_kernel_modules · 10 dans test_compare |
| v0.2.3 | 4262 | +1 nouveau · 4 renommés : NOT_LISTENING en INFO · IoT sans déduction · séparation du libellé « SSH arrêté » |
| v0.2.2 | 4255 | +17 nouveaux tests · 2 mis à jour : `TestStatFallback` · `TestScoringInvariants` · correction des règles orphelines sur port nu · ClamAV 1 pt · `ScoreCap.key` · domaines INFO exclus |
| v0.2.0 | 4238 | +32 nouveaux tests · 3 corrigés : refonte du scoring · détection du MTA cron · faux positif noyau `-unsigned` · dominance IoT dans les logs en WARN |
| v0.1.1 | 4206 | +4 tests de régression : sortie au format arbre de fwupd 1.9+ (parseur `├─`/`└─`) — bug trouvé sur Ubuntu 26.04 LTS |
| v0.3.3  | 4348  | +7 nouveaux −6 supprimés (TestWasCapped → TestCappedIndices) : `TestCappedIndices` dans test_domain_scores |
| v0.3.2  | 4347  | +21 nouveaux (whitelist utilisateur) −2 supprimés (DC-1 code mort) : `TestFromSystemUserWhitelist` · `TestGetSuidWhitelist` · `TestGlobMatching` dans test_suid_audit |
| v0.3.1  | 4328  | +6 nouveaux tests : `TestWasCapped` dans test_domain_scores · flag was_capped · propriétés moteur en cache |
| v0.3.0  | 4322  | +48 nouveaux tests : affichage `--breakdown` · scénarios golden scoring · 16 dans test_breakdown · 32 dans test_golden_scenarios · 1 renommé dans test_min_level |
| v0.2.4  | 4274  | +12 nouveaux tests : UX kernel Debian -unsigned · sentinel None deduction_total · 2 dans test_kernel_modules · 10 dans test_compare |
| v0.2.3  | 4262  | +1 nouveau · 4 renommés : NOT_LISTENING INFO · IoT sans déduction · label SSH arrêté scindé |
| v0.2.2  | 4255  | +17 nouveaux tests · 2 mis à jour : `TestStatFallback` · `TestScoringInvariants` · fix règle UFW sans protocole · ClamAV 1pt · `ScoreCap.key` · domaines INFO exclus |
| v0.2.0  | 4238  | +32 nouveaux tests · 3 corrigés : `_strip_unsigned` · `_detect_mta` · `set_global_score` · plafonds par outil · dominance IoT WARN |
| v0.1.1  | 4206  | +4 tests de régression : parser fwupd 1.9+ format arbre (`├─`/`└─`) — bug trouvé sur Ubuntu 26.04 LTS |
| post-v0.1.0 | 4202 | +2 tests de régression : findings INFO non détectés en surface d'attaque (`ssh.not_installed`, `fail2ban.not_installed`) — bugs trouvés sur Ubuntu 26.04 LTS |
| v0.1.0  | 4200  | Version initiale — 65 fichiers de test ; 39 nouveaux tests dans `test_cis_refs.py` (mapping benchmarks CIS) ; couverture complète des 46 vérifications |

---

### v0.6.1 — 4600/4600 (26-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4600 passed in ~7s
```

**Net : +17 (4583 → 4600).** Première release de durcissement sur v0.6.x. Le sub-agent d'audit a produit 14 findings ; 6 importants + 4 mineurs livrés. Les +17 tests épinglent tous la couverture de régression :

| Classe de test | Nombre | Finding épinglé |
|---|---|---|
| `TestAtomicWritePublicAPI` (test_atomic_v061.py) | 4 | Contrat `atomic_write` — mode préservé, contenu écrasé proprement, atomicité sur échec simulé |
| `TestCronLegacyAliasStillWorks` | 1 | `bob.cron._io._atomic_write is bob._atomic.atomic_write` (rétrocompatibilité des patchs de test) |
| `TestHistoryFileMode` | 2 | I-5 première écriture en 0o600 + mode préservé en append |
| `TestIgnoreAtomic` | 2 | I-6 écriture atomique + échec simulé d'`os.replace` laissant le contenu intact |
| `TestSafeInput` | 3 | I-2 `safe_input()` renvoie "" sur EOF + `prompt_wizard()` renvoie None sur EOF |
| `TestStepBoundedToFieldRange` (test_cron.py) | 5 | I-3 bornes de pas pour minute / heure / limite / zéro / expression complète |

#### Timeline du compteur de tests mise à jour

```
v0.5.0  →  4538 tests
v0.5.5  →  4545 tests  (+7  — régressions hardening)
v0.5.6  →  4560 tests  (+15 — logs.py)
v0.5.7  →  4571 tests  (+11 — TUI curses)
v0.5.8  →  4583 tests  (+12 — cleanup mineurs déférés)
v0.6.0  →  4583 tests  (0   — splits + sunset contract-preserving)
v0.6.1  →  4600 tests  (+17 — atomic-write + EOF + cron step bounds)
```

#### Test terrain

Approche standard de couverture cross-distro. La sortie wire (plain-text + JSON) est bit-identique à v0.6.0 — seule la chaîne d'erreur de `--watch=N` diffère (« entier ≥ 10 » au lieu de « entier positif »). Tous les autres changements sont internes :
- La migration atomic-write est bit-identique aux 5 implémentations préexistantes
- La gestion EOF est bit-identique pour les entrées non-EOF (seul le crash devient une sortie propre)
- I-3 ne rejette que de nouvelles entrées (du type `*/200`) auparavant acceptées mais produisant un cron cassé
- I-4 n'affecte que la sémantique `--fix --apply` sur des chemins comportant des espaces
- I-5 ne change que le mode à la première création (les `history.jsonl` existants ne sont pas touchés)

Testé par un run sudo sur so6desktop avant livraison pour vérifier que le score de référence v0.5.x (9/10) est préservé.

Les 4600 tests passent en ~7s sur Python 3.12 / Linux Mint 22.3.

---

### v0.6.0 — 4583/4583 (25-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4583 passed in ~7s
```

**Net : 0.** Bump architectural majeur ouvrant la branche v0.6.x. Deux splits package (#13 ssh.py → bob/checks/ssh/, #14 cron.py → bob/cron/) et un sunset (`UFW_AUDIT_SHARE`). Tout structurel — aucun changement de comportement, aucune nouvelle classe de test, aucun test retiré.

Trois updates d'infrastructure test ont été requis pour accommoder le layout package (pas des changements de couverture) :

| Fichier test | Update | Raison |
|---|---|---|
| `tests/test_template_vars_migration.py` | `_check_modules()` → `_module_paths()` walk `iterdir()` + gère à la fois fichiers et répertoires package ; `_module_has_template_vars(path)` fait `rglob("*.py")` pour les packages | L'AST scanner doit recurser dans `bob/checks/ssh/` pour trouver les call sites `template_vars=` des 4 sous-modules |
| `tests/test_domain_scores_mapping_complete.py` | `_CHECKS_DIR.glob("*.py")` → `_CHECKS_DIR.rglob("*.py")` + filtre `__pycache__` | Même besoin de récursion — l'AST scanner doit voir chaque sous-module de check pour les préfixes de clé émis |
| `tests/test_cron.py::TestApplyCronScheduleAtomic` | Target patch shifté de `bob.cron._atomic_write` à `bob.cron._io._atomic_write` | `apply_cron_schedule` vit dans `_io.py` post-split et appelle le `_atomic_write` local directement ; le spy doit être set où le call site lit |

Ces updates sont mécaniques — les assertions et la couverture qu'ils enforcent sont inchangées.

#### Timeline du compteur de tests mis à jour

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8 : domain mapping AST scan + cron coverage)
v0.5.1  →  4538 tests  (sans changement — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (sans changement — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (sans changement — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (sans changement — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — régressions hardening post-cycle)
v0.5.6  →  4560 tests  (+15 — régressions hardening ciblé logs.py)
v0.5.7  →  4571 tests  (+11 — régressions hardening ciblé TUI curses)
v0.5.8  →  4583 tests  (+12 — régressions cleanup mineurs déférés v0.5.7)
v0.6.0  →  4583 tests  (0 — splits + sunset sont contract-preserving)
```

**Résumé branche v0.5.x : +45 tests nets à travers 4 releases hardening (v0.5.5 → v0.5.8).** v0.6.0 ouvre v0.6.x sans ajouter de tests parce que c'est une réorganisation structurelle.

#### Test terrain

Approche standard de couverture cross-distro. Sortie wire bit-identique à v0.5.8 (aucun changement de comportement). Deltas visibles à attendre sur les systèmes utilisateurs :
- **Aucun sur les installs standards.** Tous les imports v0.5.x continuent de marcher.
- **Seulement sur les systèmes settant encore `UFW_AUDIT_SHARE`** : l'env var est maintenant silencieusement ignorée. Mettre à jour les installers pour utiliser `BOB_SHARE`.

Tous les 4583 tests passent en ~7s sur Python 3.12 / Linux Mint 22.3.

---

### v0.5.8 — 4583/4583 (25-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4583 passed in ~6s
```

**Net : +12 (4571 → 4583).** Cleanup des 5 mineurs cosmétiques déférés par v0.5.7. Tous les +12 tests pinent la couverture de régression :

| Classe de tests | Nombre | Pin finding |
|---|---|---|
| `TestCursorShiftAfterDelete` | 2 | M-2 — deletion mixte avant/après shift le cursor seulement par le before-count ; deletions toutes-après laissent le cursor inchangé |
| `TestScheduleIntEnum` | 2 | M-5 — valeurs enum matchent les indices menu (1-4) ; parité comparaison IntEnum-vs-int préservée |
| `TestSummaryStartSentinel` | 1 | M-6 — edge case synthétique SEP62-à-index-0 correctement détecté |
| `TestIsFindingContinuation` | 4 | M-7 — accepte body indenté, rejette non-indenté, rejette markers de finding indentés, rejette délimiteurs de section indentés |
| `TestDatetimeImportLifted` | 3 | M-8 — `bob.cron.datetime` et `bob.tui.cron.datetime` exposés au niveau module ; smoke test `build_script_content` stamp toujours la date |

#### Timeline du compteur de tests mis à jour

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8 : domain mapping AST scan + cron coverage)
v0.5.1  →  4538 tests  (sans changement — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (sans changement — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (sans changement — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (sans changement — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — régressions hardening post-cycle)
v0.5.6  →  4560 tests  (+15 — régressions hardening ciblé logs.py)
v0.5.7  →  4571 tests  (+11 — régressions hardening ciblé TUI curses)
v0.5.8  →  4583 tests  (+12 — régressions cleanup mineurs déférés v0.5.7)
```

**Croissance nette sur les releases hardening v0.5.x (v0.5.5 → v0.5.8) : +45 tests** sur 4 passes focalisées, alors que les releases refactor structurel (v0.5.0 → v0.5.4) étaient contract-preserving (+39 en v0.5.0 seulement, tous depuis de nouveaux fichiers test pour helpers purs).

#### Test terrain

Approche standard de couverture cross-distro. Sortie wire (plain-text + JSON) inchangée — la migration IntEnum M-5 produit un comportement wizard bit-identique ; le helper M-7 est strictement plus strict que le prédicat précédent mais le cas over-greedy contre lequel il se défend ne surface dans aucune sortie BOB actuelle ; M-6 sentinelle gère un edge case unreachable-en-pratique ; correction cursor M-2 ne change la position d'affichage qu'après multi-sélection deletes mélangeant items avant+après le cursor ; M-8 est un lift structurel pur.

Tous les 4583 tests passent en ~6s sur Python 3.12 / Linux Mint 22.3.

---

### v0.5.7 — 4571/4571 (24-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4571 passed in ~6s
```

**Net : +11 (4560 → 4571).** Passe hardening ciblée sur le TUI curses (`bob/manage_logs.py` + `bob/tui/cron.py`). Les +11 tests sont tous des couvertures de régression pour les fix de cette release :

| Classe de tests | Nombre | Pin finding |
|---|---|---|
| `TestApplyCronScheduleAtomic` | 2 | I-3 — spy sur `_atomic_write` pour vérifier qu'il est appelé ; simule échec pour vérifier que le contenu original du fichier cron survit intact (contrat d'atomicité) |
| `TestIsPrintableInputChar` | 4 | I-1 — ASCII imprimable accepté, Latin-1 imprimable accepté, chars de contrôle rejetés (NUL/TAB/CR/LF/ESC), codes keypad curses `KEY_*` (≥ 256) rejetés sur toute la plage |
| `TestEOFErrorOnPromptPath` | 2 | I-2 — Ctrl-D au prompt de chemin retourne default (avec et sans `allow_cancel`), aucune propagation `EOFError` |
| `TestEOFErrorOnMoveConfirm` | 1 | I-2 — Ctrl-D à confirmation move-logs `[y/N]` annule le move silencieusement ; fichier log PAS déplacé |
| `TestEOFErrorOnDeleteAllConfirm` | 1 | I-2 — Ctrl-D à confirmation delete-all `[y/N]` annule la deletion silencieusement ; fichier log PAS supprimé |
| `TestDeletedOneCorrectName` | 1 | M-1 — sous échecs unlink sélectifs, le nom affiché est le PREMIER fichier effectivement supprimé, pas `pending_delete[0]` (qui peut référer à un index échoué) |

#### Pourquoi pas de tests pour M-3 et M-4

- **M-3** (dead-code elif body simplifié) — `chosen = sel` produit déjà un comportement identique dans toutes les branches que le guard autorise. Pas de changement sémantique, couvert par les tests de navigation menu existants.
- **M-4** (consolidation `from bob.cron import` dupliqué) — pure dé-duplication de la source d'import. Les noms importés restent disponibles ; `python3 -c "from bob.tui.cron import apply_cron_schedule"` continue de fonctionner.

#### Timeline du compteur de tests mis à jour

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8 : domain mapping AST scan + cron coverage)
v0.5.1  →  4538 tests  (sans changement — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (sans changement — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (sans changement — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (sans changement — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — régressions hardening post-cycle)
v0.5.6  →  4560 tests  (+15 — régressions hardening ciblé logs.py)
v0.5.7  →  4571 tests  (+11 — régressions hardening ciblé TUI curses)
```

#### Test terrain

Approche standard de couverture cross-distro. La sortie wire (plain-text + JSON) est inchangée — seul l'affichage TUI change (pas de leak de glyphes Grecs sur pression de touche de fonction ; sortie propre sur Ctrl-D). Le changement atomic-write dans `apply_cron_schedule` produit un contenu de fichier cron bit-identique en opération normale ; la différence n'est observable que sous scénarios de crash-durant-écriture (testable dans `tests/`, pas sur VMs terrain).

Tous les 4571 tests passent en ~6s sur Python 3.12 / Linux Mint 22.3.

---

### v0.5.6 — 4560/4560 (24-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4560 passed in ~6s
```

**Net : +15 (4545 → 4560).** Passe hardening single-module sur `bob/checks/logs.py`. Les +15 tests sont tous couverture régression pour les fix de cette release :

| Classe test | Compte | Pin finding |
|---|---|---|
| `TestPrivateIPDispatch` | 8 | I-1 — CGNAT (`100.64.5.1`), IPv6 link-local (`fe80::1`), ULA (`fc00::1`), loopback (`127.0.0.1`, `::1`), private (`10.0.0.1`, `192.168.1.1`), public (`8.8.8.8`), input invalide (`"fcsa"`, string vide) tous classifiés correctement via helper dispatch `_is_private_ip` |
| `TestParseTimestampYearRollover` | 3 | I-2 — entrée current-year passée (pas de rollback), entrée 1s-future (pas de rollback sous tolérance 5 min), vraie entrée Décembre parsée en Janvier (rollback appliqué) |
| `TestBlockPrefixMatcher` | 3 | M-1 — `[UFW BLOCK]` matché, `[UFW BLOCK6]` matché (était silencieusement droppé), `[UFW ALLOW]` rejeté |
| `TestProtoNormalisation` | 1 | M-8 — `proto="tcp"` normalisé à `"TCP"` au parse-time |

#### Pourquoi tous I-1/I-2/M-1/M-8 sont régression-pinned

Ces quatre étaient les seuls fixes avec changements de comportement visible sur code path. Les autres sont soit :
- **Pure délégation** (M-3 reorder path, M-4 consistance symlink, M-7 cleanup except) — couverts par tests existants qui exercent les code paths changés
- **Performance / boundary safety** (M-5 cache bound, M-6 lecture binaire) — aucun changement de comportement pour les inputs test existants ; ne fériait surface que sous fixtures contrived 10000+-IP (hors scope)
- **Ajustement locale-coverage** (M-2 restriction regex) — couvert par `test_count_available_days` indirectement

Les 4 régressions pinned couvrent la surface I-1/I-2/M-1/M-8 où de futurs contributeurs pourraient re-introduire les bugs.

#### Timeline du compteur de tests mis à jour

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8 : scan AST mapping domaines + couverture cron)
v0.5.1  →  4538 tests  (sans changement — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (sans changement — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (sans changement — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (sans changement — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — régressions hardening post-cycle)
v0.5.6  →  4560 tests  (+15 — régressions hardening ciblé logs.py)
```

#### Test terrain

Approche couverture cross-distro standard. Delta visible vs v0.5.5 attendu sur :
- Hosts émettant `[UFW BLOCK6]` (ex. Debian backports avec configs `before6.rules` custom) — ces lignes comptent maintenant dans l'agrégation `total`/`top_ips` (précédemment droppées)
- Hosts avec contenu syslog locale mixte — compte `days_available` peut diminuer (précédemment inflated par tokens mois non-anglais)

La plupart des VMs (configs UFW par défaut, locale anglaise) ne voient **aucun changement visible**.

Les 4560 tests passent en ~6s sur Python 3.12 / Linux Mint 22.3.

---

### v0.5.5 — 4545/4545 (24-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4545 passed in ~7s
```

**Net : +7 (4538 → 4545).** Premier delta de tests sur la ligne v0.5.x — la passe de hardening a fait apparaître 4 bugs réels et 4 security smells, chacun pinné par un test régression pour prévenir la ré-introduction. Changements de tests résumés :

| Catégorie | Ajoutés | Supprimés | Renommés | Net |
|---|---|---|---|---|
| Tests régression bugs (C-1, C-2, C-3, C-4) | 4 | 0 | 2 (`test_nature_is_action` → `test_nature_is_improvement`) | +4 |
| Régression sécurité (I-2, I-3) | 10 (9 dans le nouveau `tests/test_report_markdown_safety.py` + 1 dans `test_scoring.py`) | 0 | 0 | +10 |
| Changement comportement (M-4, M-10) | 3 | 1 (`test_no_fire_missing_auditd` retiré — changement sémantique) | 0 | +2 |
| Cleanup code mort (M-2 retrait `_NullReport`, M-3 clés locale mortes) | 1 (`test_enabled_flag_is_false`) | 9 (`TestNullReportIsolation` 5 + `test_any_method_returns_none` + `test_attribute_access_returns_callable` + `test_hint_key_en` + 1 autre) | 0 | −8 |
| **Total** | **18** | **10** | **2** | **+7** |

#### Nouveaux tests régression

**C-1 : `tests/test_cron.py::test_preserves_script_executable_mode`** — pin que `apply_cron_email()` garde le script à `0o755` (cassait à `0o600` et tuait silencieusement les audits programmés).

**C-2 + C-3 : `tests/test_password_policy.py::test_nature_is_improvement`** (× 2 — `TestNoQualityModule` et `TestWeakMinlen`) — renommés de `test_nature_is_action` et assertion inversée. Lock la demotion qui empêche `--fix --apply` d'essayer d'exec des cmds non-exécables.

**C-4 : `tests/test_explain.py::test_services_state_alias_routes_to_canonical`** — pin que `normalize_key("services_state.service_inactive")` résout à `services_state.enabled_inactive` via `EXPLAIN_KEY_ALIASES`.

**I-2 : `tests/test_scoring.py::test_post_finalize_deduction_is_discarded`** — utilise `caplog` pour vérifier à la fois le discard et le message log WARNING. Couvre le guard `_apply_deduction`.

**I-3 : `tests/test_report_markdown_safety.py`** — nouveau fichier avec 9 tests couvrant `_safe_url` :
- URLs plain passent through (http/https)
- Schemes inconnus bloqués (javascript:, data:, file:, vide)
- Escape double-quote (`"` → `&quot;` dans contexte attribut)
- Escape single-quote (`'` → `&#x27;`)
- Escape angle-bracket (`<` → `&lt;`)
- Texte plain html-escape
- Link rendu comme anchor
- Test full pipeline XSS attack-string (assert le href ferme correctement, pas de `"` injecté)

**M-4 : `tests/test_correlation.py::test_fires_with_only_fail2ban_inactive`** + `test_does_not_fire_when_firewall_logging_present` — pin la sémantique élargie de `corr.fully_blind`.

**M-10 : `tests/test_cron.py::test_comment_line_with_root_token_not_modified`** — pin que la regex resserrée skippe les comment lines `# 0 3 * * * root /usr/bin/legacy-bob`.

#### Tests supprimés

`tests/test_watch.py::TestNullReportIsolation` (5 tests) + `TestNullReport::test_any_method_returns_none` + `test_attribute_access_returns_callable` — ces tests testaient le magic `__getattr__` de l'ancien `bob.watch._NullReport`. M-2 le remplace par le `bob.report.NullReport` explicite (Report Protocol de v0.5.0 #10) qui a des méthodes typées `write_section` / `write_finding` / `_writeln` / `close`. Les tests d'accès attribut catch-all ne sont plus applicables.

`tests/test_ignore.py::test_hint_key_en` — testait que `t("ignored.hint", ...)` résout. M-3 a supprimé cette clé locale (orpheline — jamais utilisée par le code production).

`tests/test_correlation.py::test_no_fire_missing_auditd` — pinnait la sémantique pré-M-4 (la règle NE fire PAS quand fail2ban présent mais auditd manquant). M-4 a changé cette sémantique (fire maintenant) donc l'assertion a été inversée via deux nouveaux tests ci-dessus.

#### Timeline du compteur de tests à travers v0.5.x

```
v0.5.0  →  4538 tests  (+39 vs v0.4.8 : scan AST mapping domaines + couverture cron)
v0.5.1  →  4538 tests  (sans changement — Phase 2 contract-preserving)
v0.5.2  →  4538 tests  (sans changement — Phase 3 contract-preserving)
v0.5.3  →  4538 tests  (sans changement — Phase 4 contract-preserving)
v0.5.4  →  4538 tests  (sans changement — Phase 5 contract-preserving)
v0.5.5  →  4545 tests  (+7 — premier delta depuis v0.5.0 ; régressions hardening)
```

Le plateau 4538 à travers les Phases 2-5 confirme que la garantie contract-preservation a tenu durant tout le refactor. v0.5.5 fait grossir la suite parce qu'il fixe des bugs réels — chaque fix obtient un pin.

#### Test terrain

Même approche couverture cross-distro que v0.5.4 — pipx upgrade + `sudo bob -v -d` sur chaque VM (so6desktop, debian13vm, kali, so6minttest, so6ubuntutest). Changements visibles attendus vs v0.5.4 :

- **Shift display password_policy** : sur hosts sans `pam_pwquality` installé (so6desktop, so6ubuntutest, autres), le finding se déplace de "À corriger" (bloc action) à "Améliorations possibles" (bloc improvement) dans le summary box. Score global inchangé. Texte verdict change de "Des corrections sont nécessaires" à "Configuration globalement saine".
- **Changement shape cmd `services_state.service_inactive`** : sur hosts avec services monitorés inactifs, le cmd ne chaîne plus `&& sudo journalctl …` (ce qui le rendait non-fixable). La suggestion journalctl se déplace en `note=` pour guidance.
- **Aucun changement visible** sur hosts qui ne déclenchent pas les conditions ci-dessus (debian13vm, kali, so6minttest dans leur état actuel).

INFO C cache APT continue de fonctionner comme avant (supprimé quand mises à jour security/regular en attente).

Les 4545 tests passent en ~7s sur Python 3.12 / Linux Mint 22.3.

---

### v0.5.4 — 4538/4538 (22-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in ~6s
```

**Net : 0 (aucun nouveau test, aucune suppression).** v0.5.4 ferme l'audit v0.5.x avec la Phase 5 (findings #6 + #9 + #15b + cache APT option C). Les quatre changements sont soit des refactors contract-preserving (#6, #9), soit des raffinements display-only (ligne INFO cache APT C, re-bucketing score #15b). La suite de tests existante pin :

- Toutes les clés de finding (via scan AST `test_locale_coverage.py`)
- Tous les prefixes de clé de domain-score (via scan AST `test_domain_scores_mapping_complete.py`, ajouté en v0.5.0 — #15a)
- Tous les contrats scoring (via `test_scoring.py`, `test_domain_scores.py`, `test_golden_scenarios.py`)

#### Update whitelist `_CATCH_ALL_BY_DESIGN` (conséquence #15b)

`tests/test_domain_scores_mapping_complete.py:_CATCH_ALL_BY_DESIGN` perd 3 entrées que #15b a migrées vers mappings explicites :

| Entrée retirée | Où elle est allée (dans `_PREFIX_TO_DOMAIN`) |
|---|---|
| `fail2ban` | `ssh` |
| `virt` | `hardening` |
| `docker_audit` | `hardening` |

Les entrées restantes (`smtp`, `desktop_apps`, `prerequisites`) reçoivent des justifications rafraîchies — elles ne pointent plus vers "review in v0.5.4" puisque cette review est maintenant faite. Le bloc de commentaire au-dessus de `_CATCH_ALL_BY_DESIGN` mis à jour pour refléter la clôture (plus aucun candidat flaggé pour tightening).

Le test `test_every_emitted_prefix_is_mapped_or_whitelisted` continue d'enforcer que chaque prefixe de clé de finding émis est soit dans `_PREFIX_TO_DOMAIN` soit dans `_CATCH_ALL_BY_DESIGN`. Si un futur contributeur ajoute un check émettant un nouveau prefixe (ex `clamav_signatures.something`) sans le mapper, le test échoue au moment du PR.

#### Cache APT option C — couverture locale

Les 2 nouvelles clés locale (`updates.apt_cache_age` + `updates.apt_cache_age_detail`) sont attrapées par `test_locale_coverage.py` (scan AST introduit en v0.4.5). Le test de couverture locale enforce que chaque littéral `t("foo.bar")` dans le codebase a une entrée correspondante dans `en.json` ET `fr.json`. Les 2 nouvelles entrées passent le check.

#### #6 `prompt_wizard` — aucun nouveau test, compatibilité mock préservée

`prompt_wizard()` dans `bob/_tty.py` appelle `input()` en interne, donc les mocks `builtins.input` existants dans `tests/test_cron.py` continuent de fonctionner sans modification. Les 10 sites migrés dans `bob/cron.py` délèguent chacun à `prompt_wizard` au lieu d'appeler `input()` directement, mais la stack d'appel sous-jacente hit toujours `input()` — donc le test setup comme `patch("builtins.input", side_effect=["yes", "1", ""])` opère de la même façon.

Le helper lui-même (`prompt_wizard`) n'est pas testé unitairement directement. Son comportement est exercé end-to-end via les tests du wizard cron qui mockent déjà `input()`.

#### Test terrain

Approche de couverture cross-distro inchangée depuis les Phases 1-4 — pipx upgrade + `sudo bob -v -d` sur chaque VM. Deux changements observables sont attendus versus v0.5.3 :

1. **Ligne INFO cache APT** dans section MISES À JOUR SYSTÈME quand le host a APT, aucune mise à jour security/regular en attente, et âge du cache sous le seuil obsolète de 7 jours.
2. **Reshuffle score par domaine** sur hosts émettant findings `fail2ban.*` / `virt.*` / `docker_audit.*` — le score global est inchangé.

Sur le host dev `so6desktop` (Mint 22.3 + Docker installé + libvirt KVM), le reshuffle est observable : `Pare-feu & Services` est passé de 3/10 à 10/10 (`virt.bypass_risk` sorti du catch-all), `Durcissement` est descendu de 6/10 à 5/10 (`virt.bypass_risk` compté là maintenant). Le score global reste à 8/10.

Les 4538 tests passent en ~6s sur Python 3.12 / Linux Mint 22.3.

---

### v0.5.3 — 4538/4538 (22-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in ~6s
```

**Net : 0 (aucun nouveau test, aucune suppression).** v0.5.3 est le refactor Phase 4 (audit findings #5 + #12 + #8). Les trois sont structurels — la table `_LEVEL_DISPATCH` produit les mêmes appels `print_ok`/`print_warn`/`print_alert`/`print_info` dans le même ordre que la cascade impérative, les 3 helpers `_summary_*_lines` retournent les mêmes tuples `(content, val)` que les sections inline précédentes, et le tuple return `(CheckResult, LogReportData)` ne change pas la sémantique de l'orchestrateur (`runner.py` unpacke le tuple et passe le report explicitement à `display_log_results`).

#### Tests renommés (#8)

3 tests dans `test_logs.py` directement dépendants du champ `log_data` :

| Avant (v0.5.2) | Après (v0.5.3) | Changement |
|---|---|---|
| `test_log_data_attached` | `test_report_data_attached` | `result.log_data is not None` → `report_data is not None` ; `result.log_data["total"] == 1` → `report_data.total == 1` |
| `test_top_ips_in_log_data` | `test_top_ips_in_report_data` | `result.log_data["top_ips"]` → `report_data.top_ips` |
| `test_service_hits_in_log_data` | `test_service_hits_in_report_data` | `result.log_data["svc_hits"].get(...)` → `report_data.svc_hits.get(...)` |

#### Sites tests `result, _ = check_logs(...)`

~20 sites dans `test_logs.py` (14) et `test_degraded.py` (8) utilisent maintenant l'unpack tuple. Les tests ne consultent que `result.findings` / `result.deductions` (logique de scoring, levels), donc le 2e élément du tuple est ignoré via `_`. Pattern de migration purement mécanique via `replace_all` Edit ; aucun changement de logique de test.

#### Side-fix attrapé par les tests existants

Lors du split de `print_audit_summary` (#12), 8 tests ont fail au premier run avec `NameError: name 'score' is not defined` :

- `TestScoreTrend::test_no_prev_score_no_arrow`
- `TestScoreTrend::test_improved_shows_up_arrow`
- `TestScoreTrend::test_degraded_shows_down_arrow`
- `TestScoreTrend::test_stable_shows_no_annotation`
- `TestScoreTrend::test_improved_by_two`
- `TestScoreTrend::test_degraded_by_three`
- `TestExplainHintAbsent::test_explainable_alongside_non_explainable`
- `TestDuplicateFindings::test_two_identical_findings_produce_two_hints`

Cause : `score`, `level_str`, `ctx_str` étaient calculés au début de la fonction, utilisés dans le header (extrait dans `_summary_header_lines`), puis re-utilisés dans `report.write_summary(...)` à la fin de la fonction. Après l'extraction, les locales n'étaient plus dans la portée.

Fix : remplacer par expressions directes :
```python
report.write_summary(
    score=engine.score,
    risk_level=t(f"scoring.level.{engine.level.value}"),
    network_context=t(f"scoring.context.{network_context}"),
    ...
)
```

Les 8 tests ont passé après ce fix. Bonne illustration de l'intérêt d'avoir une couverture e2e sur les fonctions de display — un refactor "purement cosmétique" peut casser des chemins data via des références implicites.

#### Test terrain

Approche cross-distro identique à v0.5.0/v0.5.1/v0.5.2 — pipx upgrade + `sudo bob -v -d` sur chaque VM. Sortie attendue : bit-identique à v0.5.2 (modulo changements d'état système entre runs).

Les 4538 tests passent en ~6s sur Python 3.12 / Linux Mint 22.3.

---

### v0.5.2 — 4538/4538 (22-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in ~6s
```

**Net : 0 (aucun nouveau test, aucune suppression).** v0.5.2 est le refactor Phase 3 (audit findings #4 + #3). Les deux sont structurels — l'approche table-driven `_BAD_DIRECTIVES` pour sshd_config produit des entrées `Finding` et `Deduction` identiques aux if-blocks précédents, et l'extension `_sec` est keyword-only (aucun impact sur les appelants existants).

#### Pourquoi zéro delta de tests

`test_ssh.py` a 122 tests, dont 30+ pinnent le comportement sshd_config. Aucun n'a changé :
- Les tests attestent sur les listes `result.findings` et `result.deductions` (compte, attributs, key matching) — le chemin table-driven produit les mêmes entrées dans le même ordre.
- Les tests utilisent `SSHSnapshot(sshd_config={"x11forwarding": "yes", ...})` pour construire les snapshots — la boucle `for rule in _BAD_DIRECTIVES` lit les mêmes clés dict.
- Les 4 cas impératifs (PermitRootLogin, PasswordAuthentication, MaxAuthTries, LoginGraceTime) sont restés intacts — les tests sur ces directives continuent d'utiliser les mêmes chemins de code.

#### Couverture tests `_BAD_DIRECTIVES`

Les 8 directives migrées ont chacune entre 2 et 6 tests dans `test_ssh.py`. La migration a été validée par :

| Directive | Tests avant migration | Résultat après migration |
|---|---|---|
| `PermitEmptyPasswords` | `test_permit_empty_passwords_yes`, `test_permit_empty_passwords_no_no_finding` | ✓ |
| `X11Forwarding` | `test_x11_forwarding_yes`, `test_x11_forwarding_default_no` | ✓ |
| `IgnoreRhosts` | `test_ignore_rhosts_no` | ✓ |
| `HostbasedAuthentication` | `test_host_based_auth_yes` | ✓ |
| `PermitUserEnvironment` | `test_permit_user_env_yes` | ✓ |
| `StrictModes` | `test_strict_modes_no` | ✓ |
| `AllowTcpForwarding` | `test_allow_tcp_forwarding_yes`, `test_allow_tcp_forwarding_no_ok`, `test_allow_tcp_forwarding_local_ok` | ✓ (y compris le cas `safe_values=("no", "local")`) |
| `PubkeyAuthentication` | `test_pubkey_auth_disabled` | ✓ |

Tous les tests passent sur le chemin table-driven.

La validation `__post_init__` (mutual exclusion de `bad_values` et `safe_values`) est exercée au chargement du module — si un futur contributeur ajoute une entrée `_BadDirective` mal formée, l'import échoue avec un message d'erreur clair.

#### Extension `runner._sec` — aucun impact tests

Les 4 sites migrés vers `skip_if=` / `post_display=` (`samba`, `docker_audit`, `desktop_apps`, `disk`) n'ont pas de tests unitaires directs sur l'orchestration runner (`run_checks` est testé en intégration via le pipeline d'audit complet). Le séparateur keyword-only `*,` avant les nouveaux params garantit que les patterns d'appels positionnels existants continuent de compiler.

#### Test terrain

Même approche cross-distro que v0.5.0/v0.5.1 — pipx upgrade + `sudo bob -v -d` sur chaque VM. Sortie attendue : bit-identique à v0.5.1 (modulo changements d'état système entre runs).

Les 4538 tests passent en ~6s sur Python 3.12 / Linux Mint 22.3.

---

### v0.5.1 — 4538/4538 (21-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in ~6s
```

**Net : 0 (aucun nouveau test, aucune suppression).** v0.5.1 est le refactor du gros gain LoC (audit finding #1). La migration est contract-preserving : chacun des 120 sites paired `result.warn(...) + result.add_deduction(...)` collapse en un seul appel `result.warn_with_deduction(...)` (ou `.alert_with_deduction(...)`). Le helper invoque en interne la même séquence `warn`/`alert` + `add_deduction`, produisant des entrées `Finding` et `Deduction` identiques dans `result.findings` et `result.deductions`.

#### Pourquoi zéro delta de tests

Un grep à travers `tests/` a confirmé que tous les tests sur les instances `CheckResult` attestent sur les listes résultantes (`result.findings`, `result.deductions`, accès attribut sur entrées individuelles, comptes par niveau via `result.warn_count`/`result.alert_count`/etc.). **Aucun test** ne patche `CheckResult.warn` ou `CheckResult.add_deduction` pour compter les invocations. Le helper préserve la sortie wire exactement, donc la suite de tests est inaffectée.

#### Discipline de migration — 6 vagues, pytest complet entre chacune

| Vague | Fichiers | Sites | Résultat tests |
|---|---|---|---|
| 1 (fichiers 1-site) | backup, ddns, logs, memory, network_context, smtp, suid_audit | 7 | 4538/4538 |
| 2 (fichiers 2-site) | cron_audit, docker_audit, fail2ban, firmware, ipv6, kernel_modules, ntp, password_policy, ports, secure_boot, systemd_timers, umask, updates, user_accounts | 16 | 4538/4538 |
| 3 (fichiers 3-site) | auditd, file_integrity, kernel_hardening, log_rotation, rootkit | 15 | 4538/4538 |
| 4 (fichiers 4-6 sites) | file_perms, firewall_stack, firewall (pilote), disk, iptables_nftables, clamav, mac_policy, samba | 29 | 4538/4538 |
| 5 (hardening) | hardening | 8 | 4538/4538 |
| 6 (ssh) | ssh | 24 | 4538/4538 |
| **Total** | **27 fichiers** | **120 sites** | **4538/4538** |

13 sites ont été volontairement non migrés (déductions cappées, branching de niveau, points conditionnels, template_vars divergents). Voir `CHANGELOG_FR.md` pour le détail.

#### Le test terrain suit le même pattern que v0.5.0

La release Phase 1 v0.5.0 a été testée terrain sur 5 distros (Linux Mint 22.3 production + so6minttest, Debian 13 trixie, Kali Rolling, Ubuntu 26.04 LTS) avec `sudo bob -v -d --french`. Le refactor de v0.5.1 préserve la sortie wire exactement, donc la même couverture cross-distro s'applique. Le test terrain recommandé pour v0.5.1 : installer via `pipx upgrade bodyguard-of-bits` et lancer `sudo bob -v -d` — la sortie d'audit, le score breakdown, et les barres par domaine doivent être bit-identiques à v0.5.0 (modulo les changements d'état système entre runs).

---

### v0.5.0 — 4538/4538 (21-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4538 passed in 7.77s
```

**Net : +39 (aucune suppression, aucun changement de contrat).** v0.5.0 ouvre la branche refactor v0.5.x avec 6 findings d'audit + 1 bug latent remonté par les nouveaux tests. **Le comportement du pipeline d'audit est inchangé** — JSON `schema_version="1"`, les 7 domaines de score, les 116 EXPLAIN_KEYS, les 34 sections filtrables tous préservés.

#### `tests/test_domain_scores_mapping_complete.py` (+4 — nouveau fichier)

Scan AST de `bob/checks/*.py` pour chaque argument `key="X.Y"` littéral des méthodes émettrices (`add_deduction`, `warn`, `alert`, `info`, `ok`). Extrait les préfixes uniques et atteste que chaque préfixe est soit explicite dans `_PREFIX_TO_DOMAIN` soit whitelisté dans `_CATCH_ALL_BY_DESIGN` avec une justification.

| Test | Couverture |
|---|---|
| `test_every_emitted_prefix_is_mapped_or_whitelisted` | Hard-fail sur tout nouveau préfixe non-mappé (la garde anti-drift future) |
| `test_no_stale_catchall_entries` | Warn (pas fail) sur les entrées whitelist sans émetteur actuel |
| `test_no_stale_prefix_to_domain_entries` | Warn sur les entrées `_PREFIX_TO_DOMAIN` non utilisées par les call sites statiques |
| `test_all_entries_have_justifications` | Chaque entrée whitelist doit avoir une raison non-vide |

#### `tests/test_cron.py` — 5 nouvelles classes (+35)

Couverture préalable Phase 5 — cron.py était le pire-testé du codebase (0.60× selon SNAPSHOT).

| Classe | Tests | Ce qu'elle pinne |
|---|---|---|
| `TestValidateCronField` | 13 | Toutes les branches : `*`, `N`, `N-M`, `*/K`, `N-M/K`, listes `,`, out-of-bounds (classe de régression v0.4.3), range inversé, entry vide, garbage |
| `TestValidateCustomCron` | 7 | Discipline 5-fields complète, bornes par field, rejet 4-fields, rejet 6-fields |
| `TestBuildScriptContent` | 7 | Shebang, comportement `shlex.quote()` (email simple + cas avec espace), quoting `LOG_DIR`, invocation `--quiet --detailed`, exports `AUDIT_EMAIL`/`AUDIT_LOG` |
| `TestApplyCronSchedule` | 3 | Replacement de schedule préserve le commentaire email, remontée OSError fichier manquant |
| `TestApplyCronEmail` | 5 | Commentaire email + ligne script `NOTIFY_EMAILS=` + **parité regex legacy `NOTIFY_EMAIL=` (sans S)** + tolérance script manquant + quoting `shlex.quote()` |

#### Bug latent corrigé (découvert par `TestApplyCronSchedule`)

Le nouveau `TestApplyCronSchedule::test_replaces_schedule` a échoué au premier run avec `NameError: name '_os' is not defined` à `bob/cron.py:855`. Cause racine : la déduplication cron v0.4.8 a extrait `apply_cron_schedule()` de `bob/tui/cron.py` vers l'API publique `bob.cron` mais a raté le renommage de `_os.open(...)` en `os.open(...)`. L'alias `_os` est local à trois *autres* fonctions dans `cron.py` (`import os as _os` scopé à la fonction). Au niveau module, seul `os` est importé. Le helper était silencieusement mort depuis le ship v0.4.8 — la TUI curses le câblait mais n'est pas exercée par les tests automatisés, donc le bug ne se manifestait qu'à l'exécution interactive. Fix : 3 références sur 2 lignes.

#### Adaptations de tests (rebond du refactor #7)

| Fichier | Changement | Pourquoi |
|---|---|---|
| `tests/test_fail2ban.py` | `_make_run_stub` ne gère plus `systemctl is-active` (a perdu le paramètre `service_active`) ; chaque test ajoute `patch("bob.checks.fail2ban.is_unit_active", return_value=...)` | La migration vers `is_unit_active()` fait que l'appel systemctl ne passe plus par le `_run` patché ; il passe par `is_unit_active` du namespace de `_run.py` |
| `tests/test_ntp.py` | `_make_run_side_effect` réduit à timedatectl-only ; nouveau helper `_make_is_active_stub` ; chaque test patche `_run` (pour timedatectl) ET `is_unit_active` (pour la détection de service) | Même raison |

Aucune assertion changée sémantiquement — le contrat que ces tests pinnent (champs snapshot NTP/Fail2ban, inférence service-active) est préservé.

Les 4538 tests passent en 7.77s sur Python 3.12 / Linux Mint 22.3 / `so6desktop`.

---

### v0.4.8 — 4499/4499 (21-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4499 passed in 6.29s
```

**Net : −1 (aucun nouveau test, 1 suppression).** v0.4.8 est une release de hardening de code : une passe sub-agent code-review a identifié 4 important + 5 mineur + 3 suggestion findings, tous traités. Le pyproject.toml a été audité en profondeur et 6 fixes de hardening packaging ont été appliqués. Aucun nouveau comportement, aucun changement de contrat — le pipeline d'audit, le JSON `schema_version="1"`, les 7 domaines de score, les 116 EXPLAIN_KEYS, et les 34 sections filtrables sont tous inchangés.

**Pourquoi −1 test :** `test_default_method_is_none` dans `tests/test_secure_boot.py` assertait qu'un `SecureBootSnapshot` construit sans `method=` est par défaut à `None`. Ce champ s'est révélé être mort — rien ne le lit, la valeur n'est jamais propagée au rapport — donc le champ lui-même a été retiré de la dataclass. Le test qui figeait sa valeur par défaut est devenu vide de sens et a été supprimé avec le champ.

#### Nettoyage de champs morts — kwargs retirés des tests existants

| Fichier | Champ retiré | Tests mis à jour |
|---|---|---|
| `tests/test_firewall.py`, `test_degraded.py`, `test_ufw_logging.py` | `ipv4_rules_count`, `ipv6_rules_count` | Kwargs du constructeur supprimés (~6 sites) |
| `tests/test_samba.py` | `min_protocol=""` | Kwarg du constructeur supprimé (1 site) |
| `tests/test_clamav.py` | `db_path`, `last_scan_log_path` | Kwargs du constructeur supprimés + 1 assertion à la ligne 471 retirée |
| `tests/test_secure_boot.py` | `method=` | Helper `make_snap()` mis à jour + 1 test supprimé (`test_default_method_is_none`) |

Aucun changement sémantique sur les assertions restantes — ces champs n'étaient jamais lus par le code de production, donc les tests qui les figeaient étaient du bruit structurel.

#### Ce qui est couvert (pas de nouveaux tests, mais la suite existante attrape le travail)

| Finding audit | Couverture par tests existants validant le fix |
|---|---|
| I4 — `chown_to_sudo_user()` sur création rapport/log | Smoke test manuel (sudo + utilisateur non-root) ; les `test_logs.py` et `test_report.py` existants exercent les chemins autour |
| M1 — Consistance `_C_LOCALE_ENV` | Déjà couvert par le scanner AST `test_locale_coverage.py` (aucun nouveau site requis) |
| M3 — Refactor `log_rotation._service_active` | Couvert par `test_log_rotation.py` existant |
| M2/S2 — Extraction helpers cron | Couvert par `test_cron.py` existant (~150 tests) + `test_tui_cron.py` |
| S1 — Docstring fenêtre 90 jours `auth_log` | Changement doc uniquement, pas de delta comportemental |
| S3 — Export `SCORE_BAR_WIDTH` | Sites d'import mis à jour, couvert par `test_breakdown.py` + `test_domain_scores.py` existants |
| Hardening pyproject.toml | Validé via `python -m build --wheel` + `twine check dist/*` en CI |

Tous les 4499 tests passent en 6.29s sur le workstation de développement local.

---

### v0.4.7 — 4500/4500 (21-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4500 passed in 5.55s
```

**Net : 0 (aucun nouveau test, aucune suppression).** v0.4.7 est une release de maintenance : audit documentaire, harmonisation cosmétique UI (jauges), refonte de la bash completion, et automatisation CI de la création de Release GitHub. Aucun de ces changements ne modifie le comportement du pipeline d'audit ni le contrat de scoring, donc aucune couverture de test n'a été ajoutée.

3 tests dans `tests/test_breakdown.py::TestBar` ont été adaptés (pas de nouveaux tests, juste des assertions ajustées) pour gérer la nouvelle sortie de barre ANSI-colorée de `bob.output.score_bar()` :

| Test | Avant | Après |
|---|---|---|
| `test_full_score_all_filled` | `assert _bar(10) == "██████████"` (chaîne brute 10 chars) | Strip `re.compile(r"\x1b\[[0-9;]*m")` de `_bar(10)` avant comparaison à `"██████████"` |
| `test_zero_score_all_empty` | `assert _bar(0) == "░░░░░░░░░░"` | Idem : strip ANSI puis compare |
| `test_five_half_filled` | `assert len(bar) == 10` | Strip ANSI puis assert contenu visible (5 `█`, 5 `░`) et longueur |

La chaîne de barre est passée de 10 caractères à ~19 caractères avec les séquences ANSI entourant le contenu visible. Le contenu visible (les caractères `█` / `░` eux-mêmes) est inchangé — seuls les codes de couleur autour ont été ajoutés.

Tous les autres tests passent inchangés, incluant toute la suite de tests `bob/checks/` (~3000 tests), le scoring par domaines, le contrat JSON, la couverture des locales, l'héritage de profils, les scénarios golden scoring, et les tests du parser CLI.

---

### v0.4.6 — 4500/4500 (17-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4500 passed in 5.94s
```

**Net : +11 (aucune suppression).** La passe de tests terrain v0.4.5 a fait remonter deux bugs reproductibles sur 13 audits couvrant 6 systèmes (5 VMs + workstation Linux Mint de production). Les deux corrigés et couverts.

#### `tests/test_kernel_modules.py` — `TestParseInstalledKernels` (+5)

Couverture directe du **Bug 1** (`dpkg-query` ne filtrait pas sur l'état `ii`, listait des noyaux en état `rc` après `apt remove` / `autoremove`) :

| Test | Couverture |
|---|---|
| `test_status_prefixed_ii_kept` | Lignes `ii ` produisent la liste de versions (cas nominal) |
| `test_status_prefixed_rc_excluded` | Ligne `rc ` exclue tandis qu'une ligne sœur `ii ` est gardée (reproduction directe du Bug 1) |
| `test_status_prefixed_excludes_all_non_installed_states` | `ii`/`rc`/`pn`/`un`/`iU` cohabitent ; seul `ii` survit |
| `test_status_prefixed_hi_kept` | Paquets `hi` (apt-mark hold) restent dans la liste |
| `test_mixed_legacy_and_status_prefixed_format` | Rétro-compatibilité — lignes legacy (sans `|`) et nouvelles (`ii |...`) mélangées parsent correctement |

#### `tests/test_domain_scores.py` — `TestActiveDomainsIncludesOK` (+6)

Couverture directe du **Bug 2** (`active_domains_from_engine` excluait les domaines `OK`-only → score baissait après remédiation) :

| Test | Couverture |
|---|---|
| `test_ok_finding_makes_domain_active` | Un finding `OK` promeut un domaine (le fix) |
| `test_warn_finding_makes_domain_active` | Rétro-compat : `WARN` promeut toujours |
| `test_alert_finding_makes_domain_active` | Rétro-compat : `ALERT` promeut toujours |
| `test_info_only_finding_does_not_promote_domain` | Domaines `INFO`-only restent cachés (préservé par design) |
| `test_no_findings_no_active_domains` | Engine vide → set actif vide (garde-fou baseline) |
| `test_remediation_keeps_domain_at_max_score` | Reproduction directe Debian 13 : ssh a WARN (8/10) + updates remédié à OK seulement → global = `(8+10)/2 = 9` au lieu de `8` |

#### CI multi-distro intégration (additif — pas des tests unitaires)

Un nouveau workflow GitHub Actions `.github/workflows/integration.yml` lance BOB dans des conteneurs de Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41 sur chaque push/PR vers `main`. Chaque job asserte : code de sortie ≤ 3, pas de sentinelles locale `[xxx.yyy]` dans la sortie, pas de tracebacks Python. Attrape la classe de régression que les tests unitaires ne peuvent pas atteindre (suppositions subprocess spécifiques à la distro, fallback locale, familles non-Debian). 7/7 distros verts à la release v0.4.6.

Validation terrain post-release : 14 audits sur 5 systèmes confirment 7 noyaux `rc` correctement filtrés (3 + 2 + 1 + 0 + 1) et des deltas de score positifs sur les 3 systèmes avec état remédié (Debian 13 +3, Mint test +1, Ubuntu 26.04 LTS +2).

---

### v0.4.5 — 4489/4489 (17-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4489 passed in 5.81s
```

**Net : 0 (refactor pur de `tests/test_locale_coverage.py` — aucun fichier source de `bob/` modifié).**

Le scanner de couverture locale passe de regex-sur-texte-source à parsing AST (`ast.parse` + `ast.walk` + `ast.Call` + `ast.Name` checks). Mêmes 9 tests dans `TestLocaleCoverage` + `TestExplainNamespaceCoverage` + `TestPlaceholderParity`, même contrat externe.

#### Ce qui change à l'intérieur du fichier de test

| Aspect | Avant (regex) | Après (AST) |
|---|---|---|
| Lecture source | `re.finditer` sur le texte du fichier | `ast.parse(...)`, parcours d'arbre |
| Détection d'appel de traduction | Pattern `t\([\'"]([\w.]+)[\'"]` avec negative lookbehind | `ast.Call(func=ast.Name(id in {"t","_t"}))` |
| Extraction du premier argument | Groupe regex | `_literal_key_arg(call)` — vérifie `ast.Constant(str)` |
| Allowlist `_KEY_EXCLUSIONS` | 2 entrées (`samba.open_world`, `log.blocked_attempts` issus de docstring matches) | **Supprimée** — les docstrings sont des constantes string inertes, l'AST ne peut pas les confondre avec des sites d'appel |

#### Ce que ça corrige (vs la forme regex)

- **Matches dans docstrings.** Avec l'AST, les exemples comme `t("samba.open_world")` à l'intérieur d'un docstring de `bob/i18n.py` sont des constantes string-feuilles sans site d'appel — ils ne peuvent pas produire de faux positif.
- **Call sites multilignes.** L'AST est whitespace-indépendant — les appels splittés sur plusieurs lignes (`t(\n    "foo.bar",\n    x=1,\n)`) matchent identiquement.
- **Appels d'attribut.** `obj._t("foo")` résout à `ast.Attribute`, pas `ast.Name` — le type check le rejette proprement sans resserrage ad-hoc de lookbehind.

#### Note performance

Le parsing AST est ~5× plus lent que regex sur ce codebase (300 ms vs 60 ms pour `tests/test_locale_coverage.py`). Négligeable en absolu — la suite complète tourne toujours en ~6 s.

---

### v0.4.4 — 4489/4489 (16-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4489 passed in 5.66s
```

**Net : +21 (aucune suppression).** Hardening terrain cross-distro. Un bug critique + trois fixes de présentation mineurs remontés par tests terrain sur Debian 13, Kali Rolling, Mint test, Ubuntu 26.04 LTS. Les items audit-deferred de v0.4.3 ont aussi atterri (S4 symlink home-bounded, M4 refactor `_parse_ufw_covered_ports`, I2 vague-2 `key=` sur services/virtualization).

#### `tests/test_updates.py` (+9) — couverture du bug critique `updates.py`

`updates.py` reportait "système à jour" sur 100% des VMs Debian-family vierges (Debian 13 avec 59 paquets pending, Kali Rolling avec 868, Mint avec 33, Ubuntu LTS avec 23 dont 21 mises à jour de sécurité). Deux causes racines : `apt-get -s upgrade` est conservatif et back-hold tout ce qui tire un nouveau paquet (typiquement le noyau), et un cache apt obsolète retournait silencieusement 0 paquets.

| Thème de test | Couverture |
|---|---|
| Parsing `-s dist-upgrade` | Remplace `-s upgrade`, parse le nouveau format de ligne (`Inst foo (...)`/`Conf foo (...)`) |
| Détection cache apt obsolète | `Path("/var/cache/apt/pkgcache.bin")` mtime > 7 jours → `result.warn("updates.apt_cache_stale", days=N)` |
| Cross-check vs `apt list --upgradable` | Si `dist-upgrade -s` retourne 0 mais `apt list` retourne > 0 → note d'incohérence |
| Cascade "Surface d'attaque" | Quand l'état updates est `unknown`, la section surface ne dit plus "à jour" ; propage `updates_unknown` à la place |

#### `tests/test_mac_policy.py` (+2) — clé AppArmor 0-profil dédiée

Kali avait AppArmor actif avec 0 enforce + 0 complain profils. v0.4.3 émettait un message contradictoire ("aucun profil en mode enforce (0 en plainte)"). Nouvelle logique 3 cas :

| Cas | Message |
|---|---|
| `enforce > 0` + `complain > 0` | "X enforce, Y complain — passer enforce" (défaut Mint) |
| `enforce > 0` + `complain == 0` | "tous les profils en enforce — bon état" |
| `enforce == 0` + `complain == 0` | Nouveau : "AppArmor activé mais aucun profil chargé — installer apparmor-profiles-extra" |

#### `tests/test_disk.py` (+3) — skip SMART quand tout-virtuel

Sur Kali VM `/dev/vda` (libvirt), v0.4.3 émettait `ℹ /dev/vda — SMART non applicable` puis `✔ Tous les disques ont passé le contrôle SMART`. Deuxième ligne trompeuse — aucun SMART n'a réellement tourné. Fix : si tous les disques sont SMART-non-applicables, skip le résumé OK ; émet un seul INFO "SMART non-applicable — environnement virtualisé/conteneur".

#### `tests/test_ddns.py` (+2) — ports DDNS inline dans WARN

Sur Mint test VM, le WARN DDNS était émis avec la liste des ports en lignes d'action séparées `→ 22/tcp` / `→ 80/tcp`, ressemblant à des commandes de remédiation. Ports maintenant inlinés dans le WARN lui-même : `DDNS actif avec port(s) ouverts sans restriction (22/tcp, 80/tcp) — vérifiez…`.

#### `tests/test_locale_coverage.py` (nouveau, +9) — garde-fou régression locale fallback

Après l'incident sentinelle `[logs.attempts]` de v0.4.3 (clé locale retirée sans mettre à jour ses call sites dans `display.py`), ce fichier scanne tout `bob/**/*.py` pour les appels `t("xxx.yyy")` / `_t("xxx.yyy")` (forme regex initiale, refactor AST en v0.4.5) et asserte que chaque clé existe à la fois dans `en.json` et `fr.json`. Attrape la classe entière de régressions de sentinelle en CI.

Trois classes de test : `TestLocaleCoverage` (existence de clés), `TestExplainNamespaceCoverage` (chaque entrée `EXPLAIN_KEYS` a le quartet complet `title`/`why`/`how`/`cis_ref` dans les deux locales), `TestPlaceholderParity` (chaque placeholder `{var}` en EN match en FR).

#### `tests/test_ssh.py` (+1) — symlink home-bounded (S4 redesign)

Nouveau helper `_is_safe_user_path(path, owner_home)` dans `bob/checks/_run.py` : accepte les symlinks pointant à l'intérieur du home de l'owner, rejette ceux pointant ailleurs. Appliqué dans `ssh.py` (parsing authorized_keys / ssh/config) — préserve les cas d'usage dotfiles-via-git sans perdre la garde contre les attaques symlink. `_is_safe_config_path` conservé pour `/etc/cron.d/`.

---

### v0.4.3 — 4468/4468 (15-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4468 passed in 5.41s
```

**Net : +16 (incl. +4 couverture régression, aucune suppression).** Rattrapage doc + passe de hardening post-audit. Un critique (`--json-full` crash) + cinq importants + huit mineurs + cinq suggestions issus de la code review agent.

#### `tests/test_hardening.py` (+5) — régression dead-attr HardeningSnapshot `--json-full`

`bob --json --json-full` crashait parce que `bob/json_output.py` référençait 5 attributs qui avaient été retirés de `HardeningSnapshot` (`kernel.unprivileged_bpf_disabled`, `kernel.unprivileged_userns_clone`, `fs.protected_fifos`, `fs.protected_regular`, `kernel.modules_disabled`). Les tests exercent maintenant `build_json_data` avec des fixtures `HardeningSnapshot` réalistes sur les deux modes `--json` (court) et `--json --json-full` (étendu).

#### `tests/test_explain.py` (+4) — 4 clés firewall promues dans `EXPLAIN_KEYS`

`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`, `firewall.policy_routed_open` ont été promues de "documentées mais non-figées" à entrées canoniques `EXPLAIN_KEYS`. Chacune nécessitait : `title`/`why`/`how`/`cis_ref` complets dans `en.json` + `fr.json`, changement de label de groupe "Firewall Logging" → "Firewall", et un test de régression qui vérifie que `bob --explain firewall.inactive` retourne du contenu (pas "not found").

#### `tests/test_ssl_certs.py` + `tests/test_logs.py` (+2) — `strptime("%b ...")` indépendant locale

`strptime("%b ...")` cassait quand `LANG=fr_FR.UTF-8` mettait la lib C en noms de mois français ("janv", "févr"). `bob/checks/ssl_certs.py` et `bob/checks/logs.py` enveloppent maintenant l'appel avec un context manager `_C_LOCALE_ENV` pour forcer le parsing des mois en anglais quelle que soit la locale hôte.

#### `tests/test_ports.py` (+1) — faux positif IP `_is_covered_by_ufw`

Une règle UFW `from 192.168.1.22 to any` était matchée comme "couvre le port 22" parce que la regex capturait `22` depuis l'IP source. Regex d'extraction de port ancrée maintenant au champ `port/proto` uniquement.

#### `tests/test_cron_audit.py` (+1) — validateur range hors bornes

Des expressions cron comme `60 * * * *` (minute = 60 invalide) étaient acceptées. Validateur rejette maintenant les valeurs hors bornes par champ (`0-59` pour minute, `0-23` pour heure, etc.).

#### `tests/test_email.py` + `tests/test_html_output.py` (+3) — liens markdown non échappés HTML

Le rendu HTML du body email échappait le markdown `[label](url)` en tags `&lt;a&gt;` littéraux. Ordre d'opérations dans `_inline_format()` inversé pour que la conversion markdown-to-HTML se fasse avant l'échappement générique.

#### Autres items de la passe

Attribut `key=` ajouté à ~30 findings dans `docker`/`firewall_stack`/`network_context`/`ports`. 7 clés locales mortes retirées (ex. `samba.dangerous_macro`). Anti-pattern concat i18n résolu dans `ddns` et `logs` (string composée unique au lieu de `t(key1) + " " + t(key2)`). Références CIS ajoutées à 8 findings. CHANGELOG court corrigé pour v0.4.2.

---

### v0.4.2 — 4452/4452 (14-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4452 passed in 5.25s
```

**Net : +3.** Phase 3 distro-ready (discipline packaging) livre des artefacts de packaging — aucun changement code Python à ce niveau. Une passe de hardening pré-release séparée (audit agent) a ajouté de petits fix code (firewall keys, `_C_LOCALE_ENV` sur 3 sites, threading `user_config` dans `watch.py`, liste binaires AppArmor, renommage `BOB_SHARE` avec fallback) et un nouveau fichier de test `test_template_vars_migration.py` (3 tests) qui track visiblement la dette de migration Phase 2.

Validation séparée :

| Artefact | Commande de validation | Résultat |
|---|---|---|
| `man/bob.1` | `groff -man -Tutf8 man/bob.1 >/dev/null && man -l man/bob.1` | ✓ |
| `man/bob.conf.5` | idem | ✓ |
| `man/bob-profile.5` | idem | ✓ |
| `bob/data/schemas/*.json` | `python3 -c "import json; json.load(open(f))"` × 3 | ✓ |
| `debian/control` | revue manuelle, syntaxe correspond à sortie dh-make | ✓ |
| `debian/copyright` | format DEP-5, revue manuelle | ✓ |
| `debian/rules` | exécutable (`chmod +x`), syntaxe Makefile valide | ✓ |
| `debian/apparmor.d/bob` | revue manuelle, chemins cross-checkés contre sites exec `bob/checks/*` | ✓ |
| `packaging/rpm/bob.spec` | revue manuelle, patterns `pyproject-rpm-macros` | ✓ |

Validation complète `dpkg-buildpackage` + `lintian` + `rpmbuild` + `rpmlint` reportée à la première tentative de packaging communautaire (AUR/COPR ou premier upload Debian unstable). Upstream s'engage à corriger tout issue lintian/rpmlint signalée dans les patch releases suivantes.

---

### v0.4.1 — 4449/4449 (14-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4449 passed in 5.07s
```

**Net : +19 (aucune suppression).** Phase 2 distro-ready (découplage architectural) : extraction `bob/tui/`, tests d'intégration `--offline`, représentation findings/deductions indépendante de la locale via `template_vars`, plus une passe de hardening post-revue sur `bob/formatter.py` (4 tests edge-case).

#### `tests/test_formatter.py` (nouveau, +14)

`bob.formatter` — reconstruction de message indépendante de la locale :

| Classe | Tests | Couverture |
|---|---:|---|
| `TestFormatFinding` | 5 | Ordre de résolution : key + template_vars render via i18n, key seul retourne template, sans key fallback message, key inconnue fallback, cas vide |
| `TestFormatDeduction` | 2 | Même ordre de résolution appliqué à `Deduction.key` + `template_vars` → `reason` |
| `TestLocaleRoundtrip` | 1 | Même `(key, template_vars)` donne du texte différent en `fr` vs `en` — le sens du découplage |
| `TestBackwardCompatibility` | 2 | Findings legacy (sans key, sans template_vars) passent inchangés |
| `TestFormatterEdgeCases` (post-revue) | 4 | Empty template_vars sur template avec placeholders retourne raw, partial template_vars raise KeyError, key gagne sur mismatched message, empty message + no key retourne "" |

#### `tests/test_webhook.py` (+3)

Contrat mode `--offline` strict :

| Test | Couverture |
|---|---|
| `test_webhook_with_offline_flag_parses` | Le parser CLI accepte `--offline --webhook=URL` ensemble (non mutuellement exclusifs au parsing) |
| `test_offline_skips_webhook_send` | Mirroir de la branche de décision `__main__.py:277` — échoue si le gate offline est jamais abandonné |
| `test_get_public_ip_offline_skips_urllib` | Monkeypatch de `sysinfo.urllib` avec stub explosif ; lève AssertionError si urlopen est atteint en mode offline |

#### `tests/test_json_schema.py` (+2)

Champ `template_vars` exposé dans la sortie JSON :

| Test | Couverture |
|---|---|
| `test_each_deduction_has_template_vars_field` | Chaque deduction expose `template_vars` dict (vide pour les checks legacy) |
| `test_each_finding_has_template_vars_field` | Chaque finding (mode full) expose `template_vars` dict |

#### `bob/tui/cron.py` (extraction — aucun nouveau test)

`bob/cron_ui.py` (952 lignes) déplacé vers `bob/tui/cron.py` via `git mv`. Les 4430 tests existants exercent déjà le chemin d'import ; la suite complète est restée à 4430/4430 après le déplacement, prouvant que le rename est transparent.

---

### v0.4.0 — 4430/4430 (14-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4430 passed in 5.52s
```

**Net : +82 (aucune suppression).** Contrats Phase 1 distro-ready figés, plus deux passes de hardening post-revue :
- **Passe #1** (+22 tests dans `test_services_schema.py`) : regex port stricte 1–65535, factorisation `$defs`, contraintes métier `if/then`/`anyOf`, wrapper `schema_version` plugin-file.
- **Passe #2** (+3 tests, defense-in-depth) : `services-list.minItems: 1` (rejette les tableaux vides), fixtures à classes réelles remplaçant `MagicMock` dans `test_json_schema.py` (les attributs renommés lèvent `AttributeError` au lieu d'être auto-mockés), `EXPECTED_REQUIRED_KEYS_V1` dupliqué pour détecter la dérive du contrat, compat shim `RefResolver`→`referencing` pour jsonschema 4.18+, asserts via `e.absolute_path` au lieu du matching de message fragile.

#### `tests/test_i18n.py` — `TestDetectSystemLang` (+12)

Détection automatique de locale POSIX (`$LC_ALL` / `$LC_MESSAGES` / `$LANG`) :

| Test | Couverture |
|---|---|
| `test_no_env_returns_default` | Aucune var env définie → `"en"` |
| `test_lang_c_returns_default` | `LANG=C` → `"en"` |
| `test_lang_posix_returns_default` | `LANG=POSIX` → `"en"` |
| `test_lang_c_utf8_returns_default` | `LANG=C.UTF-8` → `"en"` |
| `test_fr_fr_returns_fr` | `LANG=fr_FR.UTF-8` → `"fr"` |
| `test_fr_be_returns_fr` | `LANG=fr_BE` → `"fr"` |
| `test_fr_with_modifier_returns_fr` | `LANG=fr_FR.UTF-8@euro` → `"fr"` |
| `test_en_us_returns_en` | `LANG=en_US.UTF-8` → `"en"` |
| `test_unsupported_lang_falls_back_to_default` | `ja_JP`/`de_DE`/`es_ES`/`zh_CN` → `"en"` |
| `test_lc_all_overrides_lang` | `LC_ALL=fr` prime sur `LANG=en` |
| `test_lc_messages_overrides_lang` | `LC_MESSAGES=fr` prime sur `LANG=en` |
| `test_empty_lc_all_falls_through_to_lang` | `LC_ALL=""` → consulte `LANG` |

#### `tests/test_cli.py` — intégration locale (+4)

| Test | Couverture |
|---|---|
| `test_french_overrides_system_locale` | `--french` gagne sur `LANG=ja_JP` |
| `test_lang_explicit_overrides_system_locale` | `--lang=en` gagne sur `LANG=fr_FR` |
| `test_default_uses_system_locale_when_fr` | Défaut → `fr` quand `LANG=fr_FR.UTF-8` |
| `test_default_uses_en_when_lang_c` | Défaut → `en` quand `LANG=C` |

#### `tests/test_json_schema.py` (nouveau, +17)

Invariants du schéma de sortie JSON — contrat d'API publique :

| Classe | Tests |
|---|---:|
| `TestSchemaVersion` | 2 |
| `TestRequiredKeysAlwaysPresent` | 6 |
| `TestFieldTypes` | 5 |
| `TestStableKeysExposed` | 3 |
| `TestDomainScoresStructure` | 1 |

Vérifie `schema_version="1"`, clés top-level requises, types de champs, champ `key` indépendant de la locale sur chaque finding/deduction.

**Hardening passe #2 :** toutes les injections `MagicMock` dans les fixtures remplacées par les vraies dataclasses BOB (`SystemInfo`, `PortsSnapshot`, `FirewallStackSnapshot`, `NetworkContextSnapshot`, `CheckResult`) — un attribut renommé dans `bob.json_output.build_json_data` lève `AttributeError` au lieu d'être silencieusement auto-mocké. Le test de timestamp utilise désormais `datetime.fromisoformat()` (ISO 8601 strict). Deux nouveaux tests defense-in-depth : `test_short_mode_strict_set` (rejette les clés inattendues qui fuiraient en mode short) et `test_constants_match_expected_set` (attrape la dérive entre les constantes de production et le contrat hard-codé côté test).

#### `tests/test_explain.py` — alias map + freeze (+6)

| Test | Couverture |
|---|---|
| `test_alias_map_is_dict` | `EXPLAIN_KEY_ALIASES` est un dict |
| `test_alias_targets_resolve_to_valid_keys` | Chaque cible d'alias existe dans le set canonique |
| `test_alias_keys_are_not_in_canonical_set` | Les alias ne shadowent pas les vraies clés |
| `test_normalize_key_resolves_aliases` | Alias enregistré est résolu |
| `test_normalize_key_passthrough_when_no_alias` | Clés inconnues passent inchangées |
| `test_core_keys_present_in_canonical_set` | 16 clés "load-bearing" figées doivent rester dans `EXPLAIN_KEYS` |

#### `tests/test_services_schema.py` (nouveau, +43)

JSON Schema formel pour les plugins services (Draft 2020-12), étendu après deux passes de hardening post-revue :

| Classe | Tests | Couverture |
|---|---:|---|
| `TestSchemasAreWellFormed` | 4 | Les schémas passent l'auto-validation Draft 2020-12 ; `services-list` rejette les tableaux vides (passe #2 : `minItems: 1`) |
| `TestBundledServicesMatchSchema` | 3 | `services.json` bundled valide entrée par entrée ; IDs uniques (`Counter` O(n)) |
| `TestValidPluginSamples` | 3 | Plugins valides échantillons (minimal fixed, avec detection, user config_key) |
| `TestInvalidPluginSamples` | 10 | Cas de rejet : champ manquant, mauvais risk, mauvais port, port 0/65536, champ inconnu, fixed sans ports, ID avec espaces, string binary vide. Passe #2 : 5 d'entre eux assert désormais via `e.absolute_path` (stable entre versions de jsonschema) au lieu du matching de substring de message. |
| `TestSchemaPythonParity` | 2 | Alignement Schema-valid ↔ Python-valid |
| `TestBusinessConstraints` (nouveau passe #1) | 7 | `auto` requiert `config_files`, service indétectable rejeté, `detection: {}` vide rejeté |
| `TestPluginFileWrapper` (nouveau passe #1) | 6 | Array legacy + wrapped `{schema_version, services}` acceptés ; v2 / extras rejetés. Passe #2 : résolution cross-file `$ref` via le compat shim `_make_resolved_validator` (`referencing` moderne d'abord, fallback `RefResolver` legacy). |
| `TestRegistryAcceptsBothShapes` (nouveau passe #1) | 7 | Parité Python `_extract_plugin_entries` avec le méta-schéma |
| Tests aux bornes | 2 | Port 65535 accepté, 65536 rejeté (regex stricte) |

Une fixture module-scope `service_validator` est partagée entre toutes les classes (passe #2 — remplace 4 duplications par-classe d'un one-liner).

`jsonschema` est une dépendance test-only (utilise `pytest.importorskip`).

#### `tests/test_min_level.py` — affichage du score

`TestScoreTrend::test_stable_shows_equal` renommé `test_stable_shows_no_annotation` et inversé : un score stable affiche désormais exactement `"7/10"` (sans suffixe `= 7`).

#### `tests/conftest.py` (nouveau)

Fixture autouse force `LC_ALL=C`/`LANG=C` pour chaque test, rendant les défauts CLI dépendants de la locale déterministes indépendamment de la locale hôte du dev.

---

### v0.3.6 — 4348/4348 (09-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.04s
```

**Aucun nouveau test — passe de code review.** Huit correctifs liés : `Path.home()` → `get_user_home()` dans 7 modules · ULA/link-local IPv6 dans `_is_private_or_loopback` · SSH `AllowTcpForwarding local` accepté · header journalisation UFW masqué quand UFW inactif · regex legacy `NOTIFY_EMAIL` · `_check_weak_algo` déplacé dans la section sub-check · 22 imports inutilisés supprimés (pyflakes propre sauf un `noqa` intentionnel) · 47 clés de locales mortes supprimées.

**Validation terrain :** Audit complet sur so6desktop (Linux Mint 22.3) terminé avec score 8/10. L'en-tête de section journalisation UFW est désormais masqué quand UFW est inactif ; les link-local IPv6 sont correctement classés privés ; les profils/plugins/baselines sont correctement chargés depuis `/home/so6/.config/bob/` (et non `/root/.config/bob/`).

---

### v0.3.5 — 4348/4348 (08-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.22s
```

**Aucun nouveau test — refactoring pur (`runner.py` closure `_sec` −295 lignes, `ssh.py` helper `_check_weak_algo` −26 lignes)**

---

### v0.3.4 — 4348/4348 (08-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.17s
```

**Aucun nouveau test — hotfix uniquement (passage de `user_config` à `run_checks()` — `NameError` sur la whitelist SUID)**

---

### v0.3.3 — 4348/4348 (07-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4348 passed in 5.21s
```

**Bilan : +1 par rapport à v0.3.2 (+7 nouveaux tests capped_indices, −6 tests was_capped supprimés)**

#### `tests/test_domain_scores.py` — `TestCappedIndices` remplace `TestWasCapped` (+7, −6)

`TestWasCapped` testait le flag booléen `deduction.was_capped` (supprimé en v0.3.3). Remplacé par `TestCappedIndices` qui teste la valeur de retour `frozenset[int]` de `compute_domain_scores()`.

| Test | Couverture |
|------|------------|
| `test_no_cap_returns_empty_frozenset` | Aucun cap déclenché → second retour est `frozenset()` |
| `test_single_capped_deduction_returns_index` | Une déduction dépasse le cap → indice `0` dans le frozenset retourné |
| `test_uncapped_deduction_not_in_frozenset` | Déduction dans le cap → indice absent du frozenset |
| `test_multiple_deductions_only_capped_indices` | Deux déductions, une cappée → seul l'indice cappé est retourné |
| `test_frozenset_is_immutable` | L'objet retourné est un `frozenset`, pas un `set` |
| `test_engine_capped_indices_matches_return_value` | `engine.capped_indices` égale le frozenset retourné par `compute_domain_scores()` |
| `test_non_tool_cap_key_never_capped` | Clé sans préfixe tool-cap → jamais dans le frozenset cappé |

---

### v0.3.2 — 4347/4347 (07-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4347 passed in 5.23s
```

**Net : +19 depuis v0.3.1 (+21 nouveaux tests whitelist, −2 tests code mort supprimés)**

**Nouveaux tests (+21) :**

#### `tests/test_suid_audit.py` — `TestFromSystemUserWhitelist` (+8)

| Test | Couverture |
|------|------------|
| `test_whitelisted_suid_emits_info` | Snapshot avec chemins whitelistés → résultat INFO `suid_audit.whitelisted` |
| `test_whitelisted_suid_no_deduction` | Chemins whitelistés → aucune déduction |
| `test_whitelisted_suid_ok_result_when_no_unexpected` | Tout supprimé → `suid_audit.ok` toujours présent |
| `test_whitelisted_suid_warn_result_when_unexpected_remain` | Mix whitelisté + inattendu → les deux résultats présents |
| `test_whitelisted_count_in_info_message` | 2 chemins whitelistés → "2" dans le message INFO |
| `test_no_whitelisted_finding_when_list_empty` | `whitelisted_suid` vide → pas de résultat INFO |
| `test_whitelisted_truncation_at_10` | 11 chemins whitelistés → suffixe "+1 more" |

#### `tests/test_suid_audit.py` — `TestGetSuidWhitelist` (+7)

| Test | Couverture |
|------|------------|
| `test_returns_empty_list_when_key_absent` | Clé absente → `[]` |
| `test_single_pattern` | `kismet_cap_*` → `["kismet_cap_*"]` |
| `test_multiple_patterns_comma_separated` | `a, b, c` → `["a", "b", "c"]` |
| `test_strips_whitespace_around_patterns` | `  foo_*  ,  bar  ` → `["foo_*", "bar"]` |
| `test_empty_value_returns_empty_list` | Valeur chaîne vide → `[]` |
| `test_commas_only_returns_empty_list` | ` , , ` → `[]` |
| `test_persists_and_reloads` | Écrit puis rechargé → même liste |

#### `tests/test_suid_audit.py` — `TestGlobMatching` (+7)

| Test | Couverture |
|------|------------|
| `test_glob_matches_kismet_cap_prefix` | `kismet_cap_*` correspond à 3 chemins Kismet |
| `test_exact_name_match` | Pattern basename exact → chemin correspondant whitelisté |
| `test_non_matching_pattern_leaves_unexpected` | Pattern sans correspondance → chemin reste inattendu |
| `test_empty_patterns_leaves_all_unexpected` | Patterns vides → tous les chemins restent inattendus |
| `test_wildcard_star_matches_all` | Pattern `*` → tout whitelisté |
| `test_partial_glob_mix` | Mix : un correspondant, un non |
| `test_multiple_patterns_any_match_whitelists` | Deux patterns exacts → chacun correspond à sa cible |

**Tests supprimés (−2, DC-1) :**

`tests/test_suid_audit.py` — `TestIsRootOwned` supprimée avec la fonction `_is_root_owned()` (code mort) :
- `test_nonexistent_path_returns_false`
- `test_current_user_file_not_root_owned_when_not_root`

---

### v0.3.1 — 4328/4328 (06-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4328 passed in 4.33s
```

**Nouveaux tests (+6) :**

#### `tests/test_domain_scores.py` — `TestWasCapped` (+6)

| Test | Couverture |
|------|------------|
| `test_uncapped_deduction_not_marked` | Déduction dans le plafond outil → `was_capped` reste `False` |
| `test_fully_absorbed_deduction_marked` | Deuxième déduction après épuisement du plafond → `was_capped = True` |
| `test_partially_absorbed_deduction_marked` | Déduction dépasse partiellement le plafond restant → `was_capped = True` |
| `test_non_tool_cap_key_never_marked` | Clé sans préfixe de plafond outil → `was_capped` toujours `False` |
| `test_cached_domain_scores_on_engine` | Après `apply_domain_score_override()`, `engine.domain_scores` correspond à l'appel direct |
| `test_engine_domain_scores_empty_before_override` | Avant surcharge, `engine.domain_scores` retourne `{}` |

---

### v0.3.0 — 4322/4322 (06-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4322 passed in 4.45s
```

**Nouveaux tests (+48) :**

#### `tests/test_breakdown.py` (nouveau fichier, +16)

| Classe | Test | Couverture |
|--------|------|------------|
| `TestBar` | `test_full_score_all_filled` | Score 10 → tous les blocs remplis |
| `TestBar` | `test_zero_score_all_empty` | Score 0 → tous les blocs vides |
| `TestBar` | `test_five_half_filled` | Score 5 → moitié remplie |
| `TestDisplayBreakdownClean` | `test_no_deductions_message` | Aucune déduction → clé `no_deductions` affichée |
| `TestDisplayBreakdownClean` | `test_section_title_printed` | En-tête de section affiché |
| `TestDisplayBreakdownClean` | `test_final_score_ten_shown` | Score 10 → clé `breakdown.final_score` affichée |
| `TestDisplayBreakdownWithDeductions` | `test_deductions_header_shown` | Déductions présentes → en-tête affiché |
| `TestDisplayBreakdownWithDeductions` | `test_deduction_keys_shown` | Chaque clé de déduction apparaît dans la sortie |
| `TestDisplayBreakdownWithDeductions` | `test_raw_score_shown` | Clé `breakdown.raw_score` affichée |
| `TestDisplayBreakdownWithDeductions` | `test_domain_scores_header_shown` | Domaines actifs → en-tête affiché |
| `TestDisplayBreakdownWithDeductions` | `test_domain_average_shown` | Surcharge globale définie → `breakdown.domain_average` affiché |
| `TestDisplayBreakdownWithDeductions` | `test_final_score_shown` | Clé `breakdown.final_score` affichée |
| `TestDisplayBreakdownToolCap` | `test_tool_cap_message_shown_when_exceeded` | Déductions totales > plafond → ligne info plafond outil affichée |
| `TestDisplayBreakdownToolCap` | `test_no_tool_cap_message_when_within_limit` | Déductions totales ≤ plafond → pas de message plafond outil |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_shown` | `engine.cap_info` défini → `breakdown.engine_cap_applied` affiché |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_not_shown_when_absent` | Pas de plafond → pas de message plafond |

#### `tests/test_golden_scenarios.py` (nouveau fichier, +32)

| Classe | Tests | Couverture |
|--------|-------|------------|
| `TestCleanMachine` | 4 | Score 10/10 ; pas de breakdown ; aucun domaine actif ; findings INFO exclus de l'activation des domaines |
| `TestHardenedServer` | 3 | 2 déductions durcissement → score 8 ; déductions par domaine ; assertions breakdown brut |
| `TestDefaultDesktop` | 3 | 4 déductions sur 3 domaines → score 9 ; déductions exactes par domaine |
| `TestPoorlyConfiguredServer` | 3 | Score brut 3 ; moyenne domaines 8 ; moyenne supérieure au score brut |
| `TestFirewallInactive` | 3 | Plafond moteur appliqué à 3 ; moyenne domaine peut dépasser le brut plafonné ; `cap_info` stocké |
| `TestDebian13Minimal` | 4 | Score brut 2 ; moyenne domaines 6 ; plafond outil rootkit ; 6 déductions durcissement après plafond |
| `TestToolCapInvariants` | 4 | rootkit/clamav/file_integrity plafonnés à 1pt chacun ; outil non-plafonné (ssh) s'accumule normalement |
| `TestScoreStability` | 5 | Indépendance d'ordre ; monotonicité même-domaine ; indépendance des domaines ; score ∈ [0, MAX_SCORE] ; plancher brut à 0 |
| `TestMultiDomainMachine` | 3 | 5 domaines actifs exact (frozenset) ; chaque domaine déduit une fois ; score 9 |

#### `tests/test_min_level.py` (renommé, +0 net)

`test_stable_shows_right_arrow` → `test_stable_shows_equal` — assertion mise à jour de `"→" in val` vers `"= 7" in val`.

---

### v0.2.4 — 4274/4274 (05-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4274 passed in 4.65s
```

**Nouveaux tests (+12) :**

#### `tests/test_kernel_modules.py` (+2)

| Test | Couverture |
|------|------------|
| `test_up_to_date_names_running_kernel_not_unsigned_sibling` | Kernel courant `amd64` avec sibling `-unsigned` trié en `most_recent` → le message OK nomme le kernel courant, pas le sibling non-signé |
| `test_debian_signed_unsigned_pair_uses_obsolete_same_message` | Paire signé/non-signé en tête de la liste → clé `kernels_obsolete_same` sélectionnée (sans paire "courant / récent" dans le texte), pas `kernels_obsolete` |

#### `tests/test_compare.py` — `TestDisplayDelta` (+4)

| Test | Couverture |
|------|------------|
| `test_variable_deductions_increased_shown_without_structural_change` | `deduction_delta > 0`, aucun changement structurel (pas de delta alertes/warns, pas de clés nouvelles/résolues) → message déductions variables affiché |
| `test_variable_deductions_decreased_shown_without_structural_change` | `deduction_delta < 0`, aucun changement structurel → message de diminution des déductions affiché |
| `test_variable_deductions_suppressed_when_warn_delta` | `deduction_delta != 0` mais `warn_delta != 0` → message supprimé (changement structurel explique le mouvement de score) |
| `test_variable_deductions_suppressed_when_new_finding_key` | `deduction_delta != 0` mais `new_finding_keys` non vide → message supprimé |

#### `tests/test_compare.py` — `TestDeductionTracking` (nouvelle classe, +6)

| Test | Couverture |
|------|------------|
| `test_deduction_total_none_in_new_baseline_defaults` | Valeur par défaut de `AuditBaseline().deduction_total` est `None` (pas `0`) |
| `test_load_baseline_returns_none_when_field_absent` | Ancien JSON sans clé `"deduction_total"` → `None` après `load_baseline()` |
| `test_load_baseline_returns_int_when_field_present` | Nouveau JSON avec `"deduction_total": 5` → entier `5` après `load_baseline()` |
| `test_deduction_delta_zero_when_prev_is_old_baseline` | `prev.deduction_total is None` → `compute_delta()` retourne `deduction_delta == 0` |
| `test_deduction_delta_computed_when_both_tracked` | Les deux côtés ont un `deduction_total` entier → delta signé correct calculé |
| `test_deduction_delta_zero_when_unchanged` | Même valeur des deux côtés → `deduction_delta == 0` |

---

### v0.2.3 — 4262/4262 (03-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4262 passed in 4.53s
```

**Nouveaux tests (+1) :**

#### `tests/test_exposure.py` (+1)

| Test | Couverture |
|------|------------|
| `test_not_active_shows_stopped_text` | SSH installé mais service arrêté → tableau de surface d'attaque utilise la clé `exposure.ssh_stopped` ("installé — non démarré"), pas la clé fusionnée `ssh_not_running` |

**Tests mis à jour / renommés (4) :**

| Fichier | Test | Changement |
|---------|------|------------|
| `tests/test_services.py` | `test_not_listening_critical_adds_warn` → `test_not_listening_critical_adds_info` | `NOT_LISTENING` rétrogradé en INFO quelle que soit la sévérité du service |
| `tests/test_services.py` | `test_not_listening_high_adds_warn` → `test_not_listening_high_adds_info` | Idem — asserte aussi l'absence de finding WARN |
| `tests/test_logs.py` | `test_finding_is_warn_level` → `test_finding_is_info_level` | Dominance locale IoT rétrogradée en INFO — asserte `FindingLevel.INFO` |
| `tests/test_logs.py` | `test_score_deduction_one_point` → `test_no_score_deduction` | Dominance locale IoT sans déduction — asserte `len(local_deductions) == 0` |

---

### v0.2.2 — 4255/4255 (02-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4255 passed in 4.42s
```

**Nouveaux tests (+17) :**

#### `tests/test_firewall.py` — `TestOrphanRules` (+3)

| Test | Couverture |
|------|------------|
| `test_bare_port_rule_flagged_when_nothing_listening` | `57621 ALLOW IN` sans TCP ni UDP en écoute → signalé comme orphelin |
| `test_bare_port_rule_not_flagged_when_tcp_listening` | `57621/tcp` dans les ports en écoute → non signalé |
| `test_bare_port_rule_not_flagged_when_udp_listening` | `57621/udp` dans les ports en écoute → non signalé |

#### `tests/test_scoring.py` — `TestScoringInvariants` (+5)

Invariants structurels du moteur de scoring — propriétés devant tenir quel que soit l'input :

| Test | Invariant |
|------|-----------|
| `test_score_floor_is_zero_on_huge_deduction` | Le score ne descend jamais sous 0, même avec 999 points de déduction |
| `test_score_ceiling_is_max_on_no_deductions` | Le score vaut MAX_SCORE sans déductions |
| `test_deductions_are_monotone_decreasing` | Chaque déduction ne peut qu'abaisser ou maintenir le score |
| `test_cap_above_current_score_is_noop` | Un plafond supérieur au score actuel ne le modifie pas |
| `test_score_after_domain_override_in_valid_range` | Après `apply_domain_score_override()`, score ∈ [0, 10] |

#### `tests/test_domain_scores.py` — `TestScoringInvariants` (+7)

Invariants structurels pour le pipeline de scoring par domaine :

| Test | Invariant |
|------|-----------|
| `test_info_only_findings_do_not_activate_domain` | Findings INFO sans déduction n'activent pas le domaine |
| `test_warn_finding_activates_domain` | Un finding WARN active le domaine correspondant |
| `test_alert_finding_activates_domain` | Un finding ALERT active le domaine correspondant |
| `test_deduction_alone_activates_domain` | Une déduction seule (sans finding) active le domaine |
| `test_global_average_bounded_by_active_domain_scores` | Moyenne globale ∈ [min, max] des scores de domaines actifs |
| `test_all_domain_scores_in_valid_range` | Chaque score de domaine toujours dans [0, MAX_SCORE] |
| `test_compute_global_always_in_valid_range` | `compute_global_from_domains` retourne toujours une valeur dans [0, 10] |

#### `tests/test_manage_logs.py` — `TestStatFallback` (+2)

Tests de régression pour le fix race condition `.stat()` de v0.2.1. Un fichier log peut disparaître entre le scan du répertoire et la boucle d'affichage (ex. logrotate en parallèle). Le mock cible uniquement les fichiers `.log` pour ne pas casser `Path.exists()` sur les répertoires (Python 3.12 : `exists()` appelle `self.stat()` en interne).

| Test | Couverture |
|------|------------|
| `TestStatFallback.test_cur_logs_stat_oserror_uses_fallback` | `.stat()` lève `OSError` dans la boucle `cur_logs` → sortie affiche `(0 KB)` et `"?"` sans crash |
| `TestStatFallback.test_extra_logs_stat_oserror_uses_fallback` | `.stat()` lève `OSError` dans la boucle `extra_sections` → même sortie de repli |

**Tests mis à jour (2) :**

| Fichier | Test | Changement |
|---------|------|------------|
| `tests/test_clamav.py` | `test_db_very_outdated_deducts_1` (était `_deducts_2`) | Déduction `clamav.db_very_outdated` réduite de 2pt à 1pt (Fix 3) |
| `tests/test_clamav.py` | `test_worst_case` | Total déductions 4→3 (freshclam:1 + db_very_outdated:1 + scan_very_old:1) |

---

### v0.2.0 — 4238/4238 (01-05-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4238 passed in 4.31s
```

**Nouveaux tests (+32) :**

#### `tests/test_kernel_modules.py` (+6)

| Test | Couverture |
|------|------------|
| `TestKernelRebootPending.test_no_reboot_pending_debian_signed_plus_unsigned_same_version` | `amd64` en cours avec `amd64-unsigned` installé → aucun avertissement de redémarrage |
| `TestKernelRebootPending.test_reboot_still_pending_when_genuinely_newer_debian_kernel` | Une version réellement plus récente déclenche toujours le redémarrage en attente |
| `TestStripUnsigned.test_strips_unsigned_suffix` | Suffixe `-unsigned` retiré |
| `TestStripUnsigned.test_no_change_without_suffix` | Chaîne sans suffixe inchangée |
| `TestStripUnsigned.test_no_change_ubuntu_style` | Noyau au format Ubuntu inchangé |
| `TestStripUnsigned.test_no_change_empty` | Chaîne vide sans danger |

#### `tests/test_cron.py` (+6)

| Test | Couverture |
|------|------------|
| `TestDetectMta.test_no_sendmail_returns_false` | Pas de sendmail → `(False, "")` |
| `TestDetectMta.test_postfix_detected_via_config_file` | `/etc/postfix/main.cf` présent → `(True, "Postfix")` |
| `TestDetectMta.test_exim_detected` | `exim4` dans le PATH → `(True, "Exim")` |
| `TestDetectMta.test_msmtp_detected` | `msmtp` dans le PATH → `(True, "msmtp")` |
| `TestDetectMta.test_ssmtp_detected` | `ssmtp` dans le PATH → `(True, "ssmtp")` |
| `TestDetectMta.test_unknown_mta_returns_empty_name` | sendmail trouvé, fournisseur inconnu → `(True, "")` |

#### `tests/test_scoring.py` (+6)

| Test | Couverture |
|------|------------|
| `TestSetGlobalScore.test_override_replaces_raw_score` | Valeur d'override retournée par `engine.score` |
| `TestSetGlobalScore.test_no_override_by_default` | Score brut utilisé quand aucun override n'est posé |
| `TestSetGlobalScore.test_override_clamps_above_max` | Valeurs > 10 ramenées à 10 |
| `TestSetGlobalScore.test_override_clamps_below_zero` | Valeurs < 0 ramenées à 0 |
| `TestSetGlobalScore.test_level_reflects_overridden_score` | `engine.level` dérivé de l'override |
| `TestSetGlobalScore.test_raw_score_unchanged_after_override` | `engine._raw_score` intact |

#### `tests/test_domain_scores.py` (+14)

**TestToolCaps (7 tests)**

| Test | Couverture |
|------|------------|
| `test_rootkit_two_findings_capped_at_one` | 2 déductions `rootkit.*` → le domaine en reçoit 1 |
| `test_clamav_two_findings_capped_at_one` | 2 déductions `clamav.*` → le domaine en reçoit 1 |
| `test_file_integrity_two_findings_capped_at_one` | 2 déductions `file_integrity.*` → le domaine en reçoit 1 |
| `test_uncapped_prefix_accumulates_fully` | `hardening.*` s'accumule sans plafond |
| `test_caps_do_not_bleed_across_tools` | Le plafond rootkit ne réduit pas l'allocation clamav |
| `test_cap_respects_first_deduction_points` | Une déduction unique de 2 pts contre un plafond de 1 → contribue 1 |
| `test_tool_caps_dict_contains_expected_keys` | `_TOOL_CAPS` contient rootkit, clamav, file_integrity |

**TestComputeGlobalFromDomains (4 tests)**

| Test | Couverture |
|------|------------|
| `test_average_of_two_active_domains` | Moyenne de deux scores de domaine, arrondie |
| `test_no_active_domains_returns_max` | Ensemble actif vide → MAX_SCORE |
| `test_result_clamped_to_max` | Résultat ≤ 10 |
| `test_result_non_negative` | Résultat ≥ 0 |

**TestApplyDomainScoreOverride (3 tests)**

| Test | Couverture |
|------|------------|
| `test_engine_score_changes_after_override` | `engine.score` diffère du brut après override |
| `test_score_in_valid_range` | Override dans [0, 10] |
| `test_debian13_scenario` | 8 déductions, brut = 2, moyenne des domaines ≥ 5 |

#### `tests/test_logs.py` (0 nouveau, 3 corrigés)

**3 tests corrigés dans `tests/test_logs.py` :**

| Test | Avant | Après |
|------|-------|-------|
| `test_check_logs_emits_warn_finding` | vérifiait la présence de la clé INFO | vérifie la présence de la clé WARN |
| `test_finding_is_warn_level` | vérifiait `FindingLevel.INFO` | vérifie `FindingLevel.WARN` |
| `test_score_deduction_one_point` | vérifiait l'absence de déduction | vérifie 1 déduction de 1 pt |

---

### v0.1.1 — 4206/4206 (29-04-2026)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4206 passed in 4.19s
```

**Nouveaux tests — `tests/test_firmware.py` (+4) :**

Tests de régression pour le bug du format arbre fwupd 1.9+, trouvé sur Ubuntu 26.04 LTS. fwupdmgr a changé son format de sortie — d'une liste plate vers une structure en arbre avec les caractères `├─`, `└─`, `│`. L'ancien parser capturait ces caractères comme noms d'appareils, produisant une sortie corrompue (`│, ├─UEFI CA: (+7)`).

| Test | Couverture |
|------|------------|
| `test_tree_format_extracts_device_names` | Les lignes `├─` et `└─` produisent les bons noms d'appareils |
| `test_tree_format_excludes_container_line` | Le nom du conteneur parent n'est pas capturé |
| `test_tree_format_excludes_tree_connectors` | Les caractères bruts `│`, `├`, `└` n'apparaissent pas comme noms d'appareils |
| `test_tree_format_strips_trailing_colon` | Les noms extraits de `├─Nom:` ne conservent pas les deux-points finaux |

---

### post-v0.1.0 — 4202/4202 (2026-04-27)

**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4202 passed in 4.38s
```

**Bugs trouvés lors du premier run sur Ubuntu 26.04 LTS (`so6ubuntutest`) :**

**Correction — surface d'attaque : `ssh.not_installed` et `fail2ban.not_installed` non détectés :**
Ces deux clés sont émises au niveau `INFO` par leurs vérifications respectives. `compute_exposure()` dans `exposure.py` ne consultait que `bad_keys` (ALERT+WARN), donc aucune des deux n'était jamais détectée — SSH s'affichait comme "clé uniquement, root désactivé" et fail2ban comme "actif", même quand aucun des deux n'était installé.
Correction : ajout de `all_keys = bad_keys | info_keys` ; `ssh.not_installed` et `fail2ban.not_installed` sont désormais vérifiés dans `all_keys`. (commit `3fa43b5`)

**Correction — faux positif SUID : `sudo.ws` signalé sur Ubuntu 26.04 :**
`/usr/bin/sudo.ws` est un binaire légitime livré par le paquet `sudo` sur Ubuntu 26.04 (confirmé par `dpkg -S`). Ajouté à la whitelist `_KNOWN_SUID` dans `suid_audit.py`. (commit `3fa43b5`)

---

### v0.1.0 — 4200/4200 (2026-04-26)


**Plateforme :** Linux Mint 22.3 — `so6desktop` — Python 3.12, pytest 8.x

```
pytest tests/ -q
4200 passed in 4.93s
```

#### Fichiers de test (65 au total)

| Fichier | Tests | Domaine |
|------|-------|--------|
| `test_cis_refs.py` | 39 | Mapping CIS benchmark |
| `test_iptables_nftables.py` | 51 | Pile firewall (iptables/nftables) |
| `test_firewall.py` | — | Audit des règles UFW |
| `test_ssh.py` | — | Configuration SSH |
| `test_hardening.py` | — | Sysctl de renforcement kernel |
| `test_kernel_hardening.py` | — | Renforcement kernel étendu |
| `test_kernel_modules.py` | — | Audit des modules kernel |
| `test_services.py` | — | Registre de services + risque |
| `test_services_state.py` | — | Audit de l'état des services |
| `test_docker.py` | — | Contournement UFW Docker |
| `test_docker_audit.py` | — | Renforcement du démon Docker |
| `test_ports.py` | — | Classification des ports |
| `test_exposure.py` | — | Analyse de l'exposition des ports |
| `test_scoring.py` | — | Moteur de scoring |
| `test_domain_scores.py` | — | Scores par domaine |
| `test_explain.py` | — | --explain TUI |
| `test_display_explain_hint.py` | — | Affichage des hints CIS |
| `test_cli.py` | — | Parsing des arguments CLI |
| `test_exit_codes.py` | — | Logique des codes de sortie |
| `test_correlation.py` | — | Corrélation des signaux |
| `test_recurrence.py` | — | Détections récurrentes |
| `test_compare.py` | — | Diff/baseline |
| `test_history.py` | — | Historique des scores |
| `test_ignore.py` | — | Liste d'ignorés |
| `test_fixes.py` | — | --fix / --apply |
| `test_auth_log.py` | — | Analyse des logs d'authentification |
| `test_ufw_logging.py` | — | Niveau de log UFW |
| `test_log_rotation.py` | — | Rotation des logs |
| `test_cron.py` | — | Planification cron |
| `test_cron_audit.py` | — | Sécurité des jobs cron |
| `test_manage_logs.py` | — | TUI de gestion des logs |
| `test_webhook.py` | — | Notifications webhook |
| `test_profiles.py` | — | Profils d'audit |
| `test_registry.py` | — | Registre de services |
| `test_config.py` | — | Stockage de configuration |
| `test_sysinfo.py` | — | Informations système |
| `test_network_context.py` | — | Contexte réseau |
| `test_degraded.py` | — | Mode dégradé (ss/règles/log absents) |
| `test_output.py` | — | Sortie terminal |
| `test_markdown_output.py` | — | Sortie Markdown |
| `test_html_output.py` | — | Sortie HTML |
| `test_csv_output.py` | — | Sortie CSV |
| `test_report.py` | — | Génération de rapports |
| `test_min_level.py` | — | Filtre --min-level |
| `test_watch.py` | — | Mode --watch |
| `test_check_rules.py` | — | Validation des règles |
| `test_file_perms.py` | — | Permissions de fichiers |
| `test_suid_audit.py` | — | Audit SUID/SGID |
| `test_user_accounts.py` | — | Comptes utilisateurs |
| `test_password_policy.py` | — | Politique de mot de passe |
| `test_umask.py` | — | Umask système |
| `test_updates.py` | — | Mises à jour système |
| `test_ntp.py` | — | Synchronisation NTP |
| `test_fail2ban.py` | — | Fail2ban |
| `test_rootkit.py` | — | Scan rootkit |
| `test_auditd.py` | — | Démon audit |
| `test_secure_boot.py` | — | Secure Boot |
| `test_file_integrity.py` | — | Intégrité des fichiers |
| `test_clamav.py` | — | ClamAV |
| `test_mac_policy.py` | — | AppArmor/SELinux |
| `test_backup.py` | — | Détection de sauvegarde |
| `test_disk.py` | — | Santé disque |
| `test_memory.py` | — | Mémoire/swap |
| `test_ssl_certs.py` | — | Expiration des certificats TLS |
| `test_systemd_timers.py` | — | Timers systemd |
| `test_desktop_apps.py` | — | Applications desktop |
| `test_samba.py` | — | Renforcement Samba |
| `test_ddns.py` | — | Détection DDNS |
| `test_firmware.py` | — | Firmware/microcode |
| `test_smtp.py` | — | Exposition SMTP |
| `test_ipv6.py` | — | Cohérence IPv6 |
| `test_virtualization.py` | — | Détection virtualisation |
| `test_email_store_mgmt.py` | — | Gestion stockage email |
| `test_recurrence.py` | — | Suivi de récurrence |
| `tests/helpers.py` | — | Utilitaires de test partagés |

----

**VM de test :** Linux Mint 22.3 — `so6minttest`
**État de référence** (baseline propre après chaque test) :

```bash
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80
sudo ufw enable
```

----

## Catégorie A — Wildcards open-any

Règles ouvrant tous les ports à toutes les sources — sévérité majeure.

### A1 — Wildcard complet `Anywhere ALLOW IN Anywhere`

```bash
sudo ufw allow from any
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle autorisant toutes connexions entrantes sans restriction port | ✔ v0.1.0.0 |
| Déduction score `-2` | ✔ |
| Correction proposée : `sudo ufw --force delete N` | ✔ |
| Correction appliquée correctement | ✔ |
| **Règle IPv6 aussi détectée et corrigée** (`Anywhere (v6) ALLOW IN Anywhere (v6)`) | ✔ v0.1.0 |

**Cause racine corrigée  :** `ufw status numbered` remplit lignes avec espaces trailing — l'ancre `$` dans regex ne correspondait jamais. Corrigé : `Anywhere$` → `Anywhere\s*$`. (commit `8ccd9b6`)

**Cause racine corrigée  :** Règles wildcard IPv6 (`Anywhere (v6) ALLOW IN Anywhere (v6)`) échappaient à la détection — `open_any_pattern` ne prenait pas en compte le suffixe `(v6)`. Corrigé : motif étendu avec `(?:\s+\(v6\))?` des deux côtés. Règles IPv4 et IPv6 sont maintenant signalées et corrigées indépendamment.

---

### A2 — Wildcard TCP `Anywhere/tcp ALLOW IN Anywhere/tcp`

```bash
sudo ufw allow proto tcp from any to any
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle autorisant toutes connexions entrantes sans restriction port | ✔ v0.1.0.0 |
| Déduction score `-2` | ✔ |
| Correction appliquée correctement | ✔ |
| **Variante IPv6 aussi détectée** (`Anywhere/tcp (v6) ALLOW IN Anywhere/tcp (v6)`) | ✔ v0.1.0 |

**Cause racine corrigée  :** Motif étendu à `Anywhere(?:/\w+)?` des deux côtés pour couvrir variantes `/tcp`, `/udp`. (commit `1dd9ede`)

**v0.1.0 :** Même correction IPv6 que A1 s'applique ici.

---

### A3 — Wildcard UDP `Anywhere/udp ALLOW IN Anywhere/udp`

```bash
sudo ufw allow proto udp from any to any
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle autorisant toutes connexions entrantes sans restriction port | ✔ v0.1.0.0 |
| Déduction score `-2` | ✔ |
| Correction appliquée correctement | ✔ |
| **Variante IPv6 aussi détectée** | ✔ v0.1.0 |

---

### A4 — Les trois wildcards simultanément

```bash
sudo ufw allow from any
sudo ufw allow proto tcp from any to any
sudo ufw allow proto udp from any to any
```

| Attendu | Résultat |
|----------|----------|
| 3 résultats `✖ [ALERTE]` distincts (IPv4 uniquement) | ✔ v0.1.0.0 |
| **6 résultats `✖ [ALERTE]` distincts (IPv4 + IPv6)** | ✔ v0.1.0 |
| Score : 0/10 (plafonné), Niveau risque : CRITIQUE | ✔ |
| 6 corrections proposées et appliquées en ordre index inverse | ✔ v0.1.0 |

---

### A5 — Faux positif : règle source restreinte

```bash
sudo ufw allow from 192.168.1.0/24
```

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Aucune règle 'allow from any' sans restriction de port détectée | ✔ v0.1.0 |
| Règle source-restreinte NON signalée comme open-any | ✔ |

> `ufw status numbered` montre `Anywhere ALLOW IN 192.168.1.0/24` — destination est `Anywhere` mais source est restreinte. Le motif requiert correctement que LES DEUX côtés soient `Anywhere` pour déclencher.

---

## Catégorie B — Règles dupliquées

### B1 — Duplication exacte

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/tcp   # UFW dit: "Skipping adding existing rule"
```

| Attendu | Résultat |
|----------|----------|
| UFW nativement prévient vrais doublons exacts | ✔ confirmé |
| Non testable via CLI — requirerait manipulation directe fichiers | noté |

> **Note :** Doublons exacts peuvent seulement résulter édition directe `/etc/ufw/` ou outils externes (Ansible, scripts). CLI UFW les prévient.

---

### B2 — Même règle, commentaires différents

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (pas proto) déjà présent dans baseline
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle UFW dupliquée détectée : `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0.0 |
| Commentaire supprimé avant comparaison — `# test2` ignoré | ✔ |
| `80/tcp` redondant supprimé, `80` gardé | ✔ |

**Cause racine corrigée :** Comparaison utilise maintenant texte stripé-commentaires, normalisé-espaces. (commit `b7a285a`)

---

### B3 — Duplication sémantique : `PORT/proto` redondant quand `PORT` existe

```bash
sudo ufw allow 80/tcp comment "test2"
# 80 (pas proto) déjà présent → 80/tcp est redondant
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Règle UFW dupliquée détectée : `80/tcp ALLOW IN Anywhere` | ✔ v0.1.0.0 |
| Déduction score `-1` | ✔ |
| Correction supprime la règle protocol-spécifique, garde la plus large | ✔ |

**Cause racine corrigée :** Détection deux-passes — première passe collecte toutes règles sans-protocole, deuxième passe vérifie si `PORT/proto` est subset d'existant `PORT`. (commit `b7a285a`)

---

### B4 — Duplication sémantique : variante UDP

```bash
sudo ufw allow 53/udp
sudo ufw allow 53
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` `53/udp` détecté comme redondant | ✔ unit test |

> Validé via unit test uniquement (port DNS — pas dans registry services, pas risque pratique sur VM).

---

### B5 — Pas faux positif : `PORT/tcp` + `PORT/udp` sans `PORT`

```bash
sudo ufw allow 80/tcp
sudo ufw allow 80/udp
# Pas règle nulle "80"
```

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Pas règles UFW dupliquées détectées | ✔ v0.1.0.0 |
| `80/tcp` et `80/udp` sont complémentaires — pas signalés | ✔ |

> Aussi noter : quand baseline a `80` (nu), ajouter `80/tcp` + `80/udp` correctement signale TOUTES DEUX comme doublons sémantiques de `80`. Vérifié en direct.

---

## Catégorie C — Services critiques exposés

### C1 — SSH exposé (état de la baseline)

SSH est toujours présent dans l'état de référence (`ufw allow 22/tcp`). Ce scénario documente le comportement attendu pour un service critique avec une règle UFW ALLOW non restreinte.

```bash
# État de la baseline — SSH déjà exposé
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `✖ [ALERTE]` Port 22/tcp — ouvert à internet — aucune restriction source dans UFW | ✔ v0.1.0.0 |
| Contexte risque CRITIQUE affiché | ✔ v0.1.0.0 |
| Déduction score `-2` (contexte NAT/local) | ✔ v0.1.0.0 |
| Panorama : SSH `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| DDNS `→ 22/tcp` | ✔ v0.1.0.0 |
| **Remédiation :** restriction source → passe en OPEN_LOCAL (WARN non ALERTE, sans déduction) | ✔ v0.1.0.0 |

> **Note :** `openssh-server` doit être installé et actif (`sudo apt install openssh-server && sudo systemctl enable --now ssh`). Si inactif/désactivé, le service est en INFO uniquement sans vérification d'exposition des ports.

> **Remédiation à tester :** `sudo ufw delete allow 22/tcp && sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp` → passe en OPEN_LOCAL (AVERTISSEMENT et non ALERTE, sans déduction).

---

### C3 — Redis exposé sur toutes les interfaces (service installé et actif)

```bash
sudo ufw allow 6379
# Redis configuré pour écouter sur 0.0.0.0 (pas la configuration par défaut)
```

| Attendu | Résultat |
|----------|----------|
| `✖ [ALERTE]` Port 6379/tcp — ouvert à internet (Action requise) | ✔ v0.1.0.0 |
| Contexte risque CRITIQUE affiché | ✔ |
| Déduction score `-2` (contexte NAT) | ✔ |
| Panorama : Redis `✖` → `⚠` | ✔ |
| Vérification croisée DDNS : `→ 6379/tcp` | ✔ v0.1.0.0 (`6379/udp` filtré — pas de listener UDP) |

**Cause racine corrigée (obs 1) :** Services CRITIQUE/ÉLEVÉS avec exposition `OPEN_WORLD` lèvent maintenant `alert()` au lieu `warn()`, les déplaçant à « Action requise ». (commit `e01b24b`)

---

### C3b — Redis loopback uniquement — correction faux positif 

Configuration Redis par défaut : écoute sur `127.0.0.1` uniquement, mais une règle UFW permissive existe.

```bash
sudo ufw allow 6379
# Redis par défaut : bind 127.0.0.1 (loopback uniquement)
```

| Attendu | Résultat |
|----------|----------|
| `ℹ [INFO]` Port 6379/tcp — lié uniquement sur localhost — la règle UFW n'a aucun effet sur l'accès externe | ✔ v0.1.0.0 |
| Pas d'ALERTE, pas de déduction de score | ✔ |
| Panorama : Redis `✔` (règle existe, exposition = LOOPBACK) | ✔ |
| DDNS : `6379/tcp` absent de la liste exposée (loopback uniquement) | ✔ |
| DDNS : `6379/udp` absent de la liste exposée (pas de listener UDP) | ✔ |

**Cause racine corrigée  :** `_classify_exposure()` se basait uniquement sur UFW et ne vérifiait pas les bindings réels des sockets. Correction : `PortsSnapshot` est collecté avant le CHECK 3 ; les ports dont tous les bindings `ss` sont en loopback reçoivent `Exposure.LOOPBACK` (INFO, sans déduction). `_find_open_ports()` dans `ddns.py` reçoit également les ensembles `loopback_ports` et `active_ports`. (commits `2bfc85b`, `64311be`)

---

### C2 — MySQL exposé (service non installé)

```bash
sudo ufw allow 3306
```

| Attendu | Résultat |
|----------|----------|
| Pas d'alerte service (MySQL non installé) | ✔ v0.1.0.0 |
| Port 3306 ouvert dans UFW mais non-correspondant à aucun service installé | confirmé |
| DDNS : `3306/tcp` et `3306/udp` absents de la liste exposée (aucun listener actif) | ✔ v0.1.0.0 |

> **Comportement mis à jour  :** `_find_open_ports()` effectue maintenant une vérification croisée avec les listeners non-loopback réels (ensemble `active_ports` depuis `ss`). Les règles UFW orphelines (port ouvert, aucun service actif) sont exclues de la liste d'exposition DDNS. `3306/tcp` et `3306/udp` n'apparaissent plus dans les résultats DDNS quand MySQL n'est pas installé.

---

### C4 — Nginx exposé (service à risque moyen, installé et actif)

```bash
sudo apt install nginx
sudo ufw allow 80
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `⚠ [AVERTISSEMENT]` Port 80/tcp — ouvert à internet — aucune restriction source dans UFW | ✔ v0.1.0.0 |
| Contexte risque MOYEN affiché | ✔ v0.1.0.0 |
| Déduction score `-1` | ✔ v0.1.0.0 |
| Panorama : Nginx `⚠` | ✔ v0.1.0.0 |
| Résultat dans *Améliorations possibles* (et non *Action requise*) | ✔ v0.1.0.0 |

> Les services à risque moyen utilisent `warn()` et non `alert()` — distinction par rapport aux services critiques comme SSH ou Redis.

---

### C5 — Samba exposé (service critique, installé et actif)

```bash
sudo apt install samba
sudo ufw allow 445
sudo ufw allow 139
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `✖ [ALERTE]` Port 445/tcp — ouvert à internet — aucune restriction source dans UFW | ✔ v0.1.0.0 |
| `✖ [ALERTE]` Port 139/tcp — ouvert à internet | ✔ v0.1.0.0 |
| Contexte risque CRITIQUE affiché (vecteur ransomware, EternalBlue) | ✔ v0.1.0.0 |
| Déduction `-2` × 2 ports (−4 total) | ✔ v0.1.0.0 |
| Panorama : Samba `⚠` (OPEN_WORLD) | ✔ v0.1.0.0 |
| Les deux ports dans le bloc *Action requise* | ✔ v0.1.0.0 |
| DDNS `→ 445/tcp`, `→ 139/tcp` | ✔ v0.1.0.0 |

> **Nettoyage :** `sudo apt remove --purge samba && sudo ufw delete allow 445 && sudo ufw delete allow 139`

---

### C6 — Ports ouverts dans UFW, services non installés (services multiples)

Pour chaque entrée ci-dessous : ouvrir le port dans UFW sans service correspondant installé. Comportement attendu : **aucune alerte service**, le port peut apparaître comme règle UFW orpheline.

```bash
sudo ufw allow <PORT>
sudo bob
```

| Service | Port | Comportement attendu | Résultat |
|---------|------|---------------------|----------|
| Serveur VNC | 5900/tcp | Pas d'alerte service — VNC non détecté | ✔ v0.1.0.0 |
| Serveur FTP | 21/tcp | Pas d'alerte service — FTP non détecté | ✔ v0.1.0.0 |
| PostgreSQL | 5432/tcp | Pas d'alerte service — PostgreSQL non détecté | ✔ v0.1.0.0 |
| Mosquitto (MQTT) | 1883/tcp | `ℹ [INFO]` 1883/tcp loopback — règle UFW sans effet ; 8883/tcp non en écoute — aucun message ; Panorama ✔ | ✔ v0.1.0.0 ² |
| WireGuard | 51820/udp | `ℹ [INFO]` WireGuard installé mais arrêté/désactivé — pas de vérification d'exposition (retour anticipé INACTIVE) | ✔ v0.1.0.0 ¹ |
| Gitea | 3000/tcp | Pas d'alerte service — Gitea non détecté | ✔ v0.1.0.0 |
| Jellyfin | 8096/tcp | Pas d'alerte service — Jellyfin non détecté | ✔ v0.1.0.0 |
| Home Assistant | 8123/tcp | Pas d'alerte service — HASS non détecté | ✔ v0.1.0.0 |
| Cockpit | 9090/tcp | Pas d'alerte service — Cockpit non détecté | ✔ v0.1.0.0 |

> Pour tous les cas ci-dessus : le port n'a pas de listener actif — aucune ALERTE dans ANALYSE DES SERVICES RÉSEAU.
> Vérification croisée DDNS : aucun de ces ports ne doit apparaître dans la liste exposée DDNS (aucun listener actif — correction v0.1.0).

> ¹ WireGuard était déjà installé (mais inactif) sur la VM de test. Le chemin « non installé » reste non testé — comportement confirmé : service INACTIVE avec une règle UFW ouverte → INFO uniquement, pas d'ALERTE, pas de déduction.

> ² Mosquitto était installé et ACTIF sur la VM de test (ne correspond pas au scénario C6 « non installé »). Le test a révélé un bug : les ports du registre non en écoute (8883/tcp) déclenchaient incorrectement `Exposure.NO_RULE` → panorama ✖. Corrigé en beta (commit `67743ca`) : `Exposure.NOT_LISTENING` pour les ports du registre non en écoute → panorama ✔.

> **Déjà validé :** MySQL / MariaDB (3306) → C2

---

### C7 — CUPS exposé (service à faible risque, souvent pré-installé sur desktop Linux)

CUPS (serveur d'impression) écoute sur `127.0.0.1:631` par défaut. Ce test vérifie le comportement quand CUPS est actif et une règle UFW existe.

```bash
# CUPS est souvent pré-installé sur Linux Mint
sudo ufw allow 631
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `ℹ [INFO]` Port 631/tcp — lié uniquement sur localhost — la règle UFW n'a aucun effet | ✔ v0.1.0.0 |
| Pas d'ALERTE, pas de déduction de score (binding loopback) | ✔ v0.1.0.0 |
| Panorama : CUPS `✔` (règle existe, loopback → INFO) | ✔ v0.1.0.0 |

> Si CUPS écoute sur `0.0.0.0` : `⚠ [AVERTISSEMENT]` Port 631/tcp — ouvert à internet (risque faible, nature=improvement).

---

## Catégorie D — Cohérence IPv6

### D1 — Règles IPv4 présentes, aucun équivalent IPv6 (avertissement attendu)

```bash
# Depuis la baseline : 22/tcp et 80 sont présents, aucune règle (v6)
sudo ufw status numbered
```

> **Note :** Certaines distributions (ou VMs avec `IPV6=no` dans `/etc/default/ufw`) n'ajoutent pas de règles IPv6. Si toutes les règles sont déjà couplées (IPv4 + IPv6), utiliser `sudo ufw --force reset` et re-ajouter uniquement les règles IPv4.

| Attendu | Résultat |
|----------|----------|
| `⚠ [AVERTISSEMENT]` Règles IPv6 manquantes — seules des règles IPv4 présentes | ✔ unit test |
| Déduction score `-1` | ✔ unit test |
| Test direct | ✔ v0.1.0.0 |

---

### D2 — Règles IPv4 et IPv6 toutes deux présentes (pas d'avertissement)

| Attendu | Résultat |
|----------|----------|
| `✔ [OK]` Règles IPv4 et IPv6 toutes deux présentes | ✔ unit test |
| Aucune déduction | ✔ unit test |
| Test direct | ✔ v0.1.0.0 |

---

## Catégorie E — Ports loopback uniquement 

### C8 — SSH restreint au LAN (chemin OPEN_LOCAL)

```bash
sudo ufw delete allow 22/tcp
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp
sudo bob
```

| Attendu | Résultat |
|---------|----------|
| `⚠ [AVERTISSEMENT]` Port 22/tcp — restreint au réseau local par règle UFW | ✔ v0.1.0 |
| Pas de déduction score (OPEN_LOCAL ≠ OPEN_WORLD) | ✔ v0.1.0 |
| Panorama : SSH `✔` (restriction LAN = config correcte) | ✔ v0.1.0 |
| DDNS : `ℹ` Port 22/tcp restreint au réseau local (pas d'ALERTE) | ✔ v0.1.0 |
| Contexte risque CRITIQUE toujours affiché | ✔ v0.1.0 |

> **Nettoyage :** `sudo ufw delete allow from 192.168.1.0/24 to any port 22 proto tcp && sudo ufw allow 22/tcp`

---



### E1 — Port écoutant sur localhost uniquement, sans règle UFW — INFO pas ALERTE

```bash
# Tout processus lié exclusivement à 127.0.0.1 sans règle UFW
# Redis par défaut : bind 127.0.0.1 — aucune règle UFW nécessaire
sudo bob
```

| Attendu | Résultat |
|----------|----------|
| `ℹ [INFO]` Port 6379/tcp — lié uniquement à localhost — aucune règle UFW requise (couvert par refus par défaut) | ✔ v0.1.0.0 |
| Pas d'ALERTE, pas de déduction de score | ✔ v0.1.0.0 |
| Panorama Redis ✔ | ✔ v0.1.0.0 |
| Message utilise la clé locale `services.exposure.loopback_no_rule` (ajoutée avec le fix `Exposure.LOOPBACK_NO_RULE`) | ✔ v0.1.0.0 |

> **Note :** Le message attendu initialement référençait `ports.uncovered_local`. En pratique, Redis sur loopback sans règle UFW est traité par le chemin services (`Exposure.LOOPBACK_NO_RULE`), pas le chemin ports. La clé `ports.uncovered_local` s'applique aux ports de processus non couverts par le registre de services.

---

## Observations supplémentaires

### Obs — Avahi affiche ✖ au panorama malgré message INFO (v0.1.0)

Avahi écoute sur `0.0.0.0:5353/udp` (multicast mDNS). Aucune règle UFW pour 5353 → `Exposure.NO_RULE` → panorama ✖. Le check service émet correctement `ℹ [INFO]` "couvert par la politique deny par défaut", mais le symbole panorama est déterminé par la valeur enum `NO_RULE` indépendamment de la sévérité INFO.

**Cause racine :** `NO_RULE` sur un port non-loopback, non exposé publiquement (multicast/LAN uniquement en pratique) est traité identiquement à `NO_RULE` sur un port réellement exposé. Un fix futur pourrait introduire `Exposure.NO_RULE_MULTICAST` ou un mécanisme plus large pour distinguer les `NO_RULE` à portée locale des `NO_RULE` réellement exposés.

**Impact :** cosmétique uniquement — pas de fausse ALERTE, pas de déduction de score.

---



### Obs — DDNS ne détecte pas règles sans-protocole (corrigé)

Avec `80 ALLOW IN Anywhere` (pas `/tcp`), la vérification croisée DDNS n'affichait précédemment rien pour le port 80.

**Cause racine corrigée :** `_find_open_ports()` gère maintenant les règles ports nus — ajoute `PORT/tcp` et `PORT/udp` à la liste des ports ouverts. (commit `e01b24b`)

**Validé (v0.1.0) :** Règle nue `80 ALLOW` avec Nginx écoutant sur `0.0.0.0:80` → DDNS liste correctement `→ 80/tcp` uniquement (`80/udp` filtré — aucun listener UDP sur le port 80).

---

### Obs — Faux positifs DDNS : ports système et règles orphelines 

```bash
sudo ufw allow 53
sudo ufw allow 3306
sudo ufw allow 6379
# Redis sur 127.0.0.1 uniquement, MySQL non installé
```

| Attendu | Résultat |
|----------|----------|
| DDNS : `53/tcp`, `53/udp` absents (filtre ports système) | ✔ v0.1.0.0 |
| DDNS : `3306/tcp`, `3306/udp` absents (aucun listener actif) | ✔ v0.1.0.0 |
| DDNS : `6379/tcp`, `6379/udp` absents (loopback uniquement / pas de listener UDP) | ✔ v0.1.0.0 |

**Cause racine corrigée  :** Ajout de la constante `_DDNS_SYSTEM_PORTS` (53, 67, 68, 546, 547, 5353) et vérification croisée `active_ports` dans `_find_open_ports()`. Seuls les ports avec un listener non-loopback réel dans la sortie `ss` sont inclus dans la liste d'exposition DDNS. (commit `64311be`)

---

### Obs — UFW permet règles wildcard après règles spécifiques sans erreur

```
Anywhere/tcp    ALLOW IN    Anywhere/tcp
22/tcp          ALLOW IN    Anywhere
```

UFW n'avertit pas que `Anywhere/tcp` rend `22/tcp` redondant. bob correctement signale le wildcard.

---

## Note B1 — doublons exacts via manipulation fichiers

Pour tester doublons exacts que CLI UFW prévient, règles peuvent être injectées directement :

```bash
sudo cp /etc/ufw/user.rules /etc/ufw/user.rules.bak
# Manuellement dupliquer ligne règle dans user.rules
sudo ufw reload
sudo bob
# Nettoyage :
sudo cp /etc/ufw/user.rules.bak /etc/ufw/user.rules
sudo ufw reload
```

Pas encore testé — priorité pratique basse car CLI UFW le prévient.

---


---

© 2026 Cédric Clauzel
