*[Read in English](CHANGELOG.md)* · *[Journal complet](DOCUMENTS/CHANGELOG_FULL_FR.md)*

# BOB — Journal des modifications

| Version | Date | Résumé |
|---------|------|--------|
| [v0.6.2](#v062) | 29-05-2026 | **Hotfix packaging critique.** Tous les wheels shippés depuis v0.6.0 (donc v0.6.0 + v0.6.1) manquaient `bob/checks/ssh/` et `bob/cron/` — les deux sous-packages introduits par les splits v0.6.0. Quiconque a `pipx upgrade`d hit `ModuleNotFoundError: No module named 'bob.checks.ssh'` au startup. Cause racine : `[tool.setuptools.packages.find].include` était une liste figée `["bob", "bob.checks", "bob.tui"]` d'un audit packaging v0.4.x — quand v0.6.0 a ajouté `bob.checks.ssh` et `bob.cron`, la liste n'a pas été mise à jour. Le wheel se construit mais exclut les deux packages silencieusement. Pourquoi non détecté : tests + le smoke pre-ship `sudo python3 -m bob` tournaient depuis le working tree (les répertoires sources sont visibles peu importe la config packaging) ; `.github/workflows/integration.yml` utilisait `pip install -e .` (editable mode) qui met le repo root sur `sys.path` et bypass la discovery packaging entièrement. Fix : `include = ["bob*"]` (glob) auto-découvre tout sous-package futur. CI hardened : jobs intégration utilisent maintenant `pip install .` (non-editable, build + install un vrai wheel) + nouvelle smoke step explicite qui import chaque module v0.6.x-ajouté. Aucun changement de code autre que la config packaging + workflow guard. 4600 tests inchangés. **Quiconque tourne v0.6.0 ou v0.6.1 via pipx doit `pipx upgrade bodyguard-of-bits` vers v0.6.2 pour avoir un install qui marche.** |
| [v0.6.1](#v061) | 26-05-2026 | Première release hardening sur la branche v0.6.x. Sub-agent d'audit profond a remonté 14 findings (0 critique + 6 important + 8 mineur) ; 6 important + 4 mineur shippés. **Consolidation contrat atomic-write** : extraction `bob/_atomic.py::atomic_write(path, content, *, mode=)` source unique de vérité ; migration 5 sites (`bob/config.py` ×2, `bob/compare.py`, `bob/history.py`, `bob/recurrence.py`) + fix 4 sites non-atomiques (`bob/cron/_install.py`, `bob/tui/cron.py`, `bob/ignore.py`, `bob/history.py` first-write). v0.5.7 #I-3 avait fermé le path mutation cron mais raté le path création. **Contrat EOF complet** : nouveau `bob/_tty.safe_input(prompt)` + `prompt_wizard()` catche maintenant `EOFError` ; 11 sites `input()` brut migrés (`bob/cron/_install.py` ×5, `bob/cron/_manage.py` ×5, `bob/fixes.py` ×1). Ctrl-D ne crash plus aucun wizard plain-text. **I-3** `_validate_cron_field` rejette les step values excédant le range du field (`*/200` pour minute 0-59 était accepté → cron interprétait "toutes les 200 minutes" = ne se déclenche jamais). **I-4** `shlex.quote()` appliqué sur 8 sites `cmd=f"..."` dans `bob/checks/ssh/_subchecks.py` (4) + `bob/checks/file_perms.py` (3) + `bob/checks/firmware.py` (1) où les paths de `pwd.getpwnam(SUDO_USER).pw_dir` ou scans filesystem pouvaient contenir des espaces et silently mis-target `--fix --apply`. **I-5** `bob/history.py::save_score` first-write crée `history.jsonl` avec mode `0o600` explicite via `os.open(O_WRONLY \| O_APPEND \| O_CREAT)` au lieu d'hériter du umask par défaut (typiquement `0o644` → world-readable des timestamps de score). **Minors shippés** : M-2 redundant double-`.lower()` dans `_apply_bad_directive` ; M-3 `MaxAuthTries=-1` fallback default 6 (était accepté) ; M-6 `bob/__main__.py` fatal-error handler hint `BOB_DEBUG=1` ; M-8 `--watch=N` error wording aligné. +17 tests régression. 4583 → 4600. Contrat JSON, EXPLAIN_KEYS, keybindings, fallback no-curses, exit codes — tous préservés. |
| [v0.6.0](#v060) | 25-05-2026 | **Bump majeur** — ouvre la branche v0.6.x. Deux splits architecturaux + un sunset, tous contract-preserving via re-exports `__init__.py`. **#13 split `bob/checks/ssh.py` (monolithe 1296 LoC) → package `bob/checks/ssh/`** avec 4 modules : `_directives` (165L : table `_BadDirective` + `_BAD_DIRECTIVES` + `_apply_bad_directive` + sets weak crypto), `_snapshot` (198L : 5 dataclasses + `SSHSnapshot` + `SSHSnapshot.from_system`), `_parsers` (446L : parsers purs sshd_config / authorized_keys / known_hosts / client config + helpers key-type / RSA-bits + `_collect_host_keys` + `_detect_ssh_install_cmd` + `_parse_time_seconds`), `_subchecks` (529L : entry point `check_ssh` + tous les helpers `_check_*` par zone). **#14 split `bob/cron.py` (monolithe 1204 LoC) → package `bob/cron/`** avec 4 modules : `_parse` (330L : `CronEntry` + `parse_cron_file` + `list_installed_crons` + `cron_to_human` + `build_schedule_expr` + validators + day helpers + détection MTA + constantes), `_io` (164L : `_atomic_write` + `build_script_content` + `apply_cron_schedule` + `apply_cron_email`), `_install` (319L : `prompt_emails` / `prompt_email` + `_run_install_cron_plain` + `run_install_cron` + exception `_CronQuit`), `_manage` (445L : `_manage_email_store` + `edit_cron_email` + `edit_cron_schedule` + `_run_manage_cron_plain` + `run_manage_cron`). Les deux packages préservent la full API publique v0.5.x via re-exports `__init__.py` — `from bob.checks.ssh import check_ssh, SSHSnapshot, …` et `from bob.cron import CronEntry, run_install_cron, _EMAIL_RE, datetime, …` continuent de marcher inchangés. **Sunset : env var legacy `UFW_AUDIT_SHARE` retirée** (annoncée "REMOVED in v0.6.0" dans le warning deprecation v0.5.4 — honorée). Seul `BOB_SHARE` est maintenant accepté ; les installers settant encore le legacy alias verront aucun effet. Deux tests AST-scanning (`tests/test_template_vars_migration.py`, `tests/test_domain_scores_mapping_complete.py`) mis à jour pour recurser dans les packages de check (shift d'une ligne `glob` → `rglob`). Un test régression (`TestApplyCronScheduleAtomic`) mis à jour pour patcher le nouveau site `bob.cron._io._atomic_write` au lieu du re-export package-level. 4583 tests inchangés (zéro delta net — splits + sunset sont wire-équivalents). LoC : ssh.py 1296L → 4 modules (max 529L), cron.py 1204L → 4 modules (max 445L). Le plus gros module de check est maintenant `ssh/_subchecks.py` à 529L, bien sous le soft ceiling 1000-LoC du projet. Contrat JSON (`schema_version="1"`), 116 EXPLAIN_KEYS, keybindings, fallback no-curses, exit codes — tous préservés. **Ferme le backlog refactor architectural déféré depuis v0.5.x.** |
| [v0.5.8](#v058) | 25-05-2026 | Cleanup des 5 mineurs cosmétiques explicitement déférés par v0.5.7. **M-2** `manage_logs.py` cursor shift après delete ne compte maintenant que les deletions ≤ cursor (pré-fix : `cursor -= deleted` shiftait par le total même quand la plupart des items supprimés étaient APRÈS le cursor — déplacement visible sur multi-sélection mélangeant items avant+après position active). **M-5** constantes du wizard schedule promues de `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` tuple unpack local à un `_Schedule(IntEnum)` module-level avec noms explicites `DAILY`/`WEEKDAYS`/`MONTHDAYS`/`CUSTOM` — 3 call sites mis à jour, IntEnum préserve la sémantique `choice == _Schedule.WEEKDAYS` donc wire-équivalent. **M-6** `_extract_summary_view` sentinelle `summary_start: int \| None = None` remplace le check truthy `summary_start = 0` — gère le edge case (unreachable en pratique mais sémantiquement faux) où le séparateur SEP62 est à la ligne 0. **M-7** nouveau helper `_is_finding_continuation(line)` stoppe le grouping 4-space-indent à toute frontière qui appartient évidemment à un autre finding (markers `[ALERT]`/`[WARN]`/`[OK]`/`[INFO]`) ou à un délimiteur de section (`┌`/`└`/`│`/`━`/`╔`/`╠`/`╚`/`║`) — défense contre le grouping over-greedy de contenu indenté ultérieur. **M-8** `from datetime import datetime` remonté au niveau module dans `bob/cron.py` et `bob/tui/cron.py` ; 3 imports locaux retirés (`_run_install_cron_plain`, `build_script_content`, install cron curses path). +12 tests régression à travers `tests/test_cron.py` (TestScheduleIntEnum, TestDatetimeImportLifted) et `tests/test_manage_logs.py` (TestCursorShiftAfterDelete, TestSummaryStartSentinel, TestIsFindingContinuation). 4571 → 4583 tests. Format wire JSON inchangé, EXPLAIN_KEYS inchangées, keybindings inchangés, aucun retrait d'API publique. **Ferme la campagne deep-audit v0.5.x — branche intégralement auditée (25 modules deep-audit + ~25 spot-checkés, 0 finding critique en suspens).** Prochaine version mineure (v0.6.0) réservée pour #13 (split ssh.py) et #14 (split cron.py) — les deux refactors architecturaux délibérément déférés. |
| [v0.5.7](#v057) | 24-05-2026 | Passe de hardening ciblée sur le TUI curses (`bob/manage_logs.py` 999 LoC + `bob/tui/cron.py` 920 LoC = ~1920 LoC) — le bucket explicitement déféré par les audits v0.5.5 / v0.5.6. 11 findings d'un sub-agent focalisé : 0 critique, 3 important (I-1 `_curses_readline` acceptait les codes keypad curses `KEY_*` via `chr(ch_i)` — flèches et touches de fonction insèrent glyphes Grecs/Unicode comme `Ι` / `Ω` dans les buffers d'entrée nom/email/jours/heure/expression-custom ; aucun impact sécurité grâce à la validation downstream (`_EMAIL_RE`, `_validate_custom_cron`, filtrage digit-only) mais UX visiblement corrompue. Nouveau helper `_is_printable_input_char(ch_i)` borne aux Latin-1 imprimables · I-2 trois sites `input()` dans `prompt_path` + confirmation move-logs + confirmation delete-all ne catchaient pas `EOFError` — Ctrl-D dumpait une traceback Python à l'annulation. S'aligne maintenant sur la convention `_rl()` (EOF = entrée vide) · I-3 `apply_cron_schedule` utilisait `os.open(O_WRONLY \| O_CREAT \| O_TRUNC) + fdopen.write` brut au lieu du helper `_atomic_write` du projet. Coupure de courant ou `SIGKILL` entre `open(O_TRUNC)` et `write` laisserait le fichier cron vide → cron drop silencieusement l'entrée, aucune notification. Asymétrique avec `apply_cron_email` qui utilisait déjà `_atomic_write`. Mode `0o640` enforced), 3 mineurs (M-1 status `manage_logs.deleted_one` affichait `pending_delete[0].name` même quand l'index 0 échouait au unlink et qu'un autre index réussissait — traque maintenant le premier nom effectivement supprimé · M-3 dead-code `if ch_i == ord("1"): chosen = 0 elif chosen = 1` dans `_curses_edit_sub` simplifié, garde elif réécrite avec parenthèses explicites · M-4 `from bob.cron import apply_cron_schedule, apply_cron_email` dupliqué consolidé dans le bloc d'import principal). +11 tests régression à travers `tests/test_cron.py` (TestApplyCronScheduleAtomic, TestIsPrintableInputChar) et `tests/test_manage_logs.py` (TestEOFErrorOnPromptPath, TestEOFErrorOnMoveConfirm, TestEOFErrorOnDeleteAllConfirm, TestDeletedOneCorrectName). 4560 → 4571 tests. Format wire JSON inchangé, EXPLAIN_KEYS inchangées, aucun ajout d'API publique. Deltas UX visibles : sortie Ctrl-D propre (sans traceback), touches fléchées/fonction n'insèrent plus de garbage dans les prompts TUI. Déférés à v0.5.8 (5 findings cosmétiques) : M-2 cursor-shift suppose suppressions avant cursor · M-5 constantes du wizard schedule scoped-locales → module-level / IntEnum · M-6 falsy check `summary_start` rate l'index 0 (unreachable) · M-7 regroupement over-greedy des lignes de continuation · M-8 `from datetime import` local remonté au top. Après v0.5.7, branche v0.5.x auditée intégralement (25 modules deep-audit + ~25 spot-check). |
| [v0.5.6](#v056) | 24-05-2026 | Passe de hardening ciblée sur `bob/checks/logs.py` (662 LoC parser UFW logs) — module explicitement déféré par l'audit v0.5.5 à cause de la densité regex. 10 findings depuis un sub-agent focalisé : 0 critique, 2 important (I-1 regex private-IP incohérente avec `sysinfo.py` — manquait CGNAT 100.64/10 + link-local IPv6 fe80::/10 + faux positifs sur strings commençant par `fc`/`fd` ; I-2 year-rollover droppait silencieusement les événements syslog 1s en avance de l'horloge en rollbackant d'une année entière), 8 mineurs (M-1 variante IPv6 `[UFW BLOCK6]` silencieusement ignorée — regex anchored attrape maintenant les deux ; M-2 regex `_count_available_days` restreinte aux noms de mois anglais ; M-3 ordre paths GeoIP City-avant-Country sur tous les dirs ; M-4 `geoip2_status()` accepte symlinks comme `_geo_via_geoip2` ; M-5 `_GEO_CACHE` borné à 2048 avec éviction FIFO ; M-6 arithmétique `tell()`/`seek()` mode binaire — conformité opaque-cookie TextIOBase ; M-7 `subprocess.TimeoutExpired` redondant retiré ; M-8 `proto` normalisé en upper au parse-time pour qu'un build downstream lowercase ne split pas silencieusement une campagne bruteforce). +15 tests régression dans `tests/test_logs.py` couvrant chaque classe de fix. Single-module pass, single commit. 4545 → 4560 tests. Contrat JSON préservé. Sortie wire inchangée sur hosts avec config UFW standard ; visible seulement sur hosts émettant `[UFW BLOCK6]` (précédemment droppés — maintenant comptés) ou avec logs syslog locale non-anglais (précédemment inflated days_available — maintenant exact). |
| [v0.5.5](#v055) | 24-05-2026 | Passe de hardening — 4 bugs réels (C-1 à C-4) + 4 security smells (I-1 à I-4) + 11 cleanups mineurs (M-1 à M-11) depuis un audit sub-agent profond. **C-1** : `apply_cron_email()` réécrivait les scripts wrapper via `_atomic_write()` qui forçait le mode `0o600` — les scripts perdaient leur bit exécutable `0o755` et cron arrêtait silencieusement de lancer l'audit. `_atomic_write()` prend maintenant `mode=` explicitement ; les réécritures de cron files passent `0o640`, les scripts `0o755`. **C-2 + C-3 + M-11** : 3 valeurs `cmd=` contenaient `&&` (opérateur shell rejeté par `_has_shell_ops`) ou une flèche Unicode décorative → `--fix --apply` les rejetait silencieusement. Demotion `password_policy.no_quality_module` + `password_policy.weak_minlen` de `nature="action"` à `nature="improvement"` (visible dans le summary box sous "Améliorations possibles" au lieu de "À corriger") + split du cmd `services_state.service_inactive` pour retirer le `&& journalctl` chaîné (déplacé en `note=`). **C-4** : `bob/checks/services_state.py` émet `services_state.service_inactive` mais `EXPLAIN_KEYS` déclarait `services_state.enabled_inactive` — `bob --explain` retournait "key not found". Fix via `EXPLAIN_KEY_ALIASES` (conservatif — préserve le contrat JSON output). **I-1** : `recurrence.py` + `ignore.py` écrivaient les fichiers state avec l'umask process (typiquement world-readable `0o644`) au lieu de `0o600` comme tous les autres `~/.config/bob/`. **I-2** : appels post-`finalize()` à `_apply_deduction` bypassaient silencieusement les caps de score — log WARNING + discard maintenant. **I-3** : `_safe_url` dans HTML email markdown ne re-escapait pas le contexte attribut — URL craftée contenant `"` pouvait sortir de `href=""`. Utilise maintenant `html.escape(..., quote=True)`. **I-4** : regex brittle `sysinfo._PRIVATE_IPV4_RE` (avec hack `removeprefix("^")`) remplacée par checks d'appartenance `ipaddress.ip_network` explicites ; contourne le widening Python 3.12+ de `is_private` incluant les ranges documentation. **M-1** : 3 sites regex email dupliqués unifiés via `bob.config._EMAIL_RE`. **M-2** : `bob/watch.py:_NullReport` retiré au profit de `bob.report.NullReport` (type Protocol introduit en v0.5.0 #10). **M-3** : 3 clés locale mortes retirées (`_meta.lang`, `_meta.version`, `ignored.hint`). **M-4** : règle `corr.fully_blind` asymétrique — exigait `fail2ban.not_installed` mais ignorait l'aveuglement équivalent `fail2ban.service_inactive`. Élargi pour fire quand n'importe quel layer de détection est aveugle. **M-7** : extraction helper `_has_actionable_findings()` dans `updates.py` (plus clair qu'un blacklist inline de `apt_cache_age`). **M-8 + M-9** : commentaires clarifiants dans ssh.py (skip Include après Match block) et ports.py (champs process/iface vides = "inconnu"). **M-10** : regex `apply_cron_schedule` anchored avec cron-token premier champ — les comment lines contenant "root /path" ne sont plus réécrites. **M-6 (commit séparé)** : `Optional[X]` / `List[X]` → `X \| None` / `list[X]` sur 18 modules — syntaxe Python 3.10+. 4538 → 4545 tests (+7 régression). Diff net : 23 fichiers code, +312 / −112 = +200 LoC. Score sur host dev inchangé (8/10) ; le changement `nature` password_policy fait visiblement disparaître le bloc "À corriger" sur les hosts sans pwquality. |
| [v0.5.4](#v054) | 22-05-2026 | Refactor v0.5.x Phase 5 sur 5 (finale) — **#6 + #9 + #15b + cache APT option C**. **#6 helper `prompt_wizard()`** dans `bob/_tty.py` (wrapper translation-agnostic autour de `input()` avec cancel `q`/`quit` uniforme + default-on-Enter) remplace 10 sites `input()` bruts dans les wizards install + edit de `bob/cron.py`. **#9 sunset UFW_AUDIT_SHARE** — `bob/_paths.py:resolve_share_dir()` upgradé `logger.info(...)` → `logger.warning(...)` avec message explicite "DEPRECATED depuis v0.5.4, sera REMOVED en v0.6.0" ; la legacy env var reste fonctionnelle aujourd'hui. **#15b mapping `_PREFIX_TO_DOMAIN` explicite** — trois fallbacks silencieux v0.4.x sortent du catch-all firewall : `fail2ban` → `ssh` (vocation primaire anti-bruteforce SSH), `virt` → `hardening` (bypass KVM/bridge est surface kernel/système), `docker_audit` → `hardening` (durcissement container / sécurité daemon.json). `smtp` et `desktop_apps` restent catch-all par design (pas de fit propre). **Cache APT option C** (nouvelle feature métier) — `bob/checks/updates.py` ajoute une ligne INFO `updates.apt_cache_age` quand aucune mise à jour security/regular n'est en attente ET l'âge du cache est sous le seuil obsolète, donnant une transparence permanente sur la fraîcheur du verdict "système à jour". Remonté par le test terrain VM Ubuntu du 2026-05-22 où une VM dormante retournait "à jour" malgré 8 LTS security updates en attente upstream. **#13 (split ssh.py, 1324L) et #14 (split cron.py, 1223L) déférés à v0.6.0** — selon le principe conservative-refactor, splitter des fichiers >1000 LoC pour un gain marginal de lisibilité ne passe pas le test gain × risque dans une release contract-preserving. Diff net : 12 fichiers modifiés, +118 / −69 = +49 lignes (cron.py +1, _tty.py +24, updates.py +20, domain_scores.py +10, _paths.py +5, locales +4 clés, tests −6). 4538/4538 tests inchangés. Diff de sortie vs v0.5.3 est intentionnel : nouvelle ligne INFO dans section MISES À JOUR SYSTÈME sur hosts avec cache + aucune update en attente, et reshuffle du score par domaine sur hosts émettant des findings `fail2ban.*` / `virt.*` / `docker_audit.*`. Ferme l'audit v0.5.x (13/15 findings shippés, 2 déférés avec justification). |
| [v0.5.3](#v053) | 22-05-2026 | Refactor v0.5.x Phase 4 — **#5 + #12 + #8**. **#5 Table `_LEVEL_DISPATCH`** dans `bob/display.py` collapse la cascade 4-branches OK/WARN/ALERT/INFO de `display_result()` en une seule boucle de dispatch pilotée par une dataclass frozen `_LevelTraits(report_label, threshold_key, print_fn, has_recurrence, has_body, detail_unconditional, show_note, show_cis)`. La table 4 lignes capture le comportement par niveau de manière déclarative ; le cas spécial ALERT qui imprime le détail sans `--verbose` est maintenant exprimé via `detail_unconditional=True` plutôt qu'une branche impérative. **#12 split `print_audit_summary`** — la fonction de 142 lignes est découpée en 3 helpers focalisés (`_summary_header_lines`, `_summary_findings_lines`, `_summary_breakdown_lines`) plus `_add_finding_lines` remonté d'inner-function à niveau module. L'orchestrateur devient un assembleur 3 lignes. **#8 retrait de `CheckResult.log_data`** — l'escape hatch dict typé sur `CheckResult` est remplacé par un retour tuple de `check_logs(...) -> (CheckResult, LogReportData | None)`. Nouvelle dataclass frozen `LogReportData(log_days, days_available, total, brute_hits, top_ips, top_ports, svc_hits)` dans `bob/checks/logs.py`. `runner.py` unpacke le tuple ; `display_log_results` prend le report comme arg explicite. **Diff net : 5 fichiers modifiés, +109 / −69 = +40 lignes** (display.py +23 pour signatures helpers explicites, logs.py +19 pour `LogReportData`, scoring.py −1 pour le champ retiré). 4538/4538 tests inchangés — 3 tests renommés (`test_log_data_*` → `test_report_data_*`), ~20 sites tests utilisent l'unpack tuple. Sortie wire bit-identique à v0.5.2. |
| [v0.5.2](#v052) | 22-05-2026 | Refactor v0.5.x Phase 3 — **#4 + #3**. **#4 Table directive SSH** : nouvelle dataclass `_BadDirective` + table `_BAD_DIRECTIVES` (8 entrées) + helper `_apply_bad_directive()` dans `bob/checks/ssh.py`. Migre les 8 directives `sshd_config` uniformes (PermitEmptyPasswords, X11Forwarding, IgnoreRhosts, HostbasedAuthentication, PermitUserEnvironment, StrictModes, AllowTcpForwarding, PubkeyAuthentication) d'une cascade de blocs `if value == "yes"`/`"no"` vers une boucle `for rule in _BAD_DIRECTIVES`. Helper avec deux styles de prédicats (`bad_values` ou `safe_values`) — `safe_values` couvre AllowTcpForwarding où `"local"` est acceptable en plus de `"no"`. Cas spéciaux préservés en impératif : PermitRootLogin (4-way branch), PasswordAuthentication (dépend de `ssh_exposed`), MaxAuthTries (seuil entier), LoginGraceTime (INFO-only), AllowUsers/AllowGroups (info-only), Match block, weak ciphers/macs/kex (helper séparé). Net `_check_sshd_config` : ~180 → ~50 LoC, ssh.py total +56 (coût dataclass + 8 entrées). **#3 extension runner._sec** avec params keyword-only `skip_if=Callable[[snapshot], bool]` et `post_display=Callable[[snapshot, result], None]`. Permet de remplacer 4 blocs inline par des appels `_sec` 1-liner : samba (skip_if not installed), docker_audit (skip_if not docker_installed), desktop_apps (skip_if not detected), disk (post_display=display_disk_partitions). Net runner.py : −29 lignes. **#13 (split ssh.py) déféré à Phase 5** — estimation audit (-150 LoC pour #4) trop optimiste, ssh.py reste à 1324 LoC. Tests 4538/4538 inchangés — comportement bit-identique à v0.5.1. |
| [v0.5.1](#v051) | 21-05-2026 | Refactor v0.5.x Phase 2 — **le gros gain LoC** (audit finding #1). Nouveaux helpers `CheckResult.warn_with_deduction(key, *, message, points, reason=None, ...)` et `.alert_with_deduction(...)` dans `bob/scoring.py` qui collapsent l'idiom paired `result.warn(...) + result.add_deduction(...)` qui se répétait sur ~130 sites dans `bob/checks/*.py`. **120 sites migrés** dans 27 fichiers : firewall (4), fail2ban (2), clamav (5), ntp (2), ddns (1), updates (2), ssh (24 — le gros morceau), backup (1), log_rotation (3), auditd (3), file_integrity (3), kernel_hardening (3), rootkit (3), hardening (8), samba (6), mac_policy (6), disk (5), iptables_nftables (5), firewall_stack (4), file_perms (1), suid_audit (1), smtp (1), memory (1), network_context (1), cron_audit (2), docker_audit (2), kernel_modules (2), umask (2), user_accounts (2), password_policy (2), secure_boot (2), systemd_timers (2), logs (1), firmware (2), ipv6 (1), ports (1). **13 sites volontairement non migrés** — patterns où la déduction est conditionnelle sur un prédicat différent du finding (caps via compteur local : `services_state`, `ssl_certs` x3, `file_perms` x3, `ipv6.port_no_v6_rule`), ou où le niveau du finding branche `warn`/`alert` sur une condition séparée de la déduction (`docker` x2, `services.exposure`, `ports.uncovered_public`). L'override `reason=` gère les cas où la déduction utilise une clé i18n suffixée `_reason` distincte du message du finding (ex `ssh.host_key_dsa_reason` ≠ `ssh.host_key_dsa`). **Diff net : 37 fichiers modifiés, +483 / −1002 = −519 lignes.** Tests inchangés : 4538/4538 passent (les helpers sont additifs, zéro changement de comportement). JSON `schema_version="1"`, les 7 domaines de score, les 116 EXPLAIN_KEYS, et les 34 sections filtrables tous préservés. |
| [v0.5.0](#v050) | 21-05-2026 | Refactor v0.5.x Phase 1 (ouvre la branche v0.5.x) — **6 findings de l'audit refactor + 1 bug latent trouvé par la nouvelle couverture de tests**. **#7** nouveaux helpers `is_unit_active()`/`is_unit_enabled()` dans `bob.checks._run` migrent 9 sites (`auditd`, `fail2ban`, `clamav`, `ntp`, `ddns`, `updates`, `ssh`, `backup`, `log_rotation`) en remplaçant l'idiom répété `_run("systemctl", "is-active", ...).strip() == "active"` ; `.lower()` défensif ajouté de manière centrale pour se protéger d'une sortie distro non-canonique. **#2** nouveau `bob.output.print_titled_box(title, width=62)` migre 4 sites (3× `cron.py` + 1× `manage_logs.py`) et **ferme le leak `--no-color`** où ces sites contournaient `_c` en imprimant des `\033[1;34m` littéraux. **#10** nouveau `bob.report.Report` `typing.Protocol` (type structurel PEP 544) capture le contrat partagé entre `AuditReport`, `NullReport` et `MarkdownReport` (qui étaient deux implémentations duck-typed) ; `runner.run_checks` annote maintenant `report: Report`. **#11** nouveaux closures `emit_section()` + `emit_group()` dans `runner.py` collapsent l'idiom 3-lignes `if not config.quiet: print_section(t(...)); report.write_section(t(...))` en 1 ligne à 20 sites (5 group headers + 15 section headers) ; `_sec()` lui-même dogfoode le helper. **#15a** nouveau `tests/test_domain_scores_mapping_complete.py` (+4 tests) scanne en AST `bob/checks/*.py` pour chaque `key="X.Y"` littéral et atteste que chaque préfixe est soit explicite dans `_PREFIX_TO_DOMAIN` soit whitelisté dans `_CATCH_ALL_BY_DESIGN` avec une justification (l'état v0.4.x — `smtp`/`fail2ban`/`desktop_apps`/`virt`/`docker_audit`/`ddns` etc. tombent encore dans le catch-all firewall, reporté à Phase 5 #15b). **Passe de couverture cron** (+35 tests) couvrant les 5 helpers purs non testés par les passes précédentes : `_validate_cron_field`, `_validate_custom_cron`, `build_script_content`, `apply_cron_schedule`, `apply_cron_email` (avec parité legacy `NOTIFY_EMAIL=`). **Bug latent corrigé (trouvé par les nouveaux tests cron) :** `apply_cron_schedule()` appelait `_os.open(...)` — mais `_os` n'est aliasé localement que dans 3 *autres* fonctions, jamais au niveau module. L'extraction de déduplication cron v0.4.8 avait raté ce renommage. Le helper était silencieusement mort depuis v0.4.8. Fix : `_os` → `os`. 4499 → **4538 tests** (+39 : +4 mapping / +35 cron). |
| [v0.4.8](#v048) | 21-05-2026 | Passe d'audit code-quality 4 (sub-agent) — **bug réel I4** les fichiers de log de `sudo bob -d` étaient `root:root 0600` et inaccessibles à l'utilisateur après coup (maintenant chowned-back via `chown_to_sudo_user` dans `bob/report.py` + `bob/manage_logs.py::get_or_prompt_log_dir`, même pattern que les 7 modules de config déjà chowned) · **nettoyage de fields morts** 8 champs dataclass retirés sur 5 checks (`SSHSnapshot.config_source_files`, `FirewallStatus.ipv4_rules_count`+`ipv6_rules_count`, `SambaSnapshot.min_protocol`, `ClamAVSnapshot.last_scan_log_path`+`db_path`, `SecureBootSnapshot.method`) tous populés mais jamais lus — même classe de bug que v0.4.3 C1 · `_C_LOCALE_ENV` ajouté sur 3 sites `subprocess.check_output` (desktop_apps/smtp ps + ss/netstat) pour cohérence de locale · `log_rotation._service_active` inliné via `_run("systemctl", "is-active", ...)` (était 11 lignes de réinvention) · `apply_cron_schedule()` + `apply_cron_email()` promus de helpers privés à l'API publique de `bob.cron`, `bob/tui/cron.py` les importe — corrige l'asymétrie de support legacy `NOTIFY_EMAIL=` qui n'existait que côté plain · `SCORE_BAR_WIDTH = 10` exporté depuis `bob.output` (dédoublonne la constante `_BAR_WIDTH` entre `breakdown.py` + `domain_scores.py`) · auth_log 90 jours documenté comme intentionnel (indépendant de `--log-days` qui est pour les logs UFW) · **pyproject.toml** : `Development Status :: 4 - Beta` → `5 - Production/Stable`, `authors` + `maintainers` ajoutés (PyPI affichait UNKNOWN), `[project.optional-dependencies] geoip = ["geoip2>=4.0"]` pour `pipx install "bodyguard-of-bits[geoip]"`, `wheel` retiré des build-requires, Source + Documentation URLs ajoutées, `dependencies = []` explicite et `include = ["bob", "bob.checks", "bob.tui"]` · 4499/4499 tests (-1 : `test_default_method_is_none` retiré car le champ `method` n'existe plus) |
| [v0.4.7](#v047) | 21-05-2026 | Passe d'audit documentaire + harmonisation jauges + automatisation release — audit cross-doc exhaustif (24 corrections sur 8 fichiers : README/FR · README_TECH/FR · README_DEV/FR · SECURITY_FR · `man/bob.1` · `man/bob-profile.5` · AUTOMATION/FR) · `DOCUMENTS/SNAPSHOT.md` ajouté (~640L cartographie interne, 20 passes de corrections) · barres de jauges harmonisées via `bob.output.score_bar()` (vert ≥8, jaune 5–7, rouge 0–4 — même logique de couleur que les barres de disques) · refonte complète de la bash completion (renommage fonction, dead code supprimé, **fix critique** pour la complétion de valeurs `--check=`/`--skip=`/`--format=`/etc. qui échouait silencieusement à cause du split `=` de `COMP_WORDBREAKS`) · `publish.yml` crée automatiquement la GitHub Release depuis `CHANGELOG_FULL.md` au push de tag · 4500/4500 tests (inchangé) |
| [v0.4.6](#v046) | 17-05-2026 | Correctifs passe terrain v0.4.5 — **Bug 1** `kernel_modules.py` dpkg-query ne filtrait pas l'état `ii` (installé), donc les noyaux retirés par `apt remove` / `autoremove` (passés en état `rc` config-files) restaient listés comme "installés". Reproduit Mint test VM + so6desktop production. Utilise maintenant `${db:Status-Abbrev}` et ne garde que les lignes dont le 2e caractère est `i` (couvre `ii`, `hi`). **Bug 2** inversion de score : après qu'`apt upgrade` ait résolu un WARN `updates.security_pending`, seul `updates.ok` subsistait → `active_domains_from_engine` retirait le domaine → score global *baissait* (dénominateur réduit). Reproduit Debian 13 VM (7/10 → 6/10 après remédiation). `_actionable` élargi de `(WARN, ALERT)` à `(OK, WARN, ALERT)` ; les domaines INFO-only restent cachés par design. 4500/4500 tests (+11) |
| [v0.4.5](#v045) | 16-05-2026 | Hardening de l'infrastructure de tests — `tests/test_locale_coverage.py` passe de scan regex à **parsing AST** (`ast.walk` + `ast.Call` + `ast.Name` checks) · élimine trois classes de faux positifs que le regex pouvait produire (matches dans docstrings, mauvais parse de call sites multilignes, appels d'attributs `obj._t(...)`) · allowlist `_KEY_EXCLUSIONS` complètement supprimée · mêmes 9 tests, même contrat externe, fondation plus robuste · 4489/4489 tests (inchangé) |
| [v0.4.4](#v044) | 15-05-2026 | Hardening terrain cross-distro — **bug critique `updates.py`** (4/4 VMs Debian-family : 21 mises à jour de sécurité Ubuntu LTS non détectées) : `apt-get -s upgrade` → `dist-upgrade` · détection du cache APT obsolète · cross-check vs `apt list --upgradable` · "Surface d'attaque" propage `updates_unknown` au lieu du faux "à jour" · AppArmor "0 profil chargé" clé dédiée · SMART skippé si tous les disques sont virtuels · ports DDNS inline dans le WARN · S4 redesign `_is_safe_user_path` home-bounded · M4 refactor `_parse_ufw_covered_ports` (1 parse + lookup O(1)) · I2 vague 2 `key=` sur services/virtualization · nouveau test de couverture locale (attrape les régressions `[xxx.yyy]`) · 4489/4489 tests (+21) |
| [v0.4.3](#v043) | 15-05-2026 | Rattrapage doc + passe de hardening post-audit — 4 clés firewall ajoutées à `EXPLAIN_KEYS` · fix crash `--json --json-full` (5 attributs HardeningSnapshot morts) · `strptime("%b…")` rendu indépendant de la locale (ssl_certs + logs) · faux positif `_is_covered_by_ufw` éliminé · liens markdown email plus échappés · validateur cron rejette les ranges hors-bornes · `key=` sur ~30 findings (docker, firewall_stack, network_context, ports) · 7 clés locales mortes retirées · anti-pattern concat i18n résolu (ddns, logs) · refs CIS ajoutées · CHANGELOG court corrigé pour v0.4.2 · 4468/4468 tests (+4 régression) |
| [v0.4.2](#v042) | 14-05-2026 | Phase 3 distro-ready (discipline packaging) — threat model `SECURITY.md` · 3 man pages (`bob(1)`, `bob.conf(5)`, `bob-profile(5)`) · répertoire `debian/` avec pybuild + DEP-5 + 3 paquets binaires (`bob-core`, `bob-tui`, `bob` méta) · `packaging/rpm/bob.spec` prêt pour Fedora COPR · profil AppArmor en mode complain (`debian/apparmor.d/bob`) · passe de hardening pré-release : 2 critiques + 5 importants + 4 mineurs + 1 suggestion issus de l'audit agent · 4452/4452 tests (+3 dans nouveau `test_template_vars_migration.py`) |
| [v0.4.1](#v041) | 14-05-2026 | Phase 2 distro-ready (découplage architectural) — `bob/tui/` extrait (curses optionnel) · champs additifs `Finding.template_vars` / `Deduction.template_vars` pour reconstruction indépendante de la locale · nouveau module `bob.formatter` + passe de hardening post-revue (`lang=` retiré, `i18n.try_t()`, `except KeyError` resserré) · 3 checks pilotes migrés (ssh, hardening, firewall) · template_vars exposé dans la sortie JSON · mode `--offline` vérifié + tests d'intégration · 4449/4449 tests (+19) |
| [v0.4.0](#v040) | 14-05-2026 | Phase 1 distro-ready — codes de retour / détection locale POSIX (`$LANG`) / contrat de sortie JSON (`schema_version`, champs `key`) / alias map `--explain` / JSON Schema formel pour `services.json` (avec hardening passe #1 : regex port stricte 1–65535 · factorisation `$defs` · contraintes métier `if/then` · wrapper plugin-file avec `schema_version`) · passe #2 : descriptions schémas, `services-list.minItems`, fixtures à classes réelles remplaçant MagicMock, compat shim RefResolver→referencing · suffixe `= N` redondant sur score stable supprimé · 4430/4430 tests (+82) |
| [v0.3.6](#v036) | 09-05-2026 | Passe code review — `Path.home()` → `get_user_home()` (sudo-aware) sur 7 modules · ULA/link-local IPv6 dans `_is_private_or_loopback` · SSH `AllowTcpForwarding local` accepté · header journalisation UFW masqué si UFW inactif · regex legacy `NOTIFY_EMAIL` · 22 imports inutilisés supprimés · 47 clés de locales mortes retirées · 4348/4348 tests |
| [v0.3.5](#v035) | 08-05-2026 | Refactoring — closure `_sec` dans `runner.py` (−295L) · helper `_check_weak_algo` dans `ssh.py` · correctif locale 4× `UFW-AUDIT` → `BOB` · 4348/4348 tests |
| [v0.3.4](#v034) | 08-05-2026 | Hotfix — `user_config` non transmis à `run_checks()` → `NameError` en fin d'audit (régression v0.3.2) · 4348/4348 tests |
| [v0.3.3](#v033) | 07-05-2026 | Refactoring architectural — split `cron.py` · `compute_domain_scores()` retour tuple pur · API publique `domain_scores` · helpers curses `_draw`/`_read_key` · 4348/4348 tests (+1) |
| [v0.3.2](#v032) | 06-05-2026 | Liste blanche SUID configurable dans `config.conf` · 14 corrections code review (i18n, mode quiet, idempotence moteur, code mort) · 4347/4347 tests (+19) |
| [v0.3.1](#v031) | 06-05-2026 | Fix version bannière · propagation contexte DDNS · `was_capped` sur Deduction · propriétés moteur en cache · 4328/4328 tests (+6) |
| [v0.3.0](#v030) | 06-05-2026 | Transparence du scoring `--breakdown` · `--explain` score-aware · fix rétention kernel -unsigned · reliques entête rapport supprimées · affichage delta score · 4322/4322 tests (+48) |
| [v0.2.4](#v024) | 05-05-2026 | UX kernel Debian -unsigned · sentinel None deduction_total · alias TranslationFunc (42 signatures) · _has_shell_ops() via shlex · avertissement profil introuvable · 4274/4274 tests (+12) |
| [v0.2.3](#v023) | 03-05-2026 | Corrections tournée multi-VM : NOT_LISTENING WARN→INFO · déduction IoT supprimée · affichage heredoc · garde symlink circulaire · Python 3.9 retiré · delta déductions compare · label SSH surface d'attaque · label active_disabled · 4262/4262 tests (+1) |
| [v0.2.2](#v022) | 02-05-2026 | Corrections scoring : `ScoreCap.key` · domaines INFO exclus · ClamAV 1pt · logging uniformisé · check règle UFW sans protocole · fix plafond domaine · fix locale SSH detail · tests invariants scoring · 4261/4261 tests (+23) |
| [v0.2.1](#v021) | 02-05-2026 | Hotfix — passe défensive : crash fix `--manage-logs` · 8 `except Exception` resserrés · 5 regex en module-level · regex email dédupliqué · `getattr` supprimé du scoring |
| [v0.2.0](#v020) | 01-05-2026 | Refonte du scoring (moyenne domaines · plafond par outil) · détection MTA cron · faux positif kernel `-unsigned` · dominance IoT WARN · bannière orange · 4238/4238 tests |
| [v0.1.1](#v011) | 29-04-2026 | Hotfix — parser fwupd format arbre · message `--install-completion` · renommage colonne panorama · 4206/4206 tests |
| [v0.1.0](#v010) | 26-04-2026 | Version initiale — 46 vérifications · 9 domaines · 32 services · mapping CIS · FR/EN · 4200/4200 tests |

---

## [v0.6.2] — 29-05-2026

**Hotfix packaging critique.** Tous les wheels shippés depuis v0.6.0 (donc v0.6.0 + v0.6.1) manquaient `bob/checks/ssh/` et `bob/cron/` — les deux sous-packages introduits par les splits v0.6.0. Les utilisateurs qui avaient `pipx upgrade`d hit un crash dur au startup :

```
$ sudo bob -v -d --french
Traceback (most recent call last):
  File "/usr/local/bin/bob", line 3, in <module>
    from bob.__main__ import main
  File ".../bob/__main__.py", line 38, in <module>
    from bob.runner import (
  File ".../bob/runner.py", line 46, in <module>
    from bob.checks.ssh import SSHSnapshot, check_ssh
ModuleNotFoundError: No module named 'bob.checks.ssh'
```

### Cause racine

`pyproject.toml::[tool.setuptools.packages.find]` avait une liste figée `include = ["bob", "bob.checks", "bob.tui"]` héritée d'un audit packaging v0.4.x. Quand v0.6.0 a splité `bob/checks/ssh.py` → package `bob/checks/ssh/` et `bob/cron.py` → package `bob/cron/`, cette liste n'a pas été mise à jour. `find_packages()` de setuptools a donc EXCLU les deux sous-packages du wheel — ils existent dans le source tree mais ne sont jamais dans la distribution.

### Pourquoi trois couches de tests l'ont raté

1. **Tests unitaires** importent depuis le source tree (`from bob.checks.ssh import …` résout via `sys.path` contenant le repo root). La config packaging est non-pertinente.
2. **Smoke pre-ship `sudo python3 -m bob`** tournait depuis le working tree (`~/github/bodyguard-of-bits/`). Même résolution source-tree — wheel jamais impliqué.
3. **CI `integration.yml`** utilisait `pip install -e .` (mode editable), qui ajoute le repo root à `site-packages` via un fichier `.pth`. Les editable installs bypassent DÉLIBÉRÉMENT la discovery `find_packages()` pour iteration rapide — masquant exactement cette classe de bug.

Le premier signal est venu d'un `pipx upgrade` utilisateur sur un système clean, qui build et installe un vrai wheel.

### Fix

**`pyproject.toml`** :
```diff
 [tool.setuptools.packages.find]
 where = ["."]
-include = ["bob", "bob.checks", "bob.tui"]
+include = ["bob*"]
```

Le glob `bob*` matche `bob`, `bob.checks`, `bob.checks.ssh`, `bob.cron`, `bob.tui`, et tout futur sous-package `bob.*`. Exclut toujours la cible du garde original (répertoires non-bob top-level `bob_something/`).

**`.github/workflows/integration.yml`** :
- Changé `pip install -e .` → `pip install .` (build + install un vrai wheel sur chaque distro)
- Nouveau smoke step qui import explicitement chaque module v0.6.x-ajouté

Ce deuxième garde fail-fast sur un module manquant *à l'install-time sur la CI*, pas au runtime sur un système utilisateur.

### Compatibilité

- **Contrat JSON**, EXPLAIN_KEYS, sortie wire — tous inchangés.
- **Changements code** : zéro. Seulement `pyproject.toml` (1 ligne) et `.github/workflows/integration.yml` (~15 lignes) modifiés.
- **Tests** : 4600 inchangés. (Le code test ne touche pas le packaging ; ce bug n'est pas unit-testable sans spawn un build venv, ce qui est la nouvelle étape CI.)
- **Path d'upgrade** : `pipx upgrade bodyguard-of-bits` sur tout système pipx-installé pour fixer l'install cassé.

### Action requise

Si vous avez upgradé vers v0.6.0 ou v0.6.1 via pipx, vous avez actuellement un install cassé (le binaire `bob` crash à chaque invocation). Exécutez :

```bash
pipx upgrade bodyguard-of-bits
```

pour obtenir le wheel v0.6.2 fonctionnel.

### Leçons enregistrées

- **Les editable installs cachent les bugs packaging.** Tous les futurs jobs CI integration utilisent `pip install .` (non-editable).
- **Smoke step d'import explicite** pour chaque nouveau sous-package fait maintenant partie de la matrice intégration. Ajouter un nouveau `bob/foo/` sous-package dans le futur requiert l'ajouter à la liste smoke — visible en code review.
- **Memory note** : cette classe de bug est un risque récurrent pour les projets qui pinent des listes de package-discovery. Glob > liste figée pour `setuptools.packages.find.include`.

---

## [v0.6.1] — 26-05-2026

**Première release hardening sur la branche v0.6.x.** Audit profond sub-agent a produit 14 findings (0 critique + 6 important + 8 mineur) ; 6 important + 4 mineur shippés. L'audit a révélé deux **contrats demi-appliqués** depuis v0.5.x — atomic-write (paths de mutation fixés en v0.5.7 #I-3 mais pas les paths de création) et gestion EOF (`manage_logs.py` fixé en v0.5.7 #I-2 mais pas les wizards cron ni `fixes.py`) — plus une **branche validator non-testée** dans le parser de step cron. Tous adressés avec fixes localisés.

Voir `CHANGELOG.md` pour le détail par finding. Cette release introduit aussi `bob/_atomic.py` (helper consolidé) et `bob/_tty.safe_input()` (nouveau wrapper).

### Important (6)

- **I-1 + consolidation atomic-write** : extraction `bob/_atomic.py::atomic_write` source unique. Migration 5 sites existants + fix 4 sites non-atomiques. `bob/cron/_io.py::_atomic_write` gardé en alias pour backwards-compat tests.
- **I-2 EOF contract** : `safe_input()` + `prompt_wizard()` EOFError-safe. 11 sites migrés.
- **I-3** : `_validate_cron_field` borne step ≤ (hi - lo + 1).
- **I-4** : `shlex.quote()` sur 8 paths user-contrôlés.
- **I-5** : `history.jsonl` mode `0o600` au first-write.
- **I-6** : `ignore.py` atomic via `atomic_write`.

### Minor (4 shippés + 4 déférés)

Shippés : M-2 (double `.lower()` redondant), M-3 (`MaxAuthTries<=0` rejected), M-6 (`BOB_DEBUG=1` traceback hint), M-8 (`--watch=N` wording).

Déférés : M-1 (parse_cron_file silent downgrade — low-impact), M-4 (path constants au import-time — DOCUMENTÉ intentionnel), M-5 (fd leak window — addressé transitivement par I-1), M-7 (`--check/--skip` warning — judgment call UX).

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4600 passed in ~7s
```

**4583 → 4600 (+17).** Nouveaux : `TestAtomicWritePublicAPI` (4), `TestCronLegacyAliasStillWorks` (1), `TestHistoryFileMode` (2), `TestIgnoreAtomic` (2), `TestSafeInput` (3), `TestStepBoundedToFieldRange` (5).

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, 116 EXPLAIN_KEYS — inchangés.
- **Score** : inchangé.
- **Sortie wire** : inchangée. Seul `--watch=N` error wording change (user-visible string).
- **API externe** : `bob._atomic.atomic_write` + `bob._tty.safe_input` nouveaux (semi-publics via `_` prefix module name). Additifs.
- **Backwards-compat** : `bob.cron._io._atomic_write` reste alias. Tests patchant ce nom continuent de marcher.

### Suivi campagne audit

| Release | Findings | Tests |
|---|---|---|
| v0.5.5 | 19 (4C + 4I + 11M) | +7 |
| v0.5.6 | 10 (0C + 2I + 8M) | +15 |
| v0.5.7 + v0.5.8 | 11 (0C + 3I + 8M) | +23 |
| **v0.6.1** | **14 (0C + 6I + 8M)** | **+17** |

**Cumul** : 30 modules deep-audited, 0 finding critique en suspens. Deux contrats (atomic-write, gestion EOF) maintenant uniformément enforced à travers le codebase.

---

## [v0.6.0] — 25-05-2026

**Bump majeur ouvrant la branche v0.6.x.** Deux splits architecturaux (#13 + #14) délibérément déférés tout au long du cycle v0.5.x, plus un sunset honoré. Les trois changements sont contract-preserving via re-exports `__init__.py` — chaque appel `from bob.checks.ssh import …` ou `from bob.cron import …` dans le codebase et dans les scripts utilisateurs continue de marcher inchangé.

### #13 — `bob/checks/ssh.py` → package `bob/checks/ssh/`

Le module SSH check de 1296 lignes splité en 4 sous-modules focalisés :

| Module | LoC | Contenu |
|---|---|---|
| `_directives.py` | 165 | Table déclarative `_BadDirective` + tuple `_BAD_DIRECTIVES` + helper `_apply_bad_directive` + sets de référence weak crypto (`_WEAK_CIPHERS`, `_WEAK_MACS`, `_WEAK_KEX`) |
| `_snapshot.py` | 198 | 5 dataclasses (`HostKeyInfo`, `PrivateKeyInfo`, `AuthorizedKeyEntry`, `KnownHostEntry`, `ClientConfigEntry`) + `SSHSnapshot` + `SSHSnapshot.from_system` |
| `_parsers.py` | 446 | Parsers purs : `_parse_config_file`, `_collect_private_keys`, `_detect_private_key_type`, `_key_type_from_algo`, `_rsa_bits_from_*`, `_has_passphrase`, `_parse_authorized_keys`, `_parse_client_config`, `_parse_known_hosts`, `_collect_host_keys`, `_detect_ssh_install_cmd`, `_parse_time_seconds` |
| `_subchecks.py` | 529 | Entry point `check_ssh` + tous les helpers `_check_*` par zone (`_check_host_keys`, `_check_sshd_config`, `_check_weak_algo`, `_check_ssh_dir`, `_check_private_keys`, `_check_authorized_keys`, `_check_client_config`, `_check_known_hosts`) |
| `__init__.py` | 64 | Re-exports publics |

**Break du cycle** : `_parsers` importe les dataclasses depuis `_snapshot` au niveau module ; `_snapshot.SSHSnapshot.from_system` utilise un import local de fonction `from . import _parsers` pour éviter le dep autrement-circulaire. Propre et intention-revealing.

### #14 — `bob/cron.py` → package `bob/cron/`

Le module cron de 1204 lignes splité en 4 sous-modules focalisés :

| Module | LoC | Contenu |
|---|---|---|
| `_parse.py` | 330 | Dataclass `CronEntry` + `parse_cron_file` + `list_installed_crons` + `cron_to_human` + `build_schedule_expr` + `make_slug` + `suggest_name` + `_validate_cron_field` + `_validate_custom_cron` + `_parse_day_names` + `_parse_dom` + `_ordinal` + `_detect_mta` + constantes (`CRON_DIR`, `SCRIPT_DIR`, `LEGACY_*`, `_DAYS_EN`, `_DAYS_FR`, `_CRON_FIELD_BOUNDS`) |
| `_io.py` | 164 | `_atomic_write` + `build_script_content` + `apply_cron_schedule` + `apply_cron_email` (tous les helpers de mutation fichier) |
| `_install.py` | 319 | `prompt_emails` + `prompt_email` + `_run_install_cron_plain` + `run_install_cron` + exception `_CronQuit` (partagée avec `_manage`) |
| `_manage.py` | 445 | `_manage_email_store` + `edit_cron_email` + `edit_cron_schedule` + `_run_manage_cron_plain` + `run_manage_cron` |
| `__init__.py` | 101 | Re-exports publics incluant `datetime` + `_EMAIL_RE` pour backwards-compat |

**Note sur la résolution de chemin de `build_script_content`** : la fonction utilise `Path(__file__).parent.parent.parent` pour dériver `PYTHONPATH` pour le script cron généré — post-split `__file__` résout vers `bob/cron/_io.py` donc on remonte maintenant TROIS parents (`_io.py` → `cron/` → `bob/` → repo root) au lieu de deux. Vérifié par le smoke test existant (`tests/test_cron.py::TestDatetimeImportLifted::test_build_script_content_still_stamps_date`).

### Sunset : env var legacy `UFW_AUDIT_SHARE`

Annoncé "REMOVED in v0.6.0" par le warning deprecation shippé en v0.5.4 (`bob/_paths.py:60`). Honoré. Seul `BOB_SHARE` est maintenant accepté par `resolve_share_dir()`. Les installers settant encore `UFW_AUDIT_SHARE` verront aucun effet — les mettre à jour pour utiliser `BOB_SHARE`. La chaîne de deprecation :

- v0.4.2 : `BOB_SHARE` devient le contrat documenté ; `UFW_AUDIT_SHARE` accepté comme alias legacy
- v0.5.4 : `logger.info(...)` upgradé à `logger.warning(...)` avec message explicite "REMOVED in v0.6.0"
- **v0.6.0** : Retiré (cette release)

Drop de 3 lignes dans `bob/_paths.py` (constante `_ENV_LEGACY`, lecture fallback, branche warning legacy) plus 2 updates de docstring dans `bob/i18n.py` et `bob/registry.py`.

### Compatibilité backwards

Chaque symbole public des monolithes v0.5.x est re-exporté par les nouveaux packages `__init__.py` :

```python
# Marche encore en v0.6.0 :
from bob.checks.ssh import SSHSnapshot, check_ssh, AuthorizedKeyEntry  # et 8+ autres
from bob.cron import CronEntry, run_install_cron, apply_cron_schedule, _EMAIL_RE, datetime, _CronQuit
```

C'était le facteur déterminant pour le split conservateur — l'alternative (forcer des changements de chemin d'import user-visible) serait un vrai breaking change et n'est pas justifié pour un refactor interne. Le packaging garde l'option ouverte pour v0.7+ si un redesign API plus profond est voulu plus tard.

### Updates infrastructure tests (2 fixes AST scan triviaux)

La discovery des modules check dans deux tests d'introspection a eu besoin de recurser dans les nouveaux répertoires de package :

- **`tests/test_template_vars_migration.py`** : `_check_modules()` (maintenant `_module_paths()`) walk `iterdir()` et retourne soit des fichiers `.py` simples soit des répertoires de package ; `_module_has_template_vars(path)` fait `rglob("*.py")` pour les cibles package. Liste pilote convertie de `frozenset({"ssh.py", "hardening.py", "firewall.py"})` à la forme module-name `frozenset({"ssh", "hardening", "firewall"})`.
- **`tests/test_domain_scores_mapping_complete.py`** : changement d'une seule ligne — `_CHECKS_DIR.glob("*.py")` → `_CHECKS_DIR.rglob("*.py")` avec filtre `__pycache__`, donc le scan AST pickup `bob/checks/ssh/_subchecks.py` et toutes les emissions de clé des sous-modules siblings.

Un test de régression (`tests/test_cron.py::TestApplyCronScheduleAtomic`) a été mis à jour pour spy sur `bob.cron._io._atomic_write` plutôt que le re-export package-level — parce que `apply_cron_schedule` vit maintenant dans `_io.py` et appelle le `_atomic_write` local directement. Le spy doit être set sur le module où le call site lit.

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS — inchangés.
- **Score par domaine** : inchangé. Score global inchangé.
- **Sortie wire** : inchangée.
- **API Python externe** : tous les symboles publics v0.5.x re-exportés depuis les nouveaux packages. Aucun retrait.
- **Variables d'environnement** : `UFW_AUDIT_SHARE` retirée (annoncé pour 12+ mois). Seul `BOB_SHARE` accepté.
- **Keybindings**, **fallback no-curses**, **exit codes** — inchangés.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4583 passed in ~7s
```

**4583 inchangés.** Aucun nouveau test, aucun test retiré — les splits + sunset sont structurels et ne changent pas le comportement. Les 3 fichiers tests mis à jour (template_vars_migration, domain_scores_mapping_complete, test_cron) shift les targets d'assertion pour accommoder le nouveau layout module mais gardent le même scope de couverture.

### Diff net

| Fichier | Delta |
|---|---|
| `bob/checks/ssh.py` (supprimé) | −1296L |
| `bob/checks/ssh/__init__.py` + 4 sous-modules | +1402L (165 + 198 + 446 + 529 + 64) |
| `bob/cron.py` (supprimé) | −1204L |
| `bob/cron/__init__.py` + 4 sous-modules | +1359L (330 + 164 + 319 + 445 + 101) |
| `bob/_paths.py` | −20L (path alias legacy + warning) |
| `bob/i18n.py`, `bob/registry.py` | −2L (updates docstring) |
| 2 updates fichiers tests | +20L net (rglob + migration path-not-stem) |
| 1 fix target patch test | +2L net (cron_io vs cron_mod) |
| Bump version + changelogs | ~17 fichiers standard |

Overhead : +261L total à travers les deux packages vs l'équivalent monolithique. C'est le coût des re-exports `__init__.py` + imports module-level + docstrings par fichier. Vaut le coup pour la modularité.

### Roadmap

v0.6.0 ferme le backlog architectural-split de v0.5.x. La branche v0.6.x accueillera :
- **Maintenance** de la structure maintenant modulaire
- **Bug reports terrain** des tests cross-distro
- **Unification prompt TUI** (`_curses_readline` / `prompt_wizard` / `_rl` → hiérarchie plus plate) — listée comme candidate v0.6.0 mais punted pour maintenir le focus de release
- **Planning cadence schema JSON v2** (préparation pour breaking changes en v1.0)
- **Préparation EOL Python 3.10** (deviendra candidate bump min-version en v0.7+)

Aucune campagne deep-audit prévue pour v0.6.x — la campagne v0.5.x s'est fermée exhaustivement (25 modules deep-auditeurs + ~25 spot-checkés, 0 finding critique en suspens).

---

## [v0.5.8] — 25-05-2026

**Release cleanup.** Clear des 5 mineurs cosmétiques explicitement déférés par v0.5.7 (M-2, M-5, M-6, M-7, M-8). Tous les cinq sont des améliorations layout / lisibilité / nommage-explicite avec zéro changement de comportement en opération normale. **Cela ferme la campagne deep-audit v0.5.x.**

### Fixes (5)

**M-2 — `manage_logs.py` cursor shift après delete**

`cursor = max(0, cursor - deleted)` supposait que toutes les suppressions étaient à ou avant le cursor. Avec multi-sélection où certains items marqués étaient APRÈS la position active, le cursor shiftait quand même à gauche par le total des deletions → il finissait sur le mauvais fichier. Maintenant :

```python
deleted_before_cursor = 0
for li in sorted(pending_delete, reverse=True):
    ...
    if li <= cursor:
        deleted_before_cursor += 1
...
cursor = max(0, cursor - deleted_before_cursor)
```

**M-5 — Constantes wizard schedule → `IntEnum` module-level**

Le wizard avait un tuple-unpack local `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` (noter le `_` jetable pour DAILY = 1). Promu en :

```python
class _Schedule(IntEnum):
    DAILY = 1
    WEEKDAYS = 2
    MONTHDAYS = 3
    CUSTOM = 4
```

`IntEnum` préserve la sémantique `choice == _Schedule.WEEKDAYS` où `choice` est un int brut dérivé de la position menu. 3 call sites mis à jour (`if choice == _Schedule.WEEKDAYS:` etc.).

**M-6 — `_extract_summary_view` sentinelle `None`**

`summary_start = 0` + `if summary_start: break` traitait l'index 0 comme "non trouvé". Si le séparateur `SEP62` était à la ligne 0 (unreachable en pratique — les logs commencent toujours par des lignes header), la boucle mis-détecterait. Remplacé par :

```python
summary_start: int | None = None
...
if summary_start is not None:
    break
```

**M-7 — `_extract_summary_view` grouping continuation over-greedy**

`while ... lines[j].startswith("    ")` avalait N'IMPORTE QUELLE ligne indentée 4-espaces comme continuation du finding ALERT/WARN précédent, y compris des lignes body non liées d'autres sections. Helper extrait :

```python
def _is_finding_continuation(line: str) -> bool:
    if not line.startswith("    "):
        return False
    stripped = line.lstrip()
    if any(m in stripped for m in ("[ALERT]", "[WARN]", "[OK]", "[INFO]")):
        return False
    if stripped[:1] in ("┌", "└", "│", "━", "╔", "╠", "╚", "║"):
        return False
    return True
```

Stoppe sur les markers de finding et sur les délimiteurs de section même si la ligne se trouve être indentée 4-espaces. Fix layout-only ; aucun impact sécurité.

**M-8 — `from datetime import datetime` remonté au top du module**

Trois imports locaux à l'intérieur de corps de fonctions (`bob/cron.py:_run_install_cron_plain`, `bob/cron.py:build_script_content`, `bob/tui/cron.py:_run_install_cron_curses`) → un import module-level dans chaque fichier. Retire aussi un `import os` local redondant et un `from pathlib import Path` (les deux déjà importés en haut de `bob/cron.py`).

### Tests

`tests/test_cron.py` :
- `TestScheduleIntEnum` (2) — les valeurs matchent les indices menu ; IntEnum compare égal à un int brut (préserve la sémantique des call sites existants).
- `TestDatetimeImportLifted` (3) — `bob.cron.datetime` et `bob.tui.cron.datetime` exposés au niveau module + smoke test `build_script_content` stamp toujours la date du jour.

`tests/test_manage_logs.py` :
- `TestCursorShiftAfterDelete` (2) — deletion mixte avant/après ne shift le cursor que par le count des avants ; deletions toutes-après laissent le cursor inchangé.
- `TestSummaryStartSentinel` (1) — edge case synthétique SEP62-à-index-0 correctement détecté.
- `TestIsFindingContinuation` (4) — accepte les body lines indentées ; rejette non-indentées ; rejette markers `[ALERT]`/`[WARN]`/`[OK]`/`[INFO]` indentés ; rejette les délimiteurs de section indentés.

4571 → **4583 tests** (+12).

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS — inchangés.
- **Score** : inchangé. Aucun changement score-engine.
- **Sortie wire** : inchangée.
- **API externe** : `_Schedule(IntEnum)` et `_is_finding_continuation()` sont de nouveaux symboles module-level dans `bob.tui.cron` et `bob.manage_logs` respectivement. Aucun retrait. Trois `from datetime import datetime` locaux retirés des corps de fonctions (pas partie d'une surface publique).
- **Keybindings** : inchangés.

### Campagne deep-audit v0.5.x — FERMÉE

Après v0.5.8, la branche v0.5.x est à son état final de maintenance :

| Release | Scope | Findings shippés |
|---|---|---|
| v0.5.5 | 22 modules core (deep) + ~15 spot-checkés | 19 (4C + 4I + 11M) |
| v0.5.6 | `bob/checks/logs.py` (662L) | 10 (0C + 2I + 8M) |
| v0.5.7 | `bob/manage_logs.py` + `bob/tui/cron.py` (~1920L) | 6 shippés + 5 déférés |
| **v0.5.8** | **Les 5 mineurs déférés de v0.5.7** | **5 (tous mineurs)** |

**Total** : 25 modules deep-audit + ~25 spot-checkés. 0 finding critique en suspens sur la branche.

### Prochaines étapes

- **v0.6.0** (bump majeur) réservée pour les refactors architecturaux délibérément déférés :
  - **#13** : split `bob/checks/ssh.py` (1324 LoC après la consolidation table `_BadDirective` v0.5.2)
  - **#14** : split `bob/cron.py` (1223 LoC après l'extraction des helpers de file-patching v0.4.8 + le lift d'import v0.5.8)
  - Autres décisions architecturales (unification prompt TUI, cadence schema JSON v2, etc.)

Les deux fichiers excèdent le soft ceiling 1000-LoC du projet. Les splits ont été déférés parce que gain × risque ne justifiait pas le churn dans une release minor contract-preserving.

---

## [v0.5.7] — 24-05-2026

**Passe de hardening ciblée sur le TUI curses.** Les audits v0.5.5 et v0.5.6 ont explicitement déféré `bob/manage_logs.py` (999 LoC) et `bob/tui/cron.py` (920 LoC) — les deux modules curses interactifs principaux — à une passe future dédiée. Cette release ferme ce bucket. Un sub-agent focalisé a produit 11 findings : 6 shippés en v0.5.7 (3 important + 3 minor triviaux), 5 minors cosmétiques documentés pour v0.5.8.

### Important (3)

**I-1 — `_curses_readline` acceptait les codes `KEY_*` curses comme caractères**

`_read_key` collapse la sortie de `stdscr.get_wch()` en un seul int peu importe que le type sous-jacent soit `str` (imprimable) ou `int` (keypad). Downstream, `_curses_readline` filtrait sur `ch_i >= ord(" ")` — mais les touches spéciales comme `curses.KEY_UP = 259`, `KEY_F1 = 265`, `KEY_RIGHT = 261` passent toutes ce gate. `chr(259)` est `Ι` (iota capital grec), `chr(265)` est `Ω`. Appuyer sur les flèches ou les touches de fonction dans les prompts nom/email/jours/heure/expression-custom insérait des glyphes grecs dans le buffer.

Aucun impact sécurité — chaque consommateur downstream valide : `_EMAIL_RE` rejette le garbage, `_validate_custom_cron` rejette les expressions cron malformées, le filtrage `re.split` + `isdigit()` drop les non-digits, le regex whitelist `make_slug` strip tout hors `[a-z0-9]`. Mais UX visiblement corrompue (`Mon Audit│Ι Ω`).

Fix : helper `_is_printable_input_char(ch_i)` extrait au scope module bornant les entrées à `32 <= ch_i < 256 and chr(ch_i).isprintable()`. Range Latin-1 imprimable pur ; rejette explicitement toutes les constantes `curses.KEY_*` (toutes ≥ 256).

**I-2 — Sites `input()` bruts ne catchaient pas Ctrl-D**

Trois appels `input()` dans `manage_logs.py` propagaient `EOFError` directement : le prompt de chemin dans `prompt_path()` (ligne 104), la confirmation `[y/N]` move-logs dans la branche change-location (ligne 360), et la confirmation `[y/N]` delete-all (ligne 378). Tous les autres sites de lecture interactive du codebase passent par `bob._tty.read_line` qui mappe déjà `EOFError` à chaîne vide. Ctrl-D à n'importe lequel de ces trois prompts dumpait une traceback Python à l'utilisateur.

Fix : wrap chaque `input()` dans `try/except EOFError` alignant sur la convention `_rl()` — EOF traité comme chaîne vide, qui fall through à "use default" pour le path prompt et "no" pour les confirmations. `KeyboardInterrupt` non catché délibérément (l'exit Python 130 par défaut est correct).

**I-3 — `apply_cron_schedule` non atomique**

Vit dans `bob/cron.py` (techniquement hors scope strict du TUI) mais le flow d'édition cron curses est son appelant principal via `_apply_cron_schedule` (`bob/tui/cron.py:135`). La fonction faisait :

```python
fd = os.open(str(entry.cron_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
with os.fdopen(fd, "w") as fh:
    fh.write(new_text)
```

Coupure de courant, `SIGKILL`, ou crash de process entre `open(O_TRUNC)` et `write` laisserait le fichier cron vide. `cron` et `crond` drop ensuite silencieusement l'entrée — aucun warning, aucune notification d'échec, l'audit planifié arrête juste de tourner. Asymétrique avec la sœur `apply_cron_email` qui utilisait déjà `_atomic_write` (introduit en v0.5.5 #C-1).

Fix : switch vers `_atomic_write(entry.cron_path, new_text, mode=0o640)`. Mode `0o640` préservé (cron skip les fichiers avec mauvais mode). Changement d'une ligne ; les tests `TestApplyCronSchedule` existants passent toujours.

### Mineur (3 shippés + 5 déférés v0.5.8)

| # | Statut | Fix |
|---|---|---|
| **M-1** | shippé | Status `manage_logs.deleted_one` flashait `pending_delete[0].name` même quand l'index 0 échouait au unlink (permission denied) et qu'un autre index réussissait — nom affiché ne matchait pas la deletion. Traque maintenant le PREMIER nom effectivement supprimé |
| **M-3** | shippé | Dead-code elif body dans `_curses_edit_sub` (`if ch_i == ord("1"): chosen = 0 elif ord("2"): chosen = 1` — garde déjà constrained `chosen == sel`). Simplifié à `chosen = sel` unique, elif réécrite avec parenthèses explicites |
| **M-4** | shippé | `from bob.cron import apply_cron_schedule, apply_cron_email` dupliqué à ligne 132 (après un commentaire section) consolidé dans le bloc d'import principal au top. Commentaire section nettoyé |
| **M-2** | déféré v0.5.8 | Cursor shift après delete suppose toutes les suppressions sont avant le cursor — cosmétique |
| **M-5** | déféré v0.5.8 | Constantes wizard schedule scoped-locales (`_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4`) → promote à `IntEnum` module-level |
| **M-6** | déféré v0.5.8 | `_extract_summary_view` `summary_start` falsy check rate l'index 0 (unreachable en pratique ; sentinelle `None` serait plus propre) |
| **M-7** | déféré v0.5.8 | Groupement des lignes de continuation dans `_extract_summary_view` over-greedy — avale n'importe quelle ligne indentée 4-espaces. Artifact layout-only |
| **M-8** | déféré v0.5.8 | `from datetime import datetime` local dans le block de build cron — remonter au top |

### Observations cross-cutting (informationnel, pas des findings)

- **Aucune vulnérabilité de comparaison `datetime.now()`** trouvée à travers les 1920 LoC de scope — un seul site `datetime.now()` existe (génération du timestamp header cron, pas de comparaison). La classe de bug v0.5.6 #I-2 est contenue à `logs.py`.
- **Aucun `os.system`, `shell=True`, ou appel subprocess non sanitisé** dans aucun des deux modules. La génération cron dans `bob/cron.py::build_script_content` utilise déjà `shlex.quote` pour tous les champs contrôlés par l'utilisateur (notify_email, log_dir, audit_bin, bob_path).
- **Aucun path-traversal** — `prompt_path` appelle `_resolve_path` qui fait `Path(raw).expanduser().resolve()` (normalise `..`, suit symlinks une fois).
- **`raw_name` ne peut pas injecter de lignes crontab** malgré être écrit verbatim dans le commentaire header cron `# name: {raw_name}` : `_curses_readline` filtre `\n`/`\r`/`\t` (< 32), et le paste terminal collapse l'input multi-ligne en single-ligne.

### Lignée des classes de bugs

- **I-3** mirror **v0.5.5 #C-1** (régression mode `_atomic_write`) et **v0.5.5 #I-1** (enforcement mode 0o600 pour `recurrence.py` / `ignore.py`) — l'enforcement du contrat atomic-write est maintenant uniforme à travers toutes les mutations de fichiers dans le codebase.
- **I-2** mirror **v0.5.5 #C-2/C-3** (UX défensive) — la gestion Ctrl-D / Ctrl-C est maintenant uniforme à travers tous les sites de lecture interactive (`_rl`, `prompt_path`, deux prompts de confirmation).

### Couverture tests

- `tests/test_cron.py` : +6 tests (`TestApplyCronScheduleAtomic`, `TestIsPrintableInputChar`)
- `tests/test_manage_logs.py` : +5 tests (`TestEOFErrorOnPromptPath`, `TestEOFErrorOnMoveConfirm`, `TestEOFErrorOnDeleteAllConfirm`, `TestDeletedOneCorrectName`)
- 4560 → **4571 tests** (+11)

### Ce qui N'EST PAS dans cette release

- Les 5 mineurs déférés (M-2, M-5, M-6, M-7, M-8) — explicitement trackés pour v0.5.8
- Aucun changement man-page (keybindings TUI inchangés)
- Aucun changement locale (pas de churn de strings user-facing)
- Aucun changement `bob/data/services.json`
- Aucun changement score-engine
- Aucune nouvelle API publique

### Roadmap

Après v0.5.7, la branche v0.5.x a été deeply auditée end-to-end (22 core modules en v0.5.5 + `checks/logs.py` en v0.5.6 + les 2 modules TUI curses en v0.5.7 = 25 modules deep-audit + ~25 autres spot-check). v0.5.8 clearera les 5 minors TUI déférés. Le prochain cap de version mineure (v0.6.0) est réservé pour #13 (split `ssh.py` 1324 LoC) et #14 (split `cron.py` 1223 LoC), les deux refactors architecturaux délibérément déférés du roadmap v0.5.x.

---

## [v0.5.6] — 24-05-2026

**Passe de hardening ciblée sur `bob/checks/logs.py`.** L'audit v0.5.5 avait explicitement déféré ce module ("not deeply audited") à cause de sa densité regex — parser UFW logs + fallback systemd-journald + intégration GeoIP2 + détection bruteforce en 662 LoC. Un audit sub-agent focalisé a produit 10 findings : 0 critique, 2 important, 8 mineur. Tous shippent dans cette release single-module.

### Important (2)

**I-1 — Regex `_PRIVATE_IP` incohérente avec `sysinfo.py`**

La regex hand-rolled `^(10\.|172\.…|192\.168\.|127\.|::1$|fc|fd)` avait trois problèmes vs les helpers canoniques `sysinfo._is_private_or_loopback_ipv4/_ipv6` (réécrits en v0.5.5 #I-4) :
- **Manquait CGNAT** (`100.64.0.0/10`, RFC 6598) — sources derrière NAT carrier-grade subissaient GeoIP-lookup au lieu d'être labellées "local"
- **Manquait IPv6 link-local** (`fe80::/10`) — bruit IoT local mal-classifié comme public
- **Faux positif sur n'importe quel string commençant `fc`/`fd`** — ex. `"fcsa"`, `"fdgarbage"` matchaient comme "local" (lucky harmless aujourd'hui car le champ SRC est toujours une IP, mais incohérent avec le modèle)

Même classe de finding que v0.5.5 #I-4 (`sysinfo._PRIVATE_IPV4_RE`). Fix : nouvel helper `_is_private_ip(ip)` dans `logs.py` dispatch via `:` et délègue à `sysinfo._is_private_or_loopback_ipv4/_ipv6`. Source unique de vérité dans le codebase.

**I-2 — Year-rollover droppait événements syslog quasi-temps-réel**

`_parse_timestamp` fallback à `current_year` pour format syslog (pas d'année dans la ligne). L'heuristique de rollback était :
```python
if ts > datetime.now():
    ts = ts.replace(year=ts.year - 1)
```

Un événement syslog timestampé `12:00:01` parsé à wall-clock `12:00:00` (1s en avance pour cause de jitter NTP / flush log buffer / clock skew) était roll-backé une année entière → tombait hors `cutoff_dt = now - timedelta(days=log_days)` → **silencieusement droppé**. Impact réel sur systèmes occupés avec hauts taux UFW BLOCK.

Bug subtil bonus : `current_year` et `datetime.now()` sont appelés à différents moments dans la boucle parse, donc la décision year-rollover pourrait disagree avec `current_year` si le parse traverse minuit 31 décembre.

Fix : snapshot `now` une fois en début de `_parse_log`, passe-le à `_parse_timestamp`, et utilise `if ts > now + timedelta(minutes=5)` pour absorber le skew tout en attrapant les vraies entrées year-end Décembre parsées en Janvier.

### Mineurs (8)

| # | Fix |
|---|---|
| **M-1** | Matcher anchored `r"\[UFW BLOCK6?\]"` — accepte la variante IPv6 `[UFW BLOCK6]` (silencieusement droppée pre-v0.5.6) et rejette le spoofing par substring |
| **M-2** | Regex `_count_available_days` restreinte aux noms de mois anglais — était inflated par des tokens leading non-date (ex. `"mai 23"`, noms de facility kernel boot) |
| **M-3** | `_GEOIP2_DB_PATHS` réordonné : toutes les entrées City d'abord sur tous les dirs, puis toutes les Country — `_geo_via_geoip2` retourne au premier hit, donc City gagne toujours les données plus riches quand les deux DB existent |
| **M-4** | `geoip2_status()` accepte maintenant les symlinks (`Path.resolve(strict=True)`) — matche `_geo_via_geoip2` qui le fait déjà. Fix la notice contradictoire "no database installed" sur setups `geoipupdate` utilisant symlinks |
| **M-5** | `_GEO_CACHE` borné à 2048 entrées avec éviction FIFO via helper `_geo_cache_put()` — prévient la croissance non-bornée chez les embedders long-lived |
| **M-6** | `LogsSnapshot.from_system` lit en mode binaire (`open("rb")` + `.decode("utf-8", errors="ignore")`) — `TextIOBase.tell()` retourne un nombre opaque selon la doc ; l'arithmétique byte-offset marchait par accident sur CPython |
| **M-7** | `except (OSError, subprocess.SubprocessError)` — drop le `subprocess.TimeoutExpired` redondant (sous-classe de SubprocessError) |
| **M-8** | `proto.upper()` au parse-time — un UFW patché downstream émettant `proto` lowercase splitterait silencieusement une campagne bruteforce en deux sous-groupes sous threshold |

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4560 passed in ~6s
```

**4545 → 4560 (+15).** Nouvelles classes dans `tests/test_logs.py` :
- `TestPrivateIPDispatch` (8 tests) — pin CGNAT, IPv6 link-local, ULA, IPv4 public, edge cases string invalide (I-1)
- `TestParseTimestampYearRollover` (3 tests) — current-year, 1s-skew, vraie rollback Décembre (I-2)
- `TestBlockPrefixMatcher` (3 tests) — `[UFW BLOCK]`, `[UFW BLOCK6]`, rejet `[UFW ALLOW]` (M-1)
- `TestProtoNormalisation` (1 test) — proto lowercase upper-case au parse (M-8)

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS — inchangés.
- **Sortie wire** : inchangée sur configs UFW standard. Delta visible seulement sur :
  - Hosts émettant `[UFW BLOCK6]` (précédemment silencieusement droppés — maintenant comptés dans `total` et `top_ips`)
  - Hosts avec contenu syslog locale mixte (précédemment inflated `days_available` — maintenant exact)
- **API externe** : `_is_private_ip(ip)` est un nouveau helper semi-public. Constante `_PRIVATE_IP` retirée (non documentée ; un downstream `pipx`-installed user pourrait l'importer — unlikely).
- **Score par domaine** : inchangé. Score global inchangé.
- **i18n** : aucun changement clé locale.

### Couverture

Passe single-module : `bob/checks/logs.py` audité en intégralité. Aucun autre module touché.

Queue restante (per roadmap audit) : **v0.5.7** = `manage_logs.py` + `bob/tui/cron.py` curses TUI (~1920 LoC combinés). Après ça, la ligne v0.5.x est intégralement auditée.

---

## [v0.5.5] — 24-05-2026

**Passe de hardening — post-v0.5.4 audit par un sub-agent profond.** 4 bugs réels + 4 security smells + 11 cleanups mineurs = **19 findings** adressés (17 avec changements code/test, 2 avec commentaires doc). Commit cosmétique compagnon migre le typing `Optional[X]` / `List[X]` sur 18 modules.

### Bugs critiques (4)

**C-1 — `apply_cron_email()` cassait silencieusement les audits programmés**
`bob/cron.py:apply_cron_email()` réécrivait à la fois les cron files et les wrapper scripts via `_atomic_write()`, qui ouvrait toujours le fichier temp avec mode `0o600`. Après `os.replace()`, le nouveau fichier héritait de ce mode — donc le wrapper script (originellement `0o755`) perdait son bit exécutable. Cron continuait à lire le cron file mais **ne pouvait plus exec le script**, et l'audit programmé ne tournait plus silencieusement. N'importe qui ayant utilisé `bob --manage-cron` pour changer son email de notification entrait dans cet état.

`_atomic_write(path, content, mode=0o600)` prend maintenant un mode explicite. Les callers dans `apply_cron_email` passent `0o640` (cron file) et `0o755` (script). Test régression ajouté dans `tests/test_cron.py::TestApplyCronEmail::test_preserves_script_executable_mode`.

**C-2 — `password_policy.no_quality_module` cmd non-fixable**
`cmd="sudo apt install libpam-pwquality && sudo pam-auth-update"` émis avec `nature="action"` → `--fix --apply` le rejetait via `fixes._has_shell_ops` (le `&&` est correctement flaggé comme syntaxe shell unsafe). L'utilisateur voyait le cmd dans le summary mais presser `y` ne faisait rien.

Fix : demotion à `nature="improvement"`. Le cmd apparaît toujours dans la sortie audit comme guidance — il n'entre simplement pas dans la queue fix-mode. `apt install … && pam-auth-update` 2-étapes n'est de toute façon pas chainable en un seul exec.

**C-3 — `password_policy.weak_minlen` cmd décoratif, pas exécutable**
`cmd="sudo nano /etc/security/pwquality.conf  →  minlen = 8"` — la flèche Unicode fait que `shlex.split` tokenise en arguments junk. Comme C-2, demotion à `nature="improvement"`.

**C-4 — Drift `EXPLAIN_KEYS` pour `services_state`**
`bob/checks/services_state.py` émet des findings avec `key="services_state.service_inactive"`, mais `EXPLAIN_KEYS` (dans `bob/explain.py`) déclarait le nom canonique `services_state.enabled_inactive`. `bob --explain services_state.service_inactive` retournait "key not found".

Fix : ajout de `"services_state.service_inactive": "services_state.enabled_inactive"` à `EXPLAIN_KEY_ALIASES`. Le contrat JSON output est préservé (émet toujours `service_inactive`), et les lookups `--explain` résolvent via l'alias. Option (b) plutôt que (a) (renommer la clé émise aurait été un breaking change JSON output — réservé pour v0.6.0).

### Important issues (4)

**I-1 — `recurrence.json` + `ignore.yml` écrits avec umask par défaut**
Les deux fichiers s'appuyaient sur l'umask process (typiquement `0o644` sur Debian/Ubuntu — world-readable). Tous les autres fichiers state persistants dans BOB (`config.conf`, rapports audit, historique score) s'ouvrent avec un `0o600` explicite. Corrigés tous deux pour utiliser `os.open(..., 0o600)` + `os.fdopen()`.

**I-2 — `_apply_deduction` bypassait le cap de score après `finalize()`**
Le contrat orchestrateur est one-way : `finalize()` bake-in le cap puis set `_finalized=True`. Un `engine.apply(result)` tardif muterait `_raw_score` après que le cap était appliqué — bypassant silencieusement. Ajout d'un guard défensif avec log WARNING ; la déduction est jetée.

**I-3 — `_safe_url` permettait injection `"` dans HTML email attribut href**
Le pipeline html-escape le texte d'abord (avec `quote=False` par défaut), puis re-substitue `[label](url)` en `<a href="url">label</a>`. L'URL était insérée dans le contexte attribut sans re-escape — un `[label](https://x.com" onclick="alert(1))` craft pouvait sortir du href. `_safe_url` appelle maintenant `html.escape(url, quote=True)` pour encoder `"`/`'`/`<`/`>`.

Surface d'attaque réaliste étroite (un plugin `services.d/*.json` malveillant émettant des markdown links avec strings craftés, rendu dans le mail client de l'utilisateur) mais le fix est cheap et le rapport email est désormais XSS-safe garanti.

**I-4 — `sysinfo._PRIVATE_IPV4_RE` brittle + cassure Python 3.12+**
Deux problèmes : (1) le call site ligne 192 faisait `re.search(r"via\s+" + _PRIVATE_IPV4_RE.pattern.removeprefix("^"), …)` — manipulant l'attribut `.pattern` d'un pattern compilé et droppant les flags ; (2) `ipaddress.IPv4Address.is_private` a été élargi en Python 3.12.4+ pour inclure documentation/reserved ranges comme `203.0.113.0/24`, donc un switch naïf vers stdlib mal-classifierait ces ranges comme "private" et casserait `detect_network_context()`.

Fix : tuples explicites `_PRIVATE_IPV4_NETS` + `_PRIVATE_IPV6_NETS` d'objets `ipaddress.ip_network`, avec helpers `_is_private_or_loopback_ipv4()` / `_is_private_or_loopback_ipv6()` utilisant l'appartenance `addr in net`. Couvre RFC 1918, loopback (127/8 + ::1), link-local (169.254/16 + fe80::/10), CGNAT (100.64/10), et ULA IPv6 (fc00::/7). Les ranges documentation restent "public" donc ne déclenchent pas le contexte "local".

### Cleanups mineurs (11)

| # | Fix | Fichiers |
|---|---|---|
| **M-1** | Regex email unifiée via `bob.config._EMAIL_RE` (dupliquée 3×) | `bob/cron.py` |
| **M-2** | `bob/watch.py:_NullReport` retiré → use `bob.report.NullReport` (Report Protocol de v0.5.0 #10) | `bob/watch.py`, `tests/test_watch.py` |
| **M-3** | 3 clés locale mortes retirées : `_meta.lang`, `_meta.version`, `ignored.hint` | `bob/locales/{en,fr}.json`, `tests/test_ignore.py` |
| **M-4** | Règle `corr.fully_blind` élargie : fail2ban-stoppé ou auditd-stoppé qualifient comme "aveugle" (était asymétrique — fire seulement si les deux layers complètement absents) | `bob/correlation.py`, `tests/test_correlation.py` |
| **M-7** | Extraction helper `_has_actionable_findings()` dans `updates.py` (remplace le filter inline fragile `f.key != "updates.apt_cache_age"`) + frozenset `_TRANSPARENCY_KEYS` future-proof | `bob/checks/updates.py` |
| **M-8** | Commentaire seul — clarifie pourquoi `_parse_config_file` s'arrête aux Match blocks (skippe aussi les Include suivants, intentionnel) | `bob/checks/ssh.py` |
| **M-9** | Commentaire seul — clarifie que les champs vides `ListeningPort.process`/`iface` veulent dire "inconnu" pas "pas de processus" (quand `ss -p` manque le privilège) | `bob/checks/ports.py` |
| **M-10** | Regex `apply_cron_schedule` resserrée : premier champ doit être un cron-token (`[0-9*,\-/]…`) pour que les comment lines commençant par `#` ne soient pas matchées | `bob/cron.py`, `tests/test_cron.py` |
| **M-11** | Cmd `services_state.service_inactive` : drop du chain shell `&& sudo journalctl …` (déplacé en `note=` guidance) pour que `--fix --apply` l'accepte | `bob/checks/services_state.py` |

### M-6 (commit séparé) — `Optional[X]` / `List[X]` → `X | None` / `list[X]`

Sweep mécanique sur 18 modules. Syntaxe Python 3.10+. Pur cosmétique, zéro changement de comportement. Commit isolé pour revert-chirurgical-sur-typo safety.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4545 passed in ~7s
```

**4538 → 4545 (+7).** Couverture régression pour C-1 (mode cron), C-2 + C-3 (assertion `nature`), C-4 (résolution alias), I-2 (guard post-finalize), I-3 (XSS attr-escape, 9 tests dans le nouveau `tests/test_report_markdown_safety.py`), M-4 (fail2ban-seul aveugle), M-10 (comment-line cron skippée). 8 tests supprimés (magic `_NullReport.__getattr__` obsolète de M-2, test mort `ignored.hint` de M-3). 2 tests renommés pour clarté (`test_nature_is_action` → `test_nature_is_improvement` sur `password_policy`).

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS — **inchangés**. C-4 utilise `EXPLAIN_KEY_ALIASES` (additif) pour préserver la clé émise tout en routant `--explain` vers le nom canonique.
- **Sortie wire** : Delta visible sur hosts sans `pam_pwquality` installé — le finding password_policy passe de "À corriger" (action) à "Améliorations possibles" (improvement) dans le summary box. Score global inchangé.
- **i18n** : 3 clés retirées (`_meta.lang`, `_meta.version`, `ignored.hint`). Test locale-coverage toujours vert.
- **API externe** : aucun breaking change. `prompt_wizard` (v0.5.4 #6) et `_atomic_write` (prend maintenant `mode`) gagnent des paramètres optionnels.

---

## [v0.5.4] — 22-05-2026

**Refactor v0.5.x — Phase 5 sur 5 (finale).** Trois findings d'audit clôturés (`#6`, `#9`, `#15b`) + une feature métier demandée par l'utilisateur (cache APT option C). Deux findings (`#13` split ssh.py, `#14` split cron.py) explicitement déférés à v0.6.0.

### #6 — Helper `prompt_wizard()` pour wizards plain-text

`bob/_tty.py` expose un nouveau helper `prompt_wizard(label, *, default="")` qui wrappe `input()` avec le boilerplate wizard-step que chaque wizard plain-text devait répéter :

```python
def prompt_wizard(label: str, *, default: str = "") -> "str | None":
    """Prompt wizard plain-text avec gestion uniforme cancel + default.

    Retourne :
        None — l'utilisateur a tapé 'q' ou 'quit' (case-insensitive).
        str  — input trimmé, ou default si Enter pressé tout seul.
    """
    raw = input(label).strip()
    if raw.lower() in ("q", "quit"):
        return None
    return raw or default
```

10 sites migrés dans `bob/cron.py` :

- `_run_install_cron_plain()` (5 sites) : name, schedule type, weekdays, monthdays, custom expr, time
- `edit_cron_schedule()` (4 sites) : weekdays, monthdays, custom expr, time
- (le prompt schedule-type dans `edit_cron_schedule` garde `read_line()` pour le support raw-mode Esc — asymétrie intentionnelle entre les deux wizards)

Les prompts de confirmation oui/non (4 sites dans `prompt_emails`, 1 dans install_cron overwrite, 1 dans email_store_enter) NE SONT PAS migrés — ils ne fittent pas la sémantique `default-on-Enter` de `prompt_wizard` (ils ont besoin d'un `y` explicite vs n'importe quoi d'autre).

### #9 — Sunset env var `UFW_AUDIT_SHARE`

`bob/_paths.py:resolve_share_dir()` loggait précédemment un `INFO` quand seule la legacy env var `UFW_AUDIT_SHARE` était set (sans `BOB_SHARE`). Le message disait poliment "the legacy name will be dropped in a future major release" sans s'engager sur une version.

v0.5.4 s'engage sur une version de sunset :

- Niveau bumpé `logger.info(...)` → `logger.warning(...)`
- Message réécrit : "Using legacy env var %s — DEPRECATED since v0.5.4, will be REMOVED in v0.6.0. Update your installer to %s …"
- Docstring du module mise à jour pour matcher.

`SECURITY.md` / `SECURITY_FR.md` (mis à jour en v0.5.3) déclaraient déjà la matrice de support indiquant que v0.4.x est end-of-life. Les packagers qui voient le warning ont un timeline clair pour mettre à jour leurs scripts d'installation.

### #15b — Mapping `_PREFIX_TO_DOMAIN` explicite (re-attribution medium-risk)

`bob/domain_scores.py:_PREFIX_TO_DOMAIN` gagne trois nouvelles entrées explicites qui étaient précédemment des fallbacks silencieux vers le domaine catch-all `firewall` :

| Prefix | Avant (catch-all) | Après (explicite) | Raison |
|---|---|---|---|
| `fail2ban` | firewall | **ssh** | Vocation primaire : anti-bruteforce SSH — la plupart des jails ciblent le jail sshd |
| `virt` | firewall | **hardening** | Bridge KVM/libvirt peut insérer des règles iptables bypassant UFW FORWARD — c'est une préoccupation surface d'attaque kernel/système, pas une config firewall |
| `docker_audit` | firewall | **hardening** | Durcissement container (setting iptables=false dans daemon.json, audit container actifs) est hardening système, pas surface réseau |

`smtp` et `desktop_apps` restent dans le catch-all firewall : pas de fit propre (smtp local a quelques sémantiques firewall ; desktop_apps est inventaire INFO-only).

Impact score par domaine : sur hosts émettant des findings sous ces prefixes, le breakdown shifte. Le **score global est inchangé** (les déductions sont les mêmes, juste re-bucketées). Observé sur le host dev : virt.bypass_risk WARN déplacé de `Pare-feu & Services` (3/10 → 10/10 avec autre clean-up intra-firewall) à `Durcissement` (6/10 → 5/10).

`tests/test_domain_scores_mapping_complete.py:_CATCH_ALL_BY_DESIGN` mis à jour pour retirer les 3 entrées migrées ; les `smtp` / `desktop_apps` / `prerequisites` restants ont leurs justifications rafraîchies (plus "review in v0.5.4" — c'est fait).

### Cache APT option C — INFO permanent sur l'âge du cache

Feature métier demandée par l'utilisateur. Surface l'âge du cache APT quand l'audit rapporte "système à jour" pour que l'utilisateur sache si ce verdict reflète une lecture fraîche ou un snapshot obsolète :

```python
if (
    cache_age is not None
    and not security
    and not regular
    and cache_age * 86400 < _APT_CACHE_STALE_THRESHOLD
):
    result.info(
        message=_t("updates.apt_cache_age", days=cache_age),
        detail=_t("updates.apt_cache_age_detail"),
        key="updates.apt_cache_age",
    )
```

Déclenché quand :
- APT disponible
- Aucun paquet de sécurité en attente
- Aucun paquet régulier en attente
- Âge du cache connu
- Âge du cache sous le seuil obsolète de 7 jours (le WARNING stale-cache couvre déjà le cas > 7 jours ; cet INFO couvre la zone silencieuse "frais-assez-mais-pas-zéro")

Nouvelles clés locale (EN + FR) :
- `updates.apt_cache_age` : "Âge du cache APT : {days} jour(s) — `sudo apt update` pour une lecture plus fraîche"
- `updates.apt_cache_age_detail` : explique que BOB est read-only par conception, pointe vers unattended-upgrades.

Remonté par le test terrain VM Ubuntu du 2026-05-22 où une VM dormante retournait "à jour" malgré 8 LTS security updates en attente upstream. Le cache n'était pas assez obsolète pour déclencher le WARNING `apt_cache_stale` (< 7 jours), mais assez vieux pour être désynchronisé de l'upstream. Le nouvel INFO ferme ce gap d'observabilité.

### Deferrals : `#13` (split ssh.py) et `#14` (split cron.py) → v0.6.0

L'audit v0.5.x original (2026-05-21) flagged les deux fichiers comme candidats au split :
- `ssh.py` : 1387 LoC à l'audit. Cible < 1000 après Phases 2 + 3. Réalité fin v0.5.x : **1324 LoC** (cible ratée de 32%).
- `cron.py` : 1223 LoC à l'audit. Reste à **1223 LoC** fin v0.5.x.

Décision : défer les deux à v0.6.0. Selon [`feedback_conservative_refactor`](memory) — splitter un fichier est medium-risk pour un gain de lecture marginal ; le faire dans une release contract-preserving ajoute du bruit sans payoff clair. v0.6.0 est l'endroit naturel : un bump majeur perturbe typiquement déjà les imports et tests, donc le split land aux côtés d'autres shifts structurels.

La couverture de test `#15a` (ajoutée en v0.5.0) pin toujours tous les prefixes de clé actuels contre `_PREFIX_TO_DOMAIN` et `_CATCH_ALL_BY_DESIGN` ; quelle que soit la décision du split en v0.6.0, le test attrapera les prefixes non gérés avant qu'ils régressent.

### Diff net

| Fichier | Delta | Notes |
|---|---|---|
| `bob/_tty.py` | +24 | `prompt_wizard()` + réécriture docstring |
| `bob/cron.py` | +1 | 10 sites `input()` migrés vers `prompt_wizard` |
| `bob/checks/updates.py` | +20 | Logique cache APT option C + commentaires |
| `bob/domain_scores.py` | +10 | 3 nouvelles entrées dans `_PREFIX_TO_DOMAIN` + bloc de commentaire 6 lignes |
| `bob/_paths.py` | +5 | bump log level + message DEPRECATED + update docstring |
| `bob/locales/{en,fr}.json` | +4 | 2 nouvelles clés × 2 locales |
| `tests/test_domain_scores_mapping_complete.py` | −6 | 3 entrées retirées de `_CATCH_ALL_BY_DESIGN` + commentaires simplifiés |

**Net +49 LoC sur 12 fichiers code.** Tous les changements sont contract-preserving (pas de nouveau domaine de score, pas de nouveau finding level, pas de breaking signature). La sortie wire gagne 1 nouvelle ligne INFO sur les hosts idle (cache APT C) et reshuffle les scores par domaine sur hosts avec findings `fail2ban.*` / `virt.*` / `docker_audit.*` — le **score global est inchangé**.

### Clôture audit v0.5.x : 13/15 findings shippés, 2 déférés

| # | Phase | Outcome |
|---|---|---|
| #1 | v0.5.1 | `warn_with_deduction()` / `alert_with_deduction()` — 120 sites |
| #2 | v0.5.0 | `print_titled_box()` — 4 sites + fix leak `--no-color` |
| #3 | v0.5.2 | `_sec()` skip_if= / post_display= — 4 sites |
| #4 | v0.5.2 | Table `_BAD_DIRECTIVES` pour sshd_config — 8 directives |
| #5 | v0.5.3 | Table `_LEVEL_DISPATCH` pour `display_result` |
| #6 | **v0.5.4** | Helper `prompt_wizard()` — 10 sites dans cron.py |
| #7 | v0.5.0 | `is_unit_active()` / `is_unit_enabled()` — 9 sites |
| #8 | v0.5.3 | Escape hatch `CheckResult.log_data` retiré — retour tuple |
| #9 | **v0.5.4** | Sunset `UFW_AUDIT_SHARE` (REMOVED en v0.6.0) |
| #10 | v0.5.0 | `bob.report.Report` `typing.Protocol` |
| #11 | v0.5.0 | `emit_section()` / `emit_group()` — 20 sites |
| #12 | v0.5.3 | Split `print_audit_summary` en 3 helpers |
| #13 | **déféré v0.6.0** | Split ssh.py (1324 LoC) |
| #14 | **déféré v0.6.0** | Split cron.py (1223 LoC) |
| #15a | v0.5.0 | Scan AST `test_domain_scores_mapping_complete.py` |
| #15b | **v0.5.4** | Mapping `_PREFIX_TO_DOMAIN` explicite pour `fail2ban` / `virt` / `docker_audit` |

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (inchangé).** Phase 5 est contract-preserving — tous les changements sont soit extraction d'helper interne (#6), soit raffinements display-only (cache APT C, re-bucketing #15b), soit messaging log non-fonctionnel (#9).

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS — **inchangés**.
- **Score par domaine** : re-bucketé sur hosts avec findings `fail2ban.*` / `virt.*` / `docker_audit.*`. **Score global inchangé.**
- **Sortie wire** : 1 nouvelle ligne INFO sur hosts idle (cache APT C). Reshuffle du breakdown par domaine quand les prefixes `#15b` sont émis. WARNING sur hosts utilisant la legacy `UFW_AUDIT_SHARE` (était INFO).
- **API externe** : aucun breaking change.
- **i18n** : 2 nouvelles clés locale (`updates.apt_cache_age` + `..._detail`) en EN + FR.

---

## [v0.5.3] — 22-05-2026

**Refactor v0.5.x — Phase 4 sur 5.** Trois findings d'audit : **#5 table de dispatch**, **#12 helpers summary**, **#8 retrait escape hatch `log_data`**. Aucun changement de comportement — 4538/4538 tests inchangés, sortie wire bit-identique à v0.5.2.

### #5 — Table `_LEVEL_DISPATCH` pour `display_result`

`display_result()` dans `bob/display.py` avait une cascade 4-branches OK/WARN/ALERT/INFO. Chaque branche répétait le même pattern (écrire dans le rapport, vérifier le threshold, imprimer le message, optionnellement imprimer récurrence/détail/cmd/note/CIS) avec des variations subtiles par niveau qui avaient dérivé au fil du temps.

Nouvelle dataclass frozen `_LevelTraits` + table 4-lignes exprime chaque variation comme un trait booléen :

```python
@dataclass(frozen=True)
class _LevelTraits:
    report_label:         str
    threshold_key:        str
    print_fn:             Callable[[str], None]
    has_recurrence:       bool
    has_body:             bool
    detail_unconditional: bool   # ALERT uniquement : imprime détail sans --verbose
    show_note:            bool   # ALERT uniquement
    show_cis:             bool   # WARN + ALERT
```

Le trait unique qui capture la spécificité d'ALERT (détail imprimé même sans `--verbose`) est `detail_unconditional=True`, remplaçant un branchement opaque `elif detail: print_recommendation(detail)` qui vivait sous la chaîne `if finding.cmd and verbose:`. `_emit_finding_body()` est un nouveau helper module-level qui consomme les traits.

### #12 — Split `print_audit_summary` en 3 helpers

La fonction `print_audit_summary()` de 142 lignes mélangeait trois responsabilités (lignes header, lignes finding blocks, lignes breakdown) avec une closure interne `_add_finding_lines()`. Désormais :

- `_summary_header_lines(engine, network_context, config, t, profile_name, prev_score)` — lignes score/niveau/réseau/profil/target + la flèche de tendance de score.
- `_summary_findings_lines(engine, t, inner)` — blocs action + improvement (avec la ligne de disclaimer).
- `_summary_breakdown_lines(engine, t, inner)` — déductions + cap_info.
- `_add_finding_lines(icon_prefix, item, inner)` — promu d'inner closure à helper module-level, retourne une liste de tuples `(content, val)` au lieu de muter la liste `lines` englobante.

`print_audit_summary` devient un assembleur 3 lignes `lines.extend(...)`, puis `print_summary_box(lines)`, puis le footer (ligne verdict + implicit_svcs + scope lines + `report.write_summary()`).

Side-fix : le `report.write_summary(score=score, risk_level=level_str, network_context=ctx_str, ...)` original référençait des variables locales qui n'étaient plus dans la portée après l'extraction du header. Remplacé par des expressions directes sur `engine.score` et re-évaluation `t(f"scoring.level.{engine.level.value}")` / `t(f"scoring.context.{network_context}")`.

### #8 — Escape hatch `CheckResult.log_data` supprimé

`CheckResult` avait un champ `log_data: dict | None = field(default=None)` utilisé uniquement par `bob/checks/logs.py` pour attacher des agrégations structurées (top IPs, top ports, brute hits, svc hits) à afficher par l'orchestrateur. Non typé, mono-usage, et indistinguable du flux normal des findings dans la surface dataclass.

Remplacé par :

- Nouvelle dataclass frozen `LogReportData` dans `bob/checks/logs.py` :
  ```python
  @dataclass(frozen=True)
  class LogReportData:
      log_days:       int
      days_available: int
      total:          int
      brute_hits:     list[BruteforceHit]
      top_ips:        list[tuple[str, int]]
      top_ports:      list[tuple[str, int]]
      svc_hits:       dict[str, int]
  ```
- `check_logs(...)` retourne maintenant `tuple[CheckResult, LogReportData | None]`. `None` quand aucun log file trouvé ou log vide (le result porte toujours un finding info/ok).
- `bob/runner.py:408` unpacke le tuple : `logs_result, logs_report = check_logs(...)`.
- `display_log_results(logs_result, snapshot, log_report, config, t, report)` — `log_report` est maintenant un arg positionnel explicite au lieu d'être lu depuis `logs_result.log_data`.
- Champ `CheckResult.log_data` supprimé de `bob/scoring.py`.

Test churn : 3 tests renommés (`test_log_data_attached` → `test_report_data_attached`, `test_top_ips_in_log_data` → `test_top_ips_in_report_data`, `test_service_hits_in_log_data` → `test_service_hits_in_report_data`) et réécrits pour lire `report_data.total` / `report_data.top_ips` / `report_data.svc_hits` au lieu d'un accès clé-dict. ~20 autres sites de tests dans `tests/test_logs.py` + `tests/test_degraded.py` utilisent `result, _ = check_logs(...)` puisqu'ils ne consultent pas le report data.

### Diff net

| Fichier | Delta | Notes |
|---|---|---|
| `bob/display.py` | +23 | `_LevelTraits` + `_emit_finding_body` + 3 helpers summary + `_add_finding_lines` module-level |
| `bob/checks/logs.py` | +19 | dataclass `LogReportData` + retour tuple |
| `bob/runner.py` | 0 | 1 ligne migrée à l'unpack tuple |
| `bob/scoring.py` | −1 | champ `log_data` retiré |
| `tests/test_logs.py` + `tests/test_degraded.py` | +3 | unpack tuple + 3 tests renommés |

**Net +40 LoC.** Comme les Phases 2–3, le delta LoC seul sous-vend le gain structurel : la cascade 4-branches du display devient une boucle déclarative unique, la fonction summary de 142 lignes devient un assembleur 3 lignes, et l'escape hatch `dict | None` est remplacé par une dataclass typée frozen.

### #13 / #14 / #15b toujours déférés à Phase 5

ssh.py atteint 1324 LoC à l'entrée v0.5.3, inchangé depuis v0.5.2. cron.py + ré-attribution `_PREFIX_TO_DOMAIN` non touchés en Phase 4. Les trois décisions restent dans la queue pour v0.5.4 avec re-check `wc -l` explicite.

### Garde-fou diff observable

Snapshots `sudo python3 -m bob -v --french -n` et `sudo python3 -m bob --format=json --french` capturés avant l'implémentation Phase 4, diffés aux milestones intermédiaire (#5 + #12) et final (#5 + #12 + #8). Tous les deltas confinés à la dérive d'état (timestamps, compteurs blocks UFW, ports TCP éphémères VSCode, âge rkhunter). Zéro changement structurel sur l'audit rendu, l'arbre JSON, ou le breakdown du score.

---

## [v0.5.2] — 22-05-2026

**Refactor v0.5.x — Phase 3 sur 5.** Deux findings d'audit (#4 table directive SSH + #3 callbacks `runner._sec`). Aucun changement de comportement — 4538/4538 tests inchangés, sortie wire bit-identique à v0.5.1.

### #4 — Table `_BAD_DIRECTIVES` pour `sshd_config`

`_check_sshd_config` avait ~9 blocs `if` quasi-identiques : lecture directive depuis `cfg.get()`, comparaison contre une enum "mauvaise", émission finding + déduction avec points/clé/nature fixes. Maintenant collapsé en table déclarative.

Nouveau dans `bob/checks/ssh.py` :

```python
@dataclass(frozen=True)
class _BadDirective:
    name: str          # clé cfg (lowercase)
    default: str       # valeur par défaut si absent
    level: str         # "warn" ou "alert"
    key: str           # clé i18n
    points: int
    bad_values: tuple[str, ...] = ()    # valeurs qui déclenchent le finding
    safe_values: tuple[str, ...] = ()   # alternative : tout ce qui n'est pas dans ce set est mauvais
    nature: str = ""
    detail_key: str = ""
```

`bad_values` et `safe_values` sont mutuellement exclusifs — le style `safe_values` couvre les cas comme `AllowTcpForwarding` où plusieurs valeurs (`"no"`, `"local"`) sont acceptables. Combinaisons invalides attrapées à l'instanciation par `__post_init__`.

Directives migrées (8) : `PermitEmptyPasswords`, `X11Forwarding`, `IgnoreRhosts`, `HostbasedAuthentication`, `PermitUserEnvironment`, `StrictModes`, `AllowTcpForwarding`, `PubkeyAuthentication`.

Sites gardés impératifs (5+ patterns qui ne fittent pas) :
- **`PermitRootLogin`** — branchement 4-way avec sous-états OK
- **`PasswordAuthentication`** — dépend du flag `ssh_exposed` (warn vs info)
- **`MaxAuthTries`** — seuil entier (`>3`), pas une enum
- **`LoginGraceTime`**, **`AllowUsers/AllowGroups`**, **Match block** — INFO uniquement
- **Weak Ciphers/MACs/KexAlgorithms** — logique d'intersection de set via `_check_weak_algo`

`_check_sshd_config` corps : ~180 → ~50 LoC. La dataclass + table + helper ajoutent ~130 LoC, donc ssh.py net +56. L'estimation de l'audit (-150 LoC) était trop optimiste — la verbosité des dataclass Python compense le gain de dédoublonnage. Le bénéfice est structurel (déclaratif > cascade impérative), pas LoC.

### #3 — Extension `runner._sec` avec callbacks `skip_if=` et `post_display=`

`_sec` ne savait pas gérer deux cas orthogonaux :
- **Gating conditionnel snapshot** — `if samba_snapshot.installed`, `if docker_audit.docker_installed`, `if desktop_snapshot.detected`. Forçait des blocs inline dupliquant le corps de `_sec`.
- **Appels d'affichage post-check** — `display_disk_partitions(snapshot, ...)`, etc.

Maintenant `_sec` accepte deux callbacks keyword-only :

```python
def _sec(
    section: str,
    snapshot,
    check_fn,
    *,
    skip_if=None,           # Callable[[snapshot], bool] — skip sans émettre l'en-tête
    post_display=None,      # Callable[[snapshot, result], None] — après display_result
    **check_kwargs,
) -> None: ...
```

4 blocs inline migrés :

| Section | Pattern inline | Après |
|---|---|---|
| `samba` | `if samba_snapshot.installed:` + 8 lignes | `_sec("samba", ..., skip_if=lambda s: not s.installed)` |
| `docker_audit` | `if docker_audit_snapshot.docker_installed:` + 8 lignes | `_sec("docker_audit", ..., skip_if=lambda s: not s.docker_installed)` |
| `desktop_apps` | `if desktop_snapshot.detected:` + 8 lignes | `_sec("desktop_apps", ..., skip_if=lambda s: not s.detected)` |
| `disk` | bloc `_sec`-shape + appel `display_disk_partitions` après | `_sec("disk", ..., post_display=lambda snap, _r: display_disk_partitions(snap, t, output))` |

Net runner.py : −29 LoC.

### #13 (split ssh.py) — déféré à Phase 5

La prédiction de l'audit (#4 économise ~150 LoC → ssh.py descend sous 1000 LoC → #13 inutile) ne tient pas. Phase 2 (#1) a économisé 119 LoC sur ssh.py ; Phase 3 (#4) en ajoute 56 net. ssh.py est à 1324 LoC, bien au-dessus du seuil 1000. Selon le principe [conservative-refactor](memory), splitter ssh.py est une chirurgie medium-risk — décision Phase 5 avec #14 (split cron.py) une fois l'état final connu.

### Tests

```
$ python3 -m pytest tests/ -q
4538 passed in ~6s
```

`4538 → 4538` (inchangé). #4 et #3 sont des refactors purement structurels. La suite complète `test_ssh.py` (122 tests) a passé avant, pendant et après la migration `_BAD_DIRECTIVES` — la table produit des entrées `Finding` et `Deduction` bit-identiques aux if-blocks précédents.

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, 116 EXPLAIN_KEYS, 34 sections filtrables — **inchangés**.
- **Sortie wire** : bit-identique à v0.5.1.
- **Score par domaine** : inchangé.
- **API externe** : aucun breaking change. `_BadDirective` et `_BAD_DIRECTIVES` sont module-private ; le changement de signature `_sec` est keyword-only (call sites existants inaffectés).

---

## [v0.5.1] — 21-05-2026

**Refactor v0.5.x — Phase 2 sur 5.** Le plus gros gain LoC du roadmap refactor. Audit finding #1 : l'idiom `result.warn(...) + result.add_deduction(...)` qui se répétait ~130 fois dans `bob/checks/*.py` est maintenant centralisé derrière deux méthodes helper. **Aucun changement de comportement** — les helpers composent les méthodes `warn`/`alert` et `add_deduction` existantes 1:1. Les tests restent à 4538/4538 parce que la sortie wire (findings + déductions émis par `CheckResult`) est bit-identique.

### Nouvelle API

Deux méthodes ajoutées à `CheckResult` dans `bob/scoring.py` :

```python
def warn_with_deduction(
    self,
    key: str,
    *,
    message: str,
    points: int,
    reason: str | None = None,
    context: str = "local",
    detail: str = "",
    nature: str = "improvement",
    cmd: str = "",
    cmd_type: str = "fix",
    note: str = "",
    template_vars: dict | None = None,
) -> None: ...

def alert_with_deduction(self, ...) -> None: ...   # miroir, nature default = "action"
```

L'override `reason=` gère les cas où le message du finding utilise une clé i18n et la raison de déduction utilise une variante suffixée `_reason` (ex `ssh.host_key_dsa_reason` diffère de `ssh.host_key_dsa`).

### Sites migrés (120 sur 27 fichiers)

| Fichier | Sites | Notes |
|---|---|---|
| `bob/checks/ssh.py` | 24 | Le gros morceau — directives sshd_config (PermitRootLogin, PasswordAuthentication, X11Forwarding, PermitEmptyPasswords, MaxAuthTries, IgnoreRhosts, HostbasedAuthentication, PermitUserEnvironment, StrictModes, AllowTcpForwarding, PubkeyAuthentication), clés hôte, weak algos (`_check_weak_algo`), dossier `~/.ssh`, clés privées, authorized_keys, config client, known_hosts. ssh.py : −146 lignes. |
| `bob/checks/hardening.py` | 8 | Toutes les branches sysctl : rp_filter, ICMP redirects (v4 + v6), tcp_syncookies, accept_source_route, send_redirects, protected_hardlinks, protected_symlinks. |
| `bob/checks/samba.py` | 6 | SMB1, null passwords, server signing, map_to_guest, partages invités writable/readonly. |
| `bob/checks/mac_policy.py` | 6 | AppArmor (no profiles, no enforce, inactive), SELinux (permissive, disabled), no_mac. |
| `bob/checks/clamav.py` | 5 | freshclam_missing, db_not_found, db_very_outdated, db_outdated, scan_very_old/scan_old. |
| `bob/checks/disk.py` | 5 | smart_failed, reallocated_sectors, pending_sectors, uncorrectable_errors, partition_critical. |
| `bob/checks/iptables_nftables.py` | 5 | no_backend, input_accept, no_loopback, no_conntrack, forward_accept. |
| `bob/checks/firewall.py` | 4 | duplicate_found x2 (regex + sans proto), ipv6_missing, logging_off. (5e site `open_any_found` non migré — `rule=""` ≠ `rule=clean` entre finding et reason.) |
| `bob/checks/firewall_stack.py` | 4 | iptables_bypass, iptables_forward_bypass, nftables_parallel, ip_forward_enabled. |
| `bob/checks/log_rotation.py` | 3 | logrotate_missing, journald_volatile x2 (volatile + unknown). |
| `bob/checks/auditd.py` | 3 | service_inactive, no_rules (server), missing_sensitive_rules (server). |
| `bob/checks/file_integrity.py` | 3 | no_db, no_check, check_old. |
| `bob/checks/kernel_hardening.py` | 3 | aslr_disabled, ptrace_unrestricted, suid_dump_all. |
| `bob/checks/rootkit.py` | 3 | db_outdated, no_scan, scan_old. |
| Autres fichiers | 35 | fail2ban, ntp, ddns, updates, backup, smtp, memory, network_context, cron_audit, docker_audit, kernel_modules, umask, user_accounts, password_policy, secure_boot, systemd_timers, logs, firmware, ipv6, ports, suid_audit, file_perms — chacun avec 1-2 migrations. |
| **Total** | **120** | |

### Sites volontairement non migrés (13)

Ces patterns ne fittent pas l'API 1:1 du helper :

| Cas | Fichiers | Pourquoi |
|---|---|---|
| Déduction cappée (compteur local) | `services_state` (1), `ssl_certs` (3), `file_perms` (2 sur 3), `ipv6.port_no_v6_rule` (1) | Le finding s'émet toujours ; la déduction est gardée par `if X_deductions < CAP`. Impossible de collapse en un appel helper. |
| Niveau branchant (warn OU alert) | `services.exposure` (1), `ports.uncovered_public` (1), `docker.exposed_port`/`exposed_bypass_ufw` (2) | Le choix `result.warn(...)` vs `result.alert(...)` dépend d'un champ snapshot, alors que la `add_deduction` tourne inconditionnellement après. Le helper merge niveau + déduction, donc le branching doit rester chez l'appelant. |
| Déduction conditionnelle avec prédicat différent | `docker.iptables_bypass` (1), `firewall.rules.open_any_found` (1) | La déduction a un calcul `points = 0 ou 1`, ou des `template_vars` différents entre finding (`rule=clean`) et reason (`rule=""`). |

Pour chaque skip, la recommandation de l'audit était "garde l'ancienne forme 2 appels" — respecté.

### Pourquoi c'est low-risk

- **Les helpers sont additifs sur `CheckResult`.** Les méthodes `warn`/`alert`/`add_deduction` existantes sont inchangées ; les helpers sont des wrappers fins qui les appellent en séquence.
- **Aucun changement de test requis.** Chaque test atteste toujours sur `len(result.findings)`, `len(result.deductions)`, et les attributs des findings/déductions — le helper produit un `Finding` et une `Deduction` par appel, identique à la séquence pré-migration. 4538 → 4538 tests.
- **Aucun changement de comportement dans le pipeline d'audit.** Test terrain sur 5 distros (Mint, Debian 13, Kali Rolling, Ubuntu 26.04 LTS) pour v0.5.0 — même logique de scoring, mêmes préfixes de clés, mêmes `template_vars`.
- **Migration par fichier, avec passage complet de la suite après chaque vague.** Chacune des 6 vagues (fichiers 1-site → 2-site → 3-site → 4-6 site → hardening → ssh.py) a passé 4538/4538 avant de passer à la suivante.

### Diff net

```
37 files changed, 483 insertions(+), 1002 deletions(-)
```

**−519 lignes net** — environ 5% de réduction sur les LoC totales de `bob/checks/*.py`. Par rapport à l'estimation initiale de l'audit ("~800 LoC retirés"), c'est conservateur à cause des 13 sites skip et parce que la signature helper est verbose (kwargs keyword-only) — mais l'objectif était d'éliminer la surface de drift, pas de minimiser le nombre de lignes, et c'est atteint.

### Tests

`4538 → 4538` (inchangé). Suite complète passe en ~6s sur Python 3.12 / Linux Mint 22.3.

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS, les 34 sections filtrables — **inchangés**.
- **Surface CLI** : aucun flag ajouté/retiré.
- **Score par domaine** : inchangé.
- **Sortie wire** (terminal + fichier rapport + JSON) : bit-identique à v0.5.0.

---

## [v0.5.0] — 21-05-2026

**Refactor v0.5.x — Phase 1 sur 5.** Cette release ouvre la branche v0.5.x avec 6 findings refactor low-risk et additifs issus d'un audit sub-agent (general-purpose) briefé avec `DOCUMENTS/SNAPSHOT.md`. **Zéro changement de comportement dans le pipeline d'audit :** contrat JSON `schema_version="1"` préservé, 7 domaines de score inchangés, 116 EXPLAIN_KEYS figés, 34 sections filtrables intactes.

Les 4 phases restantes (v0.5.1–v0.5.4) attaqueront les plus gros gains LoC (helper `warn_with_deduction` sur ~130 sites), la table directive SSH, le refactor display, le refactor wizards cron, et la sunset de `UFW_AUDIT_SHARE`.

### Findings d'audit traités

**#7 — `is_unit_active()` / `is_unit_enabled()` centralisés.** Ajoutés à `bob/checks/_run.py`. Migrent les 9 sites qui répétaient `out = (_run("systemctl", "is-active", X) or "").strip(); if out == "active"` : `auditd.py`, `clamav.py`, `fail2ban.py`, `ntp.py`, `ddns.py`, `updates.py`, `ssh.py`, `backup.py`, `log_rotation.py` (le dernier garde son `timeout=5` explicite). `services.py::_detect_single_unit_state` garde sa détection riche en enum selon la recommandation de l'audit. `.lower()` défensif ajouté dans le helper (la sortie systemd canonique est toujours `"active\n"` minuscule mais un fork downstream pourrait théoriquement émettre `"Active\n"` — restauré après review).

**#2 — `bob.output.print_titled_box()` extrait.** Un header de box ASCII 3 lignes était open-coded à 4 endroits dans `cron.py` (wizard install, wizard manage, sous-menu email store) et `manage_logs.py` (fallback texte). Les 4 sites contournaient `_c` (la palette de couleurs respectant `--no-color`) en inlinant les littéraux `\033[1;34m` — **ce leak est maintenant fermé**. `fixes.py` n'a *pas* été migré : sa box est un `╔ ║ ╠` streaming, forme différente, et passe déjà par `_c`.

**#10 — Protocol `bob.report.Report`.** Type structurel PEP 544 avec 12 membres (méthodes/attributs). Capture le contrat partagé entre `AuditReport` (texte), `NullReport` (no-op) et `MarkdownReport` (implémentation séparée, hors hiérarchie). `runner.run_checks(report: Report, ...)` annote maintenant le Protocol abstrait ; les classes concrètes exposent toujours des méthodes plus riches (`MarkdownReport.write_services_panorama` est unique au markdown). Pas de `@runtime_checkable` — type-checking statique uniquement, zéro overhead runtime.

**#11 — Closures `emit_section()` + `emit_group()` dans `runner.py`.** L'idiom 3-lignes `if not config.quiet: print_section(t(...)); report.write_section(t(...))` collapse en 1 ligne à 20 sites : 5 group headers (firewall_network, exposure_services, access_control, system_hardening, detection_health) + 15 section headers. `_sec()` lui-même est refactoré pour utiliser `emit_section` en interne. Net : runner.py rétrécit de 65 lignes / +37 lignes = **−28 lignes**, source unique de vérité pour l'émission de section. Deux sites volontairement NON migrés : `print_section(t("sections.logs"))` ligne 373 (pas de `report.write_section` correspondant — anomalie préexistante hors scope) et la boucle plugin ligne 648 (`plugin.name` n'est pas une clé de traduction).

**#15a — `tests/test_domain_scores_mapping_complete.py`.** Scanne en AST `bob/checks/*.py` pour chaque argument `key="X.Y"` littéral des méthodes émettrices (`add_deduction`, `warn`, `alert`, `info`, `ok`). Extrait les préfixes uniques et atteste que chaque préfixe est soit explicite dans `_PREFIX_TO_DOMAIN` (bob/domain_scores.py) soit whitelisté dans `_CATCH_ALL_BY_DESIGN` avec une justification une-ligne. Le whitelist capture l'état v0.4.x : `smtp`, `fail2ban`, `desktop_apps`, `virt`, `docker_audit`, `ddns`, et les préfixes domaine-firewall légitimes (`firewall`, `rules`, `ports`, `services`, `ipv6`, `iptables_nft`, `firewall_stack`, `network_context`, `docker`). La ré-attribution à des domaines plus sémantiques est reportée à Phase 5 #15b (medium risk : change les sorties de scoring). +4 tests. Le test échouera sur tout nouveau check ajoutant un préfixe sans handling explicite — ferme la classe de miscatégorisation silencieuse notée par l'audit.

### Passe de couverture cron (préalable Phase 5)

cron.py avait le pire ratio de tests du codebase selon SNAPSHOT (0.60×). Phase 5 refactorera les wizards (#6 : extraction `_prompt` helper, dédoublonnage des 3 wizards) — ajouter de la couverture *avant* le refactor est le filet de sécurité. **+35 tests** dans 5 nouvelles classes :

- `TestValidateCronField` (13 tests) — wildcard, entier, range, step, liste, out-of-range, range inversé, entry vide, garbage
- `TestValidateCustomCron` (7 tests) — discipline 5-fields, bornes par field (minute 0-59, hour 0-23, etc.)
- `TestBuildScriptContent` (7 tests) — shebang, comportement `shlex.quote()` pour email + log_dir, invocation `--quiet --detailed`
- `TestApplyCronSchedule` (3 tests) — replacement de schedule + préservation du commentaire email + remontée OSError
- `TestApplyCronEmail` (5 tests) — commentaire email + ligne script `NOTIFY_EMAILS=` + **parité regex legacy `NOTIFY_EMAIL=` (sans S)** + tolérance script manquant + quoting `shlex.quote()`

### Bug latent corrigé — `_os.open` dans `apply_cron_schedule` (découvert par les nouveaux tests)

La déduplication cron v0.4.8 a promu `apply_cron_schedule()` d'un helper privé de la TUI curses à l'API publique `bob.cron`. L'extraction a raté le renommage de `_os.open(...)` en `os.open(...)`. `_os` est un alias local utilisé seulement dans trois *autres* fonctions de `cron.py` (lignes 649, 931, 1215 — chacune fait `import os as _os`) ; au niveau module, seul `os` est importé. Le bug était masqué car le helper public était câblé à la TUI curses qui n'était pas exercée par les tests automatisés. **Les nouveaux tests `TestApplyCronSchedule` ont remonté immédiatement le `NameError: name '_os' is not defined`.** Fix : `_os.open` / `_os.fdopen` / `_os.O_*` → `os.*` (3 références sur 2 lignes).

### Liste de monitoring (release-watch)

Deux APIs ajoutées sans consommateur immédiat — gardées pour symétrie / flexibilité future, monitorées à chaque release :

- `bob.checks._run.is_unit_enabled(name, timeout)` — miroir de `is_unit_active`. `services.py::_detect_single_unit_state` garde son propre appel `_run` pour la state machine active/enabled et n'est pas migré.
- `bob.output.print_titled_box(title, width=62)` — le paramètre `width` n'est exercé par aucun site (les 4 sites passent le défaut 62).

Si ni l'un ni l'autre n'est consommé d'ici v0.5.4, retrait.

### Tests

`4499 → 4538` (+39). Suite complète passe en 7.77s sur Python 3.12 / Linux Mint 22.3 / `so6desktop`.

### Notes de compatibilité

- **Contrat JSON :** `schema_version="1"`, les 116 EXPLAIN_KEYS, les 34 sections filtrables — **inchangés**.
- **Surface CLI :** aucun nouveau flag, aucun flag retiré.
- **Score par domaine :** inchangé (aucune modification de `_PREFIX_TO_DOMAIN` dans cette release — voir #15b reporté à Phase 5).
- **Fichiers de config (`config.conf`, `services.json`, profils) :** inchangés.
- **Clés de locale :** inchangées.

---

## [v0.4.8] — 21-05-2026

Passe d'audit code-quality 4 — réalisée par un sub-agent `general-purpose` briefé avec `DOCUMENTS/SNAPSHOT.md` comme cartographie primaire. La passe a ciblé 4 patterns de bugs des audits précédents : champs dataclass morts, helpers réinventés, timeouts incohérents, code mort post-refactor. **4 IMPORTANT + 5 MINOR + 3 SUGGESTION findings** — tous corrigés dans cette release. 4499/4499 tests passent.

### Bug réel corrigé (I4) — fichiers de log de `sudo bob -d` appartenaient à root

**Reproduit** : `sudo bob -d` sur n'importe quelle box Linux crée le rapport détaillé à `~/.local/share/bob/logs/bob_YYYYMMDD_HHMMSS.log` avec mode `0o600` (déjà correct — output confidentiel) mais owned par `root:root` parce que le `open()` se passe dans le contexte sudo. L'utilisateur invocateur ne peut ni `cat` ni `rm` ses propres rapports après coup. Idem pour le dossier `logs/` lui-même à la première création via `mkdir(parents=True)`.

**Pourquoi ça a survécu** : le pattern chown-back (`bob.sysinfo.chown_to_sudo_user(path)`) était déjà établi dans 7 modules couvrant `~/.config/bob/` (`bob/config.py`, `bob/history.py`, `bob/ignore.py`, `bob/compare.py`, `bob/recurrence.py`, `bob/profiles.py`, `bob/registry.py`) — mais le fichier de rapport et le répertoire de logs dans `~/.local/share/bob/logs/` n'avaient jamais été branchés. L'impact utilisateur ne devient visible qu'après l'audit terminé, quand l'utilisateur essaie de lire son propre rapport.

**Fix** : 
- `bob/report.py::AuditReport.__init__` appelle `chown_to_sudo_user(path)` juste après `os.open(..., 0o600)`.
- `bob/manage_logs.py::get_or_prompt_log_dir` appelle `chown_to_sudo_user(d)` après chacune des 4 branches `d.mkdir(parents=True, exist_ok=True)`.

Quand BOB n'est pas exécuté sous sudo, `chown_to_sudo_user` est un no-op silencieux (`os.environ.get("SUDO_USER", "")` retourne `""`) — zéro changement de comportement hors sudo.

### Champs dataclass morts retirés (I1-I3 + M4-M5)

Huit champs dataclass populés par `from_system()` mais jamais lus par aucun consumer — même classe de bug que le fix v0.4.3 C1 (5 attrs morts de `HardeningSnapshot` qui crashaient `--json-full`).

| Check / dataclass | Champ(s) retiré(s) | Détection |
|---|---|---|
| `bob/checks/ssh.py::SSHSnapshot` | `config_source_files: List[str]` | Set par `_parse_config_file` walker récursif des Include ; jamais lu |
| `bob/checks/firewall.py::FirewallStatus` | `ipv4_rules_count: int` + `ipv6_rules_count: int` | Calculés via `sum(1 for ln in ...)` à chaque audit ; seuls consumers = fixtures de tests |
| `bob/checks/samba.py::SambaSnapshot` | `min_protocol: str` | Capturé depuis `min protocol` smb.conf ; `check_samba` utilise seulement `smb1_enabled` dérivé |
| `bob/checks/clamav.py::ClamAVSnapshot` | `last_scan_log_path: str` + `db_path: str` | `_find_last_scan_date()` retournait `(date, log_path)` mais seul `date` était utilisé |
| `bob/checks/secure_boot.py::SecureBootSnapshot` | `method: str` | "mokutil" / "efivars" / "bootctl" / "none" — interne à `from_system`, seul `state` est consommé |

`_find_last_scan_date()` simplifié pour retourner `Optional[str]` au lieu d'un tuple. `_parse_config_file()` dans ssh.py perd son paramètre `sources` inutilisé.

Tests mis à jour pour ne plus passer les kwargs supprimés. `tests/test_secure_boot.py::test_default_method_is_none` retiré (testait juste l'existence du champ). Net : -1 test (4500 → 4499).

### Helpers réinventés consolidés (M1 + M3)

**M1 — cohérence `_C_LOCALE_ENV`**. Trois sites subprocess dans `bob/checks/desktop_apps.py` (ligne 111 : `ps -eo comm`) et `bob/checks/smtp.py` (ligne 58 : `ps -eo comm` ; ligne 102 : `ss -tlnp` / `netstat -tlnp`) appelaient `subprocess.check_output` sans passer `env=_C_LOCALE_ENV`. Aujourd'hui c'est bénin parce que la sortie se trouve être indépendante de la locale sur les systèmes testés, mais un futur `ss` qui localiserait "LISTEN" ou `ps` qui localiserait ses headers casserait silencieusement la détection. Tous les autres sites subprocess de BOB passent `env=_C_LOCALE_ENV` — corrigé par cohérence.

**M3 — `log_rotation._service_active` était une réinvention de 12 lignes** de `_run("systemctl", "is-active", name)`. Les autres checks (clamav, fail2ban, auditd, ssh) utilisent la forme one-liner. Remplacé ; les imports `subprocess` et `_C_LOCALE_ENV` locaux maintenant inutilisés sont aussi nettoyés.

### Dédoublonnement de la gestion cron (M2 + S2)

`bob/cron.py::edit_cron_schedule` (wizard plain-text) et `bob/tui/cron.py::_apply_cron_schedule` (TUI curses) dupliquaient la même regex `r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+root\s+\S+.*$"` + pattern atomic-write. Idem pour `edit_cron_email` vs `_apply_cron_email_str`, avec l'asymétrie additionnelle que la branche plain acceptait la regex legacy `NOTIFY_EMAIL=` (sans S) tandis que la branche curses exigeait `NOTIFY_EMAILS=` uniquement — donc les users migrant d'une cron BOB pré-v0.3 pouvaient éditer leur email via le wizard plain mais pas via la TUI curses.

**Fix** : `apply_cron_schedule(entry, schedule_expr) -> str` et `apply_cron_email(entry, new_email) -> tuple[str, int]` promus en helpers publics dans `bob/cron.py`. `bob/tui/cron.py` les importe et expose des wrappers fins sous les noms privés originaux pour les call sites existants. La regex legacy `NOTIFY_EMAILS?=` est maintenant partagée — les deux branches traitent les cron files pré-v0.3 de façon identique.

### Autres changements mineurs (S1 + S3)

**S1** : `bob/checks/auth_log.py::_read_auth_from_journald` hardcode `max_days=90` pour l'historique brute-force SSH. L'audit a flaggé l'asymétrie avec `--log-days` (default 7, pour les logs UFW). C'est **intentionnel** — les tentatives brute-force SSH peuvent être lentes et sporadiques sur plusieurs mois, tandis que les logs UFW sont bruyants et une fenêtre étroite de 7 jours évite d'enterrer le rapport. Documenté dans le docstring pour que les audits futurs ne le re-flaggent pas.

**S3** : `_BAR_WIDTH = 10` était dupliqué en constante module-level dans 3 endroits (`bob/breakdown.py`, `bob/domain_scores.py`, `bob/display.py`). `SCORE_BAR_WIDTH = 10` promu dans `bob/output.py` (public ; alias privé conservé pour rétrocompat). `breakdown.py` et `domain_scores.py` l'importent maintenant. `display.py::_BAR_WIDTH` laissé seul — c'est pour la disk percent-bar (unité sémantique différente) et c'est aussi 10 par coïncidence.

### Hardening pyproject.toml (queué depuis l'analyse v0.4.7, appliqué ici)

Une analyse profonde du pyproject.toml faite pendant la prep de v0.4.7 avait identifié 6 améliorations différées. Les 6 appliquées + 1 bonus :

| # | Fix |
|---|---|
| 1 | `Development Status :: 4 - Beta` → `5 - Production/Stable` (4500 tests + 7 distros CI + hardware production audité — plus Beta) |
| 2 | Champs `authors` + `maintainers` ajoutés (PyPI affichait "Author: UNKNOWN") |
| 3 | `[project.optional-dependencies] geoip = ["geoip2>=4.0"]` ajouté — permet `pipx install "bodyguard-of-bits[geoip]"` pour la geolocation IP dans l'analyse des logs UFW |
| 4 | `wheel` retiré de `build-system.requires` (setuptools.build_meta auto-resolve wheel depuis setuptools 70) |
| 5 | URLs `Source` + `Documentation` ajoutées (PyPI affiche des icônes pour celles-ci) |
| 6 | `dependencies = []` explicite avec commentaire "zero runtime deps — preserve at all costs" |
| bonus | `include = ["bob", "bob.checks", "bob.tui"]` liste explicite de packages (remplace le glob `bob*` — protège contre un futur répertoire `bob_*` accidentel qui leak dans le wheel) |

### Tests

4499 passent (net -1 vs les 4500 de v0.4.7). Le test retiré est `tests/test_secure_boot.py::TestSecureBootSnapshot::test_default_method_is_none` — il assertait juste que le champ `method` valait `"none"` par défaut, et `method` n'existe plus. Aucun test ne dépendait des champs dataclass retirés au-delà des kwargs de fixture (nettoyés).

---

## [v0.4.7] — 21-05-2026

Release de maintenance — audit cross-documentation, harmonisation cosmétique UI, refonte de la bash completion et automatisation de la création de release. Aucun changement de comportement dans le pipeline d'audit ; 4500/4500 tests inchangés.

### Audit cross-documentation (24 corrections sur 8 fichiers)

Audit exhaustif rattrapant les claims qui ont dérivé entre l'état du code et les docs user-facing depuis v0.4.6 :

- **`README.md` / `README_FR.md`** — "9 domaines" → "7 domaines de score" (le 9 était historique de v0.1.0, périmé depuis v0.2.x) ; tableau de profils corrigé : profil `docker` listé mais inexistant (le vrai profil est `container`), et `workstation` est un alias de rétrocompatibilité qui charge `desktop` (pas un profil séparé).
- **`DOCUMENTS/README_TECH.md` + FR** — même dérive "9 domaines" ; "17 clés avec sections par profil" → 19 (vérifié en parcourant `en.json::explain.{key}.server.why`).
- **`DOCUMENTS/README_DEV.md` + FR** — même "17 clés × 3 profils" → 19 ; "~1500 clés de locale" → 1401 exactement (vérifié par flatten Python avec parité stricte EN ↔ FR).
- **`man/bob.1`** — flag `--list-checks` documenté mais **n'existe pas** (le vrai format est `--check=list`) ; `--min-level=info` listé comme valide mais le parser CLI rejette `info` (seulement `warn`/`alert` acceptés ; `info` serait un no-op puisque INFO est le plancher implicite) ; `--format=text` listé mais `text` est le défaut implicite, pas une valeur valide de `--format=` (rejeté au parse CLI).
- **`man/bob-profile.5`** — références au flag `--list-profiles` supprimées (n'existe pas) ; "Jusqu'à 5 niveaux d'héritage" → 8 (`_MAX_EXTENDS_DEPTH = 8` dans `bob/profiles.py`) ; section SHIPPED PROFILES enrichie avec l'entrée `workstation` et note explicite sur son statut d'alias.
- **`DOCUMENTS/AUTOMATION.md` + FR** — sample JSON webhook complètement faux : `alerts`/`warnings` montrés comme tableaux d'objets `{key, message}`, mais le vrai JSON top-level les expose en **entiers (compteurs)** (`engine.alert_count` / `engine.warn_count`). Champ `risk` montré en `"LOW"` uppercase mais `engine.level.value` retourne `"low"` lowercase. Sample manquait les champs `version`, `score_max`, `network_context`, `public_ip`, `deductions`, `domain_scores` que le vrai payload inclut. Claim comportemental aussi faux : "POSTé uniquement si alertes/avertissements présents" → en réalité POSTé à chaque audit dès qu'une URL est configurée (pas de seuil ; filtrer côté récepteur). Timeout "5 secondes" → 10 secondes (`_TIMEOUT_SECONDS = 10` dans `bob/webhook.py`).
- **`SECURITY_FR.md`** — header `## Threat model` non traduit → `## Modèle de menace`.

### `DOCUMENTS/SNAPSHOT.md` — nouvelle cartographie interne

Nouveau document interne de ~640 lignes fournissant une vue d'ensemble single-page du codebase : diagramme ASCII d'architecture, index des modules `bob/` racine + `bob/checks/` avec LoC et rôles, graphe de dépendances (centralité, fan-out), hotspots, patterns/conventions, 7 contracts gelés (schéma JSON, codes de sortie, EXPLAIN_KEYS, domaines, sections, schéma plugins, refs CIS), surface CLI, paths fichiers & env vars, mapping tests-to-source, décisions architecturales (kept / discarded / deferred), matrice CI, chiffres clés.

Conçu pour être chargé une seule fois avant une passe de refactor ou un audit pour ne pas avoir à re-découvrir la structure module par module. A subi 20 passes de correction contre l'état réel du code. 100% anglais (doc interne, pas user-facing — non shipped dans `debian/bob-core.docs` ni `%doc` du `bob.spec`).

### Harmonisation cosmétique des jauges (`bob/output.py::score_bar`)

Toutes les barres de progression basées sur le score (affichage live `--watch`, chemin `--breakdown`, scores par domaine dans le résumé d'audit, sparkline d'historique dans `--manage-logs`) utilisent maintenant un helper partagé `bob.output.score_bar(score)` avec la même logique de couleur que `display._disk_bar`, inversée pour "score haut = bon" :

- score ≥ 8 → **vert** (sain)
- score 5–7 → **jaune** (modéré)
- score 0–4 → **rouge** (critique)

Avant, ces barres étaient monochromes `█░░░░░░░░░`. Les barres des partitions disques (déjà colorées par seuil d'utilisation) sont inchangées — le nouveau helper aligne juste le reste de l'UI.

Renderers affectés (délégation d'une ligne chacun) : `bob/watch.py::_score_bar`, `bob/breakdown.py::_bar`, `bob/domain_scores.py::render_domain_scores`, `bob/manage_logs.py::display_history`. Le flag `--no-color` neutralise toujours les couleurs (chaînes ANSI vides).

### Refonte complète de la bash completion (`bob/data/bob.bash-completion`)

**Fix critique — la complétion de valeurs échouait silencieusement** : `bob --check=<TAB>` (et toutes les autres complétions `--xxx=<TAB>` : `--skip=`, `--min-level=`, `--format=`, `--profile=`, `--lang=`, `--target=`, `--webhook-format=`, `--output=`) ne retournaient aucune suggestion. La fonction lisait `${COMP_WORDS[COMP_CWORD]}` pour le mot courant, mais avec `COMP_WORDBREAKS` par défaut contenant `=`, bash split `--check=` en mots `[--check, =]` avec `COMP_WORDS[CWORD]="="`. Le filtre `compgen` avec `"="` ne matchait rien. **Fix** : utiliser la convention bash-completion par arguments positionnels — `$2` est le mot courant "propre" stripé du préfixe de word-break `=`, `$3` est le mot précédent. Les handlers `[[ "${prev}" == "--check" ]]` matchent alors correctement.

Diagnostiqué via tracing `set -x` de la fonction de completion dans la session interactive de l'utilisateur (Bash 5.2.21 sur Linux Mint 22.3).

**Autres fixes bundlés :**

- Fonction renommée `_ufw_audit` → `_bob` (nom legacy d'avant le rename du projet ; binding mis à jour).
- Code mort supprimé : `_ufw_audit_install()` + `complete -F _ufw_audit_install install.sh` enregistraient une completion pour un script d'installation (`install.sh`) qui n'existe plus dans le repo.
- Liste des sections factorisée dans une variable `_SECTIONS` matchant exactement la sortie de `bob --check=list` (34 entrées de `bob/runner.py::_ALL_SECTIONS`). L'ancienne liste contenait `firewall` (un check core qui tourne toujours — pas filtrable, suggestion trompeuse) et omettait `iptables_nft`, `samba`, `desktop_apps`.
- Liste des long-options matche maintenant `cli.py` exactement (parité vérifiée par diff) : ajout de `--check=`, `--skip=`, `--output-dir=`, `--breakdown`, `--no-colour`. Liste des short-options gagne `-B` (`--breakdown`). Total : 21 short, ~40 long options — parité complète avec `cli.py::parse_args`.
- Nouveau handler de valeur `--skip=` (miroir de `--check=` sans la valeur spéciale `list`).
- Tous les handlers de valeur supportent maintenant les deux formes : `--xxx=value<TAB>` (split equals) et `--xxx value<TAB>` (split espace).

### CI — release GitHub automatique au push de tag (`.github/workflows/publish.yml`)

Ajout d'un 4e job `github-release` après le publish PyPI. Le pipeline devient :

```
git push --tags
  → test (Python 3.10/3.11/3.12/3.13)
  → build (sdist + wheel)
  → publish (PyPI via Trusted Publishing OIDC)
  → github-release  ← NOUVEAU
       • Extrait le titre depuis la ligne table de CHANGELOG.md (texte avant " — ")
       • Extrait le body depuis la section DOCUMENTS/CHANGELOG_FULL.md
         entre "## [vX.Y.Z]" et le prochain "## [v"
       • Crée la release via softprops/action-gh-release@v2
       • Attache wheel + sdist comme assets de la release
       • Marque comme latest
```

Si le publish PyPI échoue, la release GitHub n'est pas créée (dépendance `needs: publish`). Si `CHANGELOG_FULL.md` n'a pas la section correspondante, le workflow échoue explicitement. Permission : `contents: write` uniquement.

Avant, la release GitHub était créée manuellement avec `gh release create` après chaque publish PyPI.

### Tests

Aucun nouveau test. 3 tests dans `tests/test_breakdown.py::TestBar` adaptés pour stripper les séquences ANSI avant d'asserter le contenu visible de la barre (les barres sont maintenant des strings ANSI-colorés au lieu de `█░░░░░░░░░` brut). 4500/4500 tests passent toujours.

---

## [v0.4.6] — 17-05-2026

La passe de tests terrain v0.4.5 a produit deux bugs reproductibles sur 13 audits couvrant 6 systèmes distincts (5 VMs + 1 workstation de production). v0.4.6 corrige les deux — hotfix strictement ciblé, aucun changement de comportement en dehors des deux scénarios rapportés.

### Bug 1 — Le listing noyaux incluait les paquets supprimés (état `rc`)

**Reproduit sur** : VM Mint test après `apt dist-upgrade` + `apt autoremove` ; workstation production Linux Mint 22.3 après le même workflow. Confirme que ce n'est pas un cas-limite VM — c'est le résultat standard de tout utilisateur exécutant `apt remove` (ou sa forme transitive `apt dist-upgrade`) sur une image noyau obsolète.

**Ce qui s'est passé** : `bob/checks/kernel_modules.py` listait les noyaux installés via `dpkg-query -W -f='${Package}\n' linux-image-[0-9]*`. `dpkg-query` retourne tout paquet matchant le pattern *quel que soit son état d'installation*, y compris ceux en état `rc` (supprimé mais fichiers de config dans `/etc` encore présents). `apt remove` (sans `--purge`) laisse un paquet en `rc` — le binaire noyau dans `/boot` est parti, mais le nom du paquet apparaît encore dans le listing de BOB. Résultat : "Installés : …, 6.17.0-20-generic, …" pour un noyau déjà désinstallé.

**Correctif** : le format dpkg-query est maintenant `${db:Status-Abbrev}|${Package}\n`. `${db:Status-Abbrev}` est un code 2-caractères décrivant l'action désirée + l'état actuel (`ii` = installé, `rc` = remove-configfiles, `pn` = purge-not-installed, `iU` = install-unpacked, etc.). `_parse_installed_kernels` ne garde que les lignes dont le 2e caractère est `i` (état actuel = installé), ce qui couvre `ii` et `hi` (held-installed) tout en excluant `rc`, `pn`, `un`, `iU`, et les états transitoires où les binaires peuvent ou non exister. Rétro-compatibilité préservée : le parser accepte toujours les lignes plain `linux-image-…` (sans préfixe, sans `|`) pour les fixtures de tests et tout appelant qui ne pré-préfixe pas.

**Sévérité** : cosmétique côté sortie BOB — pas d'impact scoring — mais portée élevée (tout utilisateur Debian-family qui a déjà nettoyé un vieux noyau).

### Bug 2 — Le score baissait après remédiation (le domaine disparaissait du set actif)

**Reproduit sur** : VM Debian 13. Pré-`apt upgrade` : WARN `updates.security_pending` présent → score 7/10. Post-`apt upgrade` : seul `updates.ok` émis → score *baissait* à 6/10. Effet utilisateur : rendre le système plus sécurisé produisait un score plus bas, l'exact inverse de l'intuition.

**Pourquoi** : `bob/domain_scores.py::active_domains_from_engine()` sélectionnait les domaines contribuant à la moyenne globale. Le filtre de sélection était `(WARN, ALERT)` uniquement — les domaines où chaque finding était OK ou INFO étaient exclus. Quand `apt upgrade` résolvait le WARN, le domaine `updates` passait à émettre uniquement `updates.ok`, sortait de `active_domains`, et la moyenne globale était recalculée sur un set plus petit :

```
Avant remédiation : avg(updates=8, hardening=4, …) / N      = 7
Après remédiation : avg(            hardening=4, …) / (N-1) = 6   ← BUG
Avec correctif    : avg(updates=10, hardening=4, …) / N     = ~7+ ← CORRECT
```

**Correctif** : `_actionable` élargi de `(WARN, ALERT)` à `(OK, WARN, ALERT)`. Un domaine devient actif dès qu'un check émet un signal reconnaissable (OK clean ou WARN/ALERT actionnable). Les findings INFO restent exclus de la promotion — la terrain Mint test confirme que c'est la bonne ligne (les domaines INFO-only restent intentionnellement cachés, aucune transition observée là-bas).

Cet élargissement cascade proprement : les domaines avec uniquement des findings OK apparaissent maintenant à 10/10 dans la moyenne globale, donc les aspects bien sécurisés du système sont visibles dans le score au lieu d'être implicites.

### Ajouts de tests

- `tests/test_kernel_modules.py` : 5 nouveaux tests couvrant `ii` keep, `rc` exclude, mixed `ii`+`rc`+`pn`+`un`+`iU` filtering, `hi` (hold) keep, et legacy/prefixed format mixed parsing.
- `tests/test_domain_scores.py` : 6 nouveaux tests sous `TestActiveDomainsIncludesOK`, dont le scénario exact de remédiation Debian 13 qui asserte que le global passe de 8 à 9 quand le domaine résolu reste visible.

### Vérification

- 4500/4500 tests (+11 vs v0.4.5). Aucune régression sur le reste de la suite.
- Bug 1 reproduit et corrigé sur Mint test VM (listing post-autoremove précis) et so6desktop (linux-image-6.17.0-20-generic n'apparaît plus après `apt remove`).
- Bug 2 reproduit et corrigé sur Debian 13 VM (le score monte maintenant après `apt upgrade`).

---

## [v0.4.5] — 16-05-2026

Release de hardening de l'infrastructure de tests. Le nouveau test de couverture locale introduit en v0.4.4 fonctionnait correctement mais reposait sur un scan regex du code source, ce qui a des limites structurelles connues. v0.4.5 remplace le pipeline regex par un vrai parsing AST, éliminant trois classes de faux positif d'un coup et retirant l'allowlist `_KEY_EXCLUSIONS` qui était le symptôme de la limitation sous-jacente.

### Ce qui change

`tests/test_locale_coverage.py` ne lit plus les fichiers source comme du texte. Il utilise `ast.parse` par `bob/**/*.py`, parcourt l'arbre, et traite uniquement les nodes matchant `ast.Call(func=ast.Name(id="t" | "_t"), args=[ast.Constant(str), ...])` comme des sites d'appel de traduction. Le premier argument positionnel est la clé littérale.

### Ce que ça corrige (vs la forme regex)

- **Matches dans docstrings.** Le regex matchait n'importe quel littéral `t("...")` dans le texte source, y compris les exemples de documentation. v0.4.4 a dû allowlister `samba.open_world` et `log.blocked_attempts` parce qu'ils apparaissent comme exemples dans les docstrings de `bob/i18n.py`. Avec le parsing AST, les docstrings sont des constantes string inertes sans site d'appel — elles ne peuvent pas produire de faux positif. L'allowlist a disparu.
- **Mauvais parse de call sites multilignes.** Le regex exigeait que la parenthèse ouvrante et le guillemet ouvrant soient proches sur la même fenêtre matchée. Les appels splitté sur plusieurs lignes ou enroulés sur `,` pouvaient occasionnellement faire trébucher le pattern. L'AST est whitespace-independent — le même `ast.Call` est reconnu quel que soit le formatage.
- **Faux positifs sur appels d'attributs.** `obj._t("foo.bar")` matchait le regex (le negative lookbehind ajouté en v0.4.4 sur `.` couvrait la majorité mais pas tous les edge cases). Avec l'AST, `obj._t` résout en `ast.Attribute`, pas `ast.Name` — le type check le rejette proprement.

### Ce qui est préservé

Le contrat externe des tests est identique : mêmes 9 tests (`TestLocaleCoverage` + `TestExplainNamespaceCoverage` + `TestPlaceholderParity`), mêmes fixtures, mêmes assertions. Seuls `_all_t_keys()` et ses helpers ont été refactorés. Le compteur reste à 4489.

### Note de performance

Le parsing AST est ~5× plus lent que le regex sur ce codebase (300 ms vs 60 ms pour `tests/test_locale_coverage.py`). Négligeable en absolu — la suite de tests complète tourne toujours en ~6.5 s.

### Tests

4489/4489 — inchangé vs v0.4.4. Cette release est un refactor pur d'un fichier de test existant. Aucun code source dans `bob/` n'a été modifié.

### Reporté à une release ultérieure

Les items qui étaient déjà dans la roadmap y restent :

- Phase 2 Option A — migration `Finding.template_vars` sur les ~37 checks non-pilotes (toujours tracée pour v0.5.0+).
- Cleanup cosmétique M3 (`os.path` → `pathlib`).
- Matrice CI multi-distros et PKGBUILD AUR.

---

## [v0.4.4] — 15-05-2026

Release de hardening terrain cross-distro. Quatre nouveaux tests sur VM (Debian 13, Kali Rolling, Linux Mint 22.3, Ubuntu 26.04 LTS — toutes installées depuis PyPI via `pipx upgrade`) ont fait remonter **un bug critique, trois mineurs, et validé en production les fixes v0.4.3**. Tous les fixes plus les items reportés de l'audit v0.4.3 sont groupés ici.

### 🔴 Critique — `updates.py` rapporte "0 en attente" sur chaque installation fraîche Debian-family

Reproduit sur **4/4** VMs vierges :

| Distro | apt-rapporté pendants | dont security | BOB v0.4.3 |
|---|---|---|---|
| Debian 13 | 59 | inconnu | 0 |
| Kali Rolling | 868 | inconnu | 0 |
| Mint 22.3 (test VM) | 33 | inconnu | 0 |
| **Ubuntu 26.04 LTS** | **23** | **21 LTS security** | **0** |

Deux causes combinées :

1. **`apt-get -s upgrade` conservateur.** `upgrade` (pas `dist-upgrade`) refuse tout paquet pendant qui exigerait d'installer un nouveau paquet ou d'en retirer un autre. Sur Debian/Ubuntu cela cache toute mise à jour de sécurité liée à une transition de noyau ou un nouveau soname.
2. **Cache APT obsolète.** BOB lit `/var/cache/apt/pkgcache.bin` ; si `apt update` n'a pas tourné récemment le cache rapporte un état périmé.

Trois fixes en couches :

- Switch `apt-get -s upgrade` → `apt-get -s dist-upgrade` dans [`bob/checks/updates.py:_collect_pending_updates`](bob/checks/updates.py).
- Ajout de `apt_cache_age_days` dans `UpdatesSnapshot`. Si > 7 jours → nouveau WARN `updates.apt_cache_stale` avec `cmd="sudo apt update"`.
- Ajout de `upgradable_count` (depuis `apt list --upgradable`) en cross-check. Si `dist-upgrade` retourne 0 mais `apt list` retourne N > 0 → nouveau WARN `updates.dist_upgrade_inconsistent`.

**Cascade** dans [`bob/exposure.py`](bob/exposure.py) — la synthèse "Surface d'attaque" affichait précédemment `✔ Mises à jour sécurité à jour` même quand le snapshot était peu fiable. Affiche maintenant `⚠ état inconnu — cache APT obsolète ou incohérent` quand l'un des deux nouveaux WARNs est présent. Une fausse réassurance sur un check de sécurité est pire que d'admettre qu'on ne sait pas.

### 🟡 Mineurs — trois régressions cosmétiques depuis les VMs cross-distro

- **Cas AppArmor "0 profil chargé"** (Kali). v0.4.3 émettait `AppArmor actif mais aucun profil en mode enforce (0 en plainte)` — la parenthèse se contredisait quand Kali avait littéralement 0 profils au total. Nouveau chemin dédié dans [`bob/checks/mac_policy.py`](bob/checks/mac_policy.py) : quand enforce == 0 ET complain == 0 → nouvelle clé `mac_policy.apparmor_no_profiles` avec message "AppArmor actif mais aucun profil chargé — le framework tourne sans rien à appliquer" et recommandation d'installer `apparmor-profiles` / `apparmor-profiles-extra`.
- **SMART "tous passés" sur systèmes uniquement virtuels** (Kali). Sur une VM avec `/dev/vda`, BOB affichait `ℹ /dev/vda — SMART non applicable` puis immédiatement `✔ Tous les disques ont passé le contrôle SMART`. Trompeur — aucune lecture SMART réelle n'avait été effectuée. [`bob/checks/disk.py`](bob/checks/disk.py) n'émet maintenant `disk.ok` que si au moins un check SMART **réel** (non-virtuel) a effectivement tourné.
- **Liste des ports ouverts DDNS rendue comme sous-items orphelins** (Mint test VM). Les lignes `→ 22/tcp` / `→ 80/tcp` apparaissaient visuellement comme des actions du conseil INFO, mais c'était la liste des ports concernés par le WARN. Maintenant interpolée inline dans le message WARN : `DDNS actif avec port(s) ouverts sans restriction (22/tcp, 80/tcp) — ...`. La boucle de print côté display dans [`bob/runner.py`](bob/runner.py) a disparu.

### Items reportés de l'audit v0.4.3

Tous flaggés par l'audit agent sur v0.4.2 et explicitement reportés. Tous appliqués ici :

- **S4 redesign — lectures ssh symlink-safe.** v0.4.3 n'appliquait délibérément PAS `_is_safe_config_path()` sur `~/.ssh/authorized_keys` ou `~/.ssh/config` parce que cela cassait les setups dotfiles légitimes (configs symlinkées depuis un repo git). Nouveau helper [`_is_safe_user_path(path, owner_home)`](bob/checks/_run.py) accepte les symlinks qui résolvent **dans** le home de l'owner, rejette ceux pointant ailleurs. Appliqué dans [`bob/checks/ssh.py`](bob/checks/ssh.py) sur `authorized_keys`, `~/.ssh/config`, et `known_hosts`. Ferme le gap de trust boundary SECURITY.md sur les fichiers de config user-controlled.
- **M4 refactor — `_parse_ufw_covered_ports`.** Précédemment `_is_covered_by_ufw` recompilait un regex pour chaque port vérifié contre le même texte de règles UFW. Maintenant [`bob/checks/ports.py`](bob/checks/ports.py) parse les règles **une seule fois** dans un `set[(port, proto)]`, et les lookups sont O(1). Reprend le fix v0.4.3 I4 (matching ancré sur la colonne "To") proprement. L'ancienne API texte est préservée pour rétrocompatibilité.
- **I2 vague 2 — `key=` sur les findings restants.** v0.4.3 couvrait `docker.py`, `firewall_stack.py`, `network_context.py`, `ports.py` (4 fichiers). Cette release finit le pattern sur [`bob/checks/services.py`](bob/checks/services.py) (10 ajoutés) et [`bob/checks/virtualization.py`](bob/checks/virtualization.py) (2 ajoutés). `disk.py`, `docker_audit.py`, `desktop_apps.py`, `memory.py`, `suid_audit.py` étaient déjà à 100%.
- **Test de couverture i18n.** v0.4.3 avait eu une quasi-régression quand `logs.attempts` avait été retirée des deux locales mais était encore référencée par 7 sites dans `display.py`. Seul le test terrain avait attrapé la sentinelle résultante `[logs.attempts]`. Nouveau [`tests/test_locale_coverage.py`](tests/test_locale_coverage.py) scanne tout `bob/**/*.py` pour les appels `t("KEY")` / `_t("KEY")` et asserte que chacun résout dans **les deux** en.json et fr.json, plus la parité structurelle EN/FR. Toute future suppression d'une clé encore référencée fait échouer la CI.

### Écarté du rapport d'audit v0.4.3

- **M3** (`os.path` → `pathlib` dans 4 fichiers). Cosmétique, sans impact.
- **M7** (résolution lazy de `_PLUGIN_DIR`). Déjà rejeté en v0.4.3 — le gotcha était spéculatif et la tentative cassait 20 tests. **Décision permanente.**

### Tests

4489/4489 — +21 vs v0.4.3 :
- +10 dans [`tests/test_updates.py`](tests/test_updates.py) — 5 cas cache-stale, 5 cas dist-upgrade-inconsistency.
- +2 dans [`tests/test_mac_policy.py`](tests/test_mac_policy.py) — chemins desktop INFO et server WARN pour la nouvelle clé `apparmor_no_profiles`.
- +9 dans [`tests/test_locale_coverage.py`](tests/test_locale_coverage.py) — scan corpus complet, résolution locales EN+FR, parité, couverture des prefixes dynamiques, baseline sanity (5 tests) ; plus couverture exhaustive `explain.*` générée depuis `EXPLAIN_KEYS` + check non-empty-string (3 tests, ferme la zone aveugle laissée par le bypass précédent) et parité des placeholders entre EN/FR (1 test, protège contre la classe de crash runtime `{count}` vs `{cnt}`).

### Validé cross-distro

Les fixes v0.4.3 confirmés en production sur **5 systèmes différents** :
- Linux Mint 22.3 (dev box + VM test) : UFW actif, scénario DDNS, audit complet
- Debian 13 (VM) : minimal, smoke test
- Kali Rolling (VM) : 15 SUID inattendus (kismet_cap_*), NOPASSWD:ALL, détection COMPOUND risk
- Ubuntu 26.04 LTS (VM) : UFW inactif → ALERTE `firewall.inactive` correctement déclenchée avec ref CIS + lien `--explain` (valide la chaîne v0.4.2 C1 + v0.4.3 EXPLAIN_KEYS en production)

### Reporté à une release ultérieure

- Cleanup cosmétique M3 (`os.path` → `pathlib`) — à inclure dans une éventuelle release "consistency pass".
- Phase 2 Option A — migration systématique `Finding.template_vars` sur les ~37 checks restants. Toujours en piste pour v0.5.0+.
- Matrice CI multi-distros et PKGBUILD AUR (toujours bienvenus en contribution communautaire).

---

## [v0.4.3] — 15-05-2026

Release de rattrapage doc qui s'est étendue en passe de hardening. Un nouvel audit agent sur la base v0.4.2 a fait remonter **1 critique + 5 importants + 8 mineurs + 6 suggestions** — tous appliqués ici. Faits marquants :

- **C1 (critique)** — `bob --json --json-full` crashait avec `AttributeError` dès qu'un `HardeningSnapshot` était passé. Cinq lectures de champs dans `bob/json_output.py` (`fail2ban_active`, `auto_updates_enabled`, `apparmor_mode`, `apparmor_enforced`, `apparmor_complain`) ciblaient des attributs migrés vers `mac_policy.py`. Les lectures mortes ont été supprimées et la sortie JSON expose désormais les vrais champs du dataclass. **Un test de régression couvre maintenant le chemin full+snapshot.**
- **I1** — `datetime.strptime("%b ...")` dépend de la locale du **process Python** lui-même (le `LC_ALL=C` sur les subprocess ne couvre pas ce cas). Sous `LC_TIME=fr_FR.UTF-8`, `strptime("May 14 ...")` levait `ValueError`, donc `_read_cert_expiry` retournait "could not parse notAfter" pour chaque certificat et `_parse_timestamp` ignorait silencieusement chaque ligne syslog UFW. Nouveau helper `_parse_english_month_day()` dans `bob/checks/_run.py` indépendant de la locale.
- **I4** — Le regex de `_is_covered_by_ufw` matchait le numéro de port n'importe où sur la ligne UFW status, donc une IP source `192.168.1.22` "couvrait" le port 22. Ancrage sur la colonne "To" (juste après `[ N]`).
- **I3** — Les rapports HTML email rendaient les liens markdown `[label](url)` en **balises `<a>` échappées littérales**. Ordre d'opérations inversé dans `_inline_format()`.
- **I5** — `_validate_custom_cron` ne contrôlait que les champs entiers pleins. `0-1000 * * * *` et `*/200 * * * *` passaient silencieusement et étaient rejetés ensuite par cron, perdant la planification. Validation maintenant des ranges, listes et steps sur les 5 champs.
- **I2** — Environ 30 appels `result.alert()/.warn()/.info()/.ok()/.add_deduction()` dans `docker.py`, `firewall_stack.py`, `network_context.py`, `ports.py` n'avaient pas `key=`. Sans, ni `--ignore` ni les profils d'audit ni les consommateurs JSON ne peuvent matcher les findings. Même classe de bug que le C1 v0.4.2, généralisée aux 4 fichiers les plus touchés.

Plus le rattrapage doc initialement prévu :

1. **4 clés firewall promues dans `EXPLAIN_KEYS`** — `prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`, `firewall.policy_unknown` étaient câblées comme `Finding.key` en v0.4.2 (donc `--ignore` / profils / consommateurs JSON matchaient) mais `bob --explain firewall.policy_open` retournait encore "not found". Cette release écrit le contenu title / why / how complet en `en.json` et `fr.json` plus les références CIS.

2. **CHANGELOG.md court corrigé pour v0.4.2** — la section lisait "**Aucun changement de code** · 4449/4449 tests (inchangé)" ce qui était faux : la passe de hardening livrée avec v0.4.2 a modifié 11 fichiers Python et ajouté 3 tests. La section a été réécrite avec le détail complet de la passe de hardening (C1, C2, I1-I5, M1-M5, S1-S3).

### Mineurs + suggestions

- **M1** — Suppression de 7 clés locale mortes (vestiges de la migration AppArmor de `hardening.py` vers `mac_policy.py`, plus `services.port_auto`, `services.port_from_config`, `services.state.inactive_enabled`).
- **M2** — `ntp.py:103` `subprocess.run(["ntpstat"])` passe maintenant `env=_C_LOCALE_ENV` pour cohérence avec le reste du codebase.
- **M5** — `disk.py` a perdu la `_SKIP_TYPES_RE` redondante (déjà couverte par `not device.startswith("/dev/")`).
- **M6** — Remplacement de l'anti-pattern de concat i18n dans `ddns.py` (`_t("ddns.found") + f": {client}"`) et `logs.py` (`_t("logs.brute_found") + ...`) par des clés à `{placeholders}` propres. `_identity_t` fait maintenant la substitution de placeholders pour mimer le comportement production dans les tests.
- **M8** — `services_state.py` strip maintenant `@instance` des noms de systemd unit, donc les futures unités template comme `auditd@daily.service` matchent bien `auditd`.
- **S1+S2** — `bob/sysinfo.py` 3 appels subprocess (`ufw --version`, `ip route`, `ip addr`) passent maintenant `env=_C_LOCALE_ENV` par cohérence.
- **S3** — `bob/checks/cron_audit.py` `_read_cron_file()` skip maintenant les symlinks sous répertoires user-controlled (trust boundary SECURITY.md — empêche un attaquant avec write access sur `/var/spool/cron/crontabs/` de matérialiser des contenus arbitraires de fichiers dans les rapports d'audit).
- **S5** — `bob/domain_scores.py` `_domain_for_key()` log maintenant en DEBUG le fallback vers "firewall" pour les préfixes non mappés (aide à repérer les nouvelles clés check absentes de `_PREFIX_TO_DOMAIN`).
- **S6** — `bob/__init__.py` définit `__all__`.

### Écarté du rapport d'audit

- **M3** — `os.path` → `pathlib` cleanup dans 4 fichiers. Cosmétique pur, aucun impact.
- **M4** — Recompilation regex dans `_is_covered_by_ufw`. Le module Python `re` cache les 512 derniers patterns, négligeable.
- **M7** — Résolution lazy de `_PLUGIN_DIR`. Revertée parce que convertir la constante module-level en fonction cassait 20 tests qui font `patch("bob.registry._PLUGIN_DIR", ...)`. Le "gotcha" était spéculatif ; BOB tourne one-shot par audit.
- **S4** — Check symlink sur `~/.ssh/authorized_keys` et `~/.ssh/config`. Les utilisateurs peuvent légitimement utiliser des symlinks dans `~/.ssh/`. Reporté pour discussion design.

### Vérifié

- `bob --explain firewall.inactive` (EN + FR) — title, WHY IT IS A RISK, HOW TO FIX, ref CIS tous présents.
- `bob --explain firewall.policy_open` / `firewall.policy_unknown` / `prerequisites.ufw_missing` — idem.
- `bob --explain firewall.logging_off` — inchangé (clé pré-existante, vérifiée en régression).
- `bob --explain list` — affiche le groupe "Firewall" avec les 5 clés.
- `LC_TIME=fr_FR.UTF-8 python3 -c "from datetime import datetime; ..."` — `_parse_english_month_day` réussit là où `strptime("%b ...")` échouait.
- `_is_covered_by_ufw(22, "tcp", ...)` — retourne `False` quand le port 22 n'apparaît que dans une IP source comme `192.168.1.22`.
- `build_json_data(full=True, hardening_snapshot=HardeningSnapshot())` — ne lève plus `AttributeError`.

### Tests

4468/4468 — +16 vs v0.4.2 :
- +12 invocations paramétrées depuis les 4 nouvelles entrées EXPLAIN_KEYS (3 checks paramétrés × 4 clés : title, headers WHY/HOW, ref CIS).
- +4 nouveaux tests de régression dans `tests/test_json_schema.py::TestFullModeWithOptionalSnapshots` couvrant le chemin `full=True` + `hardening_snapshot`/`ipv6_snapshot` (la lacune qui a laissé C1 passer en v0.4.2).

### Reporté à une release ultérieure

- Migration systématique des ~37 checks non-pilotes restants vers `Finding.template_vars` (Phase 2 Option A). Toujours en piste pour **v0.5.0+** selon la roadmap initiale.
- Matrice CI multi-distros et PKGBUILD AUR (toujours bienvenus en contribution communautaire).
- Protection symlink `~/.ssh/*` (S4 ci-dessus).

---

## [v0.4.2] — 14-05-2026

Phase 3 de la roadmap distro-ready — discipline packaging. Livre les artefacts de packaging et documents de politique nécessaires aux mainteneurs distros downstream, plus une passe de hardening pré-release qui a clos 2 critiques + 5 importants + 4 mineurs + 1 suggestion issus d'un audit agent. 4452/4452 tests (+3 depuis `tests/test_template_vars_migration.py`).

Le dépôt contient désormais tout ce qu'un packager doit pour produire un BOB prêt à distribuer sans patcher le source.

### Nouveaux artefacts

- **`SECURITY.md`** — threat model formel et politique de disclosure de vulnérabilités. Documente ce que BOB défend, ce qui est hors scope (compromission root préalable, attaques niveau noyau), les trois frontières de confiance et leurs défenses respectives, la surface réseau (2 appels HTTPS sortants désactivables par `--offline`), et les garanties de manipulation de données (permissions fichiers, auto-chown vers `SUDO_USER`).
- **`man/bob.1`** (~280 lignes) — page de manuel principale côté utilisateur. Documente chaque option CLI groupée par finalité, les codes de sortie comme API publique stable, le contrat de sortie JSON, les chemins fichiers sous `~/.config/bob/`, les variables d'environnement, et le modèle de sécurité avec cross-référence `SEE ALSO`.
- **`man/bob.conf(5)`** (~80 lignes) — référence du format du fichier de config (`~/.config/bob/config.conf`) : ports services personnalisés, `log_dir`, patterns `suid_whitelist`, defaults webhook, carnet d'emails.
- **`man/bob-profile(5)`** (~100 lignes) — format des fichiers de profil d'audit : métadonnées `[profile]`, override par-clé `[overrides]` (`info`/`warn`/`alert`/`skip`), chaîne `extends`, ordre de découverte, et les 3 profils livrés.
- **`debian/`** — répertoire paquet source Debian complet :
  - `control` — 3 paquets binaires : `bob-core` (moteur d'audit, sans curses), `bob-tui` (TUI curses), `bob` (meta-package). Build-Depends sur `debhelper-compat (= 13)` et `pybuild-plugin-pyproject`. Rules-Requires-Root: no.
  - `copyright` — format DEP-5, MIT partout, stanzas distinctes pour `bob/data/`, `bob/locales/`, `bob/data/schemas/`, `debian/`.
  - `changelog` — entrée initiale Debian `0.4.2-1`.
  - `rules` — basé pybuild, installe les man pages et `SECURITY.md` dans `bob-core`.
  - `source/format` — `3.0 (quilt)`.
  - `bob-core.install` / `bob-tui.install` — listes de fichiers explicites par paquet binaire (curses confiné à `bob-tui`, tout le reste sous `bob-core`).
  - `bob-core.docs` / `bob-core.manpages` — installations doc.
- **`debian/apparmor.d/bob`** — profil AppArmor (~140 lignes). Livré en mode `complain` par défaut avec un chemin `enforce` opt-in. Permet lecture sur `/etc/`, `/proc/`, `/sys/`, `/var/log/`, `~/.config/bob/`, `~/.ssh/`. Whitelist ~30 binaires système que BOB exec (`ufw`, `ss`, `iptables`, `systemctl`, `journalctl`, `openssl`, `smartctl`, `fwupdmgr`, `apt-cache`, `aa-status`, etc.). TCP sortant autorisé mais gaté au niveau application par `--offline`.
- **`packaging/rpm/bob.spec`** — spec RPM Fedora COPR / RHEL bâti sur `pyproject-rpm-macros`. Paquet binaire `bob` unique (pas de split bob-core/bob-tui — Fedora ne split pas typiquement comme ça pour les paquets Python). `%check` exécute la suite pytest complète. Man pages et `SECURITY.md` installés.

### Documentation de politique

- **`DOCUMENTS/README_TECH.md` + FR** — nouvelle section "Politique de support Python" formalisant la fenêtre de support **N et N-2**. À partir de v0.4.2 : Python 3.10 / 3.11 / 3.12 (et 3.13 à sa sortie). 3.9 est end-of-life depuis v0.2.3. La procédure d'abandon est documentée : un abandon de Python s'étale sur au moins 3 releases minor BOB (valider / annoncer / retirer) pour un préavis minimum de 6 mois — les packagers peuvent compter là-dessus pour planifier leurs rebuilds.
- **`DOCUMENTS/README_TECH.md` + FR** — nouvelle section "Packaging (depuis v0.4.2)" pointant les mainteneurs distros vers les artefacts pertinents.

### Contexte roadmap — statut Phase 3

| Item | Statut |
|---|---|
| `SECURITY.md` threat model | ✅ fait |
| Man pages | ✅ fait |
| Paquet source `debian/` | ✅ fait |
| Spec RPM (Fedora COPR) | ✅ fait |
| Profil AppArmor (mode complain) | ✅ fait |
| Politique support Python | ✅ fait |
| Matrice CI multi-distro | ⏳ reporté (v0.4.x) |
| PKGBUILD AUR | ⏳ reporté — contribution communautaire bienvenue |
| Vérification lintian-clean + rpmlint-clean | ⏳ en cours (passe initiale clean, test packaging réel à faire) |

### Évaluation distro readiness après v0.4.2

- **Packaging communautaire AUR / COPR** — viable maintenant (l'était depuis v0.4.0, cette release le rend trivial).
- **Debian unstable** — la fenêtre cible s'ouvre : le paquet source build avec `dpkg-buildpackage` ; reste à valider lintian-clean et obtenir un parrainage upstream.
- **Fedora COPR officiel** — idem : la spec build ; reste compte COPR + rpmlint clean.
- **Debian main / Fedora main** — toujours 12–18 mois minimum, la politique s'engage sur 12 mois de stabilité des contrats avant demande.

### Passe de hardening (audit pré-release)

Un audit complet du code en pré-release a fait remonter 2 critiques + 5 importants + 4 mineurs + 1 suggestion — tous corrigés dans la même release :

- **C1** — `firewall.py` : 4 appels `result.alert()` / `result.add_deduction()` sans `key=`. Sans `key=`, ni `--ignore` ni les profils ni les consommateurs JSON ne peuvent matcher les alertes les plus critiques. Corrigé avec `key="prerequisites.ufw_missing"`, `"firewall.inactive"`, `"firewall.policy_open"` sur les sites concernés.
- **C2** — `debian/apparmor.d/bob` : 10 binaires que BOB exécute étaient absents du profil (`df`, `lsblk`, `dpkg-query`, `getenforce`, `apt-get`, `find`, `ps`, `netstat`, `ntpstat`, `docker`) + le profil déclarait `/usr/local/sbin/bob-*` rw alors que `cron.py` écrit dans `/usr/local/bin/bob-{slug}`. Les deux corrigés.
- **I1+I2** — `ssl_certs.py` + `virtualization.py` : 3 appels subprocess sans `env=_C_LOCALE_ENV`, cassant le parsing de dates en locale française.
- **I3** — `bob/_paths.py` : renommage `UFW_AUDIT_SHARE` → `BOB_SHARE` (le legacy reste accepté).
- **I4** — spec RPM : `Recommends: firewalld` était faux (BOB ne lit que ufw). Corrigé en `Recommends: ufw`. **M5** ajoute `Suggests: apparmor`.
- **I5** — `bob/watch.py` : `run_checks()` appelé sans `user_config=`, perdant silencieusement la whitelist SUID utilisateur à chaque tick `--watch`.
- **M1** — Suppression de `microsoft.gpg` untracked (résidu).
- **M2** — Docstring `bob/formatter.py` clarifiée (API publique, aucun caller interne en v0.4.x).
- **M4** — `bob.compare.BASELINE_PATH` exposé comme symbole public.
- **S1** — Nouveau `tests/test_template_vars_migration.py` (3 tests) rend visible la dette de migration Phase 2.
- **S2** — Bloc de documentation sur la politique de timeout en tête de `bob/checks/_run.py`.
- **S3** — Imports triés dans `bob/cron.py` (groupement PEP 8).

Note : 4 clés sont référencées par Findings (`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`) mais pas encore dans `EXPLAIN_KEYS` — ajouter ces clés requiert d'écrire title/why/how/CIS complets, reporté en v0.4.3.

### Tests

4452/4452 (+3 depuis `tests/test_template_vars_migration.py`). Validé :
- Les 3 man pages se rendent avec `man -l` et `groff -man -Tutf8` sans erreur.
- Les 3 fichiers schema JSON restent valides (seul l'URL `$id` a été bumpée de `v0.4.1` → `v0.4.2`).
- Les 3 revues externes style ChatGPT de la Phase 2 tiennent toujours (aucun changement de contrat).

---

## [v0.4.1] — 14-05-2026

Phase 2 de la roadmap distro-ready — découplage architectural. Trois zones traitées : finalisation du mode `--offline`, isolation curses via `bob/tui/`, et représentation indépendante de la locale des findings via `template_vars` additif. Plus une passe de hardening post-revue sur `bob/formatter.py` (4 tests edge-case + API resserrée). Tous les changements sont non-breaking (additifs). 4449/4449 tests (+19).

### Zone 2.1 — Mode `--offline` strict vérifié

Le flag `-o` / `--offline` (déjà présent depuis v0.4.0) a été audité bout en bout : tous les sites touchant le réseau sont soit déjà gatés (HTTP `get_public_ip`, POST webhook), soit purement locaux (apt-cache, fwupdmgr get-updates, journalctl, openssl x509). Ajout de 2 tests d'intégration dans `tests/test_webhook.py` qui figent le contrat offline : le webhook n'est PAS envoyé quand `config.offline=True` même si une URL webhook est fournie, et `get_public_ip(offline=True)` court-circuite avant tout appel `urllib`.

### Zone 2.2 — Sous-package curses `bob/tui/`

`bob/cron_ui.py` (952 lignes) déplacé vers `bob/tui/cron.py` sous un nouveau sous-package `bob.tui`. Les imports curses étaient déjà lazy (à l'intérieur des fonctions) — cette release rend la séparation physique. Les 2 sites d'appel dans `bob/cron.py` mis à jour vers `from bob.tui.cron import ...`. Le reste de `bob.*` (pipeline d'audit, checks, scoring, sortie JSON) reste importable sur des systèmes sans curses, prérequis pour un futur paquet Debian `bob-core` séparé de `bob-tui`.

### Zone 2.3 — Findings indépendants de la locale (additif)

Deux nouveaux champs optionnels sur `Finding` et `Deduction` :

```python
@dataclass
class Finding:
    ...
    key:           str  = ""    # déjà depuis v0.3.7
    template_vars: dict = field(default_factory=dict)   # nouveau en v0.4.1
```

`template_vars` est le mapping des variables que le check a passées à son template i18n (e.g. `{"ciphers": "aes128-cbc, des-cbc"}` pour `ssh.weak_ciphers`). Quand non-vide, un client externe peut reconstruire le message localisé depuis `(key, template_vars, locale)` sans dépendre de la chaîne pré-formatée `message`.

Nouveau module `bob.formatter` expose `format_finding(finding, lang=None)` et `format_deduction(deduction, lang=None)`. Ordre de résolution : `key + template_vars` → `key` seul → fallback sur `message` pré-formaté (chemin legacy, totalement rétrocompatible).

Les helpers `CheckResult.warn/alert/info/ok/add_finding/add_deduction` acceptent un kwarg `template_vars=` optionnel. Les 3 checks pilotes (`bob/checks/ssh.py`, `hardening.py`, `firewall.py`) démontrent la migration : le même `message=_t("key", **vars)` est gardé (compat legacy) et `template_vars={...vars...}` ajouté en parallèle. La sortie JSON expose désormais `template_vars` sur chaque deduction et finding (champ additif — dict vide pour les checks legacy).

### Contexte roadmap

Cette release ferme les zones 2.1 + 2.2 + 2.3 (Option B additive) du plan Phase 2. Trois checks pilotes démontrent le pattern ; les 40 checks restants peuvent être migrés de manière incrémentale sans breaking change. L'Option A (refactor breaking complet — `Finding.message` retiré au profit de `Finding.template_vars` obligatoire) est reportée à v0.5.0+ avec les contrats v2 du schéma plugin.

### Tests

4449/4449 (+19) :
- 3 nouveaux dans `tests/test_webhook.py` pour le mode offline (skip POST, court-circuit urllib, compat CLI)
- 14 nouveaux dans `tests/test_formatter.py` (10 base : ordre de résolution, roundtrip locale, rétrocompat ; +4 edge cases post-revue : partial template_vars, mismatch key/message, inputs vides)
- 2 nouveaux dans `tests/test_json_schema.py` (`template_vars` exposé dans le JSON pour chaque deduction et finding)

### Validation terrain

Audit bout en bout sur so6desktop : `bob.tui.cron` se charge proprement, les 3 checks pilotes émettent `template_vars` correctement, `bob --json` expose le nouveau champ sur chaque entrée, `--offline` skip le webhook.

---

## [v0.4.0] — 14-05-2026

Phase 1 de la roadmap distro-ready — cinq contrats d'API publique figés pour que scripts, dashboards et packagers downstream puissent s'appuyer sur un comportement stable. Aucune nouvelle fonctionnalité, aucun changement breaking (additif uniquement). 4405/4405 tests (+57).

### Contrat stable — Codes de retour documentés comme API publique (`bob/__main__.py`, `bob/cli.py`, `DOCUMENTS/README_TECH.md`)

Les 5 codes de retour (`EXIT_OK=0`, `EXIT_WARNINGS=1`, `EXIT_ALERTS=2`, `EXIT_ERROR=3`, `EXIT_TARGET_MISSED=4`) sont désormais formellement promus au rang d'API publique de BOB : leurs valeurs et sémantiques ne changeront pas au sein d'une même version majeure. Documentés dans `--help` (avec ajout du code 4 manquant) et dans une section dédiée du README_TECH. Constantes exportées depuis `bob.__main__` pour usage programmatique.

### Contrat stable — Détection automatique de la locale via POSIX `$LANG` (`bob/i18n.py`, `bob/cli.py`, `tests/conftest.py`)

`bob.i18n.detect_system_lang()` (nouveau) interroge `$LC_ALL` / `$LC_MESSAGES` / `$LANG` dans l'ordre POSIX standard et résout vers `"fr"` pour les locales `fr_*` ou `"en"` sinon (incluant `C`, `POSIX`, `C.UTF-8`, langues non supportées). `parse_args()` l'appelle comme valeur par défaut quand ni `--lang=` ni `--french` n'est passé ; les flags explicites priment toujours. Nouvelle fixture autouse dans `tests/conftest.py` force `LANG=C` pour des tests déterministes indépendants de la locale hôte.

### Contrat stable — Schéma de sortie JSON documenté + champ `key` exposé (`bob/json_output.py`, `bob/scoring.py`)

`schema_version="1"` était déjà présent ; cette release formalise le contrat : les clés top-level ne disparaissent jamais / ne sont jamais renommées au sein de v1, les ajouts sont libres, les changements breaking incrémentent à v2. Nouvelles constantes `SCHEMA_V1_REQUIRED_KEYS` et `SCHEMA_V1_FULL_KEYS` rendent le contrat testable. `Finding.key` et `Deduction.key` sont désormais sérialisés comme champ `key` sur chaque entrée — les clients peuvent matcher les findings via des clés pointées stables sans dépendre de `message`/`reason` localisés. Référence complète du schéma ajoutée à README_TECH (tableau de chaque clé top-level, structure des objets imbriqués, exemple de matching indépendant de la locale).

### Contrat stable — Alias map `--explain` + politique de freeze (`bob/explain.py`)

`EXPLAIN_KEY_ALIASES: dict[str, str]` introduit (vide pour l'instant) afin que les futurs renommages aient un chemin de migration documenté : ancien nom → nouveau nom, alias n'expire jamais au sein de la même version majeure du schéma. `normalize_key()` consulte la map après le strip des segments de chemin. Le docstring du module énonce explicitement la politique de freeze : pas de suppression, pas de renommage, pas de glissement sémantique, ajouts libres. 16 clés load-bearing explicitement testées comme figées.

### Contrat stable — JSON Schema formel pour les plugins services (`bob/data/schemas/`, `pyproject.toml`)

Deux fichiers JSON Schema Draft 2020-12 (`service.schema.json`, `services-list.schema.json`) décrivent la forme de `services.json` et des plugins utilisateur `*.json`. La liste bundled (`bob/data/services.json`) est vérifiée comme conforme au schéma. Les schémas sont livrés via `package_data` afin que les packagers de distros puissent valider les plugins utilisateur en externe avec `check-jsonschema` / `ajv`. La validation Python dans `Service.from_dict()` reste la source de vérité au runtime (zéro dépendance runtime ajoutée) ; le JSON Schema le reflète pour le tooling externe.

### Bonus UX — Suffixe `= N` redondant sur score inchangé supprimé (`bob/display.py`)

Quand le score était inchangé vs l'audit précédent, la boîte récap affichait `Score de sécurité : 8/10  = 8` — le `= 8` était un vestige d'un marqueur de delta antérieur. Supprimé : le score stable affiche désormais simplement `8/10` (le score est déjà visible). Test renommé `test_stable_shows_equal` → `test_stable_shows_no_annotation`.

### Tests

4430/4430 (+82) : 16 nouveaux dans `test_i18n.py` (12 `detect_system_lang` + 4 intégration CLI), 17 dans le nouveau `test_json_schema.py` (invariants top-level, types de champs, exposition des clés stables, strict-set + defense-in-depth contre dérive des constantes issus de la passe post-revue #2), 6 dans `test_explain.py` (alias map + politique freeze), 43 dans le nouveau `test_services_schema.py` (schéma valide, services bundled conformes, échantillons valides/invalides, parité Python ↔ Schema, plus factorisation `$defs` / regex port stricte 1–65535 / contraintes métier `if/then` / wrapper plugin-file `schema_version` / `minItems: 1` issus des passes post-revue #1+#2).

### Validation terrain

Audit bout en bout sur so6desktop (Linux Mint 22.3) — score 8/10, toutes les sections rendues correctement, locale auto-détectée comme français via `$LANG=fr_FR.UTF-8`.

---

## [v0.3.6] — 09-05-2026

Passe de code review suite à un audit approfondi du code. Aucune nouvelle fonctionnalité, aucun changement de comportement — corrections de bugs, hygiène et cohérence. 4348/4348 tests.

### Correctif — `Path.home()` retourne `/root` sous sudo (`bob/config.py`, `bob/recurrence.py`, `bob/history.py`, `bob/registry.py`, `bob/compare.py`, `bob/profiles.py`, `bob/plugin_checks.py`, `bob/ignore.py`)

Sept modules utilisaient `Path.home()` à l'import pour calculer les répertoires de configuration/plugins/baseline. Sous `sudo`, cela résolvait `/root/.config/bob/` au lieu du home de l'utilisateur invoquant — cassant silencieusement les profils utilisateur, les plugins de services, les plugins de checks, la baseline et la persistance recurrence/history. Le helper correct `bob.sysinfo.get_user_home()` (qui honore `SUDO_USER`) existait déjà mais n'était utilisé qu'à deux endroits. Les sept modules importent et utilisent désormais `get_user_home()`. `bob/ignore.py` avait sa propre logique dupliquée — remplacée par un appel au helper partagé.

Pour compléter le correctif, un nouveau helper `bob.sysinfo.chown_to_sudo_user(path)` est appelé après chaque création/écriture de fichier ou dossier de configuration utilisateur sous sudo, afin que l'utilisateur invoquant conserve l'accès lecture/écriture en sessions non-sudo (no-op hors contexte sudo). Appliqué dans `config.py`, `compare.py`, `recurrence.py`, `history.py`, `ignore.py` après chaque `mkdir(parents=True)` et après chaque `replace`/`write_text` atomique. Les lectures `registry.py`, `profiles.py` et `plugin_checks.py` reçoivent une garde `PermissionError` afin qu'un répertoire inaccessible en lecture (état hérité d'un run sudo antérieur au fix) retombe gracieusement sur « aucun plugin trouvé » au lieu de crasher.

### Correctif — `AllowTcpForwarding local` signalé comme avertissement (`bob/checks/ssh.py`)

Le check n'acceptait que `AllowTcpForwarding no` comme sûr. Définir `local` (plus restrictif que la valeur par défaut `yes` et explicitement recommandé dans le texte de remédiation BOB) était incorrectement compté comme un problème et déduisait 1 point. Désormais `no` et `local` sont tous deux acceptés.

### Correctif — En-tête journalisation UFW affiché quand UFW inactif (`bob/runner.py`)

Quand UFW était inactif, `check_ufw_logging()` retournait un `CheckResult` vide, mais `runner.py` imprimait quand même l'en-tête de section (`JOURNALISATION UFW`), produisant un en-tête suivi d'aucune entrée. L'en-tête n'est désormais imprimé que si `fw_status.active`.

### Correctif — ULA et link-local IPv6 traités comme externes (`bob/checks/network_context.py`)

`_is_private_or_loopback()` couvrait la loopback IPv4, RFC-1918 et `::1` IPv6 mais omettait `fc00::/7` (Unique Local Addresses) et `fe80::/10` (link-local). Les connexions dans ces plages étaient classées externes, produisant des avertissements faux positifs. Réécrit via `ipaddress.ip_network()` avec la même liste de réseaux que `bob/checks/auth_log.py`.

### Correctif — Regex `NOTIFY_EMAIL` legacy silencieusement ignoré (`bob/cron.py`, `bob/locales/{en,fr}.json`)

`edit_cron_email()` ne matchait que `NOTIFY_EMAILS=` (pluriel — format actuel) et non `NOTIFY_EMAIL=` (singulier — scripts pré-v0.x). Les anciens scripts voyaient une mise à jour d'email "réussie" qui ne patchait en réalité rien. Match désormais `NOTIFY_EMAILS?=` et avertit si aucune ligne n'a été remplacée (nouvelle clé locale `manage_cron.email_not_found_in_script`).

### Refactoring — `_check_weak_algo` déplacé dans la section sub-check (`bob/checks/ssh.py`)

Le helper était placé dans la section `# Parsing helpers` mais c'est logiquement un sub-check (il écrit sur `result`, appelle `_t`). Déplacé près des autres fonctions `_check_*` pour respecter la convention du projet.

### Nettoyage — 22 imports inutilisés supprimés (pyflakes)

Vestiges de refactorings successifs : `dataclasses.field` dans 6 modules sans valeurs par défaut ; `typing.Optional` dans 4 modules ; `pathlib.Path` dans 2 ; `bob.scoring.{ScoreEngine, Finding, FindingLevel}` dans `report.py` ; `shutil`, `_C_LOCALE_ENV`, `prompt_emails`, `WebhookError`, etc. Le shadowing de `dataclasses.field` par le paramètre `field` dans `_extract_field()` résolu en renommant en `field_name`. Variable morte `found_issue` dans `check_hardening()` (jamais lue) supprimée avec ses 8 affectations.

### Nettoyage — 47 clés de locales mortes supprimées (`bob/locales/{en,fr}.json`)

Audit de chaque clé contre les sites d'appel `t()` et `_t()` réels (incluant les patterns dynamiques `f"prefix.{var}"`). Supprimés : tout `cli.help_*` (14 clés, remplacé par `print_help` codé en dur dans `cli.py`), tout `errors.*`, `geo.*`, `profile.*`, plus orphelines dans `report`, `manage_cron`, `install_cron`, `prerequisites`, `network_context`, `ddns`, `logs`, `ports`, `summary`, `fixes`, `risk_context`, `log_dir`, `config`, `deduction`, `status`. Les deux fichiers restent synchrones en clés : 1435 → 1388 clés (−47), 2049 → 1994 lignes par fichier.

### Tests

4348/4348 (inchangé vs v0.3.5). Tous les correctifs sont couverts par les tests existants ; aucune régression introduite. Validé bout en bout sur so6desktop (Linux Mint 22.3) — audit complet avec score 8/10 et toutes les sections correctement rendues.

---

## [v0.3.5] — 08-05-2026

Refactoring interne pur et correctif des locales — aucune nouvelle fonctionnalité, aucun changement de comportement. 4348/4348 tests.

### Refactoring — closure `_sec` dans `runner.py` (`bob/runner.py`)

`run_checks()` (951L) contenait ~29 blocs identiques de 7–13 lignes : garde `_section_enabled` + `print_section` + `report.write_section` + appel `check_fn` + `apply_profile` + `engine.apply` + `display_result` + `print()` final. Extrait en une closure `_sec(section, snapshot, check_fn, **kwargs)` qui capture `config`, `profile`, `engine`, `report`, `t`, `_pr` depuis la portée externe. Toutes les sections standard utilisent `_sec` ; exceptions conservées manuellement : en-têtes firewall/réseau, ports, logs, DDNS, docker, virtualisation, samba, docker_audit, desktop_apps, iptables_nft, disk (appel d'affichage supplémentaire). Résultat net : 951L → 656L (−295 lignes). `_pname` précalculé pour les 8 sections qui acceptent `profile_name=`.

`auth_log` omettait précédemment `apply_profile` — désormais cohérent avec toutes les autres sections (sans effet en pratique, aucun profil ne définit actuellement des surcharges auth_log).

### Refactoring — helper `_check_weak_algo` dans `ssh.py` (`bob/checks/ssh.py`)

`_check_sshd_config()` contenait trois blocs structurellement identiques de 16 lignes pour les Ciphers, MACs et KexAlgorithms faibles. Extrait en `_check_weak_algo(cfg, result, _t, cfg_key, weak_set, t_key, param, points) -> bool`. Les trois blocs se réduisent à trois appels en une ligne. Résultat net : −26 lignes.

### Correctif — chaînes de locale `UFW-AUDIT` → `BOB` (`bob/locales/en.json`, `bob/locales/fr.json`)

Quatre clés de traduction référençaient encore l'ancien nom d'outil `UFW-AUDIT` au lieu de `BOB` : `install_cron.title`, `manage_cron.title`, `manage_cron.no_crons`, `report.title`. Corrigées dans les deux fichiers de locale.

---

## [v0.3.4] — 08-05-2026

Hotfix pour une régression introduite en v0.3.2. `user_config` était référencé dans `run_checks()` sans jamais être passé en paramètre — chaque audit se terminait par `Fatal error: name 'user_config' is not defined` immédiatement après la section durcissement noyau. 4348/4348 tests.

### Fix — `user_config` non transmis à `run_checks()` (`bob/runner.py`, `bob/__main__.py`)

`run_checks()` avait reçu `user_whitelist=user_config.get_suid_whitelist()` en v0.3.2 mais `user_config` n'avait jamais été ajouté à la signature de la fonction. Correction : paramètre `user_config: UserConfig | None = None` ajouté ; `__main__.py` passe `user_config=user_config` au site d'appel. Repli sur `[]` quand `None` (aucune liste blanche appliquée).

---

## [v0.3.3] — 07-05-2026

Refactoring interne pur — aucune nouvelle fonctionnalité, aucun changement de comportement. Quatre chantiers de nettoyage issus d'une passe de code review. 4348/4348 tests (+1).

### Refactoring — split `cron.py` (`bob/cron.py`, `bob/cron_ui.py`)

`bob/cron.py` (2181L) scindé en deux modules. `bob/cron.py` conserve les types de données, les parsers, la logique et les flux interactifs en texte brut. `bob/cron_ui.py` (nouveau, 955L) regroupe tout le code TUI curses. Les dispatchers `run_install_cron()` / `run_manage_cron()` utilisent des imports paresseux : contrôle `sys.stdout.isatty()` → flux texte brut ; sinon `curses.wrapper(curses_fn)` avec repli sur le flux texte brut en cas de `curses.error`.

`build_script_content(notify_email, log_dir) -> str` extrait des deux flux d'installation vers `cron.py` en tant que fonction pure, éliminant une duplication de 40 lignes.

### Refactoring — `compute_domain_scores()` retour pur (`bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`)

Champ `Deduction.was_capped: bool` supprimé. `compute_domain_scores()` retourne désormais `tuple[dict[str, dict], frozenset[int]]` — le second élément est l'ensemble des indices dans `engine.breakdown` réduits par un plafond outil. `ScoreEngine` met en cache ces indices via `set_domain_scores()` (nouveau paramètre `capped_indices`) et les expose via une propriété `capped_indices`. `breakdown.py` lit `engine.capped_indices` directement.

### Refactoring — API publique `domain_scores.py`

`_LABELS → LABELS`, `_TOOL_CAPS → TOOL_CAPS`, `_key_to_domain → key_to_domain`. Appelants mis à jour : `breakdown.py`, `explain.py`, `tests/test_domain_scores.py`.

### Refactoring — helpers curses `cron_ui.py`

`_WizardEntry(name, hour=3, minute=0)` NamedTuple remplace le stub `class _FakeEntry: pass`. `_draw(stdscr, row, col, text, attr=0)` absorbe 30+ blocs `try: addstr(…) except curses.error: pass`. `_read_key(stdscr) -> int` absorbe 9 blocs `try: get_wch() / except curses.error: continue` + normalisation de touche. Les indices magiques de type de planning remplacés par les constantes `_SCHEDULE_DAILY/WEEKDAYS/MONTHDAYS/CUSTOM`. Réduction nette : 1104L → 955L (−149 lignes).

### Tests

4348/4348 (+1 depuis v0.3.2) : `TestWasCapped` remplacé par `TestCappedIndices` (7 tests) couvrant le contrat de retour frozenset de `compute_domain_scores()`.

---

## [v0.3.2] — 06-05-2026

Liste blanche SUID configurable par l'utilisateur : les patterns déclarés dans `~/.config/bob/config.conf` suppriment les binaires légitimes connus du warning "SUID inattendu". Pas de nouveau warning — uniquement une réduction du bruit pour les environnements comme Kali qui livrent des outils SUID supplémentaires. Plus 14 corrections issues d'une passe de code review (i18n, mode quiet, idempotence moteur, code mort). 4347/4347 tests (+19).

### Fonctionnalité — `suid_whitelist` dans `config.conf` (`bob/config.py`, `bob/checks/suid_audit.py`, `bob/runner.py`)

L'utilisateur peut désormais déclarer des patterns glob pour les binaires SUID approuvés directement dans `~/.config/bob/config.conf` :

```
# ~/.config/bob/config.conf
suid_whitelist = kismet_cap_*, my_custom_tool
```

Les patterns sont appliqués sur le **basename** de chaque binaire SUID détecté via `fnmatch`. Les chemins correspondants sont retirés de la liste "SUID inattendu", éliminant les faux positifs sur Kali (15+ binaires de capture Kismet), les environnements d'entreprise, ou les systèmes avec des outils maison.

Quand au moins un binaire est supprimé, un résultat INFO `suid_audit.whitelisted` rapporte le nombre et les chemins, pour que l'utilisateur confirme que la liste blanche fonctionne sans tout masquer silencieusement.

Implémentation : `UserConfig.get_suid_whitelist() -> list[str]` lit et parse la clé séparée par des virgules. `SuidSnapshot.from_system()` reçoit un paramètre `user_whitelist` ; le runner passe `user_config.get_suid_whitelist()` à l'appel. Les chemins supprimés sont stockés dans `SuidSnapshot.whitelisted_suid` pour un rapport transparent.

### Corrections — code review (14 éléments)

| ID | Fichier | Correction |
|----|---------|-----------|
| BUG-2 | `domain_scores.py` | `compute_domain_scores()` remet `was_capped=False` avant chaque calcul — idempotent |
| BUG-3 | `runner.py` | `"samba"` et `"desktop_apps"` ajoutés à `_ALL_SECTIONS` — visibles par `--check`/`--skip`/`--list-checks` |
| BUG-4 | `output.py` | `_print_status()` et `print_risk_context()` utilisent `_p()` — mode quiet respecté |
| BUG-1 | `output.py` | `[ATTENTION]`/`[ALERTE]` → `t("status.warn")`/`t("status.alert")` — i18n câblé |
| BUG-5 | `scoring.py`, `logs.py`, `display.py` | `result._log_data` → champ propre `CheckResult.log_data` (plus de `# type: ignore`) |
| BUG-6 | `checks/logs.py` | `warn()` et `add_deduction()` bruteforce reçoivent `key="logs.brute_found"` — visible par `--ignore` et les profils |
| SF-1 | `checks/ssh.py` | Le parse de `sshd_config` émet `ssh.match_block_skipped` INFO quand un bloc `Match` tronque l'analyse |
| SF-2 | `__main__.py` | `curr_baseline = None` initialisé avant le bloc `with` — plus de risque `UnboundLocalError` |
| SEC-1 | `fixes.py` | Literals `\033[...]` remplacés par `output._c.*` — respecte `--no-color` |
| BP-2 | `scoring.py`, `domain_scores.py` | Méthode publique `engine.set_domain_scores()` — plus d'accès direct aux attributs `_privés` |
| BP-3 | `checks/ssh.py` | `f.level.value in (...)` → `f.level != FindingLevel.OK` — comparaison sûre sur l'enum |
| BP-1 | `__main__.py` | `open(os.devnull, "w", encoding="utf-8")` — encodage explicite |
| INC-2 | `runner.py` | `SambaSnapshot`/`DesktopAppsSnapshot.from_system()` déplacés dans le guard `_section_enabled()` — pas de subprocess lors d'un `--skip` |
| DC-1 | `checks/suid_audit.py` | `_is_root_owned()` supprimée — code mort privé dupliquant une logique inline |

### Tests

4347/4347 (+19 nets depuis v0.3.1) :

| Fichier | Changement |
|---------|-----------|
| `tests/test_suid_audit.py` | +21 dans `TestFromSystemUserWhitelist` (8), `TestGetSuidWhitelist` (7), `TestGlobMatching` (7) — −2 `TestIsRootOwned` (supprimés avec DC-1) |
| `tests/test_logs.py` | 3 assertions mises à jour `_log_data` → `log_data` (BUG-5) |

---

## [v0.3.1] — 06-05-2026

Deux corrections de bugs identifiées lors de la validation multi-VM, plus deux refactorisations architecturales dans le pipeline de décomposition du score. Aucune nouvelle fonctionnalité. 4328/4328 tests (+6).

### Fix — Version bannière bloquée à `0.2.4` (`bob/__init__.py`)

Après la sortie de v0.3.0, `bob/__init__.py` déclarait encore `__version__ = "0.2.4"`. La bannière et `bob -V` affichaient la mauvaise version sur toutes les plateformes. Corrigé.

### Fix — Contexte réseau DDNS non propagé vers l'entête du score (`bob/runner.py`, `bob/__main__.py`)

Quand le DDNS était actif et que des ports ouverts étaient détectés, `run_checks()` mettait à jour `network_context` de `"local"` à `"ddns"` en interne — mais `ChecksResult` (un NamedTuple) ne contenait pas ce champ, donc l'appelant voyait toujours `"local"`. L'entête du résumé affichait "Réseau local uniquement" même sur les machines avec un client DDNS actif. Correction : `network_context: str = "local"` ajouté à `ChecksResult` ; `__main__.py` lit `result.network_context` immédiatement après `run_checks()`.

### Refactorisation — `was_capped: bool` sur `Deduction` (`bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`)

`breakdown.py` re-simulait précédemment le calcul des plafonds outil pour déterminer quelles déductions avaient été absorbées — dupliquant la logique de `compute_domain_scores()` et violant le contrat "rien n'est calculé ici" du module. Correction : `Deduction` gagne `was_capped: bool = False` ; `compute_domain_scores()` le positionne quand une déduction est partiellement ou totalement absorbée. `breakdown.py` lit `d.was_capped` directement.

### Refactorisation — Propriétés `engine.domain_scores` / `engine.active_domains` en cache (`bob/scoring.py`, `bob/domain_scores.py`)

Les modules d'affichage (`__main__.py`, `breakdown.py`) appelaient précédemment `compute_domain_scores()` et `active_domains_from_engine()` indépendamment, risquant un double calcul. Correction : `apply_domain_score_override()` met en cache les résultats sur le moteur ; deux méthodes `@property` les exposent comme `engine.domain_scores` et `engine.active_domains`. Tous les appelants lisent depuis le cache.

### Tests

4328/4328 (+6 nouveaux) :

| Fichier | Modification |
|---------|--------------|
| `tests/test_domain_scores.py` | +6 `TestWasCapped` : déductions non-plafonnées / totalement absorbées / partiellement absorbées · clés hors-plafond-outil jamais marquées · scores domaine en cache sur le moteur · état moteur avant la surcharge |

---

## [v0.3.0] — 06-05-2026

Jalon transparence du scoring : `--breakdown` (`-B`) affiche le chemin complet de calcul du score — déductions, plafonds par outil, plafond moteur, score brut, scores par domaine, surcharge moyenne, et score final. `--explain <clé>` gagne une section SCORING indiquant le domaine et le plafond outil. Trois corrections ciblées : asymétrie `-unsigned` dans la logique de rétention des kernels, flèche `→` orpheline dans la ligne de delta du score, et reliques "UFW-AU" dans le rapport détaillé. 4322/4322 tests (+48).

### Fonctionnalité — option `--breakdown` / `-B` (`bob/breakdown.py`, `bob/cli.py`, `bob/__main__.py`, locales)

Nouvelle vue post-audit qui affiche le chemin complet de calcul du score sans relancer les vérifications. Affiche : toutes les déductions (clé · domaine · points · contexte), les déductions absorbées par les plafonds par outil, si le plafond moteur a été appliqué, le score brut avant moyennage par domaine, les scores par domaine avec barres de progression, si la surcharge de moyenne a été activée, et le score final coloré par sévérité.

Implémenté via `_silent_mode` : la sortie de l'audit est redirigée vers `/dev/null` via `redirect_stdout`, puis le breakdown s'affiche après restauration de stdout. Cela supprime tous les appels `print()` nus (pas seulement les appels `output.*`), donnant une vue propre.

i18n : clés `breakdown.*` ajoutées dans `bob/locales/en.json` et `bob/locales/fr.json`.

### Fonctionnalité — `--explain` score-aware (`bob/explain.py`)

`bob --explain <clé>` ajoute désormais une section SCORING après le texte de remédiation, indiquant le domaine de la clé et le plafond outil applicable. Se termine par une suggestion d'exécuter `sudo bob --breakdown` pour voir la contribution en direct.

### Correction — Asymétrie de rétention kernel `-unsigned` (`bob/checks/kernel_modules.py`)

Sur les systèmes Debian avec des paires de kernels signés/non-signés (ex. `6.12.74+deb13+1-amd64` et `6.12.74+deb13+1-amd64-unsigned`), la variante non-signée triait alphabétiquement en dernier et occupait un slot de rétention, laissant la variante signée incorrectement marquée comme obsolète. Corrigé : après la boucle de rétention, l'ensemble de conservation est étendu pour inclure les deux variantes (signée et non-signée) de chaque version de base conservée. Le message de détail des kernels obsolètes utilise maintenant `recent=running` au lieu de `recent=most_recent` afin que le conseil de vérification après redémarrage nomme toujours le kernel effectivement en cours d'exécution.

### Correction — Flèche orpheline dans le delta de score (`bob/display.py`)

Quand le score était identique entre deux audits consécutifs, la ligne de score affichait `6/10  →` sans valeur après la flèche. Remplacé par `6/10  = 6` (signe égal + score répété) pour la clarté.

### Correction — Reliques "UFW-AU" dans le rapport détaillé (`bob/report.py`, `bob/report_markdown.py`)

Le fichier de rapport détaillé ouvert avec `--detailed` contenait un bandeau ASCII représentant "UFW-AU" (ancien nom de l'outil "ufw-audit") et un champ d'en-tête "UFW: v...". Remplacé par l'art ASCII BOB (même style que le bandeau terminal) et "Firewall: ufw ...". Rapport Markdown mis à jour : "UFW:" → "Firewall (UFW):".

### Tests

4322/4322 (+48 nouveaux) :

| Fichier | Modification |
|---------|-------------|
| `tests/test_breakdown.py` | Nouveau fichier — 16 tests : helper barre, moteur propre, déductions, plafond outil, plafond moteur, surcharge domaine, labels français |
| `tests/test_golden_scenarios.py` | Nouveau fichier — 32 tests : scénarios de scoring bout-en-bout sur 9 classes (machine propre, serveur durci, desktop, mal configuré, pare-feu inactif, Debian minimal, plafonds outil, stabilité, multi-domaine) |
| `tests/test_min_level.py` | Renommé `test_stable_shows_right_arrow` → `test_stable_shows_equal` pour correspondre au format `= N` |

---

## [v0.2.4] — 05-05-2026

Passe de durcissement du codebase post-audit : deux bugs UX kernel Debian `-unsigned`, sentinel `None` pour `deduction_total`, alias `TranslationFunc` sur toutes les signatures de vérification, détection des opérateurs shell via shlex, et visibilité du fallback de profil. Aucune nouvelle fonctionnalité. 4274/4274 tests (+12).

### Corrections de bugs — UX kernel Debian (`bob/checks/kernel_modules.py`)

**Fix 1 — `kernels_up_to_date` nomme le kernel courant, pas le sibling -unsigned** — Quand le kernel courant était `6.12.74+deb13+1-amd64` et que son sibling `-unsigned` était le kernel le plus récemment trié, le message "kernel à jour" affichait le nom de la variante `-unsigned` au lieu du kernel en cours d'exécution. Cause : `version=most_recent` était passé à la clé i18n au lieu de `version=running`. Corrigé : `version=running`. Nouveau test : `test_up_to_date_names_running_kernel_not_unsigned_sibling`.

**Fix 2 — Bon template de message pour les paires signées/non-signées** — Quand le kernel courant et le plus récent forment une paire signé/non-signé, le message de nettoyage doit utiliser `kernels_obsolete_same` (sans la paire "courant / récent" dans le texte) plutôt que `kernels_obsolete`. La comparaison `running == most_recent` était littérale et retournait `False` pour cette paire. Corrigé : `_strip_unsigned(running) == _strip_unsigned(most_recent)`. Nouveau test : `test_debian_signed_unsigned_pair_uses_obsolete_same_message`.

### Correction de régression — sentinel `deduction_total` (`bob/compare.py`)

**Fix 3 — Faux "+N pt(s)" au premier audit après mise à jour** — v0.2.3 a ajouté `deduction_total: int = 0` à `AuditBaseline`. Les anciens baselines (pré-v0.2.3) n'ont pas ce champ ; `raw.get("deduction_total", 0)` retournait `0`, puis `deduction_delta = actuel − 0` affichait "Déductions variables +N pt(s)" au premier audit suivant, même sans aucun changement réel. Corrigé : `int | None = None` (même pattern que le sentinel `finding_keys`). `load_baseline()` retourne `None` si le champ est absent ; `compute_delta()` ignore le calcul du delta quand l'un des deux côtés est `None`. +10 nouveaux tests dans `TestDisplayDelta` et `TestDeductionTracking`.

### Qualité du code — passe d'audit codebase

**Typage — alias `TranslationFunc`** (`bob/checks/_run.py`, 40 fichiers checks, `bob/history.py`, `bob/plugin_checks.py`) — `TranslationFunc = Callable[..., str]` défini dans `_run.py` (déjà importé par tous les checks). Les 42 signatures de fonctions `check_*` mises à jour : `t=None` → `t: TranslationFunc | None = None`.

**Sécurité shell — `_has_shell_ops()` via `shlex`** (`bob/fixes.py`) — La détection des opérateurs shell remplace la correspondance naïve par sous-chaîne (`any(op in cmd for op in _SHELL_OPS)`) par une tokenisation via `shlex.split()`. L'ancienne méthode pouvait faussement correspondre à `>` dans des valeurs d'arguments ou des chemins de fichiers. `_has_shell_ops()` vérifie les tokens contre un frozenset, ne traitant que les tokens autonomes comme opérateurs. Les guillemets malformés retournent `True` prudemment (traité comme shell).

**UX — fallback de profil maintenant visible** (`bob/__main__.py`, locales) — Quand `--profile=X` était donné mais que le profil X n'existait pas, `load_profile()` retombait silencieusement sur `server`. L'utilisateur n'avait aucune indication que le profil demandé était introuvable. Corrigé : `output.print_warn(t("audit.profile_not_found", …))` ajouté quand le nom du profil chargé diffère de celui demandé. Nouvelles clés i18n `audit.profile_not_found` en EN et FR.

### Tests

4274/4274 (+12 nouveaux) :

| Fichier | Modification |
|---------|-------------|
| `tests/test_kernel_modules.py` | +2 : `test_up_to_date_names_running_kernel_not_unsigned_sibling` · `test_debian_signed_unsigned_pair_uses_obsolete_same_message` |
| `tests/test_compare.py` | +10 : 4 dans `TestDisplayDelta` (cas affichage/suppression déductions variables) · 6 dans le nouveau `TestDeductionTracking` (sentinel None, chargement/sauvegarde, calcul delta) |

---

## [v0.2.3] — 03-05-2026

Huit corrections identifiées lors d'une tournée d'audit multi-VM (Linux Mint, Debian 13, Kali, Ubuntu 26.04). Trois corrections comportementales, deux corrections infrastructure, trois corrections de précision UX. 4262/4262 tests (+1).

### Corrections de bugs — tournée multi-VM (`bob/checks/services.py`, `bob/checks/logs.py`, `bob/display.py`)

**Fix 1 — NOT_LISTENING toujours INFO** — Les ports présents dans le registre de services mais sans écoute active (ex. Mosquitto 8883 quand seul 1883 est lié) étaient affichés en `⚠ [ATTENTION]` pour les services CRITIQUE/ÉLEVÉ, apparaissant dans la boîte résumé. Corrigé : `NOT_LISTENING` émet maintenant toujours `result.info()` quelle que soit la sévérité du service. Tests renommés : `test_not_listening_critical_adds_info`, `test_not_listening_high_adds_info`.

**Fix 2 — Dominance locale IoT : déduction supprimée** — Quand une seule IP privée dominait les logs UFW bloqués (trafic IoT typique), l'outil émettait `result.warn(nature="improvement")` et déduisait 1 point. Un trafic bénin en provenance d'une source privée connue ne devrait pas réduire le score. Corrigé : rétrogradé en `result.info()` sans déduction. Tests : `test_finding_is_info_level`, `test_no_score_deduction`.

**Fix 3 — Heredoc non tronqué** — Les commandes multi-lignes (blocs heredoc dans les étapes de remédiation auditd) étaient passées à `_wrap_for_box()` via `text.split()`, qui supprimait tous les retours à la ligne. Corrigé : `_add_finding_lines()` itère maintenant `item.cmd.splitlines()` et appelle `_wrap_for_box()` par ligne, préservant visuellement la structure heredoc.

### Infrastructure

**`bob/completion.py` — garde contre les symlinks circulaires** — `--install-completion` créait un symlink circulaire (`~/.local/bin/bob → lui-même`) quand pipx était installé en root et que le chemin utilisateur était déjà un lien vers le chemin système. Corrigé : garde `candidate.resolve() != dst_bin.resolve()` ajouté. `exists()` retourne déjà `False` pour les symlinks cassés ; la vérification resolve empêche le cas circulaire.

**Python 3.9 retiré** (`pyproject.toml`, `.github/workflows/tests.yml`, `.github/workflows/publish.yml`) — Python 3.9 a atteint sa fin de vie en octobre 2025. `requires-python` passé à `">=3.10"`. Classifier et entrées de la matrice CI supprimés.

### Corrections de précision UX — tests multi-distros

**Compare : delta de déductions variables** (`bob/compare.py`) — Quand le score changeait entre deux audits sans nouvelle clé de finding (ex. activité log variable entre runs), la section CHANGEMENTS n'affichait que "Score dégradé de N point(s)" sans plus d'explication. Ajout de `deduction_total: int` dans `AuditBaseline` et `deduction_delta: int` dans `AuditDelta`. Quand `deduction_delta != 0` et qu'aucun changement structurel (count alertes/warns, clés findings) n'explique le mouvement de score, affiche "Déductions variables ±N pt(s) (logs, trafic réseau)". Les anciens baselines (champ absent) ont `deduction_total=0` par défaut et ne produisent aucun faux delta. Trouvé sur : VM Debian 13, VM Kali.

**Surface d'attaque : label SSH scindé** (`bob/exposure.py`) — Le tableau de surface d'attaque utilisait une seule clé i18n (`ssh_not_running` = "non installé / non démarré") pour les deux cas "SSH non installé" et "SSH installé mais arrêté". Quand SSH était installé mais inactif (ex. Kali), le label était factuellement incorrect. Scindé en `ssh_not_installed` ("non installé") et `ssh_stopped` ("installé — non démarré"), utilisés par les branches de code respectives. Nouveau test : `test_not_active_shows_stopped_text`. Trouvé sur : VM Kali.

**Services : message `active_disabled` avec label du service** (`bob/checks/services.py`) — "Le service est actif en ce moment, mais ne redémarrera pas automatiquement." apparaissait dans la boîte résumé sans identifier quel service. Le nom est visible dans l'audit complet sous l'en-tête `▶ Service`, mais perdu lors de la promotion en résumé. Corrigé : `{label}` ajouté à la chaîne i18n ; `label=snap.label` passé au site d'appel. Trouvé sur : VM Linux Mint (Redis).

### Tests

4262/4262 (+1 nouveau, 4 renommés/mis à jour) :

| Fichier | Modification |
|---------|-------------|
| `tests/test_services.py` | Renommés : `test_not_listening_critical_adds_warn` → `_adds_info` · `test_not_listening_high_adds_warn` → `_adds_info` · assertions mises à jour niveau `info` |
| `tests/test_logs.py` | Renommés : `test_finding_is_warn_level` → `_info_level` · `test_score_deduction_one_point` → `test_no_score_deduction` · assertions mises à jour |
| `tests/test_exposure.py` | Mis à jour : `test_not_installed_info_is_ok` et `test_not_installed_overrides_password_auth` assertent la clé `ssh_not_installed` · +1 nouveau `test_not_active_shows_stopped_text` |

---

## [v0.2.2] — 03-05-2026

Cinq corrections ciblées du scoring, un fix de locale, uniformisation du logging, couverture de test pour le fix de race condition v0.2.1, tests d'invariants scoring, documentation de la pondération égale des domaines, et correction du check de règle UFW sans protocole. 4261/4261 tests (+23).

### Corrections scoring (`bob/scoring.py`, `bob/domain_scores.py`, `bob/checks/clamav.py`)

**Fix 1 — Propagation `ScoreCap.key`** — `ScoreCap` gagne un champ `key: str = ""`. Les méthodes `set_cap()`, `cap()`, `apply()` et `finalize()` le propagent toutes. La `Deduction` synthétique émise quand un plafond se déclenche porte maintenant `key=self._cap.key` au lieu de `key=""`, permettant l'attribution correcte au domaine. Mis à jour : `bob/checks/firewall.py` passe `key="firewall.inactive"` à `result.set_cap()`.

**Fix 2 — Les findings INFO n'inflatent plus l'ensemble des domaines actifs** — `active_domains_from_engine()` ne compte maintenant que les findings WARN et ALERT pour déterminer quels domaines sont « actifs » dans la moyenne globale. Un domaine INFO-only (service installé, rien d'actionnable) n'est plus inclus dans la moyenne. `FindingLevel` importé directement depuis `bob.scoring`.

**Fix 3 — `clamav.db_very_outdated` 2pt → 1pt** — La déduction était de 2 pts mais le plafond outil `clamav` dans `_TOOL_CAPS` est de 1 pt. Le point excédentaire n'affectait que `engine._raw_score`, créant une asymétrie silencieuse entre score brut et score par domaine. Réduit à 1 pt pour éliminer ce point fantôme.

### Observabilité — logging uniformisé (`bob/history.py`, `bob/ignore.py`, `bob/sysinfo.py`)

`except … pass` remplacé par `_log.debug()` dans 6 emplacements sur 3 modules. `import logging` + `_log = logging.getLogger(__name__)` ajoutés à chacun. Les échecs restent non-fatals ; visibles avec `--debug`.

| Module | Fonction | Exception | Message |
|--------|----------|-----------|---------|
| `bob/history.py` | `save_score()` | `OSError` | `"Failed to save score to history: …"` |
| `bob/history.py` | `_rotate_if_needed()` | `OSError` | `"Failed to rotate history file: …"` |
| `bob/ignore.py` | `load_ignore_keys()` | `OSError` | `"Cannot read ignore file …: …"` |
| `bob/sysinfo.py` | `get_user_home()` | `KeyError` | `"SUDO_USER … not found in password database, falling back to Path.home()"` |
| `bob/sysinfo.py` | `collect_system_info()` | `OSError` | `"Cannot read /etc/os-release: …"` |
| `bob/sysinfo.py` | `detect_network_type()` ×2 | `subprocess.TimeoutExpired / FileNotFoundError / OSError` | `"ip route failed …"` / `"ip addr failed …"` |

### Contrat scoring documenté (`bob/scoring.py`)

La docstring de `finalize()` documente la séquence obligatoire : `engine.finalize()` → `apply_domain_score_override(engine)`. `set_global_score()` marqué « ne pas appeler directement ». Précise que `engine._raw_score` reste accessible pour le débogage.

### Fix 4 — Plafond de domaine non appliqué si le score brut global est déjà sous le seuil (`bob/domain_scores.py`)

`compute_domain_scores()` calcule le score de chaque domaine à partir des déductions présentes dans `engine.breakdown`. Quand un plafond se déclenche (ex. `firewall.inactive` → max 3/10), `finalize()` ajoute un delta de déduction dans `breakdown` **seulement si** `raw_global_score > cap.maximum`. Sur un système cumulant beaucoup de déductions dans différents domaines, le score brut global peut déjà être sous le seuil du plafond — le delta n'est jamais ajouté, le score du domaine cible n'est pas plafonné, et la barre d'affichage montre la valeur pré-plafond (ex. 6/10 au lieu de 3/10 pour le pare-feu quand UFW est inactif).

Correction : après accumulation des déductions par domaine depuis le breakdown, `compute_domain_scores()` lit maintenant `engine.cap_info` et, si sa clé correspond à un domaine, applique directement le plafond sur le total de déductions de ce domaine. Le fix est idempotent (si le delta était déjà dans le breakdown, le score du domaine est déjà égal au plafond, et la condition `raw_domain > cap.maximum` est fausse).

Trouvé en exécutant l'outil sur une VM Ubuntu 26.04 avec UFW inactif et plusieurs problèmes de durcissement : le détail du score affichait « Score plafonné à 3 (pare-feu inactif) » mais la barre de domaine montrait toujours 6/10.

### Fix 5 — Check de règle orpheline manquant les règles UFW sans protocole (`bob/checks/firewall.py`)

`_check_orphan_rules()` utilisait `_PORT_PROTO_RE` (`\d{1,5}/(?:tcp|udp)`) pour analyser le champ « To » des règles UFW. Une règle sans protocole explicite (ex. `57621 ALLOW IN 192.168.1.0/24`) ne matchait pas et était silencieusement ignorée avec le commentaire erroné « open-any rules ». UFW applique les règles port-sans-protocole aux deux protocoles (TCP et UDP).

Nouveau constante `_PORT_BARE_RE` gère le cas de repli : si ni `port/tcp` ni `port/udp` n'est dans les ports en écoute, la règle est signalée comme orpheline. Trouvé en exécutant l'outil sur une machine réelle où `57621` (Spotify Connect) n'était pas signalé alors que la règle jumelle `41681/tcp` l'était.

### Fix 6 — Locale SSH : commande dupliquée dans le bloc « Que faire ? » (`bob/locales/fr.json`, `bob/locales/en.json`)

`ssh.not_active_detail` contenait `"Activer avec : sudo systemctl enable --now ssh"`. Le champ `cmd` affichant déjà la commande séparément, le bloc « Que faire ? » la montrait deux fois. Corrigé : le `detail` fournit maintenant un contexte (« Le service est désactivé — activez-le si l'accès SSH est nécessaire. ») et la commande apparaît uniquement via `cmd`. Trouvé en testant l'outil sur Kali Linux où SSH est installé mais intentionnellement arrêté.

### Invariants scoring — nouvelles classes de test (`tests/test_scoring.py`, `tests/test_domain_scores.py`)

`TestScoringInvariants` ajouté aux deux fichiers — 12 nouveaux tests couvrant les propriétés devant tenir quel que soit l'input :

| Classe | Fichier | Invariants |
|--------|---------|------------|
| `TestScoringInvariants` | `test_scoring.py` | Score plancher = 0 · plafond = MAX · déductions monotones · plafond supérieur = no-op · override domaine dans la plage |
| `TestScoringInvariants` | `test_domain_scores.py` | Findings INFO n'activent pas le domaine · WARN/ALERT si · déduction seule active · moyenne globale ∈ [min, max] des actifs · tous scores dans [0, 10] · moyenne globale toujours dans [0, 10] |

### Tests

4261/4261 (+23 nouveaux, 2 mis à jour) :

| Fichier | Changement | Couverture |
|---------|------------|-----------|
| `tests/test_domain_scores.py` | +6 `TestEngineLevelDomainCap` | Plafond appliqué avec peu de déductions · plafond appliqué quand le score brut global est déjà sous seuil (delta absent du breakdown) · pas de sur-plafonnement si déjà au plafond · score ne dépasse jamais le plafond · pas de saignement vers d'autres domaines · tous scores dans la plage |
| `tests/test_firewall.py` | +3 `TestOrphanRules` | Règle bare-port signalée si rien en écoute · non signalée si TCP en écoute · non signalée si UDP en écoute |
| `tests/test_scoring.py` | +5 `TestScoringInvariants` | Plancher/plafond · déductions monotones · plafond no-op · override dans la plage |
| `tests/test_domain_scores.py` | +7 `TestScoringInvariants` | Activation INFO/WARN/ALERT · chemin déduction · bornes moyenne globale · scores dans la plage |
| `tests/test_manage_logs.py` | +2 `TestStatFallback` | Fallback `OSError` sur `.stat()` dans la boucle `cur_logs` → `(0, "?")` · idem boucle `extra_sections` |
| `tests/test_clamav.py` | renommé + mis à jour | `test_db_very_outdated_deducts_1` (était `_deducts_2`) · `test_worst_case` : 3 pts total (était 4) |

---

## [v0.2.1] — 02-05-2026

Hotfix défensif — 17 améliorations ciblées trouvées par audit dual-agent. Aucune nouvelle fonctionnalité, aucun changement de comportement. 4238/4238 tests inchangés.

### Correction de crash — mode texte `--manage-logs` (`bob/manage_logs.py`)

**Problème :** les appels `.stat()` sur les chemins de fichiers logs n'étaient pas protégés dans les boucles d'affichage mode texte. Si un fichier disparaissait entre le scan du répertoire et l'affichage, `--manage-logs` plantait avec `OSError`. Le mode curses avait déjà la protection `try/except OSError` correcte ; le mode texte non.

**Correction :** les deux boucles (`cur_logs` et `extra_sections`) enveloppent maintenant `.stat()` dans `try/except OSError` avec valeurs de repli `(size_kb=0, mtime="?")`, alignées sur l'implémentation curses.

### Resserrement des gestionnaires d'exceptions (8 emplacements)

Tous les `except Exception` remplacés par les exceptions spécifiques pouvant réellement être levées :

| Fichier | Fonction | Avant | Après |
|---------|----------|-------|-------|
| `bob/cis_refs.py` | `_load()` | `Exception` | `(OSError, json.JSONDecodeError)` |
| `bob/manage_logs.py` | `_get_extra_dirs()` | `Exception` | `(json.JSONDecodeError, ValueError, TypeError)` |
| `bob/manage_logs.py` | repli curses | `Exception` | `(curses.error, OSError)` |
| `bob/explain.py` | repli curses | `Exception` | `(curses.error, OSError)` |
| `bob/cron.py` | `run_install_cron()` | `Exception` | `(_curses.error, OSError)` |
| `bob/cron.py` | `run_manage_cron()` | `Exception` | `(_curses.error, OSError)` |
| `bob/checks/ssh.py` | `_rsa_bits_from_blob()` | `Exception` | `(struct.error, ValueError)` |
| `bob/checks/ssh.py` | `_has_passphrase()` | `Exception` | `(binascii.Error, ValueError)` |

### Regex déplacées en module-level (3 fichiers)

Patterns recompilés à chaque appel de fonction, maintenant constantes module :

| Fichier | Constantes |
|---------|-----------|
| `bob/checks/firewall.py` | `_OPEN_ANY_RE`, `_ALLOW_IN_RE`, `_PORT_PROTO_RE` |
| `bob/checks/cron_audit.py` | `_PATH_RE` |
| `bob/checks/firmware.py` | `_FLAT_SKIP_RE` |

### Qualité du code (3 corrections)

- **Regex email dédupliqué** (`bob/cron.py`) — `_EMAIL_RE` était défini identiquement dans 3 fonctions locales ; maintenant une seule constante module.
- **Helper `_resolve_path()` extrait** (`bob/manage_logs.py`) — `Path(raw).expanduser().resolve() if raw else default` était dupliqué à deux endroits.
- **Accès direct aux attributs dans `domain_scores.py`** — `getattr(engine, "findings", [])` / `getattr(deduction, "key", None)` etc. remplacés par accès direct. `ScoreEngine` initialise toujours ces attributs.

### Observabilité (2 corrections)

- **`recurrence.py`** — `except … pass` remplacé par `_log.debug()` pour que les échecs de chargement soient visibles en mode `--debug`.
- **`__main__.py`** — les échecs webhook émettent maintenant `_log.warning()` en plus de l'affichage stderr.

### Tests

4238/4238 (inchangés — aucun nouveau test ; aucun changement de comportement introduit)

---

## [v0.2.0] — 01-05-2026

Cinq améliorations : refonte du scoring, détection MTA pour le cron, correction du faux positif kernel, correction de la dominance IoT dans les logs, et bannière ASCII orange.

### Refonte du scoring (`bob/scoring.py`, `bob/domain_scores.py`)

**Problème :** le score global était la somme brute de toutes les déductions depuis 10. Huit problèmes mineurs de durcissement sur une machine par ailleurs bien configurée (SSH 10/10, pare-feu 10/10, mises à jour 10/10) pouvaient produire 2/10 CRITIQUE — un score ne reflétant pas la posture réelle.

Deux corrections ciblées :

- **Plafond par outil** — `rootkit`, `clamav` et `file_integrity` contribuent au maximum 1 point de déduction à leur domaine, quel que soit le nombre de findings individuels. Élimine la double pénalité « base rkhunter obsolète + pas de scan enregistré = −2 ».
- **Score global = moyenne des scores de domaine actifs** — le score global est désormais la moyenne arrondie de tous les scores de domaine pour lesquels au moins un finding existe (services non installés exclus). Un domaine Durcissement dégradé ne fait plus s'effondrer le score global quand SSH, pare-feu et mises à jour sont à 10/10.

**Effet sur le cas de référence Debian 13 :** 8 déductions → était 2/10 CRITIQUE, reflète maintenant la plage réelle de 6 à 9/10 selon les domaines actifs.

Nouvelle API : `ScoreEngine.set_global_score()`, `compute_global_from_domains()`, `apply_domain_score_override()`.

### Détection MTA cron (`bob/cron.py`)

**Problème :** l'assistant cron avertissait `'mail' non disponible — installez mailutils` quand `mail` était absent, mais l'envoi réel utilise `sendmail`, pas `mail`. Le conseil était incorrect et incomplet.

Nouveau helper `_detect_mta()` :
- Vérifie `sendmail` (le binaire réellement utilisé pour la livraison)
- Identifie le fournisseur : Postfix, Exim, msmtp, ssmtp
- Affiche `✔ Transport mail : Postfix` quand disponible
- Affiche des instructions d'installation claires en cas d'absence : `sudo apt install postfix` (MTA local) ou `sudo apt install msmtp-mta` (relais via Gmail/SMTP)

### Correction faux positif kernel `-unsigned` (`bob/checks/kernel_modules.py`)

**Problème :** sur Debian avec Secure Boot activé, `linux-image-X-amd64` (signé) et `linux-image-X-amd64-unsigned` sont tous deux installés. Le système démarre correctement le noyau signé, mais BOB signalait `-unsigned` comme « plus récent installé » et avertissait « redémarrage requis ».

Nouveau helper `_strip_unsigned()` : le suffixe `-unsigned` est retiré avant la comparaison de versions. Exécuter le noyau signé alors que seule la variante unsigned de la même version est également installée n'est plus signalé.

### Dominance IoT dans les logs : WARN −1 pt (`bob/checks/logs.py`)

**Problème :** quand une seule IP privée représentait ≥ 70 % du trafic UFW bloqué (≥ 50 entrées), BOB émettait un finding INFO sans déduction de score. La fonctionnalité était documentée comme WARN −1 pt mais l'implémentation utilisait `result.info()` sans appel à `add_deduction()`.

**Correction :** `result.info()` remplacé par `result.warn()` + `result.add_deduction(points=1, key="logs.local_dominance")`. Nouvelle clé de localisation `deduction.local_dominance` ajoutée dans `en.json` et `fr.json`. Trois tests existants dans `tests/test_logs.py` corrigés pour vérifier le niveau WARN et la déduction d'1 point (total inchangé).

### Bannière ASCII orange (`bob/output.py`)

L'art ASCII `BOB` dans la bannière terminal est maintenant affiché en orange bold (`\033[1;38;5;208m`). Les caractères de bordure restent en bleu.

### Tests

4238/4238 (3 tests corrigés dans `tests/test_logs.py` — dominance IoT : INFO→WARN + vérification déduction ; total inchangé)

| Fichier | Nouveaux tests | Couverture |
|---------|----------------|-----------|
| `tests/test_kernel_modules.py` | +6 | Helper `_strip_unsigned` · variantes Debian signé/non-signé · vrai redémarrage toujours détecté |
| `tests/test_cron.py` | +6 | `_detect_mta` — sans sendmail, Postfix, Exim, msmtp, ssmtp, inconnu |
| `tests/test_scoring.py` | +6 | `set_global_score` — override, clamp, niveau, score brut inchangé |
| `tests/test_domain_scores.py` | +14 | Plafonds (rootkit/clamav/file_integrity) · `compute_global_from_domains` · `apply_domain_score_override` · scénario Debian 13 |
| `tests/test_logs.py` | 0 (+3 corrigés) | Dominance IoT : niveau WARN · déduction 1 pt · sous le seuil inchangé |

---

## [v0.1.1] — 29-04-2026

Trois corrections ciblées trouvées lors des premiers lancements sur Ubuntu 26.04 LTS et Debian 13.

### Corrections

- **Parser fwupd format arbre** (`bob/checks/firmware.py`) — fwupd 1.9+ (Ubuntu 26.04+) a changé son format de sortie vers une structure en arbre avec les caractères `├─`, `└─`, `│`. L'ancien parser capturait ces caractères comme noms d'appareils, produisant une sortie corrompue (`│, ├─UEFI CA: (+7)`). Les noms d'appareils sont désormais extraits uniquement depuis les lignes `├─`/`└─`.
- **Message d'erreur `--install-completion`** (`bob/__main__.py`) — les utilisateurs qui lançaient `sudo bob --install-completion` obtenaient `sudo: 'bob': command not found` car sudo utilise un PATH restreint qui n'inclut pas les binaires pipx. Le message d'erreur avertit maintenant explicitement que `sudo bob` ne fonctionnera pas et invite à copier-coller la commande exacte avec le chemin complet.
- **En-tête de colonne du panorama des services** (`bob/locales/en.json`, `bob/locales/fr.json`) — renommé `UFW` → `SCOPE` (EN) / `PORTÉE` (FR). La colonne indique si un service a une exposition internet, pas si une règle UFW active le couvre — l'ancien label créait une fausse impression.

### Tests

4206/4206 (+4 tests de régression pour le parser fwupd format arbre dans `tests/test_firmware.py`)

---

## [v0.1.0] — 26-04-2026

Version initiale de **BOB — Bodyguard Of Bits**.

Auditeur de durcissement Linux avec mapping des benchmarks CIS. S'exécute en root, ne nécessite ni agent ni daemon.

### Vérifications de sécurité

46 vérifications réparties en 9 domaines :

- **Pare-feu** — audit des règles UFW, audit iptables/nftables (quand UFW est inactif), cohérence IPv6, analyse de la pile pare-feu, analyse d'exposition des ports
- **SSH** — 12+ paramètres de configuration (PermitRootLogin, PasswordAuthentication, qualité des clés, etc.)
- **Durcissement noyau** — 20+ paramètres sysctl ; audit des modules noyau ; Secure Boot ; firmware/microcode
- **Services** — 32 services connus avec classification du risque ; audit de l'état des services ; détection du contournement pare-feu Docker
- **Permissions fichiers** — audit SUID/SGID ; fichiers sensibles ; sudoers
- **Comptes utilisateurs** — comptes expirés ; politique de mots de passe ; login.defs ; PAM
- **Système** — mises à jour apt ; unattended-upgrades ; niveau de journalisation UFW ; rotation des logs ; analyse auth.log ; NTP ; Fail2ban ; scan rootkit ; auditd ; intégrité des fichiers (AIDE/Tripwire) ; ClamAV ; AppArmor/SELinux ; backup ; santé disque (SMART) ; mémoire/swap ; expiration certificats TLS/SSL ; timers systemd ; applications desktop ; Samba ; tâches cron ; DDNS
- **Réseau** — contexte IP publique ; détection du type de réseau (serveur/LAN/VPN) ; GeoIP optionnel
- **Docker** — configuration du daemon ; conteneurs privilégiés ; montages hôte

### Mapping des benchmarks CIS

133 entrées : 99 CIS Ubuntu 22.04 · 4 CIS Docker · 34 bonnes pratiques.
Chaque résultat avec un code CIS formel affiche `[CIS:X.Y.Z]` en ligne. Référence complète en mode `--verbose`.
`--explain CLÉ` affiche POURQUOI le résultat est important, COMMENT le corriger, et sa référence CIS.

### Formats de sortie

Terminal (coloré) · JSON · CSV · Markdown · HTML

### Profils d'audit

`server` · `workstation` · `desktop` · `docker` — ajustez la sévérité et ignorez les vérifications non pertinentes selon l'environnement.

### Automatisation

- **Cron** — assistant `--install-cron` ; TUI `--manage-cron` ; jobs nommés dans `/etc/cron.d/bob-{nom}`
- **Webhooks** — JSON générique + Slack (détecté automatiquement par l'URL)
- **Historique des scores** — tendance sparkline sur plusieurs exécutions (`--history`)
- **Scores par domaine** — scores 0–10 par domaine (firewall · SSH · hardening · updates · file_perms)
- **Mode diff** — `--diff` affiche uniquement les changements depuis la dernière baseline
- **Mode watch** — `--watch[=N]` relance toutes les N secondes

### CLI

```
sudo bob [OPTIONS]
bob --explain [CLÉ]   # sans sudo
```

Options clés : `--verbose` · `-d` (français) · `--offline` · `--fix` · `--apply` · `--check=LISTE` · `--skip=LISTE`
`--output-dir` · `--format` · `--target N` · `--min-level NIVEAU`

Complétion bash : `sudo bob --install-completion`

### i18n

Anglais et français (`--french` / `-d`).

### Installation

```
pipx install bodyguard-of-bits
sudo bob
```

---

© 2026 Cédric Clauzel
