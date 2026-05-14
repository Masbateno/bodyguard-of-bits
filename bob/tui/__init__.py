"""
BOB TUI subpackage — curses-based interactive UIs.

Modules in this subpackage import ``curses`` and are only loaded when an
interactive flow needs them. The audit pipeline (`bob.runner`, `bob.checks.*`)
NEVER imports from `bob.tui` — that allows packagers to ship a `bob-core`
variant without the curses dependency for minimal container / headless / build
environments. Adding a runtime dependency on `curses` to this subpackage MUST
keep the rest of `bob.*` importable when `curses` is missing.

Public flows that use this subpackage:
  - bob.cron.run_install_cron / run_manage_cron → bob.tui.cron
  - (future) interactive --explain picker, log browser → here

Import policy: from within `bob.tui.*`, prefer ``import curses`` at the top
of the file (we're in TUI-land by definition). From within `bob.*` (non-TUI),
import from `bob.tui.*` LAZILY inside functions so the import cost / failure
is paid only at TUI invocation time.
"""
