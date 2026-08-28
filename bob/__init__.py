"""BOB — Bodyguard Of Bits."""

import logging
import os
import sys

__version__ = "0.13.4"
__all__ = ["__version__"]

# v0.13.3: BOB never configured logging, so every ``logger.warning`` /
# ``logger.error`` in the package (~45 sites) fell through to Python's
# *lastResort* handler and printed a raw, un-prefixed, un-i18n'd line on
# stderr — bypassing ``--quiet`` and doubling the messages that BOB already
# emits through ``output.print_warn`` (visible on ``bob --profile=typo``).
#
# A NullHandler on the package logger stops lastResort without touching
# propagation: records still reach the root logger, so pytest's ``caplog``
# and any handler a downstream user configures keep working unchanged.
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Opt-in diagnostics. Must live here rather than in ``__main__`` because
# ``bob/i18n.py`` and ``bob/registry.py`` call ``resolve_share_dir()`` at
# module-import time, and that helper logs warnings for an invalid
# ``BOB_SHARE`` — configuring logging any later would silently drop exactly
# the records this switch exists to surface.
if os.environ.get("BOB_DEBUG"):
    logging.basicConfig(
        level=logging.DEBUG,
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )
