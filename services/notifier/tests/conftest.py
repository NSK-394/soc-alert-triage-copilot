"""Ensures the notifier package root is importable regardless of the
directory pytest is invoked from (sibling service directories contain a
hyphen, so this repo's convention is flat top-level imports per service
rather than dotted package imports)."""

import os
import sys

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)
