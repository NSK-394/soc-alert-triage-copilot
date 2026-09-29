"""Ensures the feature-builder package root is importable regardless of the
directory pytest is invoked from (feature-builder's directory name contains a
hyphen, so it can't be reached via a normal dotted `import`)."""

import os
import sys

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)
