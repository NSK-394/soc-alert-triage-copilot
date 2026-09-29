"""Make `replay.py` (in the parent directory) importable as `replay` when
tests are run from anywhere, e.g. `pytest` from repo root or from
data/replay-harness/."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
