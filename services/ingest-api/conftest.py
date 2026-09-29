import os
import sys

# Make `main.py`/`db.py` importable as top-level modules from tests/, regardless of
# whether pytest is invoked from this directory or the repo root.
sys.path.insert(0, os.path.dirname(__file__))
