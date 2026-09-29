import os
import sys

# Make run_pipeline.py importable as a top-level module from tests/, regardless of
# whether pytest is invoked from this directory or the repo root. Mirrors
# services/ingest-api/conftest.py and every hyphenated service's own conftest.py.
_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)
