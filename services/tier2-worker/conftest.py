import os
import sys

# Make the service's modules (providers.py, prompt.py, etc.) importable as
# top-level modules from tests/, regardless of whether pytest is invoked from
# this directory or the repo root. Mirrors services/ingest-api/conftest.py.
sys.path.insert(0, os.path.dirname(__file__))
