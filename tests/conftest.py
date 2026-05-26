import sys
import os
import pytest

# Ensure the project root is on sys.path so that `import cygor` works
# even when running tests from a subdirectory.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
