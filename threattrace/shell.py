"""Entry point wrapper for the interactive shell (threattrace-shell command)."""
import sys
import os

# Ensure the project root is on the path so main.py can be found
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

from main import main  # noqa: E402

__all__ = ["main"]
