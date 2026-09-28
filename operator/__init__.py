"""
operator package for Ghostless.
Re-exports built-in _operator functions to prevent namespace collisions with Python stdlib,
while exposing Ghostless operator modules (merkle, receipts, window_manager, db).
"""

import _operator
from _operator import *

__all__ = [name for name in dir(_operator) if not name.startswith('__')]
