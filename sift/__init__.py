"""sift-sim — detect hidden / suspicious patterns in LLM-style text.

Five detectors, each with a 0..1 score. The library returns a
:class:`SiftReport` that lists every hit with confidence, type, and the
exact span of text that triggered it.
"""

from __future__ import annotations

from .report import Finding, SiftReport
from .scanner import Sift

__all__ = ["Sift", "SiftReport", "Finding"]
__version__ = "0.1.0"
