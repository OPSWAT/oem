"""
Run output in three shapes, each for a different reader.

* ``markdown``   the report a product team reads: a summary table across the
                 whole run, then a dossier per sample
* ``csvexport``  one flat row per sample, for trending across runs
* ``console``    the short terminal summary printed when a run finishes

Keeping these apart from the collection code means the output can be reshaped
without touching anything that talks to an API.
"""

from .console import print_console_summary
from .csvexport import write_csv
from .markdown import build_report

__all__ = ["build_report", "write_csv", "print_console_summary"]
