"""
MalwareBazaar detection-coverage sweep.

A harness that builds a corpus of live malware plus known-clean controls, runs
every file through MetaDefender Cloud (sandbox, AV multiscan and Deep CDR), and
reports how the product rated files whose nature is already known.

Module layout, in the order a run uses them:

* ``config``          endpoints, catalogues, verdict ordering, timing budgets
* ``malwarebazaar``   abuse.ch queries, candidate pool, day-spread selection
* ``downloads``       where files land, and how that directory is guarded
* ``cleanfiles``      known-clean controls, and mutating them to a unique hash
* ``runstore``        dated run folders, manifests, cross-run state
* ``submit``          POSTing files to MetaDefender Cloud
* ``reportfetch``     reading scan payloads and sandbox reports back
* ``polling``         driving the submitted batch to completion
* ``reporting``       the Markdown report, the CSV, the console summary

The command-line entry point is ``malwarebazaar-sweep.py`` beside this package.
"""

__all__ = [
    "config",
    "malwarebazaar",
    "downloads",
    "cleanfiles",
    "runstore",
    "submit",
    "reportfetch",
    "polling",
    "reporting",
]
