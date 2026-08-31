"""
Scanner truth vs gate policy (spec #3, #12).

The gate must never rewrite the scanner's verdict. Severity filtering may
*withhold* a file by policy, and trust may *skip* one, but neither may relabel a
`needs_further_processing` as `clean`. These tests pin that separation at the
unit level — no subprocess, no scanner — by exercising `base_gate_decision` and
`GateResult` directly.

Run: python -m pytest test_sandbox_gate_policy.py  (or plain python for the
smoke main at the bottom).
"""

import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "sandbox_gate", os.path.join(HERE, "sandbox-gate.py"))
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def result(scanner_verdict, capabilities=None, ignored=None, incomplete=False):
    return gate.GateResult(
        "f.bin", scanner_verdict, capabilities or [], [], 1.0, 1.0,
        ignored=ignored or [], incomplete=incomplete)


def run_matrix():
    print("scanner verdict is never rewritten")

    # 1. clean -> withhold, verdict stays clean.
    r = result("clean")
    assert r.scanner_verdict == "clean"
    assert not r.submit and r.gate_reason == "SCANNER_CLEAN"

    # 2. indeterminate -> submit, never withheld.
    r = result("indeterminate")
    assert r.scanner_verdict == "indeterminate"
    assert r.submit and r.gate_reason == "SCANNER_INDETERMINATE"

    # 3. needs_further_processing with an actionable capability -> submit.
    r = result("needs_further_processing", capabilities=["executable_file"])
    assert r.submit and r.gate_reason == "CAPABILITY_ABOVE_FLOOR"
    assert r.scanner_verdict == "needs_further_processing"

    # 4. THE #3 CASE: needs_further_processing, every finding below the floor,
    #    scan complete -> withheld BY POLICY, but the scanner verdict is still
    #    needs_further_processing. It must never read as clean.
    r = result("needs_further_processing", capabilities=[], ignored=["url"],
               incomplete=False)
    assert not r.submit, "a complete below-floor scan is withheld by policy"
    assert r.gate_reason == "BELOW_SEVERITY_FLOOR"
    assert r.scanner_verdict == "needs_further_processing", \
        "the scanner verdict must not be rewritten to clean"
    assert r.scanner_verdict != "clean"

    # 5. Same, but the scan was INCOMPLETE: an empty actionable set over content
    #    we could not fully read is not "nothing there" -> submit.
    r = result("needs_further_processing", capabilities=[], ignored=["url"],
               incomplete=True)
    assert r.submit and r.gate_reason == "INCOMPLETE_SCAN"

    # 6. An unrecognised verdict is a reason to be careful -> submit.
    r = result("something_new")
    assert r.submit and r.gate_reason == "UNKNOWN_VERDICT"

    print("  ok  clean/indeterminate/nfp/floor/incomplete/unknown all correct")


def run_trust_separation():
    print("trust skips without touching the scanner verdict")

    # A trusted known file: the scanner said needs_further_processing (e.g. it is
    # an executable). Trust turns the gate decision into a skip, but the scanner
    # verdict underneath is untouched and is NOT relabelled clean.
    r = result("needs_further_processing", capabilities=["executable_file"])
    assert r.submit
    r.withhold_by_trust("trusted_known_file", "TRUSTED_KNOWN_FILE: nsrl")
    assert not r.submit
    assert r.trust_status == "trusted_known_file"
    assert r.gate_reason == "trusted_known_file"
    assert r.scanner_verdict == "needs_further_processing", \
        "trust must not rewrite the scanner verdict"
    assert r.scanner_verdict != "clean"
    print("  ok  trusted_known_file skips, scanner_verdict preserved")


def run_no_clean_from_findings():
    print("no combination of policy turns findings into clean")
    # Exhaustively: for any nfp result, across floor withhold and trust skip,
    # the scanner verdict is never clean.
    for caps, ig, inc in [([], ["url"], False), ([], ["url"], True),
                          (["macro"], [], False), ([], [], False)]:
        r = result("needs_further_processing", capabilities=caps, ignored=ig,
                   incomplete=inc)
        assert r.scanner_verdict != "clean"
        if r.submit:
            r.withhold_by_trust("trusted_known_file", "x")
        assert r.scanner_verdict != "clean"
    print("  ok  scanner_verdict stays needs_further_processing throughout")


def main():
    run_matrix()
    run_trust_separation()
    run_no_clean_from_findings()
    print("\nall policy-separation tests passed")


def test_matrix():
    run_matrix()


def test_trust_separation():
    run_trust_separation()


def test_no_clean_from_findings():
    run_no_clean_from_findings()


if __name__ == "__main__":
    main()
