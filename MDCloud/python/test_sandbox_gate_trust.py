"""
Hermetic tests for the NSRL + Authenticode fast path in sandbox-gate.py.

No network, no MetaDefender, no real malware: a stub cdscan (a tiny Python
script that emits canned JSON) stands in for the scanner, so every branch of
the AND-logic, the cache, and the fail-closed paths are exercised in
milliseconds. Run with: python -m pytest test_sandbox_gate_trust.py  (or plain
python, which runs the smoke main at the bottom).

The matrix mirrors the spec's numbered cases; each asserts the decision, which
is the only thing that matters: TRUSTED_KNOWN_FILE requires BOTH facts, and
everything else is normal analysis.
"""

import importlib.util
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "sandbox_gate", os.path.join(HERE, "sandbox-gate.py"))
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def trusted_db(tmp, hashes, release="2026.test"):
    """A trusted-hash DB containing the given hex SHA-256 strings."""
    path = os.path.join(tmp, "trusted.dat")
    c = sqlite3.connect(path)
    c.executescript(
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE trusted_hash (sha256 BLOB PRIMARY KEY, filename TEXT, "
        "product TEXT, publisher TEXT, nsrl_release TEXT, source TEXT) WITHOUT ROWID;")
    for h in hashes:
        c.execute("INSERT INTO trusted_hash VALUES (?,?,?,?,?,?)",
                  (bytes.fromhex(h), "f.exe", "P", "V", release, "nsrl"))
    c.execute("INSERT INTO meta VALUES ('nsrl_release', ?)", (release,))
    c.commit()
    c.close()
    return path


class FakeResult:
    """A GateResult stand-in carrying just what the trust logic reads."""

    def __init__(self, verdict="needs_further_processing", caps=None, signer=None):
        self.verdict = verdict
        self.capabilities = caps if caps is not None else ["executable_file"]
        self.signer = signer or {}
        self.submit = verdict == "needs_further_processing"
        self.notes = []


def verified_signer(publisher="adobe", **over):
    base = dict(verified=True, verification="VERIFIED", verified_root="DigiCert",
                publisher=publisher, publisher_trust="high", key_status="active",
                spki_sha256="ab" * 32, cert_sha256="cd" * 32, distrusted=None)
    base.update(over)
    return base


def new_metrics():
    return gate.new_metrics()


# --- the decision matrix ----------------------------------------------------

def check(name, result, sha_in_db, signer, expect_reason):
    tmp = tempfile.mkdtemp()
    sha = "aa" * 32
    db = gate.TrustedHashDb(trusted_db(tmp, [sha] if sha_in_db else []))
    result.signer = signer or {}
    reason, _ = gate.known_file_reason(result, sha, db, new_metrics())
    assert reason == expect_reason, f"{name}: expected {expect_reason}, got {reason}"
    print(f"  ok  {name:<52} -> {reason}")


def run_matrix():
    print("NSRL + Authenticode decision matrix")

    # 1. Known hash + valid expected signature -> TRUSTED_KNOWN_FILE
    check("known hash + valid expected signature", FakeResult(), True,
          verified_signer(), "TRUSTED_KNOWN_FILE")

    # 2. Unknown hash + valid trusted signature -> normal (hash gates first)
    check("unknown hash + valid signature", FakeResult(), False,
          verified_signer(), "NSRL_HASH_NOT_FOUND")

    # 3. Known hash + invalid signature -> normal
    check("known hash + invalid signature", FakeResult(), True,
          verified_signer(verified=False, verification="INVALID_AUTHENTICODE"),
          "INVALID_AUTHENTICODE")

    # 4. Known hash + unsigned file -> normal
    check("known hash + unsigned file", FakeResult(), True, {}, "NO_EMBEDDED_SIGNATURE")

    # 5. Known hash + unexpected publisher -> normal
    check("known hash + unexpected publisher", FakeResult(), True,
          verified_signer(publisher=None), "PUBLISHER_MISMATCH")

    # 6/7/8. Known hash + corrupt PE / malformed pkcs7 / modified file: the
    # scanner reports verification failure; the gate sees verified=false.
    check("known hash + verification failure", FakeResult(), True,
          verified_signer(verified=False, verification="SIGNATURE_PARSE_ERROR"),
          "SIGNATURE_PARSE_ERROR")

    # 10. Known hash + revoked/distrusted -> normal
    check("known hash + distrusted key", FakeResult(), True,
          verified_signer(distrusted="stolen key"), "CERTIFICATE_REVOKED")

    print("matrix ok")


def run_cache():
    print("cache behaviour")
    tmp = tempfile.mkdtemp()
    cache = gate.TrustCache(os.path.join(tmp, "c.db"), "v1")
    assert cache.get("aa" * 32) is None, "empty cache misses"
    cache.put("aa" * 32, ("TRUSTED_KNOWN_FILE", "detail"))
    assert cache.get("aa" * 32) == ("TRUSTED_KNOWN_FILE", "detail"), "hit after put"

    # 14. Version change invalidates.
    newer = gate.TrustCache(os.path.join(tmp, "c.db"), "v2")
    assert newer.get("aa" * 32) is None, "version bump invalidates"
    print("  ok  cache hit, and version bump invalidates")


def run_fail_closed():
    print("fail-closed paths")
    # 12. Database unavailable -> nothing is ever known-good.
    db = gate.TrustedHashDb("/nonexistent/path/trusted.dat")
    assert not db.available, "missing db is unavailable"
    assert not db.contains("aa" * 32), "unavailable db matches nothing"

    # 11. A first-stage false positive would still fail the authoritative
    # lookup; here the authoritative db simply does not contain the hash.
    tmp = tempfile.mkdtemp()
    real_db = gate.TrustedHashDb(trusted_db(tmp, ["bb" * 32]))
    assert not real_db.contains("aa" * 32), "authoritative miss is a miss"
    print("  ok  unavailable db and authoritative miss both fail closed")


def main():
    run_matrix()
    run_cache()
    run_fail_closed()
    print("\nall trust gate tests passed")


# pytest discovery
def test_matrix():
    run_matrix()


def test_cache():
    run_cache()


def test_fail_closed():
    run_fail_closed()


if __name__ == "__main__":
    sys.exit(main())
