import hashlib
import json
import unittest

from close1_audit import (
    _SameOriginRedirectHandler,
    _archive_url,
    audit_local_files,
    audit_sweep_bytes,
    verify_archive_bytes,
)


DID = "did:key:z6MkmGZTwZzkTVxKgEmUCWBGmEWyZszcA2qLC9PfF7WucJTy"
TRADE_ID = "msea2d166ee04c17"


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ArchiveAuditTests(unittest.TestCase):
    def test_full_entry_verifies_against_signed_file_hash(self):
        raw = b'{"input":{},"output":{}}'
        digest = hashlib.sha256(raw).hexdigest()
        entry = {"status": "full", "file": digest, "path": f"sweeps/{digest}.json"}
        result = verify_archive_bytes(entry, raw)
        self.assertTrue(result["archive_hash_valid"])
        self.assertTrue(result["signed_file_preimage_available"])
        self.assertFalse(result["referee_signature_verified"])

    def test_redacted_entry_verifies_archive_hash_but_not_signed_preimage(self):
        raw = b'{"input":{"trades":[{"redacted":"private room"}]},"output":{}}'
        digest = hashlib.sha256(raw).hexdigest()
        entry = {
            "status": "redacted",
            "file": "0" * 64,
            "sha256": digest,
            "redacted": 1,
            "path": "redacted/example.json",
        }
        result = verify_archive_bytes(entry, raw)
        self.assertTrue(result["archive_hash_valid"])
        self.assertFalse(result["signed_file_preimage_available"])
        self.assertFalse(result["referee_signature_verified"])
        self.assertEqual(result["redacted_records"], 1)

    def test_exact_trade_id_joins_input_and_output_by_index(self):
        record = {
            "input": {
                "t": "sweep",
                "n": 646,
                "ref": "225.21",
                "close": "225.33",
                "owners": [],
                "trades": [
                    {"id": "msea2d166ee04c170", "maker": DID},
                    {
                        "id": TRADE_ID,
                        "maker": DID,
                        "countersigner": "did:key:z6MkTaker",
                        "px": "225.21",
                        "qty": "5",
                        "side": "sell",
                        "taker": "any",
                        "until": 692,
                    },
                ],
            },
            "output": {
                "sweep": 646,
                "reference": "225.21",
                "close": "225.33",
                "global_price": "224.66",
                "minted": [],
                "trades": [
                    {"id": "msea2d166ee04c170", "outcome": "settled"},
                    {"id": TRADE_ID, "outcome": "void", "reason": "funds"},
                ],
            },
        }
        result = audit_sweep_bytes(compact(record), trade_id=TRADE_ID, did=DID)
        self.assertEqual(result["sweep"], 646)
        self.assertEqual(result["trade_matches"][0]["input_index"], 1)
        self.assertEqual(result["trade_matches"][0]["outcome"], "void")
        self.assertEqual(result["trade_matches"][0]["reason"], "funds")
        self.assertEqual(result["trade_matches"][0]["countersigner"], "did:key:z6MkTaker")
        self.assertEqual(result["did_occurrences"], 2)

    def test_substring_is_not_an_exact_trade_match(self):
        record = {
            "input": {"n": 7, "trades": [{"id": TRADE_ID + "x"}]},
            "output": {"sweep": 7, "trades": [{"id": TRADE_ID + "x", "outcome": "settled"}]},
        }
        result = audit_sweep_bytes(compact(record), trade_id=TRADE_ID, did=DID)
        self.assertEqual(result["trade_matches"], [])

    def test_mismatched_output_index_is_reported_fail_closed(self):
        record = {
            "input": {"n": 8, "trades": [{"id": TRADE_ID}]},
            "output": {"sweep": 8, "trades": [{"id": "other", "outcome": "settled"}]},
        }
        with self.assertRaisesRegex(ValueError, "index-aligned"):
            audit_sweep_bytes(compact(record), trade_id=TRADE_ID, did=DID)

    def test_non_target_trade_misalignment_is_also_rejected(self):
        record = {
            "input": {"n": 8, "trades": [{"id": TRADE_ID}, {"id": "other"}]},
            "output": {
                "sweep": 8,
                "trades": [
                    {"id": TRADE_ID, "outcome": "void"},
                    {"id": "wrong", "outcome": "settled"},
                ],
            },
        }
        with self.assertRaisesRegex(ValueError, "index-aligned"):
            audit_sweep_bytes(compact(record), trade_id=TRADE_ID, did=DID)

    def test_input_and_output_sweep_numbers_must_agree(self):
        record = {"input": {"n": 8, "trades": []}, "output": {"sweep": 9, "trades": []}}
        with self.assertRaisesRegex(ValueError, "sweep number"):
            audit_sweep_bytes(compact(record), trade_id=TRADE_ID, did=DID)

    def test_input_and_output_market_values_must_agree(self):
        cases = (
            ("reference", {"ref": "225.20", "close": "225.33"}, {"reference": "225.21", "close": "225.33"}),
            ("close", {"ref": "225.21", "close": "225.32"}, {"reference": "225.21", "close": "225.33"}),
        )
        for field, input_market, output_market in cases:
            record = {
                "input": {"n": 8, "trades": [], **input_market},
                "output": {"sweep": 8, "trades": [], **output_market},
            }
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                audit_sweep_bytes(compact(record), trade_id=TRADE_ID, did=DID)

    def test_hash_mismatch_is_detected(self):
        entry = {"status": "full", "file": "a" * 64}
        result = verify_archive_bytes(entry, b"different bytes")
        self.assertFalse(result["archive_hash_valid"])

    def test_non_hex_digest_is_rejected(self):
        entry = {"status": "full", "file": "z" * 64}
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verify_archive_bytes(entry, b"bytes")

    def test_archive_path_rejects_traversal_and_absolute_paths(self):
        for path in ("../secret", "redacted/../secret", "/absolute.json"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe"):
                _archive_url(path)

    def test_archive_path_accepts_expected_relative_path(self):
        self.assertEqual(
            _archive_url("redacted/example.json"),
            "https://challenges.technocore.chat/close-1/redacted/example.json",
        )

    def test_cross_origin_redirect_is_rejected_before_following(self):
        handler = _SameOriginRedirectHandler()
        with self.assertRaisesRegex(ValueError, "cross-origin"):
            handler.redirect_request(
                None,
                None,
                302,
                "Found",
                {},
                "https://example.com/archive.json",
            )

    def test_local_audit_checks_hash_and_sweep_number(self):
        import tempfile
        from pathlib import Path

        record = {
            "input": {"n": 646, "trades": [{"id": TRADE_ID, "maker": DID}]},
            "output": {"sweep": 646, "trades": [{"id": TRADE_ID, "outcome": "void"}]},
        }
        raw = compact(record)
        entry = {
            "n": 646,
            "status": "full",
            "file": hashlib.sha256(raw).hexdigest(),
            "path": "sweeps/example.json",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry_path = root / "entry.json"
            record_path = root / "sweep.json"
            entry_path.write_text(json.dumps(entry), encoding="utf-8")
            record_path.write_bytes(raw)
            result = audit_local_files(
                entry_file=entry_path,
                sweep_file=record_path,
                trade_id=TRADE_ID,
                did=DID,
            )
        self.assertTrue(result["verification"]["archive_hash_valid"])
        self.assertEqual(result["audit"]["sweep"], 646)

    def test_local_audit_rejects_wrong_sweep_entry(self):
        import tempfile
        from pathlib import Path

        record = {"input": {"n": 646, "trades": []}, "output": {"sweep": 646, "trades": []}}
        raw = compact(record)
        entry = {"n": 645, "status": "full", "file": hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry_path = root / "entry.json"
            record_path = root / "sweep.json"
            entry_path.write_text(json.dumps(entry), encoding="utf-8")
            record_path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "sweep number"):
                audit_local_files(
                    entry_file=entry_path,
                    sweep_file=record_path,
                    trade_id=TRADE_ID,
                    did=DID,
                )

    def test_local_audit_rejects_missing_exact_trade_id(self):
        import tempfile
        from pathlib import Path

        record = {"input": {"n": 646, "trades": []}, "output": {"sweep": 646, "trades": []}}
        raw = compact(record)
        entry = {"n": 646, "status": "full", "file": hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry_path = root / "entry.json"
            record_path = root / "sweep.json"
            entry_path.write_text(json.dumps(entry), encoding="utf-8")
            record_path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "not found"):
                audit_local_files(
                    entry_file=entry_path,
                    sweep_file=record_path,
                    trade_id=TRADE_ID,
                    did=DID,
                )

    def test_local_audit_rejects_unrelated_did(self):
        import tempfile
        from pathlib import Path

        record = {
            "input": {
                "n": 646,
                "trades": [{"id": TRADE_ID, "maker": "did:key:z6MkSomeoneElse"}],
            },
            "output": {"sweep": 646, "trades": [{"id": TRADE_ID, "outcome": "void"}]},
        }
        raw = compact(record)
        entry = {"n": 646, "status": "full", "file": hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry_path = root / "entry.json"
            record_path = root / "sweep.json"
            entry_path.write_text(json.dumps(entry), encoding="utf-8")
            record_path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "DID"):
                audit_local_files(
                    entry_file=entry_path,
                    sweep_file=record_path,
                    trade_id=TRADE_ID,
                    did=DID,
                )


if __name__ == "__main__":
    unittest.main()
