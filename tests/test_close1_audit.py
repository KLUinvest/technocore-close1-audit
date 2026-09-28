import hashlib
import json
import unittest

from close1_audit import audit_sweep_bytes, verify_archive_bytes


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
        self.assertTrue(result["signed_file_hash_verifiable"])

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
        self.assertFalse(result["signed_file_hash_verifiable"])
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


if __name__ == "__main__":
    unittest.main()
