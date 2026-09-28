#!/usr/bin/env python3
"""Read-only verifier for public close-1 sweep archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE_URL = "https://challenges.technocore.chat/close-1/"
ALLOWED_HOST = "challenges.technocore.chat"


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https" or target.hostname != ALLOWED_HOST:
            raise ValueError("cross-origin redirect refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_archive_bytes(entry: dict[str, Any], raw: bytes) -> dict[str, Any]:
    status = entry.get("status")
    if status == "full":
        expected = entry.get("file")
        signed_verifiable = True
    elif status == "redacted":
        expected = entry.get("sha256")
        signed_verifiable = False
    else:
        raise ValueError(f"unsupported archive status: {status!r}")
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ValueError("archive entry has no valid expected SHA-256")
    actual = _sha256(raw)
    return {
        "status": status,
        "sha256": actual,
        "expected_sha256": expected,
        "archive_hash_valid": actual == expected,
        "signed_file_preimage_available": signed_verifiable,
        "referee_signature_verified": False,
        "redacted_records": int(entry.get("redacted", 0) or 0),
    }


def _count_exact(value: Any, needle: str) -> int:
    if isinstance(value, dict):
        return sum(_count_exact(item, needle) for item in value.values())
    if isinstance(value, list):
        return sum(_count_exact(item, needle) for item in value)
    return int(value == needle)


def audit_sweep_bytes(raw: bytes, *, trade_id: str, did: str) -> dict[str, Any]:
    record = json.loads(raw)
    if not isinstance(record, dict):
        raise ValueError("sweep record must be a JSON object")
    sweep_input = record.get("input")
    sweep_output = record.get("output")
    if not isinstance(sweep_input, dict) or not isinstance(sweep_output, dict):
        raise ValueError("sweep record requires input and output objects")
    inputs = sweep_input.get("trades", [])
    outputs = sweep_output.get("trades", [])
    if not isinstance(inputs, list) or not isinstance(outputs, list):
        raise ValueError("trade collections must be arrays")
    if len(inputs) != len(outputs):
        raise ValueError("input/output trades are not index-aligned")
    input_sweep = sweep_input.get("n")
    output_sweep = sweep_output.get("sweep")
    if not isinstance(input_sweep, int) or input_sweep != output_sweep:
        raise ValueError("input/output sweep numbers disagree")
    if sweep_input.get("ref") is not None and sweep_output.get("reference") is not None:
        if sweep_input["ref"] != sweep_output["reference"]:
            raise ValueError("input/output reference values disagree")
    if sweep_input.get("close") is not None and sweep_output.get("close") is not None:
        if sweep_input["close"] != sweep_output["close"]:
            raise ValueError("input/output close values disagree")

    for input_trade, output_trade in zip(inputs, outputs):
        if not isinstance(input_trade, dict) or not isinstance(output_trade, dict):
            raise ValueError("input/output trades are not index-aligned")
        input_id = input_trade.get("id")
        output_id = output_trade.get("id")
        if (input_id is not None or output_id is not None) and input_id != output_id:
            raise ValueError("input/output trade IDs are not index-aligned")

    matches: list[dict[str, Any]] = []
    for index, input_trade in enumerate(inputs):
        if not isinstance(input_trade, dict) or input_trade.get("id") != trade_id:
            continue
        output_trade = outputs[index]
        if not isinstance(output_trade, dict) or output_trade.get("id") != trade_id:
            raise ValueError("input/output trade IDs are not index-aligned")
        item = {
            "input_index": index,
            "terms": input_trade,
            "outcome_record": output_trade,
            "outcome": output_trade.get("outcome"),
        }
        if "reason" in output_trade:
            item["reason"] = output_trade["reason"]
        if "countersigner" in input_trade:
            item["countersigner"] = input_trade["countersigner"]
        matches.append(item)

    return {
        "sweep": output_sweep,
        "reference": sweep_output.get("reference", sweep_input.get("ref")),
        "close": sweep_output.get("close", sweep_input.get("close")),
        "global_price": sweep_output.get("global_price"),
        "trade_id": trade_id,
        "trade_matches": matches,
        "did": did,
        "did_occurrences": _count_exact(record, did),
    }


def _validate_requested_evidence(audit: dict[str, Any], trade_id: str) -> None:
    matches = audit["trade_matches"]
    if not matches:
        raise ValueError(f"trade id {trade_id!r} not found in sweep {audit['sweep']}")
    did = audit["did"]
    if not any(_count_exact(match["terms"], did) for match in matches):
        raise ValueError(f"requested DID is unrelated to trade id {trade_id!r}")


def _get(url: str) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != ALLOWED_HOST:
        raise ValueError("only HTTPS reads from challenges.technocore.chat are allowed")
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "close1-audit/1.0"})
    opener = urllib.request.build_opener(_SameOriginRedirectHandler())
    with opener.open(request, timeout=60) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != ALLOWED_HOST:
            raise ValueError("cross-origin redirect refused")
        return response.read()


def _archive_url(path: str) -> str:
    if not isinstance(path, str) or path.startswith("/") or ".." in path.split("/"):
        raise ValueError("unsafe archive path")
    return urllib.parse.urljoin(BASE_URL, path)


def fetch_and_audit(*, sweep: int, trade_id: str, did: str) -> dict[str, Any]:
    index_raw = _get(urllib.parse.urljoin(BASE_URL, "index.json"))
    index = json.loads(index_raw)
    entries = index.get("sweeps") if isinstance(index, dict) else None
    if not isinstance(entries, list):
        raise ValueError("invalid archive index")
    entry = next((item for item in entries if isinstance(item, dict) and item.get("n") == sweep), None)
    if entry is None:
        raise ValueError(f"sweep {sweep} is absent from the archive index")
    raw = _get(_archive_url(entry.get("path")))
    verification = verify_archive_bytes(entry, raw)
    if not verification["archive_hash_valid"]:
        raise ValueError("archive SHA-256 mismatch")
    audit = audit_sweep_bytes(raw, trade_id=trade_id, did=did)
    if entry.get("n") != audit["sweep"]:
        raise ValueError("archive entry and record disagree on sweep number")
    _validate_requested_evidence(audit, trade_id)
    return {
        "source": {
            "provenance": "official_https_index",
            "base_url": BASE_URL,
            "entry": entry,
        },
        "verification": verification,
        "audit": audit,
    }


def audit_local_files(
    *, entry_file: str | Path, sweep_file: str | Path, trade_id: str, did: str
) -> dict[str, Any]:
    """Audit already-downloaded files without making a network request."""
    entry = json.loads(Path(entry_file).read_text(encoding="utf-8"))
    if not isinstance(entry, dict):
        raise ValueError("archive entry file must contain a JSON object")
    raw = Path(sweep_file).read_bytes()
    verification = verify_archive_bytes(entry, raw)
    if not verification["archive_hash_valid"]:
        raise ValueError("archive SHA-256 mismatch")
    audit = audit_sweep_bytes(raw, trade_id=trade_id, did=did)
    if entry.get("n") != audit["sweep"]:
        raise ValueError("archive entry and record disagree on sweep number")
    _validate_requested_evidence(audit, trade_id)
    return {
        "source": {
            "provenance": "local_unverified_entry",
            "entry_file": str(Path(entry_file)),
            "sweep_file": str(Path(sweep_file)),
            "entry": entry,
        },
        "verification": verification,
        "audit": audit,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--sweep", type=int, help="download and audit this official sweep")
    mode.add_argument("--sweep-file", help="audit an already-downloaded sweep file")
    parser.add_argument("--entry-file", help="index entry JSON required with --sweep-file")
    parser.add_argument("--trade-id", required=True)
    parser.add_argument("--did", required=True)
    parser.add_argument("--output", help="write the JSON report to this path")
    args = parser.parse_args(argv)
    if args.sweep_file:
        if not args.entry_file:
            parser.error("--entry-file is required with --sweep-file")
        result = audit_local_files(
            entry_file=args.entry_file,
            sweep_file=args.sweep_file,
            trade_id=args.trade_id,
            did=args.did,
        )
    else:
        if args.entry_file:
            parser.error("--entry-file is only valid with --sweep-file")
        result = fetch_and_audit(sweep=args.sweep, trade_id=args.trade_id, did=args.did)
    rendered = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if args.output:
        with open(args.output, "x", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
