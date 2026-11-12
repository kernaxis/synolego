import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from security_reports import govulncheck, main, zizmor


class SecurityReportsTest(unittest.TestCase):
    def test_govulncheck_groups_by_advisory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "govuln.jsonl"
            path.write_text("\n".join(json.dumps(message, indent=2) for message in [
                {"config": {"scanner_name": "govulncheck", "scan_level": "symbol", "scan_mode": "source"}},
                {"osv": {"id": "GO-2026-1234", "summary": "Example issue"}},
                {"finding": {"osv": "GO-2026-1234", "trace": [{"module": "example.org/unreachable"}]}},
                {"finding": {"osv": "GO-2026-1234", "trace": [{"module": "example.org/a", "function": "Vulnerable"}]}},
                {"finding": {"osv": "GO-2026-1234", "trace": [{"module": "example.org/b", "function": "Vulnerable"}]}},
            ]))
            findings = govulncheck(path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["key"], "GO-2026-1234")
            self.assertIn("example.org/a, example.org/b", findings[0]["body"])
            self.assertNotIn("example.org/unreachable", findings[0]["body"])

    def test_unreachable_go_finding_does_not_open_issue(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "govuln.json"
            path.write_text("\n".join(json.dumps(message, indent=2) for message in [
                {"config": {"scan_level": "symbol", "scan_mode": "source"}},
                {"osv": {"id": "GO-2026-1234"}},
                {"finding": {"osv": "GO-2026-1234", "trace": [{"module": "example.org/a"}]}},
            ]))
            self.assertEqual(govulncheck(path), [])

    def test_zizmor_key_ignores_line_and_suppressed_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "zizmor.sarif"
            result = {"ruleId": "zizmor/unpinned-uses", "message": {"text": "Unpinned action"},
                      "locations": [{"physicalLocation": {"artifactLocation": {
                          "uri": "jellyfin-mcp/.github/workflows/ci.yml"},
                          "region": {"startLine": 10}}}]}
            path.write_text(json.dumps({"runs": [{"results": [result, result | {"suppressions": [{}]}]}]}))
            findings = zizmor(path)
            self.assertEqual([item["key"] for item in findings],
                             ["zizmor/unpinned-uses:.github/workflows/ci.yml"])

    def test_scan_error_cannot_produce_closing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "scan.sarif"
            target = Path(directory) / "zizmor-report.json"
            source.write_text(json.dumps({"runs": [{"results": []}]}))
            with patch.object(sys, "argv", ["security_reports.py", "zizmor", str(source), str(target), "1"]), \
                    patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
                with self.assertRaises(ValueError):
                    main()
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
