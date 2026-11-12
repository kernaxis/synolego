import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sync_security_issues as sync


class SecurityIssueSyncTest(unittest.TestCase):
    def test_identical_finding_causes_no_daily_write(self):
        finding = {"key": "GO-2026-1234", "title": "Example", "body": "Details"}
        identity = ("govulncheck", sync.issue_id("govulncheck", finding["key"]))
        current = {identity: {"number": 1, "title": finding["title"], "body": sync.body_for("govulncheck", finding),
                              "state": "open", "labels": [{"name": "security"}]}}
        with patch.object(sync, "api") as api:
            sync.reconcile(current, {"govulncheck": [finding]})
            api.assert_not_called()

    def test_only_reported_tool_can_close_issues(self):
        go = ("govulncheck", sync.issue_id("govulncheck", "GO-2026-1234"))
        zizmor = ("zizmor", sync.issue_id("zizmor", "rule:file"))
        current = {go: {"number": 1, "state": "open"}, zizmor: {"number": 2, "state": "open"}}
        with patch.object(sync, "api") as api:
            sync.reconcile(current, {"govulncheck": []})
            api.assert_called_once_with("issues/1", "PATCH", {"state": "closed"})

    def test_reappearing_finding_reopens_issue(self):
        finding = {"key": "GO-2026-1234", "title": "Example", "body": "Details"}
        identity = ("govulncheck", sync.issue_id("govulncheck", finding["key"]))
        current = {identity: {"number": 1, "title": finding["title"], "body": sync.body_for("govulncheck", finding),
                              "state": "closed", "labels": [{"name": "security"}]}}
        with patch.object(sync, "api") as api:
            sync.reconcile(current, {"govulncheck": [finding]})
            api.assert_called_once_with("issues/1", "PATCH", {"state": "open"})

    def test_new_finding_has_security_label(self):
        finding = {"key": "GO-2026-1234", "title": "Example", "body": "Details"}
        with patch.object(sync, "api") as api:
            sync.reconcile({}, {"govulncheck": [finding]})
            api.assert_called_once_with("issues", "POST", {
                "title": "Example", "body": sync.body_for("govulncheck", finding), "labels": ["security"]
            })

    def test_missing_security_label_is_added_without_replacing_other_labels(self):
        finding = {"key": "GO-2026-1234", "title": "Example", "body": "Details"}
        identity = ("govulncheck", sync.issue_id("govulncheck", finding["key"]))
        current = {identity: {"number": 1, "title": finding["title"], "body": sync.body_for("govulncheck", finding),
                              "state": "open", "labels": [{"name": "P1"}]}}
        with patch.object(sync, "api") as api:
            sync.reconcile(current, {"govulncheck": [finding]})
            api.assert_called_once_with("issues/1/labels", "POST", {"labels": ["security"]})

    def test_scan_for_old_main_does_not_change_issues(self):
        with patch.dict(os.environ, {"SCANNED_SHA": "a" * 40}), \
                patch.object(sync, "api", return_value={"commit": {"sha": "b" * 40}}) as api, \
                patch.object(sync, "reconcile") as reconcile:
            sync.main()
            api.assert_called_once_with("branches/main")
            reconcile.assert_not_called()

    def test_missing_reports_do_not_close_issues(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {"SCANNED_SHA": "a" * 40, "REPORT_DIR": directory}), \
                patch.object(sync, "api", return_value={"commit": {"sha": "a" * 40}}) as api, \
                patch.object(sync, "reconcile") as reconcile:
            sync.main()
            api.assert_called_once_with("branches/main")
            reconcile.assert_not_called()

    def test_report_from_another_commit_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "govuln-report.json").write_text(json.dumps({
                "schema": 1, "tool": "govulncheck", "sha": "a" * 40, "findings": []
            }))
            with self.assertRaises(ValueError):
                sync.reports(directory, "b" * 40)

    def test_marker_in_human_issue_is_not_managed(self):
        finding = {"key": "GO-2026-1234", "title": "Example", "body": "Details"}
        issue = {"user": {"login": "maintainer"}, "body": sync.body_for("govulncheck", finding)}
        with patch.object(sync, "api", return_value=[issue]):
            self.assertEqual(sync.existing_issues(), {})


if __name__ == "__main__":
    unittest.main()
