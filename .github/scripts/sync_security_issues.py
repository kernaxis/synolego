#!/usr/bin/env python3
"""Reconcile bot-owned issues from complete scans of the current main commit."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


MARKER = re.compile(r"<!-- security-finding:v1:(govulncheck|zizmor):([0-9a-f]{32}) -->")
TOOLS = {"govulncheck", "zizmor"}
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "")


def api(path, method="GET", payload=None):
    command = ["gh", "api", f"repos/{REPOSITORY}/{path}", "--method", method]
    if payload is not None:
        command += ["--input", "-"]
    response = subprocess.check_output(command, input=json.dumps(payload).encode() if payload is not None else None)
    return json.loads(response)


def issue_id(tool, key):
    return hashlib.sha256(f"{tool}:{key}".encode()).hexdigest()[:32]


def body_for(tool, finding):
    marker = f"<!-- security-finding:v1:{tool}:{issue_id(tool, finding['key'])} -->"
    return f"{marker}\nAutomated finding from `{tool}`.\n\n{finding['body']}\n"


def reports(directory, revision):
    result = {}
    for path in Path(directory).glob("*-report.json"):
        report = json.loads(path.read_text())
        tool = report["tool"]
        if report["schema"] != 1 or tool not in TOOLS or report["sha"] != revision or tool in result:
            raise ValueError(f"Invalid or duplicate report: {path}")
        findings = report["findings"]
        if not isinstance(findings, list) or len(findings) > 200:
            raise ValueError(f"Invalid finding count: {path}")
        keys = [finding["key"] for finding in findings]
        if len(keys) != len(set(keys)):
            raise ValueError(f"Duplicate finding keys: {path}")
        result[tool] = findings
    return result


def existing_issues():
    found = {}
    for page in range(1, 51):
        batch = api(f"issues?state=all&per_page=100&page={page}")
        for issue in batch:
            if "pull_request" in issue or issue.get("user", {}).get("login") != "github-actions[bot]":
                continue
            match = MARKER.search(issue.get("body") or "")
            if match:
                key = (match.group(1), match.group(2))
                if key in found:
                    raise ValueError(f"Duplicate automated issues: {key}")
                found[key] = issue
        if len(batch) < 100:
            return found
    raise ValueError("Issue listing exceeded 5000 records")


def reconcile(current, desired):
    for tool, findings in desired.items():
        active = set()
        for finding in findings:
            identity = (tool, issue_id(tool, finding["key"]))
            active.add(identity)
            title = finding["title"]
            body = body_for(tool, finding)
            issue = current.get(identity)
            if issue is None:
                api("issues", "POST", {"title": title, "body": body, "labels": ["security"]})
                print(f"Created {tool} issue: {finding['key']}")
                continue
            changes = {}
            if issue["title"] != title:
                changes["title"] = title
            if issue["body"] != body:
                changes["body"] = body
            if issue["state"] != "open":
                changes["state"] = "open"
            if changes:
                api(f"issues/{issue['number']}", "PATCH", changes)
                print(f"Updated {tool} issue #{issue['number']}")
            if "security" not in {label["name"] for label in issue.get("labels", [])}:
                api(f"issues/{issue['number']}/labels", "POST", {"labels": ["security"]})
        for identity, issue in current.items():
            if identity[0] == tool and identity not in active and issue["state"] == "open":
                api(f"issues/{issue['number']}", "PATCH", {"state": "closed"})
                print(f"Closed {tool} issue #{issue['number']}")


def main():
    revision = os.environ["SCANNED_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid scanned commit SHA")
    current_main = api("branches/main")["commit"]["sha"]
    if current_main != revision:
        print("Main advanced after this scan; leaving issues unchanged")
        return
    desired = reports(os.environ["REPORT_DIR"], revision)
    if not desired:
        print("No complete scanner reports; leaving issues unchanged")
        return
    reconcile(existing_issues(), desired)


if __name__ == "__main__":
    main()
