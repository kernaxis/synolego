#!/usr/bin/env python3
"""Convert successful security scans into small, stable issue reports."""

import json
import os
from pathlib import Path
import re
import sys


def govulncheck(path):
    stream = Path(path).read_text()
    decoder = json.JSONDecoder()
    messages = []
    offset = 0
    while offset < len(stream):
        while offset < len(stream) and stream[offset].isspace():
            offset += 1
        if offset < len(stream):
            message, offset = decoder.raw_decode(stream, offset)
            messages.append(message)
    configurations = [message["config"] for message in messages if "config" in message]
    if len(configurations) != 1:
        raise ValueError("govulncheck output has no configuration record")
    config = configurations[0]
    if config.get("scan_level") != "symbol" or config.get("scan_mode") != "source":
        raise ValueError("govulncheck did not complete a source symbol scan")
    advisories = {message["osv"]["id"]: message["osv"] for message in messages if "osv" in message}
    packages = {}
    for message in messages:
        finding = message.get("finding")
        if not finding:
            continue
        trace = finding.get("trace", [])
        if not trace or not trace[0].get("function"):
            continue
        advisory_id = finding["osv"]
        if not re.fullmatch(r"GO-[0-9]{4}-[0-9]+", advisory_id):
            raise ValueError("unexpected Go vulnerability identifier")
        packages.setdefault(advisory_id, set())
        if trace[0].get("module"):
            packages[advisory_id].add(trace[0]["module"])
    results = []
    for advisory_id, modules in sorted(packages.items()):
        advisory = advisories.get(advisory_id, {})
        summary = advisory.get("summary") or advisory_id
        body = f"Advisory: https://pkg.go.dev/vuln/{advisory_id}\n\nAffected modules: " + (
            ", ".join(sorted(modules)) or "see advisory"
        )
        fixes = sorted({event["fixed"] for affected in advisory.get("affected", [])
                        for version_range in affected.get("ranges", [])
                        for event in version_range.get("events", []) if event.get("fixed")})
        if fixes:
            body += "\n\nFixed versions: " + ", ".join(fixes)
        if advisory.get("severity"):
            body += "\n\nSeverity: " + ", ".join(
                f"{item.get('type', 'score')} {item.get('score', '')}" for item in advisory["severity"]
            )
        results.append({"key": advisory_id, "title": f"[security] {advisory_id}: {summary}"[:240], "body": body})
    return results


def zizmor(path):
    report = json.loads(Path(path).read_text())
    runs = report["runs"]
    if not isinstance(runs, list) or not runs:
        raise ValueError("zizmor SARIF has no runs")
    grouped = {}
    for run in runs:
        for result in run.get("results", []):
            if result.get("suppressions"):
                continue
            rule = result.get("ruleId")
            if not rule or not re.fullmatch(r"[A-Za-z0-9_/-]+", rule):
                raise ValueError("zizmor finding has an invalid rule")
            locations = result.get("locations", [])
            if not locations:
                raise ValueError("zizmor finding has no location")
            for location in locations:
                uri = location["physicalLocation"]["artifactLocation"]["uri"]
                uri = uri[uri.index(".github/"):] if ".github/" in uri else uri
                if not uri.startswith(".github/"):
                    raise ValueError("zizmor finding is outside .github")
                key = f"{rule}:{uri}"
                entry = grouped.setdefault(key, {"rule": rule, "file": uri, "messages": set(), "levels": set()})
                entry["messages"].add(result.get("message", {}).get("text", rule))
                entry["levels"].add(result.get("level", "unknown"))
    return [{"key": key, "title": f"[security] zizmor {value['rule']} in {value['file']}"[:240],
             "body": "Severity: " + ", ".join(sorted(value["levels"])) + "\n\n" +
                     "\n\n".join(sorted(value["messages"])) + f"\n\nFile: `{value['file']}`"}
            for key, value in sorted(grouped.items())]


def main():
    tool, source, destination, raw_status = sys.argv[1:]
    status = int(raw_status)
    if tool not in {"govulncheck", "zizmor"} or status not in {0, 3 if tool == "govulncheck" else 14}:
        raise ValueError(f"{tool} did not complete a valid scan (exit {status})")
    findings = (govulncheck if tool == "govulncheck" else zizmor)(source)
    if status != 0 and not findings:
        raise ValueError("scanner failed without structured findings")
    Path(destination).write_text(json.dumps({"schema": 1, "tool": tool, "sha": os.environ["GITHUB_SHA"],
                                             "findings": findings}, sort_keys=True) + "\n")
    print(f"{tool}: {len(findings)} findings")
    if findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
