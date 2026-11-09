#!/usr/bin/env python3
"""Generate redistribution materials in a build directory, never in the source tree."""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0"}
# Declarations reviewed in these exact module versions, not blanket exceptions.
DECLARATIONS = {
    ("github.com/OpenDNS/vegadns2client", "v0.0.0-20180418235048-a3fa4a771d87"): ("LICENSE", "apache"),
    ("github.com/alibabacloud-go/endpoint-util", "v1.1.0"): ("README.md", "readme"),
    ("github.com/go-acme/tencentclouddnspod", "v1.0.1208"): ("v20210323/modifiedclient.go", "header"),
    ("github.com/nrdcg/oci-go-sdk/common/v1065", "v1065.95.2"): ("common.go", "dual"),
    ("github.com/nrdcg/oci-go-sdk/dns/v1065", "v1065.95.2"): ("dns_client.go", "dual"),
}


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, env={**os.environ, "CGO_ENABLED": "0"}, text=True)


def json_stream(text):
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        text = text.lstrip()[end:]
        yield value


def owner(package, modules):
    return max((name for name in modules if package == name or package.startswith(name + "/")), key=len)


def declaration(module):
    key = (module["Path"], module["Version"])
    if key not in DECLARATIONS:
        raise ValueError(f"License requires review: {key[0]}@{key[1]}")
    filename, kind = DECLARATIONS[key]
    text = (Path(module["Dir"]) / filename).read_text()
    if kind == "readme":
        text = text[text.index("## License"):]
    elif kind in {"header", "dual"}:
        text = text.split("\npackage ", 1)[0]
        if kind == "dual":
            text = "\n".join(text.splitlines()[:2]) + "\n"
    if not any(marker in text for marker in ("Apache License", "Apache-2.0")):
        raise ValueError(f"Expected Apache declaration missing: {key}")
    return filename, text


def source_url(module):
    path = "".join("!" + c.lower() if c.isupper() else c for c in module["Path"])
    return "https://proxy.golang.org/" + path + "/@v/" + urllib.parse.quote(module["Version"], safe="") + ".zip"


def is_notice(path):
    return path.is_file() and path.name.lower().startswith(
        ("license", "licence", "notice", "copying", "copyright", "authors", "patents")
    )


def source_metadata(info):
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def generate(output, go, scanner):
    output = output.resolve()
    if output == ROOT or output in ROOT.parents:
        raise ValueError("The output must be a build directory, not the repository or an ancestor")
    output.mkdir(parents=True, exist_ok=True)
    # Verify both extracted sources and module ZIPs before redistributing them.
    run(go, "mod", "verify")
    packages = list(json_stream(run(go, "list", "-deps", "-json", ".")))
    modules = {p["Module"]["Path"]: p["Module"] for p in packages
               if p.get("Module", {}).get("Version")}
    own = next(p["Module"]["Path"] for p in packages if p.get("Module", {}).get("Main"))
    with tempfile.TemporaryDirectory(prefix=".legal-", dir=output) as scratch:
        stage = Path(scratch)
        template = stage / "report.tmpl"
        template.write_text("{{range .}}{{.Name}}\t{{.LicenseName}}\t{{.LicensePath}}\n{{end}}")
        report = run(scanner, "report", ".", "--ignore", own, "--template", str(template))
        families = {name: set() for name in modules}
        texts = {}
        for package, license_id, filename in csv.reader(io.StringIO(report), delimiter="\t"):
            name = owner(package, modules)
            module = modules[name]
            if license_id == "Unknown":
                relative, text = declaration(module)
                texts[f"{name}@{module['Version']}/{relative}"] = text
                license_id = "Apache-2.0"
            elif license_id not in ALLOWED:
                raise ValueError(f"License compatibility requires review: {package}: {license_id}")
            else:
                path = Path(filename)
                relative = path.relative_to(module["Dir"])
                texts[f"{name}@{module['Version']}/{relative}"] = path.read_text()
            families[name].add(license_id)
        missing = [name for name, ids in families.items() if not ids]
        if missing:
            raise ValueError(f"Incomplete license inventory: {missing}")
        # Include notices at each compiled package's directory and its module ancestors.
        for package in packages:
            module = package.get("Module", {})
            if not module.get("Version"):
                continue
            directory, base = Path(package["Dir"]), Path(module["Dir"])
            while True:
                for path in directory.iterdir():
                    if is_notice(path):
                        texts[f"{module['Path']}@{module['Version']}/{path.relative_to(base)}"] = path.read_text()
                if directory == base:
                    break
                if base not in directory.parents:
                    raise ValueError(f"Package escaped module directory: {package['ImportPath']}")
                directory = directory.parent
        # Full Apache text also covers the reviewed short-form declarations.
        if any("Apache-2.0" in ids for ids in families.values()):
            apache = next((text for text in texts.values()
                           if "TERMS AND CONDITIONS FOR USE, REPRODUCTION" in text), None)
            if apache is None:
                raise ValueError("Full Apache-2.0 text missing; review the distribution notices")
            texts["Apache-2.0 (full text)"] = apache
        goroot = Path(run(go, "env", "GOROOT").strip())
        for filename in ("LICENSE", "PATENTS"):
            if (goroot / filename).is_file():
                texts[f"Go/{filename}"] = (goroot / filename).read_text()
        lines = ["Third-party redistribution materials", "Go toolchain: " + run(go, "env", "GOVERSION").strip(),
                 "", "MPL source files are supplied in MPL-2.0-SOURCES.tar.gz.",
                 "Oracle OCI components are distributed under their Apache-2.0 option.", "", "Module inventory:"]
        for name, module in sorted(modules.items()):
            lines.append(f"{name}@{module['Version']} — {', '.join(sorted(families[name]))}\n  {source_url(module)}")
        for label, text in sorted(texts.items()):
            lines.extend(["", "=" * 72, label, "=" * 72, text])
        (stage / "THIRD_PARTY_LICENSES.txt").write_text("\n".join(lines) + "\n")
        with tarfile.open(stage / "MPL-2.0-SOURCES.tar.gz", "w:gz") as archive:
            for name, module in sorted(modules.items()):
                if "MPL-2.0" not in families[name]:
                    continue
                base = Path(module["Dir"])
                for path in sorted(base.rglob("*")):
                    if path.is_symlink():
                        raise ValueError(f"Unexpected source symlink: {name}")
                    if path.is_file():
                        relative = f"{name}@{module['Version']}/{path.relative_to(base)}"
                        archive.add(path, arcname=relative, recursive=False, filter=source_metadata)
        for filename in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            shutil.copyfile(ROOT / filename, stage / filename)
        for filename in ("LICENSE", "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_LICENSES.txt", "MPL-2.0-SOURCES.tar.gz"):
            os.replace(stage / filename, output / filename)
    print(f"Generated notices for {len(modules)} modules; MPL sources included")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--scanner", default="go-licenses")
    args = parser.parse_args()
    try:
        generate(args.output, args.go, args.scanner)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"License packaging failed: {error}\n")
