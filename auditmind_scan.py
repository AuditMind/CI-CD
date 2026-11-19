#!/usr/bin/env python3
import argparse
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile

VERSION = "1.0.0"
DEFAULT_API_URL = "https://api.auditmind.tech"
APP_URL = "https://app.auditmind.tech"
MAX_ARCHIVE_SIZE = 150 * 1024 * 1024
LEVELS = ["low", "medium", "high", "critical"]
IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode",
    "node_modules", "__pycache__", "venv", ".venv", "dist", "build",
}

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class AuditMindError(Exception):
    pass


class AuditMindClient:
    def __init__(self, api_url, api_key):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key

    def _request(self, method, path, data=None, content_type=None):
        request = urllib.request.Request(self.api_url + path, data=data, method=method)
        request.add_header("Authorization", "Bearer " + self.api_key)
        request.add_header("User-Agent", "auditmind-scan/" + VERSION)
        if content_type:
            request.add_header("Content-Type", content_type)

        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                body = response.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AuditMindError("API key was rejected (401). Check AUDITMIND_API_KEY.")
            if e.code == 413:
                raise AuditMindError("The archive is too large (limit 150 MB).")
            if e.code == 429:
                raise AuditMindError("Too many scans started with this API key. Try again later.")
            details = e.read().decode("utf-8", "replace")[:300]
            raise AuditMindError("%s %s failed with %d: %s" % (method, path, e.code, details))
        except urllib.error.URLError as e:
            raise AuditMindError("Could not reach %s: %s" % (self.api_url, e.reason))

        if not body:
            return {}
        return json.loads(body)

    def get(self, path):
        return self._request("GET", path)

    def post_json(self, path, payload):
        return self._request("POST", path, json.dumps(payload).encode("utf-8"), "application/json")

    def upload_zip(self, filename, content):
        boundary = uuid.uuid4().hex
        filename = filename.replace('"', "_")
        body = (
            ("--%s\r\n" % boundary).encode()
            + ('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % filename).encode()
            + b"Content-Type: application/zip\r\n\r\n"
            + content
            + ("\r\n--%s--\r\n" % boundary).encode()
        )
        return self._request("POST", "/v1/repositories/upload", body,
                             "multipart/form-data; boundary=" + boundary)


def make_zip(path):
    # a ready .zip is uploaded as is
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return os.path.basename(path), f.read()

    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise AuditMindError("%s is neither a directory nor a .zip file" % path)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for current_dir, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for name in files:
                file_path = os.path.join(current_dir, name)
                if os.path.islink(file_path):
                    continue
                zf.write(file_path, os.path.relpath(file_path, root))
    return os.path.basename(root) + ".zip", buf.getvalue()


def wait_for_scan(client, scan_id, timeout, interval):
    started = time.time()
    last_status = None

    while time.time() - started < timeout:
        scan = client.get("/v1/scans/%s" % scan_id)["scan"]
        status = scan["status"]
        progress = scan.get("progress", 0)

        if (status, progress) != last_status:
            print("  %s %s%%" % (status, progress), flush=True)
            last_status = (status, progress)

        if status == "complete":
            return
        if status in ("failed", "cancelled"):
            raise AuditMindError("Scan %s: %s" % (status, scan.get("error") or "no details"))

        time.sleep(interval)

    raise AuditMindError("Scan did not finish within %d seconds" % timeout)


def get_level(finding):
    # the json report has no level field, the app shows confidence as the level
    for key in ("level", "confidence"):
        value = str(finding.get(key) or "").lower().strip()
        if value in LEVELS:
            return value
    return "low"


def print_annotation(finding, is_error):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    kind = "error" if is_error else "warning"
    title = "%s: %s" % (get_level(finding).upper(), finding.get("title", "Finding"))
    title = title.replace("\n", " ")
    print("::%s file=%s,line=%s,title=AuditMind::%s" % (
        kind, finding.get("file_path", ""), finding.get("start_line", 1), title))


def run_scan(client, args):
    filename, content = make_zip(args.path)
    if len(content) > MAX_ARCHIVE_SIZE:
        raise AuditMindError("The archive is %d MB, the limit is 150 MB." % (len(content) // 1024 // 1024))

    print("Uploading %s (%d KB)" % (filename, len(content) // 1024), flush=True)
    repo = client.upload_zip(filename, content)

    files = client.get("/v1/repositories/%s/files" % repo["id"])["files"]
    paths = [f["path"] for f in files if f.get("selected")]
    if not paths:
        paths = [f["path"] for f in files]
    if not paths:
        raise AuditMindError("No files to scan were found in the archive.")

    scan = client.post_json("/v1/scans", {
        "repository_id": repo["id"],
        "paths": paths,
        "ai_triage": args.ai_triage,
    })
    print("Scan %s started: %s/en/scans/%s" % (scan["id"], APP_URL, scan["id"]), flush=True)

    wait_for_scan(client, scan["id"], args.timeout, args.poll)
    return client.get("/v1/scans/%s/report?format=json" % scan["id"])


def check_findings(report, fail_on):
    # findings marked as false positive in the app are skipped
    findings = [f for f in report.get("findings", []) if f.get("state") != "rejected"]
    failed = 0

    for finding in findings:
        level = get_level(finding)
        is_error = fail_on != "none" and LEVELS.index(level) >= LEVELS.index(fail_on)
        if is_error:
            failed += 1
        print("  [%s] %s %s:%s" % (level.upper(), finding.get("title", "Finding"),
                                   finding.get("file_path", ""), finding.get("start_line", "")))
        print_annotation(finding, is_error)

    print("Open findings: %d" % len(findings), flush=True)
    return failed


def parse_args():
    parser = argparse.ArgumentParser(description="Scan a project with AuditMind and fail the build on findings.")
    parser.add_argument("path", help="project directory or .zip archive")
    parser.add_argument("--api-url", default=os.environ.get("AUDITMIND_API_URL", DEFAULT_API_URL))
    parser.add_argument("--fail-on", choices=LEVELS + ["none"], default="high",
                        help="fail on findings of this level or higher (default: high)")
    parser.add_argument("--ai-triage", action="store_true",
                        help="also run AI triage, it counts towards your weekly limit")
    parser.add_argument("--timeout", type=int, default=1800, help="seconds to wait for the scan")
    parser.add_argument("--poll", type=int, default=10, help="seconds between status checks")
    parser.add_argument("--report", help="save the JSON report to this file")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser.parse_args()


def main():
    args = parse_args()

    api_key = os.environ.get("AUDITMIND_API_KEY")
    if not api_key:
        print("AUDITMIND_API_KEY is not set", file=sys.stderr)
        return EXIT_ERROR

    client = AuditMindClient(args.api_url, api_key)
    try:
        report = run_scan(client, args)
    except AuditMindError as e:
        print("Error: %s" % e, file=sys.stderr)
        return EXIT_ERROR

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    failed = check_findings(report, args.fail_on)
    if failed:
        print("Failed: %d finding(s) at level %s or higher" % (failed, args.fail_on), file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("Error: unexpected failure: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        sys.exit(EXIT_ERROR)
