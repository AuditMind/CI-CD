# AuditMind scan for CI

Scan your code with [AuditMind](https://auditmind.tech) on every push or pull request and fail the build when it finds vulnerabilities.

The script uploads the project, waits for the scan and prints the open findings. It needs only Python 3, with no extra packages.

## Get an API key

1. Sign in at [app.auditmind.tech](https://app.auditmind.tech).
2. Open **Settings → Security**, find **API Key** and refresh it to get a new key. The key is shown once; refreshing revokes the old one.
3. Save it in your CI secrets as `AUDITMIND_API_KEY`. Never commit it: anyone with the key can run scans and read results as you.

## GitHub Actions

```yaml
name: AuditMind
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AuditMind/CI-CD@v1
        with:
          api-key: ${{ secrets.AUDITMIND_API_KEY }}
          fail-on: high
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: auditmind-report
          path: auditmind-report.json
```

Findings show up as annotations on the changed lines.

| Input | Default | Description |
|---|---|---|
| `api-key` | — | AuditMind API key, required |
| `path` | `.` | project directory or `.zip` archive |
| `fail-on` | `high` | fail on findings of this level or higher: `low`, `medium`, `high`, `critical`, or `none` to never fail |
| `ai-triage` | `false` | also run AI triage; counts towards your weekly limit |
| `report` | `auditmind-report.json` | where to save the JSON report; empty to skip |
| `timeout` | `1800` | seconds to wait for the scan |

## GitLab CI

```yaml
auditmind:
  image: python:3.12-slim
  script:
    - python3 -c "import urllib.request as u; u.urlretrieve('https://raw.githubusercontent.com/AuditMind/CI-CD/v1/auditmind_scan.py', 'auditmind_scan.py')"
    - python3 auditmind_scan.py . --fail-on high --report auditmind-report.json
  artifacts:
    when: always
    paths: [auditmind-report.json]
```

Add `AUDITMIND_API_KEY` as a masked variable in **Settings → CI/CD → Variables**. You can also copy `auditmind_scan.py` into your repository instead of downloading it.

## Any other CI or local run

```bash
export AUDITMIND_API_KEY=ak_...
python3 auditmind_scan.py . --fail-on high --report auditmind-report.json
```

| Option | Default | Description |
|---|---|---|
| `path` | — | project directory or `.zip`. `.git`, `node_modules`, `venv`, `dist`, `build` and similar folders are skipped |
| `--fail-on` | `high` | `low`, `medium`, `high`, `critical` or `none` |
| `--ai-triage` | off | also run AI triage |
| `--report` | — | save the JSON report to a file |
| `--timeout` | `1800` | seconds to wait for the scan |
| `--api-url` | `https://api.auditmind.tech` | API address, also read from `AUDITMIND_API_URL` |

Exit codes: `0` — passed, `1` — findings at or above `--fail-on`, `2` — the scan could not run (key, network, limit, timeout). Findings marked as false positives do not fail the build.

## Limits

- Archive size up to 150 MB.
- Up to 20 scans per hour per API key; after that the API answers `429`.
- Each run creates a new project in your scan list.

## API

You can do the same from your own code. Every request needs the header `Authorization: Bearer ak_...`.

| Step | Request |
|---|---|
| Upload a zip | `POST /v1/repositories/upload`, multipart field `file` |
| List files | `GET /v1/repositories/{id}/files` |
| Start a scan | `POST /v1/scans` with `{"repository_id": "...", "paths": [...], "ai_triage": false}` |
| Wait | `GET /v1/scans/{id}`, fields `scan.status` and `scan.progress` |
| Get results | `GET /v1/scans/{id}/report?format=json` |

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache License 2.0](LICENSE-APACHE), at your option.
