#!/usr/bin/env python3
"""
AEGIS-Recon CLI — Standalone command-line interface.

Usage:
    python scripts/cli.py scan --target 192.168.56.101 --profile quick
    python scripts/cli.py list
    python scripts/cli.py findings <scan_id>
    python scripts/cli.py report <scan_id> --format html
    python scripts/cli.py enrich <scan_id>
    python scripts/cli.py status

Design principles:
- No LLM / no network access required for basic operations.
- Communicates with the running AEGIS-Recon API server (localhost:8000 by default).
- Supports --api-key for authenticated endpoints.
- Human-readable tables by default; --json flag for machine-readable output.
- Never executes Nmap directly — always goes through the validated API.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request as URLRequest
from urllib.request import urlopen

# ── ANSI colour helpers (no deps needed) ─────────────────────────────────────

BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"


def _supports_colour() -> bool:
    return sys.stdout.isatty() and os.name != "nt" or os.environ.get("FORCE_COLOR") == "1"


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if _supports_colour() else text


# ── HTTP helpers ──────────────────────────────────────────────────────────────


def _request(
    method: str,
    url: str,
    *,
    api_key: str = "",
    body: dict[str, Any] | None = None,
) -> Any:
    """Minimal HTTP client using stdlib only."""
    data = json.dumps(body).encode() if body else None
    headers: dict[str, str] = {"Accept": "application/json", "Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    req = URLRequest(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            payload = json.loads(raw)
            msg = payload.get("detail") or payload.get("message") or str(e)
        except Exception:
            msg = str(e)
        _die(f"API error {e.code}: {msg}")
    except URLError as e:
        _die(
            f"Cannot connect to AEGIS-Recon API.\n"
            f"  Reason: {e.reason}\n"
            f"  Is the server running?  python -m uvicorn app.main:app --port 8000"
        )


def _die(msg: str) -> None:
    print(c(f"✗ {msg}", RED), file=sys.stderr)
    sys.exit(1)


# ── Table renderer ────────────────────────────────────────────────────────────


def _table(headers: list[str], rows: list[list[str]], *, title: str = "") -> None:
    """Print a minimal ASCII table."""
    if title:
        print(c(f"\n  {title}", BOLD + CYAN))
    if not rows:
        print(c("  (no data)", DIM))
        return
    widths = [
        max(len(h), max((len(str(r[i])) for r in rows), default=0)) for i, h in enumerate(headers)
    ]
    sep = "  " + "-+-".join("-" * w for w in widths)
    header_line = "  " + " | ".join(c(h.ljust(widths[i]), BOLD) for i, h in enumerate(headers))
    print(header_line)
    print(sep)
    for row in rows:
        print("  " + " | ".join(str(row[i]).ljust(widths[i]) for i in range(len(headers))))
    print()


def _severity_colour(sev: str) -> str:
    colours = {
        "CRITICAL": RED,
        "HIGH": YELLOW,
        "MEDIUM": CYAN,
        "LOW": GREEN,
    }
    return c(sev, colours.get(sev.upper(), DIM))


# ── Subcommands ───────────────────────────────────────────────────────────────


def cmd_status(args: argparse.Namespace) -> None:
    """Check API server health."""
    data = _request("GET", f"{args.base_url}/api/health")
    status = data.get("status", "unknown")
    version = data.get("version", "?")
    db = data.get("database", "?")

    if args.json:
        print(json.dumps(data, indent=2))
        return

    colour = GREEN if status == "healthy" else RED
    print()
    print(c("  AEGIS-Recon API Status", BOLD))
    print(f"  Status   : {c(status.upper(), colour)}")
    print(f"  Version  : {version}")
    print(f"  Database : {db}")
    print()


def cmd_scan(args: argparse.Namespace) -> None:
    """Start a new scan."""
    print(c(f"\n  ▶ Starting scan against {args.target} (profile: {args.profile}) …", CYAN))
    body: dict[str, Any] = {"target": args.target, "profile": args.profile}
    if args.ports:
        body["ports"] = args.ports

    data = _request("POST", f"{args.base_url}/api/scans", api_key=args.api_key, body=body)

    if args.json:
        print(json.dumps(data, indent=2))
        return

    status = data.get("status", "?")
    colour = GREEN if status == "completed" else (RED if status == "failed" else YELLOW)
    print(f"  Scan ID  : {c(data.get('scan_id', '?'), BOLD)}")
    print(f"  Status   : {c(status.upper(), colour)}")
    print(f"  Message  : {data.get('message', '')}")
    print()
    print(c("  Tip: run  aegis-cli findings <scan_id>  to view results.", DIM))
    print()


def cmd_list(args: argparse.Namespace) -> None:
    """List all scans."""
    data = _request("GET", f"{args.base_url}/api/scans?limit={args.limit}")

    if args.json:
        print(json.dumps(data, indent=2))
        return

    scans = data.get("scans", [])
    rows = [
        [
            s.get("scan_id", "")[:12] + "…",
            s.get("target", ""),
            s.get("profile", ""),
            s.get("status", ""),
            (s.get("start_time") or "")[:19],
        ]
        for s in scans
    ]
    _table(
        ["SCAN ID", "TARGET", "PROFILE", "STATUS", "STARTED"],
        rows,
        title=f"Scans ({len(scans)} total)",
    )


def cmd_findings(args: argparse.Namespace) -> None:
    """Show findings for a scan, optionally trigger enrichment first."""
    if args.enrich:
        print(c(f"  ⚡ Running enrichment for {args.scan_id} …", CYAN))
        _request(
            "POST", f"{args.base_url}/api/findings/{args.scan_id}/enrich", api_key=args.api_key
        )

    data = _request("GET", f"{args.base_url}/api/findings/{args.scan_id}")

    if args.json:
        print(json.dumps(data, indent=2))
        return

    findings = data.get("findings", [])
    if not findings:
        print(c("\n  No findings. Run with --enrich to fetch CVE intelligence first.\n", DIM))
        return

    rows = []
    for f in findings:
        sev = f.get("cvss_severity") or f.get("severity") or "N/A"
        rows.append(
            [
                f.get("cve_id", ""),
                _severity_colour(sev),
                f"{f.get('priority_score', 0):.0f}",
                "✓ KEV" if f.get("is_kev") else "",
                f.get("confidence", ""),
                (f.get("title") or "")[:60],
            ]
        )

    # Sort by priority descending
    rows.sort(key=lambda r: -int(r[2]))

    _table(
        ["CVE ID", "SEVERITY", "PRIORITY", "KEV", "CONFIDENCE", "TITLE"],
        rows,
        title=f"Findings for scan {args.scan_id[:12]}… ({len(findings)} total)",
    )


def cmd_report(args: argparse.Namespace) -> None:
    """Download a JSON or HTML report for a scan."""
    fmt = args.format.lower()
    url = f"{args.base_url}/api/reports/{args.scan_id}/{fmt}"

    if fmt == "json":
        data = _request("GET", url, api_key=args.api_key)
        output = json.dumps(data, indent=2)
        ext = "json"
    else:
        # HTML — fetch raw bytes
        headers: dict[str, str] = {}
        if args.api_key:
            headers["X-API-Key"] = args.api_key
        req = URLRequest(url, headers=headers)
        try:
            with urlopen(req, timeout=30) as resp:
                output = resp.read().decode("utf-8")
        except HTTPError as e:
            _die(f"API error {e.code}: {e.read().decode()}")
        ext = "html"

    out_path = args.output or f"aegis-report-{args.scan_id[:8]}.{ext}"

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(output)

    print(c(f"\n  ✓ Report saved: {out_path}\n", GREEN))


def cmd_enrich(args: argparse.Namespace) -> None:
    """Trigger CVE enrichment for a scan."""
    print(c(f"\n  ⚡ Running NVD+KEV enrichment for {args.scan_id} …", CYAN))
    data = _request(
        "POST",
        f"{args.base_url}/api/findings/{args.scan_id}/enrich",
        api_key=args.api_key,
    )

    if args.json:
        print(json.dumps(data, indent=2))
        return

    print(f"  Findings created : {c(str(data.get('findings_created', 0)), BOLD)}")
    print(f"  Message          : {data.get('message', '')}")
    print()


# ── Argument parser ───────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-cli",
        description="AEGIS-Recon — Evidence-based vulnerability intelligence CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/cli.py status
  python scripts/cli.py scan --target 192.168.56.101 --profile quick
  python scripts/cli.py list --limit 20
  python scripts/cli.py findings <scan_id> --enrich
  python scripts/cli.py report <scan_id> --format html --output report.html
  python scripts/cli.py enrich <scan_id>
        """,
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("AEGIS_BASE_URL", "http://127.0.0.1:8000"),
        help="Base URL of the AEGIS-Recon API (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("AEGIS_API_KEY", ""),
        help="API key for authenticated endpoints (or set AEGIS_API_KEY env var)",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of tables")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # status
    sub.add_parser("status", help="Check API server health")

    # scan
    scan_p = sub.add_parser("scan", help="Start a new scan")
    scan_p.add_argument(
        "--target", required=True, help="Target IP, CIDR, or hostname (must be in allowlist)"
    )
    scan_p.add_argument(
        "--profile", default="quick", choices=["quick", "standard", "thorough"], help="Scan profile"
    )
    scan_p.add_argument("--ports", default=None, help="Optional port list/range (e.g. 22,80,443)")

    # list
    list_p = sub.add_parser("list", help="List all scans")
    list_p.add_argument("--limit", type=int, default=20, help="Maximum number of scans to show")

    # findings
    find_p = sub.add_parser("findings", help="Show findings for a scan")
    find_p.add_argument("scan_id", help="Scan ID")
    find_p.add_argument("--enrich", action="store_true", help="Run NVD+KEV enrichment first")

    # enrich
    enrich_p = sub.add_parser("enrich", help="Trigger CVE enrichment for a scan")
    enrich_p.add_argument("scan_id", help="Scan ID")

    # report
    report_p = sub.add_parser("report", help="Download a report")
    report_p.add_argument("scan_id", help="Scan ID")
    report_p.add_argument(
        "--format", default="json", choices=["json", "html"], help="Report format"
    )
    report_p.add_argument(
        "--output", default=None, help="Output file path (default: aegis-report-<id>.ext)"
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "status": cmd_status,
        "scan": cmd_scan,
        "list": cmd_list,
        "findings": cmd_findings,
        "enrich": cmd_enrich,
        "report": cmd_report,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
