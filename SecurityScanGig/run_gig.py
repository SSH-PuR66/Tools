"""
run_gig.py  --  one command: scan an authorized target, then build the client PDF.

This wraps your existing RangeCheck tool and generate_report.py so a full
delivery is a single step during a gig.

PREREQUISITE: a signed CLIENT_AUTHORIZATION for the target (see that file).
Never run this against a host you are not authorized to test.

Examples:
    # from an authorized scope file (recommended):
    py run_gig.py --scope scope.yaml --client "Acme Coffee LLC"

    # or a single authorized target with explicit confirmation:
    py run_gig.py --target 203.0.113.10 --client "Acme Coffee LLC" --confirm-authorized
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# Point this at your RangeCheck checkout.
RANGECHECK_DIR = Path(r"C:\Users\sergi\Desktop\tools\RangeCheck")
REPORTS_DIR = RANGECHECK_DIR / "reports"


def run_scan(args) -> None:
    cmd = [sys.executable, "-m", "rangecheck.cli"]
    if args.scope:
        cmd += ["--scope", str(Path(args.scope).resolve())]
    else:
        cmd += [args.target]
        if args.confirm_authorized:
            cmd += ["--confirm-authorized"]
    if args.ports:
        cmd += ["--ports", args.ports]
    print(f"[*] Running RangeCheck: {' '.join(cmd)}")
    # rangecheck writes reports into RANGECHECK_DIR/reports
    subprocess.run(cmd, cwd=str(RANGECHECK_DIR / "src"), check=True)


def newest_json() -> Path:
    jsons = sorted(REPORTS_DIR.glob("rangecheck-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not jsons:
        raise SystemExit(f"No JSON report found in {REPORTS_DIR}. Did the scan run?")
    return jsons[0]


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan + build client PDF in one step.")
    ap.add_argument("--scope", help="RangeCheck YAML scope file (preferred).")
    ap.add_argument("--target", help="Single authorized IP/CIDR (requires --confirm-authorized).")
    ap.add_argument("--confirm-authorized", action="store_true")
    ap.add_argument("--ports", default="21,22,23,25,53,80,110,143,443,3306,3389,5432,6379,8080,8443")
    ap.add_argument("--client", required=True, help="Client name for the report cover.")
    ap.add_argument("--json", help="Skip scanning; build PDF from an existing JSON report.")
    args = ap.parse_args()

    if not args.json:
        if not args.scope and not (args.target and args.confirm_authorized):
            raise SystemExit("Provide --scope, OR --target with --confirm-authorized, OR --json.")
        run_scan(args)
        report_json = newest_json()
    else:
        report_json = Path(args.json)

    print(f"[*] Building PDF from {report_json}")
    gen = Path(__file__).with_name("generate_report.py")
    subprocess.run([sys.executable, str(gen), str(report_json), "--client", args.client], check=True)
    print("[+] Done. Deliverable is in ./deliverables/")


if __name__ == "__main__":
    main()
