#!/usr/bin/env python3
"""
IAM Risk Analyzer — Microsoft Entra ID / Azure AD
Analyzes IAM security posture and generates a professional HTML pentest-style report.

Usage:
    python main.py --auth-method client_secret --tenant-id <tid> --client-id <cid> --client-secret <secret>
    python main.py --auth-method certificate --tenant-id <tid> --client-id <cid> --cert-path ./cert.pfx
    python main.py --auth-method device_code --tenant-id <tid> --client-id <cid>

Configuration can also be supplied via a .env file in the working directory
(see .env.example). Command-line flags override .env / environment values.
"""

import argparse
import os
import sys
import logging
from datetime import datetime

# Load a local .env file (if present) so AZURE_* variables are available.
# Optional dependency: falls back silently if python-dotenv isn't installed.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from auth.authenticator import Authenticator, AuthMethod
from graph.client import GraphClient
from checks.critical import run_critical_checks
from checks.high import run_high_checks
from checks.medium import run_medium_checks
from checks.informational import run_informational_checks
from report.html_generator import generate_report
from report.pdf_generator import generate_pdf
from utils.scoring import calculate_score

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IAM Risk Analyzer — Entra ID / Azure AD Security Posture"
    )

    # Auth method
    parser.add_argument(
        "--auth-method",
        choices=["client_secret", "certificate", "device_code"],
        default=os.getenv("AZURE_AUTH_METHOD", "device_code"),
        help="Authentication method (default: device_code)",
    )

    # Common auth params
    parser.add_argument(
        "--tenant-id",
        default=os.getenv("AZURE_TENANT_ID"),
        help="Azure tenant ID (or AZURE_TENANT_ID env var)",
    )
    parser.add_argument(
        "--client-id",
        default=os.getenv("AZURE_CLIENT_ID"),
        help="App Registration client ID (or AZURE_CLIENT_ID env var)",
    )

    # client_secret specific
    parser.add_argument(
        "--client-secret",
        default=os.getenv("AZURE_CLIENT_SECRET"),
        help="Client secret (client_secret method only, or AZURE_CLIENT_SECRET env var)",
    )

    # certificate specific
    parser.add_argument(
        "--cert-path",
        default=os.getenv("AZURE_CERT_PATH"),
        help="Path to PFX or PEM certificate file (certificate method only)",
    )
    parser.add_argument(
        "--cert-password",
        default=os.getenv("AZURE_CERT_PASSWORD"),
        help="Certificate password if PFX is encrypted (or AZURE_CERT_PASSWORD env var)",
    )

    # Output
    parser.add_argument(
        "--output",
        default="iam_risk_report.html",
        help="Output HTML report path (default: iam_risk_report.html)",
    )
    parser.add_argument(
        "--pdf-output",
        default=None,
        help="Output PDF audit report path (default: derived from --output, e.g. report_auditoria.pdf)",
    )
    parser.add_argument(
        "--no-pdf",
        action="store_true",
        help="Skip PDF audit report generation (HTML only)",
    )

    # Selective checks
    parser.add_argument(
        "--checks",
        default=None,
        help="Comma-separated list of check IDs to run (e.g. CR-01,CR-02,HI-01). Runs all if omitted.",
    )

    # Verbosity
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    """Validate required args per auth method and raise early with clear messages."""
    if not args.tenant_id:
        sys.exit("ERROR: --tenant-id is required (or set AZURE_TENANT_ID)")
    if not args.client_id:
        sys.exit("ERROR: --client-id is required (or set AZURE_CLIENT_ID)")

    if args.auth_method == "client_secret" and not args.client_secret:
        sys.exit(
            "ERROR: --client-secret is required for client_secret auth (or set AZURE_CLIENT_SECRET)"
        )
    if args.auth_method == "certificate" and not args.cert_path:
        sys.exit(
            "ERROR: --cert-path is required for certificate auth (or set AZURE_CERT_PATH)"
        )


# ---------------------------------------------------------------------------
# Check filter
# ---------------------------------------------------------------------------
def filter_checks(checks_str: str | None) -> set[str] | None:
    """Return a set of check IDs to run, or None to run all."""
    if not checks_str:
        return None
    return {c.strip().upper() for c in checks_str.split(",")}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    validate_args(args)

    selected_checks = filter_checks(args.checks)

    logger.info("=== IAM Risk Analyzer — Starting ===")
    logger.info(f"Auth method : {args.auth_method}")
    logger.info(f"Tenant ID   : {args.tenant_id}")
    logger.info(f"Output      : {args.output}")

    # ------------------------------------------------------------------
    # 1. Authenticate
    # ------------------------------------------------------------------
    logger.info("Authenticating against Entra ID...")
    auth = Authenticator(
        method=AuthMethod(args.auth_method),
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        client_secret=args.client_secret,
        cert_path=args.cert_path,
        cert_password=args.cert_password,
    )
    token = auth.acquire_token()
    logger.info("Authentication successful.")

    # ------------------------------------------------------------------
    # 2. Build Graph client
    # ------------------------------------------------------------------
    graph = GraphClient(token=token)

    # Fetch tenant info for the report header
    tenant_info = graph.get_tenant_info()
    logger.info(f"Tenant: {tenant_info.get('displayName', 'Unknown')} ({args.tenant_id})")

    # ------------------------------------------------------------------
    # 3. Run checks
    # ------------------------------------------------------------------
    run_start = datetime.utcnow()
    findings = []

    logger.info("Running Critical checks...")
    findings += run_critical_checks(graph=graph, selected=selected_checks)

    logger.info("Running High checks...")
    findings += run_high_checks(graph=graph, selected=selected_checks)

    logger.info("Running Medium checks...")
    findings += run_medium_checks(graph=graph, selected=selected_checks)

    logger.info("Running Informational checks...")
    findings += run_informational_checks(graph=graph, selected=selected_checks)

    run_end = datetime.utcnow()
    elapsed = (run_end - run_start).seconds

    logger.info(f"Analysis complete in {elapsed}s — {len(findings)} findings.")

    # ------------------------------------------------------------------
    # 4. Score
    # ------------------------------------------------------------------
    score = calculate_score(findings)
    logger.info(f"Risk score: {score['value']}/100 — {score['label']}")

    # ------------------------------------------------------------------
    # 5. Generate HTML report
    # ------------------------------------------------------------------
    logger.info(f"Generating HTML report → {args.output}")
    generate_report(
        output_path=args.output,
        findings=findings,
        score=score,
        tenant_info=tenant_info,
        tenant_id=args.tenant_id,
        auth_method=args.auth_method,
        run_start=run_start,
        run_end=run_end,
    )
    logger.info(f"HTML report saved to: {args.output}")

    # ------------------------------------------------------------------
    # 6. Generate PDF audit report (unless disabled)
    # ------------------------------------------------------------------
    if not args.no_pdf:
        import os as _os

        pdf_path = args.pdf_output
        if not pdf_path:
            stem, _ = _os.path.splitext(args.output)
            pdf_path = f"{stem}_auditoria.pdf"
        try:
            logger.info(f"Generating PDF audit report → {pdf_path}")
            generate_pdf(
                output_path=pdf_path,
                findings=findings,
                score=score,
                tenant_info=tenant_info,
                tenant_id=args.tenant_id,
                auth_method=args.auth_method,
                run_start=run_start,
                run_end=run_end,
            )
            logger.info(f"PDF audit report saved to: {pdf_path}")
        except Exception as e:
            logger.error(f"PDF generation failed ({e}). HTML report is still available.")

    logger.info("=== Done ===")


if __name__ == "__main__":
    main()
