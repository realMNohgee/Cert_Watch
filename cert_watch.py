#!/usr/bin/env python3
"""Cert_Watch — SSL/TLS certificate expiry monitor."""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Optional, Sequence


# ── Certificate checking ───────────────────────────────────────────────────

def _get_cert_expiry(host: str, port: int, timeout: float = 10.0) -> tuple[datetime, str]:
    """Connect and retrieve the certificate expiry date. Returns (expiry, issuer)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            # Parse expiry date from cert
            not_after = cert.get("notAfter", "")
            # ASN.1 format: 'Jun  3 12:00:00 2025 GMT' or 'Jun 3 12:00:00 2025 GMT'
            # Try parsing
            expiry = _parse_asn1_date(not_after)
            issuer_info = ""
            issuer_tuple = cert.get("issuer", ())
            for item in issuer_tuple:
                for part in item:
                    if part[0] == "commonName":
                        issuer_info = part[1]
                        break
            return expiry, issuer_info


def _parse_asn1_date(date_str: str) -> datetime:
    """Parse ASN.1 date format like 'Jun  3 12:00:00 2025 GMT'."""
    if not date_str:
        raise ValueError("No date string provided")
    # Remove any extra spaces
    cleaned = " ".join(date_str.split())
    try:
        return datetime.strptime(cleaned, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.strptime(cleaned, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _days_remaining(expiry: datetime) -> int:
    """Return days until expiry (negative if expired)."""
    now = datetime.now(timezone.utc)
    delta = expiry - now
    return delta.days


def _color_for_days(days: int) -> str:
    """Return ANSI color code for terminal output."""
    if days < 0:
        return "\033[1;35m"  # magenta for expired
    elif days <= 7:
        return "\033[1;31m"  # red
    elif days <= 14:
        return "\033[1;33m"  # orange/yellow
    elif days <= 30:
        return "\033[0;33m"  # yellow
    else:
        return "\033[0;32m"  # green


_RESET = "\033[0m"


def _check_domain(domain: str, port: int, timeout: float) -> dict:
    """Check a single domain. Returns result dict."""
    try:
        expiry, issuer = _get_cert_expiry(domain, port, timeout)
        days = _days_remaining(expiry)
        return {
            "domain": domain,
            "port": port,
            "expiry": expiry.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_remaining": days,
            "issuer": issuer,
            "status": "expired" if days < 0 else "ok",
        }
    except socket.gaierror:
        return {
            "domain": domain,
            "port": port,
            "error": "DNS resolution failed",
            "days_remaining": None,
            "status": "error",
        }
    except socket.timeout:
        return {
            "domain": domain,
            "port": port,
            "error": "Connection timed out",
            "days_remaining": None,
            "status": "error",
        }
    except ConnectionRefusedError:
        return {
            "domain": domain,
            "port": port,
            "error": "Connection refused",
            "days_remaining": None,
            "status": "error",
        }
    except Exception as e:
        return {
            "domain": domain,
            "port": port,
            "error": str(e),
            "days_remaining": None,
            "status": "error",
        }


# ── Output ─────────────────────────────────────────────────────────────────

def _output_text(results: list[dict]) -> None:
    for r in results:
        if r["status"] == "error":
            print(f"  {r['domain']}:{r['port']}  ERROR — {r.get('error', 'unknown')}")
        else:
            days = r["days_remaining"]
            color = _color_for_days(days)
            label = "EXPIRED" if days is not None and days < 0 else f"{days}d"
            print(
                f"  {color}{r['domain']}:{r['port']}  {label}  "
                f"(expires {r['expiry']})  issuer: {r['issuer']}{_RESET}"
            )


# ── Subcommand handlers ────────────────────────────────────────────────────

def cmd_check(args: argparse.Namespace) -> None:
    result = _check_domain(args.domain, args.port, args.timeout)
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        _output_text([result])


def cmd_bulk(args: argparse.Namespace) -> None:
    try:
        with open(args.file) as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    results = [_check_domain(d, args.port, args.timeout) for d in domains]

    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        _output_text(results)


# ── Common argument helpers ────────────────────────────────────────────────

def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Port to connect to (default: 443)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Connection timeout in seconds (default: 10)",
    )


# ── Main ───────────────────────────────────────────────────────────────────

def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Cert_Watch — SSL/TLS certificate expiry monitor.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # check
    p_check = sub.add_parser("check", help="Check SSL certificate for a single domain")
    p_check.add_argument("domain", help="Domain name to check (e.g., example.com)")
    add_common_args(p_check)

    # bulk
    p_bulk = sub.add_parser("bulk", help="Check SSL certificates for domains in a file")
    p_bulk.add_argument("file", help="File with one domain per line")
    add_common_args(p_bulk)

    args = parser.parse_args(argv)

    if args.command == "check":
        cmd_check(args)
    elif args.command == "bulk":
        cmd_bulk(args)


if __name__ == "__main__":
    main()
