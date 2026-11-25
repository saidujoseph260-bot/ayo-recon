#!/usr/bin/env python3
"""
ayo-recon: Passive Domain, TLS Certificate & OWASP HTTP Security Header Inspector.
Built for authorized security assessments, defensive posture checks, and educational labs.
"""

import argparse
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

OWASP_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "weight": 20,
        "remediation": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to enforce HTTPS.",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "weight": 25,
        "remediation": "Define a restrictive Content-Security-Policy to mitigate XSS and unauthorized script execution.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "weight": 15,
        "remediation": "Set 'X-Content-Type-Options: nosniff' to block MIME-type sniffing attacks.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "weight": 15,
        "remediation": "Set 'X-Frame-Options: DENY' (or CSP frame-ancestors) to prevent clickjacking.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "weight": 10,
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer data leakage.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "weight": 15,
        "remediation": "Configure 'Permissions-Policy' to restrict sensitive browser APIs (camera, microphone, geolocation).",
    },
}

INFO_LEAK_HEADERS = ("server", "x-powered-by", "x-aspnet-version")


def normalize_target(raw_target: str) -> tuple[str, str]:
    """Return (hostname, https_url) from user input."""
    cleaned = raw_target.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    parsed = urllib.parse.urlparse(cleaned)
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("Invalid domain or URL provided.")
    return hostname, f"https://{hostname}"


def resolve_dns(hostname: str) -> dict:
    """Resolve IPv4/IPv6 addresses for the target host."""
    try:
        records = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        ips = sorted({item[4][0] for item in records})
        return {"status": "ok", "ip_addresses": ips}
    except socket.gaierror as exc:
        return {"status": "error", "error": str(exc), "ip_addresses": []}


def inspect_tls(hostname: str, timeout: float = 8.0) -> dict:
    """Inspect TLS protocol version, cipher suite, and X.509 certificate validity."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_name, tls_version, key_bits = ssock.cipher()

                not_after_raw = cert.get("notAfter", "")
                expiry_dt = datetime.strptime(
                    not_after_raw, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                days_left = (expiry_dt - datetime.now(timezone.utc)).days

                issuer = dict(x[0] for x in cert.get("issuer", ()))
                subject = dict(x[0] for x in cert.get("subject", ()))

                return {
                    "status": "ok",
                    "tls_version": tls_version,
                    "cipher": cipher_name,
                    "key_bits": key_bits,
                    "subject_cn": subject.get("commonName", "N/A"),
                    "issuer_org": issuer.get("organizationName", issuer.get("commonName", "N/A")),
                    "expires_on": expiry_dt.strftime("%Y-%m-%d"),
                    "days_remaining": days_left,
                }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def audit_http_headers(url: str, timeout: float = 10.0) -> dict:
    """Fetch HTTP response headers and evaluate OWASP security posture."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "AyoRecon-SecurityAudit/1.0 (+https://github.com/saidujoseph260-bot)"},
    )
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            final_url = resp.geturl()
            status_code = resp.status
    except urllib.error.HTTPError as err:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
        raw_headers = {k.lower(): v for k, v in err.headers.items()}
        final_url = err.geturl()
        status_code = err.code
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    score = 0
    present = []
    missing = []

    for key, meta in OWASP_HEADERS.items():
        if key in raw_headers:
            score += meta["weight"]
            present.append({"header": meta["name"], "value": raw_headers[key]})
        else:
            missing.append({"header": meta["name"], "remediation": meta["remediation"]})

    # Treat CSP frame-ancestors as partial clickjacking protection if X-Frame-Options is absent
    csp_val = raw_headers.get("content-security-policy", "").lower()
    if "x-frame-options" not in raw_headers and "frame-ancestors" in csp_val:
        score += OWASP_HEADERS["x-frame-options"]["weight"]
        missing = [m for m in missing if m["header"] != "X-Frame-Options"]
        present.append({"header": "X-Frame-Options (via CSP frame-ancestors)", "value": "Configured"})

    disclosures = {h: raw_headers[h] for h in INFO_LEAK_HEADERS if h in raw_headers}

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return {
        "status": "ok",
        "final_url": final_url,
        "http_status": status_code,
        "latency_ms": elapsed_ms,
        "score": score,
        "grade": grade,
        "present_headers": present,
        "missing_headers": missing,
        "info_disclosures": disclosures,
    }


def print_report(report: dict) -> None:
    """Render a clean terminal report."""
    print("\n" + "=" * 62)
    print(f"  AYO-RECON SECURITY POSTURE REPORT | Target: {report['target']}")
    print("=" * 62)

    dns = report["dns"]
    if dns["status"] == "ok":
        print(f"[+] Resolved IPs : {', '.join(dns['ip_addresses'])}")
    else:
        print(f"[!] DNS Error    : {dns['error']}")
        return

    tls = report["tls"]
    print("\n--- TLS / Certificate Posture ---")
    if tls["status"] == "ok":
        print(f"[+] Protocol     : {tls['tls_version']} ({tls['cipher']}, {tls['key_bits']}-bit)")
        print(f"[+] Issuer       : {tls['issuer_org']}")
        print(f"[+] Valid Until  : {tls['expires_on']} ({tls['days_remaining']} days remaining)")
    else:
        print(f"[!] TLS Error    : {tls['error']}")

    http = report["http"]
    print("\n--- OWASP HTTP Security Headers Audit ---")
    if http["status"] != "ok":
        print(f"[!] HTTP Error   : {http['error']}")
        return

    print(f"[+] Final URL    : {http['final_url']} (HTTP {http['http_status']} in {http['latency_ms']} ms)")
    print(f"[+] Security Grade: {http['grade']} ({http['score']}/100)")

    print("\n[Present Controls]")
    if http["present_headers"]:
        for item in http["present_headers"]:
            val = item["value"] if len(item["value"]) <= 68 else item["value"][:65] + "..."
            print(f"  [PASS] {item['header']}: {val}")
    else:
        print("  None detected.")

    print("\n[Missing Controls & Remediation]")
    if http["missing_headers"]:
        for item in http["missing_headers"]:
            print(f"  [MISS] {item['header']}")
            print(f"         -> Fix: {item['remediation']}")
    else:
        print("  All checked OWASP headers are configured!")

    if http["info_disclosures"]:
        print("\n[Server Banner / Technology Disclosure]")
        for hdr, val in http["info_disclosures"].items():
            print(f"  [WARN] {hdr}: {val} (Consider stripping version banners)")

    print("=" * 62 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ayo-recon",
        description="Passive Domain, TLS Certificate & OWASP Security Header Inspector",
    )
    parser.add_argument("target", nargs="?", help="Target domain or URL (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Optional path to save JSON report (e.g., report.json)")
    args = parser.parse_args()

    target_input = args.target
    if not target_input:
        print("=== ayo-recon CLI (Interactive Mode) ===")
        target_input = input("Enter authorized target domain (e.g. example.com): ").strip()

    try:
        hostname, https_url = normalize_target(target_input)
    except ValueError as err:
        print(f"[!] Error: {err}")
        sys.exit(1)

    report = {
        "target": hostname,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "dns": resolve_dns(hostname),
        "tls": inspect_tls(hostname),
        "http": audit_http_headers(https_url),
    }

    print_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] JSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
