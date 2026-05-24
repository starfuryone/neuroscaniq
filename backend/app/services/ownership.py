"""Ownership validation.

Implements the four supported proof methods:
  * DNS TXT challenge
  * Email to an admin/whois contact
  * Verification file upload (HTTP /.well-known/neuroscaniq.txt)
  * ASN attestation (manual, requires admin approval)

Each verifier returns (ok: bool, detail: str). The caller persists the
result and flips the Asset to `verified` only on success.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass

import httpx

from app.config import settings


def new_challenge() -> str:
    """Generate a fresh challenge nonce."""
    return f"neuroscaniq-verify={secrets.token_urlsafe(24)}"


@dataclass
class ProofResult:
    ok: bool
    detail: str


# ---------- DNS TXT ----------
async def verify_dns_txt(domain: str, expected: str) -> ProofResult:
    """Look up TXT records on `domain` and check for `expected`."""
    import dns.asyncresolver

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        answers = await resolver.resolve(domain, "TXT")
        records = [b"".join(r.strings).decode("utf-8", "ignore") for r in answers]
    except Exception as e:
        return ProofResult(False, f"DNS lookup failed: {e}")

    if any(expected in r for r in records):
        return ProofResult(True, f"TXT record found on {domain}")
    return ProofResult(
        False,
        f"TXT record not found. Saw: {records[:3]}",
    )


# ---------- File upload ----------
async def verify_file_upload(domain: str, expected: str) -> ProofResult:
    """Fetch http(s)://<domain>/.well-known/neuroscaniq.txt and look for token."""
    urls = [
        f"https://{domain}/.well-known/neuroscaniq.txt",
        f"http://{domain}/.well-known/neuroscaniq.txt",
    ]
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        for url in urls:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as e:
                continue
            if resp.status_code == 200 and expected in resp.text:
                return ProofResult(True, f"Token found at {url}")
    return ProofResult(False, "Verification file not found")


# ---------- Email ----------
async def verify_email_token(submitted: str, expected: str) -> ProofResult:
    """Used after the user clicks the email link; values are compared
    in constant time."""
    ok = secrets.compare_digest(submitted, expected)
    return ProofResult(ok, "Email token matches" if ok else "Email token mismatch")


# ---------- ASN attestation ----------
async def verify_asn_attestation(submitted: str, expected: str) -> ProofResult:
    """Placeholder — ASN attestation requires manual admin review.

    Real implementation pulls RIR data (whois -h whois.arin.net AS<n>)
    and matches `OrgAbuseEmail` or `OrgTechEmail` against the submitting
    user. For now we just accept admin-approved attestations.
    """
    if submitted == expected:
        return ProofResult(True, "Attestation token matches")
    return ProofResult(False, "Attestation token mismatch; awaiting admin review")
