"""
checks/medium.py
Medium severity checks (ME-01 to ME-04).
"""

import logging

from graph.client import GraphClient
from utils.finding import Finding, Severity
from checks.common import assignments_by_principal, has_mfa

logger = logging.getLogger(__name__)

GUEST_RATIO_THRESHOLD = 0.20  # 20%
SUSPICIOUS_REDIRECT_PATTERNS = ["localhost", "127.0.0.1", "*", "http://"]

# Safety cap: MFA lookups are one Graph call per user, so bound the work on
# large tenants. Above this many non-privileged users we sample the first N.
ME01_MAX_USERS = 500
_GUEST = "Guest"


def run_medium_checks(graph: GraphClient, selected: set[str] | None) -> list[Finding]:
    results = []
    checks = [check_me01, check_me02, check_me03, check_me04]
    for fn in checks:
        check_id = fn.__name__.replace("check_", "").upper().replace("_", "-")
        check_id = check_id[:2] + "-" + check_id[2:]
        if selected and check_id not in selected:
            continue
        try:
            results.append(fn(graph))
        except Exception as e:
            logger.error(f"[{check_id}] Unexpected error: {e}")
            results.append(
                Finding(
                    id=check_id,
                    title=f"Check {check_id} failed",
                    severity=Severity.MEDIUM,
                    description="",
                    evidence=[],
                    recommendation="",
                    error=str(e),
                )
            )
    return results


def check_me01(graph: GraphClient) -> Finding:
    """ME-01: Non-privileged, enabled users without MFA (sampled on large tenants)."""
    privileged_ids = {pid for pid, e in assignments_by_principal(graph).items() if e["roles"]}

    candidates = [
        u
        for u in graph.get_all_users()
        if u.get("accountEnabled")
        and u.get("id") not in privileged_ids
        and (u.get("userType") or "").lower() != _GUEST.lower()
    ]

    sampled = candidates[:ME01_MAX_USERS]
    truncated = len(candidates) > ME01_MAX_USERS

    flagged = []
    for user in sampled:
        if not has_mfa(graph, user["id"]):
            flagged.append(
                {
                    "displayName": user.get("displayName", "Unknown"),
                    "userPrincipalName": user.get("userPrincipalName", "—"),
                }
            )

    if flagged:
        scope = (
            f"first {ME01_MAX_USERS} of {len(candidates)} users (sampled)"
            if truncated
            else f"{len(candidates)} users"
        )
        return Finding(
            id="ME-01",
            title="Non-privileged users without MFA",
            severity=Severity.MEDIUM,
            description=(
                f"{len(flagged)} non-privileged user(s) have no second factor registered "
                f"(checked {scope}). Accounts without MFA are the most common entry point "
                "for phishing and password-spray attacks."
            ),
            evidence=flagged,
            recommendation=(
                "Roll out an MFA registration campaign and require MFA for all users via "
                "Conditional Access or security defaults."
            ),
            reference="https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks",
        )
    return Finding(
        id="ME-01",
        title="All sampled non-privileged users have MFA",
        severity=Severity.MEDIUM,
        description="No non-privileged user without MFA found in the checked set.",
        evidence=[],
        recommendation="",
        passed=True,
    )


def check_me02(graph: GraphClient) -> Finding:
    """ME-02: Guest users exceed 20% of the directory."""
    users = graph.get_all_users()
    total = len(users)
    guests = sum(1 for u in users if (u.get("userType") or "").lower() == _GUEST.lower())
    ratio = (guests / total) if total else 0.0

    if total and ratio > GUEST_RATIO_THRESHOLD:
        return Finding(
            id="ME-02",
            title="Excessive guest user ratio",
            severity=Severity.MEDIUM,
            description=(
                f"Guests make up {ratio:.0%} of the directory ({guests} of {total}), above "
                f"the {GUEST_RATIO_THRESHOLD:.0%} threshold. A large external population "
                "widens the attack surface and complicates access governance."
            ),
            evidence=[
                {
                    "totalUsers": total,
                    "guestUsers": guests,
                    "guestRatio": f"{ratio:.1%}",
                }
            ],
            recommendation=(
                "Run access reviews on guests, remove stale external accounts, and govern "
                "guest lifecycle with entitlement management and expiration policies."
            ),
            reference="https://learn.microsoft.com/entra/external-id/",
        )
    return Finding(
        id="ME-02",
        title="Guest user ratio within limit",
        severity=Severity.MEDIUM,
        description=f"Guests are {ratio:.0%} of the directory ({guests} of {total}).",
        evidence=[],
        recommendation="",
        passed=True,
    )


def check_me03(graph: GraphClient) -> Finding:
    """ME-03: Security / M365 groups with a single owner."""
    flagged = []
    for group in graph.get_all_groups():
        group_types = group.get("groupTypes") or []
        is_unified = "Unified" in group_types
        is_security = group.get("securityEnabled")
        if not (is_unified or is_security):
            continue
        owners = graph.get_group_owners(group.get("id"))
        if len(owners) == 1:
            owner = owners[0]
            flagged.append(
                {
                    "groupName": group.get("displayName", "Unknown"),
                    "groupId": group.get("id", "—"),
                    "owner": owner.get("userPrincipalName")
                    or owner.get("displayName", "—"),
                }
            )

    if flagged:
        return Finding(
            id="ME-03",
            title="Groups with a single owner",
            severity=Severity.MEDIUM,
            description=(
                f"{len(flagged)} security/M365 group(s) have exactly one owner. A single "
                "owner is an orphan risk: if that account is disabled or leaves, the group "
                "becomes unmanaged, which can strand access grants."
            ),
            evidence=flagged,
            recommendation=(
                "Assign at least two owners to each group, and periodically review "
                "ownership as part of access governance."
            ),
            reference="https://learn.microsoft.com/entra/identity/users/groups-self-service-management",
        )
    return Finding(
        id="ME-03",
        title="No single-owner groups",
        severity=Severity.MEDIUM,
        description="No security or M365 group has a single owner.",
        evidence=[],
        recommendation="",
        passed=True,
    )


def check_me04(graph: GraphClient) -> Finding:
    """ME-04: App registrations with suspicious redirect URIs."""
    flagged = []
    for app in graph.get_all_applications():
        uris = []
        uris += (app.get("web") or {}).get("redirectUris") or []
        uris += (app.get("publicClient") or {}).get("redirectUris") or []
        suspicious = [
            u
            for u in uris
            if any(pat in (u or "").lower() for pat in SUSPICIOUS_REDIRECT_PATTERNS)
        ]
        if suspicious:
            flagged.append(
                {
                    "appName": app.get("displayName", "Unknown"),
                    "appId": app.get("appId", "—"),
                    "suspiciousUris": suspicious,
                }
            )

    if flagged:
        return Finding(
            id="ME-04",
            title="App registrations with suspicious redirect URIs",
            severity=Severity.MEDIUM,
            description=(
                f"{len(flagged)} app registration(s) use redirect URIs that are localhost, "
                "wildcard, or plain HTTP. These can enable token interception or "
                "authorization-code theft if the app handles user sign-in."
            ),
            evidence=flagged,
            recommendation=(
                "Remove development/wildcard/HTTP redirect URIs from production apps and "
                "restrict to exact HTTPS URLs you control."
            ),
            reference="https://attack.mitre.org/techniques/T1550/001/",
        )
    return Finding(
        id="ME-04",
        title="No suspicious redirect URIs",
        severity=Severity.MEDIUM,
        description="No app registration uses a suspicious redirect URI.",
        evidence=[],
        recommendation="",
        passed=True,
    )
