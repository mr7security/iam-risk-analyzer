"""
checks/medium.py
Medium severity checks (ME-01 to ME-04).

TODO(devin): Implement the body of each check function.
             Do NOT change function signatures or Finding field names.
"""

import logging
from graph.client import GraphClient
from utils.finding import Finding, Severity

logger = logging.getLogger(__name__)

GUEST_RATIO_THRESHOLD = 0.20  # 20%
SUSPICIOUS_REDIRECT_PATTERNS = ["localhost", "127.0.0.1", "*", "http://"]


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
    """
    ME-01: Usuarios sin MFA (no privilegiados)
    Trigger: non-privileged users without any MFA method registered.

    Logic:
      1. Get all enabled users
      2. Get role assignments to exclude privileged users (already covered in HI-01)
      3. For remaining users, check auth methods
      4. Flag users with only password method

    Evidence rows: [{"displayName": ..., "userPrincipalName": ...}]
    Note: This check can be slow on large tenants — consider sampling or pagination limit.
    """
    # TODO(devin): implement
    raise NotImplementedError("ME-01 not yet implemented")


def check_me02(graph: GraphClient) -> Finding:
    """
    ME-02: Guest users excesivos
    Trigger: more than 20% of all users are guests.

    Logic:
      1. Get all users with userType field
      2. Count total vs guest count
      3. If guest_count / total > 0.20 → finding

    Evidence rows: [{"totalUsers": ..., "guestUsers": ..., "guestRatio": ...}]
    """
    # TODO(devin): implement
    raise NotImplementedError("ME-02 not yet implemented")


def check_me03(graph: GraphClient) -> Finding:
    """
    ME-03: Grupos con owner único
    Trigger: security or M365 group with only 1 owner.

    Logic:
      1. Get all groups
      2. For each group, call graph.get_group_owners(group_id)
      3. If ownerCount == 1 → flag (orphan risk)

    Evidence rows: [{"groupName": ..., "groupId": ..., "owner": ...}]
    Note: Paginate group list, avoid calling owners for every group in huge tenants.
          Only check groups with securityEnabled=True or groupTypes contains "Unified".
    """
    # TODO(devin): implement
    raise NotImplementedError("ME-03 not yet implemented")


def check_me04(graph: GraphClient) -> Finding:
    """
    ME-04: Apps con redirect URIs sospechosas
    Trigger: App Registration with redirect URIs containing localhost, 127.0.0.1, wildcard (*), or http://.

    Logic:
      1. Get all applications via graph.get_all_applications()
      2. Check web.redirectUris and publicClient.redirectUris
      3. For each URI, check against SUSPICIOUS_REDIRECT_PATTERNS
      4. Flag if any suspicious URI found

    Evidence rows: [{"appName": ..., "appId": ..., "suspiciousUris": [...]}]
    Reference: https://attack.mitre.org/techniques/T1550/001/
    """
    # TODO(devin): implement
    raise NotImplementedError("ME-04 not yet implemented")
