"""
checks/high.py
High severity checks (HI-01 to HI-04).

TODO(devin): Implement the body of each check function.
             Do NOT change function signatures or Finding field names.
"""

import logging
from datetime import datetime, timezone, timedelta
from graph.client import GraphClient
from utils.finding import Finding, Severity

logger = logging.getLogger(__name__)

DORMANT_DAYS = 90  # days without sign-in to be considered dormant


def run_high_checks(graph: GraphClient, selected: set[str] | None) -> list[Finding]:
    results = []
    checks = [check_hi01, check_hi02, check_hi03, check_hi04]
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
                    severity=Severity.HIGH,
                    description="",
                    evidence=[],
                    recommendation="",
                    error=str(e),
                )
            )
    return results


def check_hi01(graph: GraphClient) -> Finding:
    """
    HI-01: Usuarios privilegiados sin MFA
    Trigger: user with ANY directory role assigned + no MFA method registered.

    Logic:
      1. Get all role assignments → collect unique user IDs with roles
      2. For each user, call graph.get_user_auth_methods(user_id)
      3. MFA method types (non-password): microsoftAuthenticatorAuthenticationMethod,
         phoneAuthenticationMethod, fido2AuthenticationMethod, softwareOathAuthenticationMethod
      4. If no MFA method → add to finding
      5. Exclude guest users (userType == "Guest") — covered separately in HI-03

    Evidence rows: [{"displayName": ..., "userPrincipalName": ..., "roles": [...]}]
    Reference: https://attack.mitre.org/techniques/T1078/
    """
    # TODO(devin): implement
    raise NotImplementedError("HI-01 not yet implemented")


def check_hi02(graph: GraphClient) -> Finding:
    """
    HI-02: Cuentas dormidas con roles activos
    Trigger: lastSignInDateTime > 90 days ago AND has active role assignment.

    Logic:
      1. Get all users with signInActivity field (beta endpoint)
      2. Filter: lastSignInDateTime < (now - 90 days) OR lastSignInDateTime is null
      3. Get role assignments, filter by users from step 2
      4. If overlap → finding

    Evidence rows: [{"displayName": ..., "userPrincipalName": ..., "lastSignIn": ..., "roles": [...]}]
    Reference: CIS Microsoft 365 Foundations Benchmark 1.1.3
    """
    # TODO(devin): implement
    raise NotImplementedError("HI-02 not yet implemented")


def check_hi03(graph: GraphClient) -> Finding:
    """
    HI-03: Guest users con roles de directorio
    Trigger: userType == "Guest" AND has any directory role assignment.

    Logic:
      1. Get all users, filter userType == "Guest"
      2. Get all role assignments, filter by guest user IDs
      3. If any guest has a role → finding

    Evidence rows: [{"displayName": ..., "userPrincipalName": ..., "roles": [...]}]
    Reference: https://attack.mitre.org/techniques/T1078/004/
    """
    # TODO(devin): implement
    raise NotImplementedError("HI-03 not yet implemented")


def check_hi04(graph: GraphClient) -> Finding:
    """
    HI-04: Service Principals con Client Secret vencido o próximo a vencer (<30 días)
    Trigger: SP passwordCredentials where endDateTime < now+30d

    Logic:
      1. Get all SPs via graph.get_all_service_principals()
      2. For each SP, inspect passwordCredentials list
      3. For each credential: if endDateTime < (now + 30 days) → flag
      4. Include both already-expired and soon-to-expire in evidence

    Evidence rows: [{"displayName": ..., "appId": ..., "secretHint": ..., "expiresOn": ..., "status": "expired"|"expiring"}]
    """
    # TODO(devin): implement
    raise NotImplementedError("HI-04 not yet implemented")
