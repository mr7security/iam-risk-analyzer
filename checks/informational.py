"""
checks/informational.py
Informational checks (IN-01 to IN-04).
These always produce findings (inventories) — never passed=True.

TODO(devin): Implement the body of each check function.
             Do NOT change function signatures or Finding field names.
"""

import logging
from graph.client import GraphClient
from utils.finding import Finding, Severity

logger = logging.getLogger(__name__)


def run_informational_checks(graph: GraphClient, selected: set[str] | None) -> list[Finding]:
    results = []
    checks = [check_in01, check_in02, check_in03, check_in04]
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
                    severity=Severity.INFO,
                    description="",
                    evidence=[],
                    recommendation="",
                    error=str(e),
                )
            )
    return results


def check_in01(graph: GraphClient) -> Finding:
    """
    IN-01: Inventario de Global Admins
    Always produces a finding listing all current Global Administrators.

    Logic:
      1. Get Global Admin role ID
      2. Get all role assignments filtered by that role
      3. Return complete list as evidence

    Evidence rows: [{"displayName": ..., "userPrincipalName": ..., "id": ...}]
    """
    # TODO(devin): implement
    raise NotImplementedError("IN-01 not yet implemented")


def check_in02(graph: GraphClient) -> Finding:
    """
    IN-02: Inventario de Service Principals con permisos Graph
    Lists all SPs that have been granted Microsoft Graph API permissions.

    Logic:
      1. Get all SPs
      2. For each SP, get app role assignments
      3. Filter assignments where resourceDisplayName == "Microsoft Graph"
      4. Return inventory

    Evidence rows: [{"displayName": ..., "appId": ..., "graphPermissions": [...]}]
    """
    # TODO(devin): implement
    raise NotImplementedError("IN-02 not yet implemented")


def check_in03(graph: GraphClient) -> Finding:
    """
    IN-03: Usuarios sin actividad en 30 días
    Lists users whose lastSignInDateTime > 30 days ago.

    Logic:
      1. Get all users with signInActivity (beta)
      2. Filter: lastSignInDateTime < (now - 30 days) OR null (never signed in)
      3. Return list

    Evidence rows: [{"displayName": ..., "userPrincipalName": ..., "lastSignIn": ..., "accountEnabled": ...}]
    """
    # TODO(devin): implement
    raise NotImplementedError("IN-03 not yet implemented")


def check_in04(graph: GraphClient) -> Finding:
    """
    IN-04: Conditional Access Policies activas
    Inventory of all Conditional Access policies and their state.

    Logic:
      1. Get all CA policies via graph.get_conditional_access_policies()
      2. Return list with state, conditions summary, grant controls

    Evidence rows: [{"displayName": ..., "state": ..., "conditions": ..., "grantControls": ...}]
    """
    # TODO(devin): implement
    raise NotImplementedError("IN-04 not yet implemented")
