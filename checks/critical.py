"""
checks/critical.py
Critical severity checks (CR-01 to CR-04).

Each check function signature:
    def check_CRID(graph: GraphClient) -> Finding

All checks return a Finding — either with evidence (issue found),
passed=True (no issue), or error set (check failed to run).

TODO(devin): Implement the body of each check function.
             The stub raises NotImplementedError as a placeholder.
             Do NOT change function signatures or Finding field names.
"""

import logging
from graph.client import GraphClient
from utils.finding import Finding, Severity

logger = logging.getLogger(__name__)

ALL_IDS = {"CR-01", "CR-02", "CR-03", "CR-04"}


def run_critical_checks(graph: GraphClient, selected: set[str] | None) -> list[Finding]:
    """Run all critical checks (or only those in `selected`)."""
    results = []
    checks = [check_cr01, check_cr02, check_cr03, check_cr04]
    for fn in checks:
        check_id = fn.__name__.replace("check_", "").upper().replace("_", "-")
        # Normalize: cr01 → CR-01
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
                    severity=Severity.CRITICAL,
                    description="",
                    evidence=[],
                    recommendation="",
                    error=str(e),
                )
            )
    return results


def check_cr01(graph: GraphClient) -> Finding:
    """
    CR-01: Global Admins excesivos
    Trigger: más de 3 usuarios con rol Global Administrator activo.

    Logic:
      1. Get Global Administrator roleDefinitionId via graph.get_global_admin_role_id()
      2. Get all role assignments via graph.get_directory_role_assignments()
      3. Filter by roleDefinitionId matching Global Admin
      4. If count > 3 → finding with list of admins as evidence
      5. Else → passed=True

    Evidence rows: [{"displayName": ..., "userPrincipalName": ..., "id": ...}]
    """
    # TODO(devin): implement
    raise NotImplementedError("CR-01 not yet implemented")


def check_cr02(graph: GraphClient) -> Finding:
    """
    CR-02: Global Admin sin MFA
    Trigger: cualquier Global Admin con MFA no registrado.

    Logic:
      1. Get list of Global Admins (reuse CR-01 logic or call helper)
      2. For each admin user, call graph.get_user_auth_methods(user_id)
      3. Check if any method with type != "#microsoft.graph.passwordAuthenticationMethod" exists
         (i.e. MFA method: microsoftAuthenticatorAuthenticationMethod, phoneAuthenticationMethod, etc.)
      4. If no MFA method found → add to findings
      5. Return finding with list of admins without MFA, or passed=True

    Evidence rows: [{"displayName": ..., "userPrincipalName": ..., "authMethods": [...]}]

    Note: graph.get_user_auth_methods may require per-user calls — batch carefully.
    """
    # TODO(devin): implement
    raise NotImplementedError("CR-02 not yet implemented")


def check_cr03(graph: GraphClient) -> Finding:
    """
    CR-03: Service Principals con permisos RoleManagement.ReadWrite
    Trigger: any SP granted RoleManagement.ReadWrite.Directory app role.

    Logic:
      1. Get all SPs via graph.get_all_service_principals()
      2. For each SP, get app role assignments via graph.get_sp_app_role_assignments(sp_id)
      3. Check if any assignment has appRoleId matching RoleManagement.ReadWrite.Directory
         Known Graph API appRoleId: "9e3f62cf-ca93-4e39-b65c-4b9e28a22b7a"
      4. If found → finding with SP details
      5. Else → passed=True

    Evidence rows: [{"displayName": ..., "appId": ..., "permission": "RoleManagement.ReadWrite.Directory"}]
    """
    # TODO(devin): implement
    raise NotImplementedError("CR-03 not yet implemented")


def check_cr04(graph: GraphClient) -> Finding:
    """
    CR-04: Cuentas con password nunca expira + rol privilegiado
    Trigger: user has passwordPolicies containing "DisablePasswordExpiration" AND has any directory role assigned.

    Logic:
      1. Get all users with passwordPolicies field
      2. Filter users where "DisablePasswordExpiration" in passwordPolicies
      3. Get all role assignments, filter by users in step 2
      4. If overlap found → finding
      5. Else → passed=True

    Evidence rows: [{"displayName": ..., "userPrincipalName": ..., "roles": [...]}]
    """
    # TODO(devin): implement
    raise NotImplementedError("CR-04 not yet implemented")
