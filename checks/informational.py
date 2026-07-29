"""
checks/informational.py
Informational checks (IN-01 to IN-04). Always produce inventories (never passed=True).
Bilingual finding text.
"""

import logging
from datetime import datetime, timezone, timedelta

from graph.client import GraphClient
from utils.finding import Finding, Severity
from checks.common import T, get_global_admins, parse_graph_datetime, signin_activity_available

logger = logging.getLogger(__name__)

INACTIVE_DAYS = 30
_GRAPH_RESOURCE = "Microsoft Graph"


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
                    title=T(f"Comprobación {check_id} fallida", f"Check {check_id} failed"),
                    severity=Severity.INFO,
                    description=T("", ""),
                    evidence=[],
                    recommendation=T("", ""),
                    error=str(e),
                )
            )
    return results


def check_in01(graph: GraphClient) -> Finding:
    """IN-01: Inventory of all Global Administrators."""
    admins = get_global_admins(graph)
    evidence = [
        {"displayName": a["displayName"], "userPrincipalName": a["userPrincipalName"], "id": a["id"]}
        for a in admins
    ]
    return Finding(
        id="IN-01",
        title=T(f"Inventario de Administradores Globales ({len(admins)})",
                f"Global Administrator inventory ({len(admins)})"),
        severity=Severity.INFO,
        description=T(
            f"{len(admins)} cuenta(s) tienen actualmente el rol de Administrador Global. Revise "
            "esta lista con regularidad y manténgala lo más reducida posible.",
            f"{len(admins)} account(s) currently hold the Global Administrator role. Review this "
            "list regularly and keep it as small as possible.",
        ),
        evidence=evidence,
        recommendation=T("", ""),
    )


def check_in02(graph: GraphClient) -> Finding:
    """IN-02: Inventory of Service Principals with Microsoft Graph permissions."""
    inventory = []
    for sp in graph.get_all_service_principals():
        sp_id = sp.get("id")
        if not sp_id:
            continue
        graph_roles = [
            a.get("appRoleId") for a in graph.get_sp_app_role_assignments(sp_id)
            if a.get("resourceDisplayName") == _GRAPH_RESOURCE
        ]
        if graph_roles:
            inventory.append(
                {"displayName": sp.get("displayName", "Unknown"), "appId": sp.get("appId", "—"),
                 "graphPermissions": graph_roles}
            )

    return Finding(
        id="IN-02",
        title=T(f"Service Principals con permisos de Microsoft Graph ({len(inventory)})",
                f"Service Principals with Microsoft Graph permissions ({len(inventory)})"),
        severity=Severity.INFO,
        description=T(
            f"{len(inventory)} service principal(s) tienen concedidos permisos de aplicación de "
            "Microsoft Graph. Se muestran los IDs de rol de aplicación; revise cualquiera con "
            "ámbitos amplios o de escritura.",
            f"{len(inventory)} service principal(s) have been granted Microsoft Graph application "
            "permissions. App role IDs are shown; review any with broad or write scopes.",
        ),
        evidence=inventory,
        recommendation=T("", ""),
    )


def check_in03(graph: GraphClient) -> Finding:
    """IN-03: Users inactive for 30+ days (or never signed in)."""
    users = graph.get_all_users()

    if not signin_activity_available(users):
        return Finding(
            id="IN-03",
            title=T("Inventario de usuarios inactivos no disponible (requiere licencia premium)",
                    "Inactive-user inventory unavailable (needs premium license)"),
            severity=Severity.INFO,
            description=T(
                "La actividad de inicio de sesión (lastSignInDateTime) no está disponible para este "
                "tenant. Este dato requiere una licencia Entra ID P1/P2, por lo que no se pudo "
                "generar el informe de usuarios inactivos.",
                "Sign-in activity (lastSignInDateTime) is not available for this tenant. This data "
                "requires an Entra ID P1/P2 license, so inactive-user reporting could not be "
                "produced.",
            ),
            evidence=[],
            recommendation=T("", ""),
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=INACTIVE_DAYS)
    inventory = []
    for user in users:
        activity = user.get("signInActivity") or {}
        last_signin = parse_graph_datetime(activity.get("lastSignInDateTime"))
        if last_signin is None or last_signin < cutoff:
            inventory.append(
                {"displayName": user.get("displayName", "Unknown"),
                 "userPrincipalName": user.get("userPrincipalName", "—"),
                 "lastSignIn": activity.get("lastSignInDateTime") or "never",
                 "accountEnabled": user.get("accountEnabled")}
            )

    return Finding(
        id="IN-03",
        title=T(f"Usuarios inactivos durante {INACTIVE_DAYS}+ días ({len(inventory)})",
                f"Users inactive for {INACTIVE_DAYS}+ days ({len(inventory)})"),
        severity=Severity.INFO,
        description=T(
            f"{len(inventory)} usuario(s) no han iniciado sesión en {INACTIVE_DAYS} días (o nunca). "
            "Considere deshabilitar o depurar las cuentas obsoletas.",
            f"{len(inventory)} user(s) have not signed in within {INACTIVE_DAYS} days (or have never "
            "signed in). Consider disabling or cleaning up stale accounts.",
        ),
        evidence=inventory,
        recommendation=T("", ""),
    )


def check_in04(graph: GraphClient) -> Finding:
    """IN-04: Inventory of Conditional Access policies."""
    inventory = []
    for policy in graph.get_conditional_access_policies():
        conditions = policy.get("conditions") or {}
        users = (conditions.get("users") or {})
        apps = (conditions.get("applications") or {})
        grant = policy.get("grantControls") or {}
        inventory.append(
            {"displayName": policy.get("displayName", "Unknown"), "state": policy.get("state", "—"),
             "conditions": {"includeUsers": users.get("includeUsers"),
                            "includeApplications": apps.get("includeApplications")},
             "grantControls": grant.get("builtInControls")}
        )

    return Finding(
        id="IN-04",
        title=T(f"Inventario de políticas de Acceso Condicional ({len(inventory)})",
                f"Conditional Access policy inventory ({len(inventory)})"),
        severity=Severity.INFO,
        description=T(
            f"Se encontraron {len(inventory)} política(s) de Acceso Condicional. Revise los estados "
            "(habilitada / soloInforme / deshabilitada) y asegúrese de que se aplican controles de "
            "MFA y de dispositivo.",
            f"{len(inventory)} Conditional Access policy/policies found. Review states (enabled / "
            "reportOnly / disabled) and ensure MFA and device controls are enforced.",
        ),
        evidence=inventory,
        recommendation=T("", ""),
    )
