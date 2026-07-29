"""
checks/high.py
High severity checks (HI-01 to HI-04). Bilingual finding text.
"""

import logging
from datetime import datetime, timezone, timedelta

from graph.client import GraphClient
from utils.finding import Finding, Severity
from checks.common import (
    T,
    assignments_by_principal,
    has_mfa,
    parse_graph_datetime,
    signin_activity_available,
)

logger = logging.getLogger(__name__)

DORMANT_DAYS = 90
SECRET_EXPIRY_WINDOW_DAYS = 30
_GUEST = "Guest"


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
                    title=T(f"Comprobación {check_id} fallida", f"Check {check_id} failed"),
                    severity=Severity.HIGH,
                    description=T("", ""),
                    evidence=[],
                    recommendation=T("", ""),
                    error=str(e),
                )
            )
    return results


def _users_by_id(graph: GraphClient) -> dict[str, dict]:
    return {u["id"]: u for u in graph.get_all_users() if u.get("id")}


def check_hi01(graph: GraphClient) -> Finding:
    """HI-01: Privileged users (non-guest) without MFA."""
    assignments = assignments_by_principal(graph)
    users = _users_by_id(graph)
    flagged = []

    for principal_id, entry in assignments.items():
        if not entry["roles"]:
            continue
        user = users.get(principal_id)
        if user is None:
            continue
        if (user.get("userType") or "").lower() == _GUEST.lower():
            continue
        if not has_mfa(graph, principal_id):
            flagged.append(
                {"displayName": user.get("displayName", "Unknown"),
                 "userPrincipalName": user.get("userPrincipalName", "—"), "roles": entry["roles"]}
            )

    if flagged:
        return Finding(
            id="HI-01",
            title=T("Usuarios privilegiados sin MFA", "Privileged users without MFA"),
            severity=Severity.HIGH,
            description=T(
                f"{len(flagged)} usuario(s) con un rol de directorio no tienen registrado un "
                "segundo factor. Las cuentas privilegiadas sin MFA son un objetivo primario de los "
                "ataques basados en credenciales.",
                f"{len(flagged)} user(s) holding a directory role have no second factor registered. "
                "Privileged accounts without MFA are a primary target for credential-based attacks.",
            ),
            evidence=flagged,
            recommendation=T(
                "Exija MFA a todos los titulares de roles mediante Acceso Condicional y registre un "
                "método fuerte para cada uno. Considere PIM para limitar el privilegio permanente.",
                "Enforce MFA for all role-holders via Conditional Access and register a strong "
                "method for each. Consider PIM to limit standing privilege.",
            ),
            reference="https://attack.mitre.org/techniques/T1078/",
        )
    return Finding(
        id="HI-01",
        title=T("Todos los usuarios privilegiados tienen MFA", "All privileged users have MFA"),
        severity=Severity.HIGH,
        description=T(
            "Todo usuario no invitado con un rol de directorio tiene un segundo factor registrado.",
            "Every non-guest user with a directory role has a second factor registered."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )


def check_hi02(graph: GraphClient) -> Finding:
    """HI-02: Dormant accounts (90+ days) with active role assignments."""
    assignments = assignments_by_principal(graph)
    users = _users_by_id(graph)

    if not signin_activity_available(users.values()):
        return Finding(
            id="HI-02",
            title=T("Comprobación de cuentas inactivas omitida (sin datos de inicio de sesión)",
                    "Dormant account check skipped (sign-in data unavailable)"),
            severity=Severity.HIGH,
            description=T(
                "La actividad de inicio de sesión (lastSignInDateTime) no está disponible para este "
                "tenant. Este dato requiere una licencia Entra ID P1/P2, por lo que no se pudo "
                "ejecutar la detección de cuentas inactivas.",
                "Sign-in activity (lastSignInDateTime) is not available for this tenant. This data "
                "requires an Entra ID P1/P2 license, so dormant-account detection could not run.",
            ),
            evidence=[],
            recommendation=T(
                "Habilite Entra ID P1/P2 para detectar cuentas privilegiadas inactivas, o revise "
                "los registros de inicio de sesión manualmente.",
                "Enable Entra ID P1/P2 to surface dormant privileged accounts, or review sign-in "
                "logs manually.",
            ),
            passed=True,
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=DORMANT_DAYS)
    flagged = []
    for principal_id, entry in assignments.items():
        if not entry["roles"]:
            continue
        user = users.get(principal_id)
        if user is None:
            continue
        activity = user.get("signInActivity") or {}
        last_signin = parse_graph_datetime(activity.get("lastSignInDateTime"))
        if last_signin is None or last_signin < cutoff:
            flagged.append(
                {"displayName": user.get("displayName", "Unknown"),
                 "userPrincipalName": user.get("userPrincipalName", "—"),
                 "lastSignIn": activity.get("lastSignInDateTime") or "never", "roles": entry["roles"]}
            )

    if flagged:
        return Finding(
            id="HI-02",
            title=T("Cuentas inactivas con roles activos", "Dormant accounts with active roles"),
            severity=Severity.HIGH,
            description=T(
                f"{len(flagged)} cuenta(s) con un rol de directorio no han iniciado sesión en "
                f"{DORMANT_DAYS}+ días (o nunca). Las cuentas privilegiadas sin uso son candidatas "
                "ideales para la toma de control porque nadie detecta actividad anómala.",
                f"{len(flagged)} account(s) with a directory role have not signed in for "
                f"{DORMANT_DAYS}+ days (or never). Unused privileged accounts are prime candidates "
                "for takeover because nobody notices anomalous activity.",
            ),
            evidence=flagged,
            recommendation=T(
                "Revise cada cuenta: retire roles a las que ya no los necesiten, deshabilite o "
                "elimine cuentas inactivas, y exija rejustificar el acceso conservado.",
                "Review each account: remove roles from those no longer needed, disable or delete "
                "dormant accounts, and require re-justification for retained access.",
            ),
            reference="https://learn.microsoft.com/entra/identity/monitoring-health/",
        )
    return Finding(
        id="HI-02",
        title=T("Sin cuentas inactivas con roles activos", "No dormant accounts with active roles"),
        severity=Severity.HIGH,
        description=T("Todos los titulares de roles han iniciado sesión dentro de la ventana.",
                      "All role-holders have signed in within the dormancy window."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )


def check_hi03(graph: GraphClient) -> Finding:
    """HI-03: Guest users with directory roles."""
    assignments = assignments_by_principal(graph)
    users = _users_by_id(graph)
    flagged = []

    for principal_id, entry in assignments.items():
        if not entry["roles"]:
            continue
        user = users.get(principal_id)
        if user is None:
            continue
        if (user.get("userType") or "").lower() == _GUEST.lower():
            flagged.append(
                {"displayName": user.get("displayName", "Unknown"),
                 "userPrincipalName": user.get("userPrincipalName", "—"), "roles": entry["roles"]}
            )

    if flagged:
        return Finding(
            id="HI-03",
            title=T("Usuarios invitados con roles de directorio", "Guest users with directory roles"),
            severity=Severity.HIGH,
            description=T(
                f"{len(flagged)} usuario(s) invitado(s) (externos) tienen roles de directorio. Los "
                "invitados se gestionan fuera de su tenant, por lo que su higiene de credenciales y "
                "su ciclo de vida no están bajo su control; concederles privilegios extiende su "
                "frontera de confianza.",
                f"{len(flagged)} guest (external) user(s) hold directory roles. Guests are managed "
                "outside your tenant, so their credential hygiene and lifecycle are not under your "
                "control — granting them privilege extends your trust boundary.",
            ),
            evidence=flagged,
            recommendation=T(
                "Retire los roles de directorio de las cuentas invitadas. Si se requiere acceso "
                "privilegiado externo, use cuentas internas dedicadas o gestión de derechos con "
                "revisiones de acceso con límite temporal.",
                "Remove directory roles from guest accounts. If external privileged access is "
                "required, use dedicated internal accounts or entitlement management with time-bound "
                "access reviews.",
            ),
            reference="https://attack.mitre.org/techniques/T1078/004/",
        )
    return Finding(
        id="HI-03",
        title=T("Sin usuarios invitados con roles de directorio",
                "No guest users with directory roles"),
        severity=Severity.HIGH,
        description=T("Ninguna cuenta invitada tiene un rol de directorio.",
                      "No guest account holds a directory role."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )


def check_hi04(graph: GraphClient) -> Finding:
    """HI-04: Service Principal secrets expired or expiring within 30 days."""
    now = datetime.now(timezone.utc)
    window = now + timedelta(days=SECRET_EXPIRY_WINDOW_DAYS)
    flagged = []

    for sp in graph.get_all_service_principals():
        for cred in sp.get("passwordCredentials") or []:
            end = parse_graph_datetime(cred.get("endDateTime"))
            if end is None:
                continue
            if end < window:
                status = "expired" if end < now else "expiring"
                hint = cred.get("hint") or cred.get("displayName") or "—"
                flagged.append(
                    {"displayName": sp.get("displayName", "Unknown"), "appId": sp.get("appId", "—"),
                     "secretHint": hint, "expiresOn": cred.get("endDateTime"), "status": status}
                )

    if flagged:
        expired = sum(1 for f in flagged if f["status"] == "expired")
        return Finding(
            id="HI-04",
            title=T("Secretos de Service Principals caducados o próximos a caducar",
                    "Service Principal secrets expired or expiring soon"),
            severity=Severity.HIGH,
            description=T(
                f"{len(flagged)} secreto(s) de service principal están caducados o caducan en "
                f"{SECRET_EXPIRY_WINDOW_DAYS} días ({expired} ya caducados). Los secretos caducados "
                "rompen integraciones; los próximos a caducar arriesgan cortes súbitos, y los "
                "secretos olvidados de larga duración son un riesgo de fuga de credenciales.",
                f"{len(flagged)} service principal secret(s) are expired or expiring within "
                f"{SECRET_EXPIRY_WINDOW_DAYS} days ({expired} already expired). Expired secrets break "
                "integrations; soon-to-expire ones risk sudden outages, and forgotten long-lived "
                "secrets are a credential-leak risk.",
            ),
            evidence=flagged,
            recommendation=T(
                "Rote los secretos antes de que caduquen y elimine las credenciales sin uso. Prefiera "
                "credenciales de certificado o identidades administradas frente a secretos de cliente "
                "cuando sea posible.",
                "Rotate secrets before expiry and remove unused credentials. Prefer certificate "
                "credentials or managed identities over client secrets where possible.",
            ),
            reference="https://learn.microsoft.com/entra/identity-platform/howto-create-service-principal-portal",
        )
    return Finding(
        id="HI-04",
        title=T("Sin secretos de Service Principals próximos a caducar",
                "No expiring Service Principal secrets"),
        severity=Severity.HIGH,
        description=T(
            f"Ningún secreto de service principal caduca en {SECRET_EXPIRY_WINDOW_DAYS} días.",
            f"No service principal secret expires within {SECRET_EXPIRY_WINDOW_DAYS} days."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )
