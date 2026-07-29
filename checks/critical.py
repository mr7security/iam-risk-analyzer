"""
checks/critical.py
Critical severity checks (CR-01 to CR-04).
Finding text is bilingual (es/en) via the T() helper.
"""

import logging

from graph.client import GraphClient
from utils.finding import Finding, Severity
from checks.common import (
    ROLE_MANAGEMENT_READWRITE_APPROLE_ID,
    T,
    assignments_by_principal,
    get_global_admins,
    has_mfa,
)

logger = logging.getLogger(__name__)

ALL_IDS = {"CR-01", "CR-02", "CR-03", "CR-04"}

MAX_GLOBAL_ADMINS = 3


def run_critical_checks(graph: GraphClient, selected: set[str] | None) -> list[Finding]:
    """Run all critical checks (or only those in `selected`)."""
    results = []
    checks = [check_cr01, check_cr02, check_cr03, check_cr04]
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
                    severity=Severity.CRITICAL,
                    description=T("", ""),
                    evidence=[],
                    recommendation=T("", ""),
                    error=str(e),
                )
            )
    return results


def check_cr01(graph: GraphClient) -> Finding:
    """CR-01: More than 3 Global Administrators."""
    admins = get_global_admins(graph)
    if len(admins) > MAX_GLOBAL_ADMINS:
        evidence = [
            {"displayName": a["displayName"], "userPrincipalName": a["userPrincipalName"], "id": a["id"]}
            for a in admins
        ]
        return Finding(
            id="CR-01",
            title=T("Número excesivo de Administradores Globales",
                    "Excessive number of Global Administrators"),
            severity=Severity.CRITICAL,
            description=T(
                f"El tenant tiene {len(admins)} Administradores Globales. Microsoft recomienda "
                "menos de 5 (esta herramienta marca más de 3). Cada Administrador Global es una "
                "cuenta con control total y un objetivo de alto valor; cuantos más haya, mayor es "
                "la superficie de ataque para el abuso de privilegios.",
                f"The tenant has {len(admins)} Global Administrators. Microsoft recommends fewer "
                "than 5 (this tool flags more than 3). Every Global Admin is a full-control account "
                "and a high-value target; the more there are, the larger the attack surface for "
                "privilege abuse.",
            ),
            evidence=evidence,
            recommendation=T(
                "Reduzca los Administradores Globales al mínimo imprescindible. Traslade las tareas "
                "diarias a roles de menor privilegio (p. ej. Administrador de Usuarios, Lector de "
                "Seguridad) y proteja a los admins restantes con MFA resistente a phishing y PIM.",
                "Reduce Global Administrators to the minimum required. Move day-to-day duties to "
                "least-privilege roles (e.g. User Administrator, Security Reader) and protect "
                "remaining admins with phishing-resistant MFA and PIM.",
            ),
            reference="https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices",
        )
    return Finding(
        id="CR-01",
        title=T("Recuento de Administradores Globales dentro del límite recomendado",
                "Global Administrator count within recommended limit"),
        severity=Severity.CRITICAL,
        description=T(f"El tenant tiene {len(admins)} Administradores Globales.",
                      f"The tenant has {len(admins)} Global Administrators."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )


def check_cr02(graph: GraphClient) -> Finding:
    """CR-02: Global Admin accounts without MFA registered."""
    admins = get_global_admins(graph)
    without_mfa = []
    for a in admins:
        if not has_mfa(graph, a["id"]):
            without_mfa.append(
                {"displayName": a["displayName"], "userPrincipalName": a["userPrincipalName"],
                 "authMethods": "password only"}
            )

    if without_mfa:
        return Finding(
            id="CR-02",
            title=T("Administradores Globales sin MFA", "Global Administrators without MFA"),
            severity=Severity.CRITICAL,
            description=T(
                f"{len(without_mfa)} cuenta(s) de Administrador Global no tienen registrado un "
                "segundo factor de autenticación. Una contraseña comprometida en cualquiera de "
                "estas cuentas otorga control total del tenant.",
                f"{len(without_mfa)} Global Administrator account(s) have no second authentication "
                "factor registered. A compromised password on any of these accounts grants full "
                "control of the tenant.",
            ),
            evidence=without_mfa,
            recommendation=T(
                "Exija MFA resistente a phishing para toda cuenta privilegiada mediante una política "
                "de Acceso Condicional, y registre de inmediato un método fuerte (FIDO2 o Microsoft "
                "Authenticator) para cada administrador.",
                "Require phishing-resistant MFA for every privileged account via a Conditional "
                "Access policy, and register a strong method (FIDO2 or Microsoft Authenticator) for "
                "each admin immediately.",
            ),
            reference="https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks",
        )
    return Finding(
        id="CR-02",
        title=T("Todos los Administradores Globales tienen MFA",
                "All Global Administrators have MFA"),
        severity=Severity.CRITICAL,
        description=T(
            f"Los {len(admins)} Administradores Globales tienen un segundo factor registrado.",
            f"All {len(admins)} Global Administrators have a second factor registered."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )


def check_cr03(graph: GraphClient) -> Finding:
    """CR-03: Service Principals with RoleManagement.ReadWrite.Directory."""
    flagged = []
    for sp in graph.get_all_service_principals():
        sp_id = sp.get("id")
        if not sp_id:
            continue
        for assignment in graph.get_sp_app_role_assignments(sp_id):
            if assignment.get("appRoleId") == ROLE_MANAGEMENT_READWRITE_APPROLE_ID:
                flagged.append(
                    {"displayName": sp.get("displayName", "Unknown"), "appId": sp.get("appId", "—"),
                     "permission": "RoleManagement.ReadWrite.Directory"}
                )
                break

    if flagged:
        return Finding(
            id="CR-03",
            title=T("Service Principals pueden gestionar roles de directorio",
                    "Service Principals can manage directory roles"),
            severity=Severity.CRITICAL,
            description=T(
                f"{len(flagged)} service principal(s) tienen RoleManagement.ReadWrite.Directory. "
                "Este permiso permite a la aplicación conceder cualquier rol de directorio —incluido "
                "Administrador Global— a cualquier entidad, lo que es una vía directa al compromiso "
                "total del tenant si la aplicación es abusada.",
                f"{len(flagged)} service principal(s) hold RoleManagement.ReadWrite.Directory. This "
                "permission lets the app grant any directory role — including Global Administrator — "
                "to any principal, which is a direct path to full tenant compromise if the app is "
                "abused.",
            ),
            evidence=flagged,
            recommendation=T(
                "Elimine RoleManagement.ReadWrite.Directory salvo que sea estrictamente necesario. "
                "Prefiera solo lectura (RoleManagement.Read.Directory), rote las credenciales de la "
                "aplicación y audite quién puede consentir permisos de Graph de alto privilegio.",
                "Remove RoleManagement.ReadWrite.Directory unless strictly required. Prefer "
                "read-only (RoleManagement.Read.Directory), rotate the app's credentials, and audit "
                "who can consent to high-privilege Graph permissions.",
            ),
            reference="https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview",
        )
    return Finding(
        id="CR-03",
        title=T("Ningún Service Principal con acceso de escritura a la gestión de roles",
                "No Service Principals with role-management write access"),
        severity=Severity.CRITICAL,
        description=T("Ningún service principal tiene RoleManagement.ReadWrite.Directory.",
                      "No service principal holds RoleManagement.ReadWrite.Directory."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )


def check_cr04(graph: GraphClient) -> Finding:
    """CR-04: Non-expiring passwords on accounts with privileged roles."""
    assignments = assignments_by_principal(graph)
    flagged = []

    for user in graph.get_all_users():
        policies = user.get("passwordPolicies") or ""
        if "DisablePasswordExpiration" not in policies:
            continue
        user_id = user.get("id")
        entry = assignments.get(user_id)
        if entry and entry["roles"]:
            flagged.append(
                {"displayName": user.get("displayName", "Unknown"),
                 "userPrincipalName": user.get("userPrincipalName", "—"), "roles": entry["roles"]}
            )

    if flagged:
        return Finding(
            id="CR-04",
            title=T("Cuentas privilegiadas con contraseñas que no expiran",
                    "Privileged accounts with non-expiring passwords"),
            severity=Severity.CRITICAL,
            description=T(
                f"{len(flagged)} cuenta(s) con un rol de directorio tienen la expiración de "
                "contraseña deshabilitada. Una contraseña estática y de larga duración en una cuenta "
                "privilegiada aumenta enormemente la ventana para el robo y la reutilización de "
                "credenciales.",
                f"{len(flagged)} account(s) with a directory role have password expiration disabled. "
                "A static, long-lived password on a privileged account greatly increases the window "
                "for credential theft and reuse.",
            ),
            evidence=flagged,
            recommendation=T(
                "Elimine la política DisablePasswordExpiration de las cuentas privilegiadas, o "
                "migre a autenticación sin contraseña / basada en certificado. Aplique MFA y "
                "considere la activación just-in-time con PIM para estos roles.",
                "Remove the DisablePasswordExpiration policy from privileged accounts, or migrate "
                "them to passwordless / certificate-based auth. Enforce MFA and consider PIM "
                "just-in-time activation for these roles.",
            ),
            reference="https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy",
        )
    return Finding(
        id="CR-04",
        title=T("Sin cuentas privilegiadas con contraseñas que no expiran",
                "No privileged accounts with non-expiring passwords"),
        severity=Severity.CRITICAL,
        description=T("Ninguna cuenta privilegiada tiene la expiración de contraseña deshabilitada.",
                      "No privileged account has password expiration disabled."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )
