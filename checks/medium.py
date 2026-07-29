"""
checks/medium.py
Medium severity checks (ME-01 to ME-04). Bilingual finding text.
"""

import logging

from graph.client import GraphClient
from utils.finding import Finding, Severity
from checks.common import T, assignments_by_principal, has_mfa

logger = logging.getLogger(__name__)

GUEST_RATIO_THRESHOLD = 0.20
SUSPICIOUS_REDIRECT_PATTERNS = ["localhost", "127.0.0.1", "*", "http://"]
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
                    title=T(f"Comprobación {check_id} fallida", f"Check {check_id} failed"),
                    severity=Severity.MEDIUM,
                    description=T("", ""),
                    evidence=[],
                    recommendation=T("", ""),
                    error=str(e),
                )
            )
    return results


def check_me01(graph: GraphClient) -> Finding:
    """ME-01: Non-privileged, enabled users without MFA (sampled on large tenants)."""
    privileged_ids = {pid for pid, e in assignments_by_principal(graph).items() if e["roles"]}

    candidates = [
        u for u in graph.get_all_users()
        if u.get("accountEnabled") and u.get("id") not in privileged_ids
        and (u.get("userType") or "").lower() != _GUEST.lower()
    ]

    sampled = candidates[:ME01_MAX_USERS]
    truncated = len(candidates) > ME01_MAX_USERS

    flagged = []
    for user in sampled:
        if not has_mfa(graph, user["id"]):
            flagged.append(
                {"displayName": user.get("displayName", "Unknown"),
                 "userPrincipalName": user.get("userPrincipalName", "—")}
            )

    if flagged:
        scope_es = (f"primeros {ME01_MAX_USERS} de {len(candidates)} usuarios (muestreado)"
                    if truncated else f"{len(candidates)} usuarios")
        scope_en = (f"first {ME01_MAX_USERS} of {len(candidates)} users (sampled)"
                    if truncated else f"{len(candidates)} users")
        return Finding(
            id="ME-01",
            title=T("Usuarios no privilegiados sin MFA", "Non-privileged users without MFA"),
            severity=Severity.MEDIUM,
            description=T(
                f"{len(flagged)} usuario(s) no privilegiado(s) no tienen registrado un segundo "
                f"factor (revisados {scope_es}). Las cuentas sin MFA son el punto de entrada más "
                "común para el phishing y los ataques de password-spray.",
                f"{len(flagged)} non-privileged user(s) have no second factor registered (checked "
                f"{scope_en}). Accounts without MFA are the most common entry point for phishing and "
                "password-spray attacks.",
            ),
            evidence=flagged,
            recommendation=T(
                "Lance una campaña de registro de MFA y exija MFA a todos los usuarios mediante "
                "Acceso Condicional o valores predeterminados de seguridad.",
                "Roll out an MFA registration campaign and require MFA for all users via Conditional "
                "Access or security defaults.",
            ),
            reference="https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks",
        )
    return Finding(
        id="ME-01",
        title=T("Todos los usuarios no privilegiados muestreados tienen MFA",
                "All sampled non-privileged users have MFA"),
        severity=Severity.MEDIUM,
        description=T("No se encontraron usuarios no privilegiados sin MFA en el conjunto revisado.",
                      "No non-privileged user without MFA found in the checked set."),
        evidence=[],
        recommendation=T("", ""),
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
            title=T("Proporción excesiva de usuarios invitados", "Excessive guest user ratio"),
            severity=Severity.MEDIUM,
            description=T(
                f"Los invitados representan el {ratio:.0%} del directorio ({guests} de {total}), por "
                f"encima del umbral del {GUEST_RATIO_THRESHOLD:.0%}. Una población externa grande "
                "amplía la superficie de ataque y complica la gobernanza de accesos.",
                f"Guests make up {ratio:.0%} of the directory ({guests} of {total}), above the "
                f"{GUEST_RATIO_THRESHOLD:.0%} threshold. A large external population widens the "
                "attack surface and complicates access governance.",
            ),
            evidence=[{"totalUsers": total, "guestUsers": guests, "guestRatio": f"{ratio:.1%}"}],
            recommendation=T(
                "Ejecute revisiones de acceso sobre los invitados, elimine cuentas externas "
                "obsoletas y gobierne su ciclo de vida con gestión de derechos y políticas de "
                "expiración.",
                "Run access reviews on guests, remove stale external accounts, and govern guest "
                "lifecycle with entitlement management and expiration policies.",
            ),
            reference="https://learn.microsoft.com/entra/external-id/",
        )
    return Finding(
        id="ME-02",
        title=T("Proporción de invitados dentro del límite", "Guest user ratio within limit"),
        severity=Severity.MEDIUM,
        description=T(f"Los invitados son el {ratio:.0%} del directorio ({guests} de {total}).",
                      f"Guests are {ratio:.0%} of the directory ({guests} of {total})."),
        evidence=[],
        recommendation=T("", ""),
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
                {"groupName": group.get("displayName", "Unknown"), "groupId": group.get("id", "—"),
                 "owner": owner.get("userPrincipalName") or owner.get("displayName", "—")}
            )

    if flagged:
        return Finding(
            id="ME-03",
            title=T("Grupos con un único propietario", "Groups with a single owner"),
            severity=Severity.MEDIUM,
            description=T(
                f"{len(flagged)} grupo(s) de seguridad/M365 tienen exactamente un propietario. Un "
                "único propietario es un riesgo de orfandad: si esa cuenta se deshabilita o se va, "
                "el grupo queda sin gestión, lo que puede dejar accesos huérfanos.",
                f"{len(flagged)} security/M365 group(s) have exactly one owner. A single owner is an "
                "orphan risk: if that account is disabled or leaves, the group becomes unmanaged, "
                "which can strand access grants.",
            ),
            evidence=flagged,
            recommendation=T(
                "Asigne al menos dos propietarios a cada grupo y revise periódicamente la propiedad "
                "como parte de la gobernanza de accesos.",
                "Assign at least two owners to each group, and periodically review ownership as part "
                "of access governance.",
            ),
            reference="https://learn.microsoft.com/entra/identity/users/groups-self-service-management",
        )
    return Finding(
        id="ME-03",
        title=T("Sin grupos de un único propietario", "No single-owner groups"),
        severity=Severity.MEDIUM,
        description=T("Ningún grupo de seguridad o M365 tiene un único propietario.",
                      "No security or M365 group has a single owner."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )


def check_me04(graph: GraphClient) -> Finding:
    """ME-04: App registrations with suspicious redirect URIs."""
    flagged = []
    for app in graph.get_all_applications():
        uris = []
        uris += (app.get("web") or {}).get("redirectUris") or []
        uris += (app.get("publicClient") or {}).get("redirectUris") or []
        suspicious = [u for u in uris
                      if any(pat in (u or "").lower() for pat in SUSPICIOUS_REDIRECT_PATTERNS)]
        if suspicious:
            flagged.append(
                {"appName": app.get("displayName", "Unknown"), "appId": app.get("appId", "—"),
                 "suspiciousUris": suspicious}
            )

    if flagged:
        return Finding(
            id="ME-04",
            title=T("Registros de aplicaciones con URIs de redirección sospechosas",
                    "App registrations with suspicious redirect URIs"),
            severity=Severity.MEDIUM,
            description=T(
                f"{len(flagged)} registro(s) de aplicación usan URIs de redirección que son "
                "localhost, comodín o HTTP plano. Estas pueden permitir la interceptación de tokens "
                "o el robo del código de autorización si la app gestiona el inicio de sesión.",
                f"{len(flagged)} app registration(s) use redirect URIs that are localhost, wildcard, "
                "or plain HTTP. These can enable token interception or authorization-code theft if "
                "the app handles user sign-in.",
            ),
            evidence=flagged,
            recommendation=T(
                "Elimine las URIs de redirección de desarrollo/comodín/HTTP de las apps de producción "
                "y restrinja a URLs HTTPS exactas que usted controle.",
                "Remove development/wildcard/HTTP redirect URIs from production apps and restrict to "
                "exact HTTPS URLs you control.",
            ),
            reference="https://attack.mitre.org/techniques/T1550/001/",
        )
    return Finding(
        id="ME-04",
        title=T("Sin URIs de redirección sospechosas", "No suspicious redirect URIs"),
        severity=Severity.MEDIUM,
        description=T("Ningún registro de aplicación usa una URI de redirección sospechosa.",
                      "No app registration uses a suspicious redirect URI."),
        evidence=[],
        recommendation=T("", ""),
        passed=True,
    )
