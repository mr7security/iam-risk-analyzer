"""
checks/common.py
Shared helpers used by multiple check modules.

Kept dependency-light: only relies on the public GraphClient methods.
No writes to Entra ID — all read-only.
"""

import logging
from datetime import datetime, timezone

from graph.client import GraphClient

logger = logging.getLogger(__name__)

# Auth method @odata.type that is NOT a second factor.
PASSWORD_METHOD_TYPE = "#microsoft.graph.passwordAuthenticationMethod"

# Graph app role that grants write access to role management (used by CR-03 / IN-02
# to detect over-privileged service principals).
ROLE_MANAGEMENT_READWRITE_APPROLE_ID = "9e3f62cf-ca93-4e39-b65c-4b9e28a22b7a"

_USER_ODATA_TYPE = "#microsoft.graph.user"


def parse_graph_datetime(value: str | None) -> datetime | None:
    """Parse an ISO-8601 Graph timestamp into an aware UTC datetime, or None."""
    if not value:
        return None
    try:
        # Graph returns e.g. "2024-01-15T09:30:00Z"
        cleaned = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        logger.debug(f"Could not parse datetime: {value!r}")
        return None


def signin_activity_available(users) -> bool:
    """
    True if at least one user carries a lastSignInDateTime. On Entra ID Free
    tenants signInActivity is unavailable, so dormancy checks must be skipped
    rather than flagging every account as dormant.
    """
    for u in users:
        if (u.get("signInActivity") or {}).get("lastSignInDateTime"):
            return True
    return False


def has_mfa(graph: GraphClient, user_id: str) -> bool:
    """
    Return True if the user has at least one non-password authentication
    method registered (i.e. a real second factor).

    Reusable by CR-02, HI-01 and ME-01.
    """
    methods = graph.get_user_auth_methods(user_id)
    for method in methods:
        if method.get("@odata.type") != PASSWORD_METHOD_TYPE:
            return True
    return False


def build_role_definition_map(graph: GraphClient) -> dict[str, str]:
    """Return {roleDefinitionId: displayName} for all directory role definitions."""
    return {
        rd.get("id"): rd.get("displayName", "Unknown role")
        for rd in graph.get_role_definitions()
        if rd.get("id")
    }


def assignments_by_principal(graph: GraphClient) -> dict[str, dict]:
    """
    Collapse all directory role assignments into a per-principal view.

    Returns {principalId: {
        "principal": <expanded principal dict or {}>,
        "roleIds": [roleDefinitionId, ...],
        "roles":   [roleDisplayName, ...],
    }}
    """
    role_map = build_role_definition_map(graph)
    result: dict[str, dict] = {}

    for a in graph.get_directory_role_assignments():
        principal_id = a.get("principalId")
        if not principal_id:
            continue
        role_id = a.get("roleDefinitionId")
        role_name = role_map.get(role_id, role_id or "Unknown role")

        entry = result.setdefault(
            principal_id,
            {"principal": a.get("principal") or {}, "roleIds": [], "roles": []},
        )
        # Prefer a populated expanded principal if a later assignment has one.
        if not entry["principal"] and a.get("principal"):
            entry["principal"] = a["principal"]
        if role_id and role_id not in entry["roleIds"]:
            entry["roleIds"].append(role_id)
            entry["roles"].append(role_name)

    return result


def _principal_is_user(principal: dict) -> bool:
    return principal.get("@odata.type", _USER_ODATA_TYPE) == _USER_ODATA_TYPE


def get_global_admins(graph: GraphClient) -> list[dict]:
    """
    Return a list of user principals holding the Global Administrator role.

    Each item: {"id", "displayName", "userPrincipalName"}.
    """
    ga_role_id = graph.get_global_admin_role_id()
    admins: list[dict] = []
    if not ga_role_id:
        logger.warning("Global Administrator role definition not found.")
        return admins

    seen: set[str] = set()
    for a in graph.get_directory_role_assignments():
        if a.get("roleDefinitionId") != ga_role_id:
            continue
        principal = a.get("principal") or {}
        principal_id = a.get("principalId") or principal.get("id")
        if not principal_id or principal_id in seen:
            continue
        # Only count user principals as "admins" for the people-focused checks.
        if principal and not _principal_is_user(principal):
            continue
        seen.add(principal_id)
        admins.append(
            {
                "id": principal_id,
                "displayName": principal.get("displayName", "Unknown"),
                "userPrincipalName": principal.get("userPrincipalName", "—"),
            }
        )
    return admins
