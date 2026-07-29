"""
graph/client.py
Thin wrapper around Microsoft Graph API.
Handles:
  - Bearer token injection
  - Automatic pagination via @odata.nextLink
  - Per-request error handling (logs and returns empty on failure)
  - v1.0 and beta endpoint support
"""

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

# Max automatic retries when Graph returns 429 (throttling).
MAX_THROTTLE_RETRIES = 4
DEFAULT_RETRY_AFTER = 10  # seconds, used when Graph omits the Retry-After header

GRAPH_V1 = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class GraphClient:
    def __init__(self, token: str):
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "ConsistencyLevel": "eventual",  # required for $count and advanced filters
            }
        )

    # ------------------------------------------------------------------
    # Core HTTP
    # ------------------------------------------------------------------
    def get(self, url: str, params: dict | None = None) -> dict | None:
        """
        Single GET. Returns parsed JSON or None on error.

        Automatically retries on HTTP 429 (throttling), honouring the
        Retry-After header, up to MAX_THROTTLE_RETRIES times.
        """
        for attempt in range(MAX_THROTTLE_RETRIES + 1):
            try:
                resp = self._session.get(url, params=params, timeout=30)

                if resp.status_code == 429 and attempt < MAX_THROTTLE_RETRIES:
                    retry_after = int(
                        resp.headers.get("Retry-After", DEFAULT_RETRY_AFTER)
                    )
                    logger.info(
                        f"Throttled (429) on {url[:70]}... retrying in {retry_after}s "
                        f"(attempt {attempt + 1}/{MAX_THROTTLE_RETRIES})."
                    )
                    time.sleep(retry_after)
                    continue

                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.HTTPError as e:
                logger.warning(
                    f"HTTP error on GET {url}: {e.response.status_code} {e.response.text[:200]}"
                )
                return None
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request error on GET {url}: {e}")
                return None
        return None

    def get_all(self, url: str, params: dict | None = None) -> list[dict]:
        """
        GET with automatic pagination.
        Follows @odata.nextLink until exhausted.
        Returns flat list of all 'value' items.
        """
        results = []
        next_url: str | None = url

        while next_url:
            data = self.get(next_url, params=params if next_url == url else None)
            if data is None:
                logger.warning(f"Pagination interrupted at {next_url}")
                break

            items = data.get("value", [])
            results.extend(items)

            next_url = data.get("@odata.nextLink")
            if next_url:
                logger.debug(f"Fetching next page: {next_url[:80]}...")

        return results

    # ------------------------------------------------------------------
    # Tenant
    # ------------------------------------------------------------------
    def get_tenant_info(self) -> dict:
        """Return organization display name and tenant ID."""
        data = self.get(f"{GRAPH_V1}/organization")
        if data and data.get("value"):
            org = data["value"][0]
            return {
                "displayName": org.get("displayName", "Unknown"),
                "id": org.get("id", "Unknown"),
                "verifiedDomains": [
                    d["name"] for d in org.get("verifiedDomains", []) if d.get("isDefault")
                ],
            }
        return {"displayName": "Unknown", "id": "Unknown", "verifiedDomains": []}

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------
    def get_all_users(self, select: list[str] | None = None) -> list[dict]:
        """
        Return all users. Optionally limit fields with $select.

        Tries the beta endpoint first because signInActivity (used by dormancy
        checks) is only exposed there. On Entra ID Free tenants that property
        is not licensed and the beta call is rejected, so we fall back to the
        v1.0 endpoint without signInActivity — the rest of the checks still run.
        """
        default_select = [
            "id", "displayName", "userPrincipalName", "accountEnabled",
            "signInActivity", "passwordPolicies", "userType", "createdDateTime",
        ]
        fields = select or default_select

        users = self.get_all(
            f"{GRAPH_BETA}/users",
            params={"$select": ",".join(fields), "$top": "999"},
        )
        if users:
            return users

        # Fallback: drop signInActivity (premium-only) and use v1.0.
        basic_fields = [f for f in fields if f != "signInActivity"]
        logger.info(
            "beta /users returned nothing (likely a non-premium tenant); "
            "falling back to v1.0 /users without signInActivity."
        )
        return self.get_all(
            f"{GRAPH_V1}/users",
            params={"$select": ",".join(basic_fields), "$top": "999"},
        )

    def get_user_auth_methods(self, user_id: str) -> list[dict]:
        """Return registered authentication methods for a user."""
        return self.get_all(
            f"{GRAPH_V1}/users/{user_id}/authentication/methods"
        )

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------
    def get_directory_role_assignments(self) -> list[dict]:
        """Return all role assignments (unified role assignments)."""
        return self.get_all(
            f"{GRAPH_V1}/roleManagement/directory/roleAssignments",
            params={"$expand": "principal", "$top": "999"},
        )

    def get_role_definitions(self) -> list[dict]:
        """Return all built-in and custom role definitions."""
        return self.get_all(
            f"{GRAPH_V1}/roleManagement/directory/roleDefinitions"
        )

    def get_global_admin_role_id(self) -> str | None:
        """Return the roleDefinitionId for Global Administrator."""
        roles = self.get_role_definitions()
        for role in roles:
            if role.get("displayName") == "Global Administrator":
                return role.get("id")
        return None

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------
    def get_all_groups(self) -> list[dict]:
        return self.get_all(
            f"{GRAPH_V1}/groups",
            params={
                "$select": "id,displayName,groupTypes,mailEnabled,securityEnabled",
                "$top": "999",
            },
        )

    def get_group_owners(self, group_id: str) -> list[dict]:
        return self.get_all(f"{GRAPH_V1}/groups/{group_id}/owners")

    # ------------------------------------------------------------------
    # Service Principals / Applications
    # ------------------------------------------------------------------
    def get_all_service_principals(self) -> list[dict]:
        return self.get_all(
            f"{GRAPH_V1}/servicePrincipals",
            params={
                "$select": "id,displayName,appId,keyCredentials,passwordCredentials,appRoles",
                "$top": "999",
            },
        )

    def get_sp_app_role_assignments(self, sp_id: str) -> list[dict]:
        """Return app role assignments for a service principal."""
        return self.get_all(
            f"{GRAPH_V1}/servicePrincipals/{sp_id}/appRoleAssignments"
        )

    def get_all_applications(self) -> list[dict]:
        return self.get_all(
            f"{GRAPH_V1}/applications",
            params={
                "$select": "id,displayName,appId,web,publicClient,passwordCredentials,keyCredentials",
                "$top": "999",
            },
        )

    # ------------------------------------------------------------------
    # Conditional Access
    # ------------------------------------------------------------------
    def get_conditional_access_policies(self) -> list[dict]:
        return self.get_all(
            f"{GRAPH_V1}/identity/conditionalAccess/policies"
        )

    # ------------------------------------------------------------------
    # Audit / Sign-in logs
    # ------------------------------------------------------------------
    def get_signin_logs(self, top: int = 100) -> list[dict]:
        """Return recent sign-in logs (requires AuditLog.Read.All)."""
        return self.get_all(
            f"{GRAPH_BETA}/auditLogs/signIns",
            params={"$top": str(top), "$orderby": "createdDateTime desc"},
        )
