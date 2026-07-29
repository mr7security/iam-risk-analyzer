"""
auth/authenticator.py
Handles MSAL authentication for three methods:
  - client_secret
  - certificate (PFX or PEM)
  - device_code (interactive browser flow)
"""

import logging
import sys
from enum import Enum
from pathlib import Path

import msal

logger = logging.getLogger(__name__)

GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]


class AuthMethod(str, Enum):
    CLIENT_SECRET = "client_secret"
    CERTIFICATE = "certificate"
    DEVICE_CODE = "device_code"


class AuthenticationError(Exception):
    """Raised when authentication fails."""


class Authenticator:
    def __init__(
        self,
        method: AuthMethod,
        tenant_id: str,
        client_id: str,
        client_secret: str | None = None,
        cert_path: str | None = None,
        cert_password: str | None = None,
    ):
        self.method = method
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.cert_path = cert_path
        self.cert_password = cert_password
        self.authority = f"https://login.microsoftonline.com/{tenant_id}"

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------
    def acquire_token(self) -> str:
        """Acquire and return a bearer token string."""
        if self.method == AuthMethod.CLIENT_SECRET:
            return self._client_secret_flow()
        elif self.method == AuthMethod.CERTIFICATE:
            return self._certificate_flow()
        elif self.method == AuthMethod.DEVICE_CODE:
            return self._device_code_flow()
        else:
            raise AuthenticationError(f"Unknown auth method: {self.method}")

    # ------------------------------------------------------------------
    # Private — flows
    # ------------------------------------------------------------------
    def _client_secret_flow(self) -> str:
        logger.debug("Using client_secret flow")
        app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority,
        )
        result = app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        return self._extract_token(result)

    def _certificate_flow(self) -> str:
        logger.debug("Using certificate flow")
        cert_path = Path(self.cert_path)

        if not cert_path.exists():
            raise AuthenticationError(f"Certificate file not found: {cert_path}")

        # Load certificate bytes
        cert_bytes = cert_path.read_bytes()

        # Build credential dict depending on format
        if cert_path.suffix.lower() == ".pfx":
            credential = {
                "private_key_pfx": cert_bytes,
                "passphrase": self.cert_password,  # may be None if not encrypted
            }
        else:
            # PEM: expects separate private_key and public_certificate
            # For simplicity Devin should handle PEM splitting here
            # TODO(devin): parse PEM and split into private_key / public_certificate
            raise NotImplementedError(
                "PEM certificate support: Devin to implement PEM parsing in _certificate_flow"
            )

        app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=credential,
            authority=self.authority,
        )
        result = app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        return self._extract_token(result)

    def _device_code_flow(self) -> str:
        logger.debug("Using device_code flow")
        app = msal.PublicClientApplication(
            client_id=self.client_id,
            authority=self.authority,
        )

        flow = app.initiate_device_flow(scopes=GRAPH_SCOPES)
        if "user_code" not in flow:
            raise AuthenticationError(
                f"Failed to initiate device code flow: {flow.get('error_description')}"
            )

        # Print instructions to stderr so they're visible even with piped stdout
        print(flow["message"], file=sys.stderr)

        result = app.acquire_token_by_device_flow(flow)
        return self._extract_token(result)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_token(result: dict) -> str:
        """Extract access_token from MSAL result or raise AuthenticationError."""
        if "access_token" in result:
            logger.debug("Token acquired successfully")
            return result["access_token"]

        error = result.get("error", "unknown_error")
        description = result.get("error_description", "No description provided")
        raise AuthenticationError(f"Authentication failed [{error}]: {description}")
