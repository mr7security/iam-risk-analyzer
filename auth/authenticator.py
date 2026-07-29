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

        cert_bytes = cert_path.read_bytes()

        if cert_path.suffix.lower() == ".pfx":
            credential = {
                "private_key_pfx": cert_bytes,
                "passphrase": self.cert_password,  # may be None if not encrypted
            }
        else:
            # PEM (.pem/.crt/.key): parse private key + certificate and hand MSAL
            # an unencrypted private key, the public cert, and the SHA-1 thumbprint.
            credential = self._build_pem_credential(cert_bytes)

        app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=credential,
            authority=self.authority,
        )
        result = app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        return self._extract_token(result)

    def _build_pem_credential(self, cert_bytes: bytes) -> dict:
        """
        Parse a PEM file (which may hold both the private key and the certificate)
        and return the credential dict MSAL expects for certificate auth.

        Supports encrypted private keys via self.cert_password.
        """
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography import x509
        except ImportError as e:
            raise AuthenticationError(
                "PEM certificate support requires the 'cryptography' package. "
                "Install it with: pip install cryptography"
            ) from e

        password = (
            self.cert_password.encode("utf-8") if self.cert_password else None
        )

        # Load the private key from the PEM bytes.
        try:
            private_key = serialization.load_pem_private_key(
                cert_bytes, password=password
            )
        except (ValueError, TypeError) as e:
            raise AuthenticationError(
                f"Failed to load private key from PEM (wrong password or format?): {e}"
            ) from e

        # Re-serialize the key to unencrypted PEM for MSAL.
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Load the certificate (from the same PEM bundle) to compute the thumbprint.
        try:
            certificate = x509.load_pem_x509_certificate(cert_bytes)
        except ValueError as e:
            raise AuthenticationError(
                "PEM file does not contain a certificate. Provide a PEM bundle with "
                f"both the private key and the certificate: {e}"
            ) from e

        thumbprint = certificate.fingerprint(hashes.SHA1()).hex()
        public_cert_pem = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode("utf-8")

        return {
            "private_key": private_key_pem,
            "thumbprint": thumbprint,
            "public_certificate": public_cert_pem,
        }

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
