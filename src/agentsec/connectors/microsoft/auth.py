"""Microsoft OAuth2 authentication via MSAL."""

from __future__ import annotations

import logging

import msal

logger = logging.getLogger(__name__)


class MSAuthProvider:
    """Handles OAuth2 client credentials flow for Microsoft APIs.
    
    Manages token acquisition and caching via MSAL.
    """

    GRAPH_SCOPE = "https://graph.microsoft.com/.default"
    DEFENDER_SCOPE = "https://api.security.microsoft.com/.default"

    def __init__(
        self, tenant_id: str, client_id: str, client_secret: str
    ) -> None:
        self.tenant_id = tenant_id
        self.client_id = client_id
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )

    def get_graph_token(self) -> str:
        """Acquire a token for Microsoft Graph API."""
        return self._acquire_token(self.GRAPH_SCOPE)

    def get_defender_token(self) -> str:
        """Acquire a token for Microsoft Defender API."""
        return self._acquire_token(self.DEFENDER_SCOPE)

    def _acquire_token(self, scope: str) -> str:
        """Acquire token using client credentials flow with cache."""
        # Try cache first
        result = self._app.acquire_token_silent(
            scopes=[scope], account=None
        )
        if result and "access_token" in result:
            return result["access_token"]

        # Acquire new token
        result = self._app.acquire_token_for_client(scopes=[scope])
        if "access_token" in result:
            logger.debug("Token acquired for scope: %s", scope)
            return result["access_token"]

        error = result.get("error_description", result.get("error", "Unknown error"))
        raise RuntimeError(f"Failed to acquire token: {error}")
