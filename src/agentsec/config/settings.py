"""Application settings loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()


@dataclass
class Settings:
    """Global application settings.
    
    All settings are loaded from environment variables.
    USE_MOCK_DATA=true (default) enables mock connectors for development.
    """

    # Operation mode
    use_mock_data: bool = field(default=True)

    # LLM Provider
    llm_provider: str = field(default="gemini")
    llm_model: str = field(default="gemini-3.6-flash")
    gemini_api_key: str = field(default="")

    # Microsoft Defender (OAuth2)
    defender_tenant_id: str = field(default="")
    defender_client_id: str = field(default="")
    defender_client_secret: str = field(default="")

    # CVE Sources
    nvd_api_key: str = field(default="")

    # QuimeraX CTI
    quimerax_api_key: str = field(default="")
    quimerax_base_url: str = field(default="https://api.quimerax.com")

    # License tier flags
    has_defender_p2: bool = field(default=False)
    has_entra_p2: bool = field(default=False)

    def __post_init__(self) -> None:
        """Load values from environment variables after init."""
        self.use_mock_data = os.environ.get("USE_MOCK_DATA", "true").lower() == "true"
        self.llm_provider = os.environ.get("LLM_PROVIDER", self.llm_provider)
        self.llm_model = os.environ.get("LLM_MODEL", self.llm_model)
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY", self.gemini_api_key)
        self.defender_tenant_id = os.environ.get("DEFENDER_TENANT_ID", self.defender_tenant_id)
        self.defender_client_id = os.environ.get("DEFENDER_CLIENT_ID", self.defender_client_id)
        self.defender_client_secret = os.environ.get(
            "DEFENDER_CLIENT_SECRET", self.defender_client_secret
        )
        self.nvd_api_key = os.environ.get("NVD_API_KEY", self.nvd_api_key)
        self.quimerax_api_key = os.environ.get("QUIMERAX_API_KEY", self.quimerax_api_key)
        self.quimerax_base_url = os.environ.get("QUIMERAX_BASE_URL", self.quimerax_base_url)
        self.has_defender_p2 = os.environ.get("HAS_DEFENDER_P2", "false").lower() == "true"
        self.has_entra_p2 = os.environ.get("HAS_ENTRA_P2", "false").lower() == "true"

    def validate_for_real_mode(self) -> list[str]:
        """Validate that required settings are present for real (non-mock) mode.
        
        Returns a list of error messages. Empty list means all OK.
        """
        errors: list[str] = []
        if not self.gemini_api_key:
            errors.append("GEMINI_API_KEY é obrigatório")
        if not self.defender_tenant_id:
            errors.append("DEFENDER_TENANT_ID é obrigatório para integração Microsoft")
        if not self.defender_client_id:
            errors.append("DEFENDER_CLIENT_ID é obrigatório para integração Microsoft")
        if not self.defender_client_secret:
            errors.append("DEFENDER_CLIENT_SECRET é obrigatório para integração Microsoft")
        return errors

    @property
    def is_microsoft_configured(self) -> bool:
        """Check if Microsoft credentials are fully configured."""
        return bool(
            self.defender_tenant_id
            and self.defender_client_id
            and self.defender_client_secret
        )

    @property
    def is_quimerax_configured(self) -> bool:
        """Check if QuimeraX credentials are configured."""
        return bool(self.quimerax_api_key and self.quimerax_base_url)


# Global singleton
settings = Settings()
