import pytest
from unittest.mock import patch, MagicMock

from agentsec.agent.orchestrator import SecurityAgent
from agentsec.config.settings import Settings

def test_agent_initialization(mock_registry):
    settings = Settings(gemini_api_key="mock_key", use_mock_data=True)
    
    # We mock the genai Client to avoid actual network calls during init
    with patch("agentsec.agent.orchestrator.genai.Client"):
        agent = SecurityAgent(settings, mock_registry)
        assert agent._registry is not None
        assert agent._client is not None
        assert len(agent._tool_functions) > 0
