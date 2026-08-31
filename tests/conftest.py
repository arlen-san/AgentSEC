import pytest
from agentsec.connectors.registry import create_registry

@pytest.fixture
def mock_registry():
    """Returns a ConnectorRegistry using mock data."""
    return create_registry(use_mock=True)
