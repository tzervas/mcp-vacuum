"""
Tests for the ConversionAgent class.
"""
import asyncio
import pytest
import structlog
from typing import Any

from mcp_vacuum.config import Config
from mcp_vacuum.adk.conversion_agent import ConversionAgent


class MockConfig:
    """Mock Config class for testing."""
    def __init__(self, settings: Any = None):
        self.agent_settings = settings


class MockAgentSettings:
    """Mock agent settings class for testing."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


@pytest.fixture
def logger():
    return structlog.get_logger()


@pytest.fixture
def output_queue():
    return asyncio.Queue()


def test_init_with_fail_fast_true(logger, output_queue):
    """Test ConversionAgent initialization with fail_fast_conversion=True."""
    settings = MockAgentSettings(fail_fast_conversion=True)
    config = MockConfig(settings)
    agent = ConversionAgent(config, logger, output_queue)
    assert agent.fail_fast_conversion is True


def test_init_with_fail_fast_false(logger, output_queue):
    """Test ConversionAgent initialization with fail_fast_conversion=False."""
    settings = MockAgentSettings(fail_fast_conversion=False)
    config = MockConfig(settings)
    agent = ConversionAgent(config, logger, output_queue)
    assert agent.fail_fast_conversion is False


def test_init_with_fail_fast_missing(logger, output_queue):
    """Test ConversionAgent initialization with missing fail_fast_conversion."""
    settings = MockAgentSettings()
    config = MockConfig(settings)
    agent = ConversionAgent(config, logger, output_queue)
    assert agent.fail_fast_conversion is False


def test_init_with_fail_fast_invalid_type(logger, output_queue):
    """Test ConversionAgent initialization with non-boolean fail_fast_conversion."""
    settings = MockAgentSettings(fail_fast_conversion="True")  # String instead of bool
    config = MockConfig(settings)
    agent = ConversionAgent(config, logger, output_queue)
    assert agent.fail_fast_conversion is False


def test_init_with_agent_settings_none(logger, output_queue):
    """Test ConversionAgent initialization with None agent_settings."""
    config = MockConfig(None)
    agent = ConversionAgent(config, logger, output_queue)
    assert agent.fail_fast_conversion is False
