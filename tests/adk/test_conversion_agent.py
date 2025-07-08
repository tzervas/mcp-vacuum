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

@pytest.mark.asyncio
async def test_conversion_agent_workflow(logger, output_queue):
    """Test ConversionAgent workflow with mock schema input."""
    settings = MockAgentSettings(fail_fast_conversion=False)
    config = MockConfig(settings)
    agent = ConversionAgent(config, logger, output_queue)

    # Mock MCP schema input
    mock_mcp_schema = {
        "type": "object",
        "properties": {"test": {"type": "string"}}
    }

    # Test conversion workflow
    await agent.convert_schema(mock_mcp_schema)
    result = await output_queue.get()
    assert "openapi" in result
    assert result["openapi"] == "3.0.0"

@pytest.mark.asyncio
async def test_conversion_agent_error_handling(logger, output_queue):
    """Test ConversionAgent error handling."""
    settings = MockAgentSettings(fail_fast_conversion=True)
    config = MockConfig(settings)
    agent = ConversionAgent(config, logger, output_queue)

    # Test invalid schema
    with pytest.raises(ValueError):
        await agent.convert_schema({"invalid": "schema"})

@pytest.mark.asyncio
async def test_conversion_agent_batch_processing(logger, output_queue):
    """Test ConversionAgent batch schema processing."""
    settings = MockAgentSettings(fail_fast_conversion=False)
    config = MockConfig(settings)
    agent = ConversionAgent(config, logger, output_queue)

    # Mock multiple schemas
    mock_schemas = [
        {"type": "object", "properties": {"test1": {"type": "string"}}},
        {"type": "object", "properties": {"test2": {"type": "number"}}}
    ]

    # Test batch conversion
    for schema in mock_schemas:
        await agent.convert_schema(schema)

    # Verify results
    results = []
    while not output_queue.empty():
        results.append(await output_queue.get())

    assert len(results) == len(mock_schemas)
    for result in results:
        assert "openapi" in result
        assert result["openapi"] == "3.0.0"

@pytest.mark.asyncio
async def test_conversion_agent_schema_validation(logger, output_queue):
    """Test ConversionAgent schema validation."""
    settings = MockAgentSettings(fail_fast_conversion=True)
    config = MockConfig(settings)
    agent = ConversionAgent(config, logger, output_queue)

    # Test cases for schema validation
    test_cases = [
        ({}, "Empty schema"),  # Empty schema
        (None, "None schema"),  # None input
        ({"type": "invalid"}, "Invalid type"),  # Invalid type
        ({"type": "object", "required": "wrong"}, "Invalid required field")  # Wrong format for required
    ]

    for schema, case in test_cases:
        with pytest.raises(ValueError, message=f"Failed to catch invalid case: {case}"):
            await agent.convert_schema(schema)

@pytest.mark.asyncio
async def test_conversion_agent_recovery(logger, output_queue):
    """Test ConversionAgent recovery from failures."""
    settings = MockAgentSettings(fail_fast_conversion=False)
    config = MockConfig(settings)
    agent = ConversionAgent(config, logger, output_queue)

    # Test mixed valid and invalid schemas
    schemas = [
        {"invalid": "schema"},  # Should fail
        {"type": "object", "properties": {"valid": {"type": "string"}}},  # Should succeed
        {"another": "invalid"},  # Should fail
        {"type": "object", "properties": {"also_valid": {"type": "number"}}}  # Should succeed
    ]

    success_count = 0
    for schema in schemas:
        try:
            await agent.convert_schema(schema)
            success_count += 1
        except ValueError:
            continue

    # Verify partial success
    assert success_count == 2  # Two valid schemas should have been converted
    assert not output_queue.empty()  # Queue should have successful conversions
