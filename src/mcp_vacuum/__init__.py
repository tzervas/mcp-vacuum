"""MCP Vacuum - AI agent for discovering and integrating MCP Servers with Kagent.

An AI agent developed in Python 3.12 using the Google Python Agent Developer Kit (ADK)
designed to discover, authenticate with, and integrate MCP Servers.
"""

__version__ = "0.3.0"
__author__ = "Tyler Zervas"
__email__ = "tz-dev@vectorweight.com"

# from .agent import MCPVacuumAgent # Commented out due to ModuleNotFoundError: No module named 'mcp_vacuum.agent'
from .config import Config

# __all__ = ["MCPVacuumAgent", "Config"]
__all__ = ["Config"] # Adjusted __all__
