"""Test the development environment setup."""
import sys
from pathlib import Path


def test_python_version():
    """Ensure we're running Python 3.12+."""
    assert sys.version_info >= (3, 12), "Python version should be 3.12 or higher"


def test_project_structure():
    """Verify basic project structure."""
    project_root = Path(__file__).parent.parent
    assert (project_root / "src" / "mcp_vacuum").is_dir()
    assert (project_root / "pyproject.toml").is_file()


def test_development_tools():
    """Verify development tools are installed."""
