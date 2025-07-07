# Changelog

## [0.3.0] - 2023-10-12
### Added
- Added fixed 128-character PKCE verifiers for improved security.
- Implemented async DNS resolution and overlapping discovery support.
- Introduced a fail-fast option in the ConversionAgent for immediate error reporting.
- Standardized type annotations with PEP 604 unions.
- Enhanced token storage and improved keyring error handling.

### Changed
- Updated JSONRPC to JSON-RPC notation in documentation.
- Refactored documentation to reflect PR 5 changes and improvements.

### Removed
- Removed pytest coverage flags from pyproject.toml.

### Fixed
- Corrected backoff to cap correctly and fixed unreachable code paths.
