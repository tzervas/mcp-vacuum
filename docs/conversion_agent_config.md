# Conversion Agent Configuration Options

## Overview
The Conversion Agent is tasked with transforming MCP tool schemas into formats compatible with Kagent CRDs. Configuration settings allow for customization of conversion behavior, error handling, and performance tuning.

## Configuration Options

### Fail-Fast Conversion
- **Key**: `fail_fast_conversion`
- **Type**: `boolean`
- **Default**: `False`
- **Description**: Determines if the agent should stop processing immediately on the first schema transformation failure.

### Batch Size
- **Key**: `batch_size`
- **Type**: `integer`
- **Default**: `10`
- **Description**: Number of MCP schemas processed in a single thread. Useful for managing load on the system and controlling memory usage.

### Logging Level
- **Key**: `logging_level`
- **Type**: `string` (one of "DEBUG", "INFO", "WARNING", "ERROR")
- **Default**: `INFO`
- **Description**: Sets the logging verbosity level to track conversion detail in logs. 

### Max Retries
- **Key**: `max_retries`
- **Type**: `integer`
- **Default**: `3`
- **Description**: Number of retries to attempt for conversion tasks in case of transient failures.

### Validation Schema
- **Key**: `validation_schema_path`
- **Type**: `string`
- **Default**: `null`
- **Description**: Path to a custom schema definition for validation. If unset, default schema is used.

## Usage Example

Example configuration using a JSON config file:

```json
{
  "conversion": {
    "fail_fast_conversion": true,
    "batch_size": 5,
    "logging_level": "DEBUG",
    "max_retries": 2,
    "validation_schema_path": "/path/to/custom/schema.json"
  }
}
```

## Best Practices

1. Set `fail_fast_conversion` to `False` in batch workloads to ensure partial progress.
2. Use `logging_level: DEBUG` during development for deeper insights.
3. Monitor and adjust `batch_size` based on system performance metrics.
4. Always validate custom schemas for compatibility with conversion logic.
5. Use configuration files to manage environment-specific settings.
6. Regularly audit and update configurations to meet evolving schema standards.

