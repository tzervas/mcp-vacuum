"""CLI entry point for MCP Vacuum."""

import asyncio
import sys
from typing import List, Optional, Dict, Any # Added Dict, Any
from pathlib import Path # Added Path

import click
# structlog is initialized by OrchestrationAgent now
# import structlog

# from .agent import MCPVacuumAgent # Old agent
from .adk.orchestration_agent import OrchestrationAgent # New ADK based agent
from .config import Config


@click.group()
@click.option(
    "--config-file", "-c",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    help="Path to a JSON configuration file.",
    envvar="MCP_VACUUM_CONFIG_FILE" # Allow setting via env var too
)
@click.option(
    "--log-level", "-l",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False),
    default=None, # Default will be taken from Config object's default, then overridden if this is set
    help="Override the logging level (e.g., DEBUG, INFO).",
    envvar="MCP_VACUUM_LOGGING_LEVEL"
)
@click.option(
    "--log-format",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default=None,
    help="Override logging format.",
    envvar="MCP_VACUUM_LOGGING_FORMAT"
)
@click.pass_context
def cli(ctx: click.Context, config_file: Optional[str], log_level: Optional[str], log_format: Optional[str]) -> None:
    """MCP Vacuum - Discovers MCP servers, authenticates, and converts schemas."""
    try:
        if config_file:
            # Load from specified file only
            cfg = Config.from_file(Path(config_file))
        else:
            # Load from environment variables (and .env file if present)
            cfg = Config()
    except Exception as e:
        import traceback
        click.echo(f"Error loading configuration: {e}", err=True)
        # Print traceback to stderr for more detailed debugging info
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    
    # Override from CLI options if provided
    if log_level:
        cfg.logging.level = log_level.upper()
    if log_format:
        cfg.logging.format = log_format.lower()
    
    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg
    # Note: Global logging is now set up by OrchestrationAgent when it's initialized.


@cli.command()
@click.option(
    "--networks", "-n",
    multiple=True,
    help="Target networks/CIDRs to scan (e.g., '192.168.1.0/24'). Can be used multiple times. If not provided, uses defaults or discovered interfaces."
)
@click.option(
    "--output-file", "-o",
    type=click.Path(dir_okay=False, writable=True, resolve_path=True),
    help="Output file path for the generated Kagent schemas (JSON format)."
)
@click.pass_context
def discover(ctx: click.Context, networks: List[str], output_file: Optional[str]) -> None:
    """Discovers MCP servers, authenticates, and generates Kagent schemas."""
    config: Config = ctx.obj["config"]
    
    # OrchestrationAgent handles its own logging setup using the passed config.
    agent = OrchestrationAgent(app_config=config)

    final_schemas: Optional[Dict[str, Any]] = None
    summary: Optional[Dict[str, int]] = None

    async def run_workflow():
        nonlocal final_schemas, summary
        try:
            await agent.start() # ADK agent lifecycle start
            # Use list(networks) to pass a concrete list, or None if empty
            target_nets = list(networks) if networks else None
            final_schemas = await agent.run_main_workflow(target_networks=target_nets)
            summary = agent.get_summary()
        finally:
            await agent.stop() # ADK agent lifecycle stop

    try:
        asyncio.run(run_workflow())
    except KeyboardInterrupt:
        click.echo("\nDiscovery process interrupted by user.", err=True)
        # asyncio.run should handle cleanup of tasks on KeyboardInterrupt if possible,
        # and agent.stop() in finally block of run_workflow should also attempt cleanup.
        sys.exit(130) # Standard exit code for Ctrl+C
    except Exception as e:
        # Catch-all for unexpected errors from the workflow itself.
        # Agent methods should ideally log specifics.
        click.echo(f"An unexpected error occurred during the discovery workflow: {e}", err=True)
        # Consider logging the full traceback here if log level is DEBUG
        # import traceback
        # if config.logging.level == "DEBUG":
        #     traceback.print_exc()
        sys.exit(1)

    if final_schemas is not None:
        if output_file:
            try:
                with open(output_file, "w") as f:
                    json.dump(final_schemas, f, indent=2)
                click.echo(f"Kagent schemas written to {output_file}")
            except IOError as e:
                click.echo(f"Error writing output file {output_file}: {e}", err=True)
                sys.exit(1)
        else:
            # Pretty print JSON to stdout
            click.echo(json.dumps(final_schemas, indent=2))
            
    if summary:
        click.echo("\n--- Summary ---")
        click.echo(f"  Discovered Servers:    {summary.get('discovered_servers', 0)}")
        click.echo(f"  Authenticated Servers: {summary.get('authenticated_servers', 0)}")
        click.echo(f"  Schemas Generated:     {summary.get('schemas_generated', 0)}")
    else:
        click.echo("\nNo summary information available (workflow might have been interrupted or failed early).")


@cli.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Show version information."""
    from . import __version__
    click.echo(f"MCP Vacuum v{__version__}")


@cli.command()
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Show current configuration."""
    config = ctx.obj["config"]
    import json
    click.echo(json.dumps(config.dict(), indent=2))


if __name__ == "__main__":
    cli()
