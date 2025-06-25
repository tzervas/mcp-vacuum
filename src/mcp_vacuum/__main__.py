"""CLI entry point for MCP Vacuum."""

import asyncio
import sys
from typing import List, Optional

import click
import structlog

from .agent import MCPVacuumAgent
from .config import Config


@click.group()
@click.option("--config", "-c", help="Configuration file path")
@click.option("--log-level", "-l", default="INFO", help="Logging level")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], log_level: str) -> None:
    """MCP Vacuum - AI agent for discovering and integrating MCP Servers."""
    # Load configuration
    if config:
        from pathlib import Path
        cfg = Config.from_file(Path(config))
    else:
        cfg = Config.from_env()
    
    # Override log level if specified
    if log_level:
        cfg.logging.level = log_level
    
    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg


@cli.command()
@click.option("--networks", "-n", multiple=True, help="Target networks to scan")
@click.option("--output", "-o", help="Output file for results")
@click.pass_context
def discover(ctx: click.Context, networks: List[str], output: Optional[str]) -> None:
    """Discover MCP servers in target networks."""
    config = ctx.obj["config"]
    
    async def run_discovery():
        agent = MCPVacuumAgent(config)
        
        try:
            schemas = await agent.run_full_discovery(list(networks) if networks else None)
            
            if output:
                import json
                with open(output, "w") as f:
                    json.dump(schemas, f, indent=2)
                click.echo(f"Results written to {output}")
            else:
                import json
                click.echo(json.dumps(schemas, indent=2))
                
            # Print summary
            summary = agent.get_discovery_summary()
            click.echo(f"\nSummary:")
            click.echo(f"  Discovered: {summary['discovered']}")
            click.echo(f"  Authenticated: {summary['authenticated']}")
            click.echo(f"  With schemas: {summary['with_schemas']}")
                
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
    
    asyncio.run(run_discovery())


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
