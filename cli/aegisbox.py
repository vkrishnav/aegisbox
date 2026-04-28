#!/usr/bin/env python3
"""AegisBox CLI — thin Python wrapper over the Go binary with rich terminal output."""

import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

console = Console()

# Resolve binary relative to this script's location (repo root / bin / aegisbox).
BINARY = Path(__file__).resolve().parent.parent / "bin" / "aegisbox"


def _run(*args: str, capture: bool = False) -> subprocess.CompletedProcess:
    if not BINARY.exists():
        console.print(f"[red]aegisbox binary not found at {BINARY}[/red]")
        console.print("Run [bold]make build[/bold] first.")
        sys.exit(1)
    return subprocess.run(
        [str(BINARY), *args],
        capture_output=capture,
        text=True,
    )


@click.group()
def cli():
    """AegisBox — safe container runtime for LLMs."""


@cli.command()
@click.argument("image")
@click.option("--config", default="config/aegisbox.yaml", show_default=True,
              help="Runtime config file")
def run(image: str, config: str):
    """Run an ABX image inside an isolated container."""
    console.print(f"[bold green]Starting[/bold green] {image}")
    result = _run("run", image, "--config", config)
    sys.exit(result.returncode)


@cli.command()
@click.argument("directory")
@click.option("--tag", "-t", required=True, help="Image tag (modelId:version)")
def build(directory: str, tag: str):
    """Build an ABX image from a model directory."""
    with console.status(f"[bold]Building[/bold] image from {directory}..."):
        result = _run("build", directory, "--tag", tag, capture=True)
    if result.returncode == 0:
        console.print(f"[bold green]✓[/bold green] {result.stdout.strip()}")
    else:
        console.print(f"[red]Build failed:[/red]\n{result.stderr.strip()}")
    sys.exit(result.returncode)


@cli.command()
@click.argument("image")
def inspect(image: str):
    """Show image manifest, SBOM, and signatures."""
    result = _run("inspect", image, capture=True)
    if result.returncode == 0:
        console.print(Syntax(result.stdout, "json", theme="monokai"))
    else:
        console.print(f"[red]{result.stderr.strip()}[/red]")
    sys.exit(result.returncode)


@cli.command()
def ps():
    """List running containers."""
    result = _run("ps", capture=True)
    if result.returncode != 0:
        console.print(f"[red]{result.stderr.strip()}[/red]")
        sys.exit(result.returncode)

    table = Table(title="Running Containers", show_header=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("MODEL", style="green")
    table.add_column("STATUS", style="yellow")

    lines = result.stdout.strip().splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 3:
            table.add_row(*parts[:3])

    console.print(table)


if __name__ == "__main__":
    cli()
