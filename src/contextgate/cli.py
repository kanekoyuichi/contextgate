import json
import sys
from pathlib import Path

import typer
from rich.console import Console

from .exceptions import ExtractionError, FileTooLargeError, UnsupportedFormatError
from .scanner import Scanner

app = typer.Typer(
    help="Detect hidden prompt injection in documents before they reach your LLM.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


@app.callback()
def _callback() -> None:
    pass

SUPPORTED_EXTENSIONS = frozenset({".txt", ".md", ".html", ".htm", ".pdf", ".docx"})


def _collect_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    files: list[Path] = []
    for f in sorted(path.rglob("*")):
        if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS:
            files.append(f)
    return files


@app.command("scan")
def scan(
    target: Path = typer.Argument(..., help="File or directory to scan"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    threshold: float = typer.Option(0.70, "--threshold", help="Block threshold (0.0-1.0)"),
) -> None:
    if not target.exists():
        err_console.print(f"[red]Error: Path not found: {target}[/red]")
        raise typer.Exit(2)

    scanner = Scanner(threshold=threshold)
    files = _collect_files(target)

    if not files:
        if json_output:
            typer.echo(json.dumps({"results": []}))
        else:
            err_console.print("[yellow]No supported files found.[/yellow]")
        raise typer.Exit(0)

    results = []
    errors = []
    exit_code = 0

    for file_path in files:
        try:
            result = scanner.scan_file(file_path)
        except UnsupportedFormatError:
            err_console.print(f"[yellow]Skipping unsupported format: {file_path}[/yellow]")
            continue
        except (ExtractionError, FileTooLargeError) as e:
            errors.append({
                "file": str(file_path),
                "error": type(e).__name__,
                "message": str(e),
            })
            exit_code = max(exit_code, 2)
            if not json_output:
                err_console.print(
                    f"[red][ERROR][/red] {file_path}: {type(e).__name__}: {e}"
                )
            continue

        file_result = {
            "file": str(file_path),
            **result.to_dict(),
        }
        results.append(file_result)

        if result.blocked:
            exit_code = max(exit_code, 1)

        if not json_output:
            if result.blocked:
                console.print(
                    f"[bold red][BLOCKED][/bold red] {file_path}  "
                    f"risk_score={result.risk_score:.2f}"
                )
                for f in result.findings:
                    console.print(
                        f"  [cyan]▸[/cyan] {f.type}  {f.severity.upper()}  "
                        f'"{f.matched_text}"'
                    )
            else:
                console.print(
                    f"[bold green][SAFE][/bold green] {file_path}  "
                    f"risk_score={result.risk_score:.2f}"
                )

    if json_output:
        output: dict = {"results": results}
        if errors:
            output["errors"] = errors
        typer.echo(json.dumps(output, indent=2))

    raise typer.Exit(exit_code)
