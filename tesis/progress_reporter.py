"""Live progress dashboard for tesis run command."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout


class EngagementProgressReporter:
    """Live dashboard for tesis run command."""

    def __init__(self, max_iterations: int, provider: str = "gemini", level: str = "low"):
        """Supports init behavior for this module."""
        self.console = Console()
        self.max_iterations = max_iterations
        self.provider = provider
        self.level = level
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="green", finished_style="green"),
            MofNCompleteColumn(),
            TextColumn("[bold]{task.fields[status]}"),
            console=self.console,
        )
        self.task = self.progress.add_task(
            "Engagement Progress", total=max_iterations, status="Starting..."
        )
        self.current_agent = "-"
        self.guardrail_status = "[green]OK[/green]"
        self.evasion_status = "[dim]N/A[/dim]"
        self.coverage = "0.000"
        self.confirmed_count = 0
        self.guardrail_count = 0
        self.evasion_attempts = 0
        self.evasion_successes = 0
        self._live = None

    def start(self):
        """Handles start behavior for this module."""
        self._live = Live(self._build_layout(), console=self.console, refresh_per_second=4)
        self._live.start()

    def stop(self):
        """Handles stop behavior for this module."""
        if self._live:
            self._live.stop()

    def _build_layout(self) -> Layout:
        """Supports build layout behavior for this module."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", size=10),
            Layout(name="progress", size=3),
            Layout(name="footer", size=3),
        )
        layout["header"].update(Panel(
            f"[bold cyan]DVWA Security Assessment[/bold cyan] | "
            f"Provider: [bold]{self.provider}[/bold] | "
            f"Level: [bold]{self.level}[/bold] | "
            f"Max Iterations: [bold]{self.max_iterations}[/bold]",
            title="TESIS Framework",
            border_style="cyan",
        ))

        status_table = Table(show_header=False, box=None)
        status_table.add_column("Metric", style="bold")
        status_table.add_column("Value")
        status_table.add_row("Current Agent", f"[bold yellow]{self.current_agent}[/bold yellow]")
        status_table.add_row("Guardrail", self.guardrail_status)
        status_table.add_row("Evasion", self.evasion_status)
        status_table.add_row("Coverage Ratio", f"[bold]{self.coverage}[/bold]")
        status_table.add_row("Confirmed Findings", f"[bold green]{self.confirmed_count}[/bold green]")
        status_table.add_row("Guardrail Refusals", f"[bold red]{self.guardrail_count}[/bold red]")
        status_table.add_row("Evasion Success", f"[bold green]{self.evasion_successes}[/bold green]/[bold]{self.evasion_attempts}[/bold]")

        layout["main"].update(Panel(status_table, title="Live Status", border_style="blue"))
        layout["progress"].update(self.progress)
        layout["footer"].update(Panel(
            "[dim]Press Ctrl+C to abort[/dim] | "
            "[bold]Red[/bold]=Refusal  [bold]Yellow[/bold]=Evasion  [bold]Green[/bold]=Success",
            border_style="dim",
        ))
        return layout

    def refresh(self):
        """Handles refresh behavior for this module."""
        if self._live:
            self._live.update(self._build_layout())

    def update(self, event: dict[str, Any]):
        """Process a telemetry event and refresh the display."""
        event_type = event.get("event", "")
        payload = event.get("payload", {})

        if "orchestrator.decision" in event_type:
            self.current_agent = payload.get("next_agent", "-")
            self.progress.update(self.task, advance=1)

        if "guardrail.rejection" in event_type:
            self.guardrail_status = "[bold red]REFUSED[/bold red]"
            self.guardrail_count += 1
            self.progress.update(self.task, status="[red]Guardrail Refusal[/red]")

        if "orchestrator.llm.response" in event_type and "guardrail" not in event_type:
            self.guardrail_status = "[green]OK[/green]"

        if "orchestrator.evasion.mutated" in event_type:
            self.evasion_status = "[bold yellow]ATTEMPTING[/bold yellow]"
            self.evasion_attempts += 1

        if "orchestrator.evasion.success" in event_type:
            self.evasion_status = "[bold green]SUCCESS[/bold green]"
            self.evasion_successes += 1
            self.progress.update(self.task, status="[green]Evasion Success[/green]")

        if "orchestrator.evasion.fallback" in event_type:
            self.evasion_status = "[bold red]FAILED[/bold red]"
            self.evasion_attempts += 1

        if "akg.route.selected" in event_type:
            self.current_agent = payload.get("next_agent", "-")

        # Update coverage from any event that carries it
        if "coverage_ratio" in payload:
            self.coverage = f"{payload['coverage_ratio']:.3f}"

        # Update confirmed count from any event that carries confirmed nodes
        confirmed = payload.get("confirmed")
        if isinstance(confirmed, list):
            self.confirmed_count = len(confirmed)

        self.refresh()

    def finalize(self, report: dict[str, Any]):
        """Render final summary after engagement completes."""
        self.progress.update(self.task, completed=self.max_iterations, status="[green]Done[/green]")
        self.refresh()
        self.stop()
        # Render final score table
        module_scores = report.get("module_scores", {}) if isinstance(report, dict) else {}
        if module_scores:
            table = Table(title="Final Module Scores")
            table.add_column("Module", style="bold")
            table.add_column("Score")
            table.add_column("Label")
            for module, payload in module_scores.items():
                if isinstance(payload, dict):
                    score = payload.get("score", 0)
                    label = payload.get("label", "-")
                    color = "green" if score >= 3 else "yellow" if score >= 1 else "red"
                    table.add_row(module, f"[bold {color}]{score}[/bold {color}]", label)
            self.console.print(table)
