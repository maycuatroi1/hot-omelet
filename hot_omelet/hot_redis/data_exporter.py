import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


def display_rich_table(data, host, port):
    console = Console()

    header = Panel(
        Text(
            f"Redis Data Extraction Results\nHost: {host}:{port}",
            justify="center",
            style="bold cyan",
        ),
        style="bold blue",
        expand=False,
    )
    console.print(header)

    if data is None:
        console.print("[bold red]✗[/bold red] No data to display (connection failed)")
        return

    if not data:
        console.print("[bold yellow]![/bold yellow] No Redis keys found in the database")
        empty_table = Table(title="Redis Database", show_header=True, header_style="bold magenta")
        empty_table.add_column("Status", style="yellow")
        empty_table.add_row("Database is empty - no keys found")
        console.print(empty_table)
        return

    table = Table(
        title=f"📊 Redis Keys Extracted ({len(data)} total)",
        show_header=True,
        header_style="bold magenta",
        show_lines=True,
        expand=False,
    )
    table.add_column("No.", style="dim", width=4)
    table.add_column("Key", style="cyan", no_wrap=False, min_width=20)
    table.add_column("Type", style="green", width=10)
    table.add_column("Size", style="blue", width=8)
    table.add_column("Value/Preview", style="yellow", overflow="fold", max_width=60)

    for idx, (key, value) in enumerate(data.items(), 1):
        if isinstance(value, str):
            data_type = "string"
            size = f"{len(value)}c"
            preview = value[:80] + "..." if len(value) > 80 else value
        elif isinstance(value, list):
            data_type = (
                "list"
                if not all(isinstance(item, tuple) and len(item) == 2 for item in value)
                else "zset"
            )
            size = f"{len(value)}"
            if len(value) == 0:
                preview = "(empty list)"
            elif len(value) <= 3:
                preview = str(value)[:80]
            else:
                preview = f"[{value[0]}, {value[1]}, ... {len(value) - 2} more]"
        elif isinstance(value, dict):
            data_type = "hash"
            size = f"{len(value)}f"
            if len(value) == 0:
                preview = "(empty hash)"
            elif len(value) <= 2:
                preview = str(value)[:80]
            else:
                first_items = list(value.items())[:2]
                preview = f"{dict(first_items)} ... +{len(value) - 2} fields"
        else:
            data_type = "unknown"
            size = "?"
            preview = str(value)[:80]

        table.add_row(str(idx), key, data_type, size, preview)

    console.print(table)

    console.print("\n")
    summary = Table(title="Summary Statistics", show_header=False, show_edge=False)
    summary.add_column("Metric", style="bold")
    summary.add_column("Value", style="cyan")
    summary.add_row("Total Keys", str(len(data)))

    type_counts = {}
    for key, value in data.items():
        if isinstance(value, str):
            type_counts["string"] = type_counts.get("string", 0) + 1
        elif isinstance(value, list):
            type_counts["list"] = type_counts.get("list", 0) + 1
        elif isinstance(value, dict):
            type_counts["hash"] = type_counts.get("hash", 0) + 1
        else:
            type_counts["other"] = type_counts.get("other", 0) + 1

    for key_type, count in type_counts.items():
        if count > 0:
            summary.add_row(f"{key_type.capitalize()} keys", str(count))

    console.print(summary)
    console.print("\n")


class DataExporter:
    @staticmethod
    def export_to_json(data, host, port):
        display_rich_table(data, host, port)

        if data is None or not data:
            return None

        filename = f"./reports/redis_data_{host}_{port}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        console = Console()
        console.print(
            f"[bold green]✓[/bold green] Data exported to: [cyan]{filename}[/cyan]"
        )

        return filename
