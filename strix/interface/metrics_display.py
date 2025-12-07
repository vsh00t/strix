"""Display de métricas LLM para interfaz CLI.

Proporciona visualización rica de métricas usando Rich library,
incluyendo tablas, paneles y gráficos ASCII.
"""
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn

from strix.telemetry.llm_metrics import get_global_metrics, LLMMetrics


def create_metrics_table(summary: dict[str, Any]) -> Table:
    """Crea tabla de métricas principal.
    
    Args:
        summary: Diccionario de métricas del LLM
        
    Returns:
        Tabla Rich formateada
    """
    table = Table(
        title="LLM Performance Metrics",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Category", style="cyan", width=15)
    table.add_column("Metric", style="magenta", width=25)
    table.add_column("Value", style="green", justify="right", width=15)
    
    # Requests
    requests = summary.get("requests", {})
    table.add_row("📊 Requests", "Total", str(requests.get("total", 0)))
    table.add_row("", "Successful", str(requests.get("successful", 0)))
    table.add_row("", "Failed", str(requests.get("failed", 0)))
    
    success_rate = requests.get("success_rate_pct", 0)
    success_style = "green" if success_rate >= 95 else "yellow" if success_rate >= 80 else "red"
    table.add_row("", "Success Rate", Text(f"{success_rate}%", style=success_style))
    
    table.add_row("", "", "")  # Separator
    
    # Tokens
    tokens = summary.get("tokens", {})
    table.add_row("🎯 Tokens", "Input (Total)", f"{tokens.get('total_input', 0):,}")
    table.add_row("", "Output (Total)", f"{tokens.get('total_output', 0):,}")
    table.add_row("", "Cached", f"{tokens.get('total_cached', 0):,}")
    table.add_row("", "Avg Input/Request", str(tokens.get("avg_input_per_request", 0)))
    
    cache_rate = tokens.get("cache_hit_rate_pct", 0)
    cache_style = "green" if cache_rate >= 30 else "yellow" if cache_rate >= 10 else "dim"
    table.add_row("", "Cache Hit Rate", Text(f"{cache_rate}%", style=cache_style))
    
    cost = tokens.get("estimated_cost_usd", 0)
    table.add_row("", "Est. Cost", Text(f"${cost:.4f}", style="yellow"))
    
    table.add_row("", "", "")  # Separator
    
    # Quality
    quality = summary.get("quality", {})
    parse_rate = quality.get("tool_parse_rate_pct", 0)
    parse_style = "green" if parse_rate >= 95 else "yellow" if parse_rate >= 80 else "red"
    table.add_row("✅ Quality", "Tool Parse Rate", Text(f"{parse_rate}%", style=parse_style))
    table.add_row("", "Parse Successes", str(quality.get("tool_parse_successes", 0)))
    table.add_row("", "Parse Failures", str(quality.get("tool_parse_failures", 0)))
    
    fp_count = quality.get("false_positives_detected", 0)
    fp_style = "green" if fp_count > 0 else "dim"
    table.add_row("", "FPs Detected", Text(str(fp_count), style=fp_style))
    
    table.add_row("", "", "")  # Separator
    
    # Performance
    perf = summary.get("performance", {})
    avg_latency = perf.get("avg_latency_ms", 0)
    latency_style = "green" if avg_latency < 2000 else "yellow" if avg_latency < 5000 else "red"
    table.add_row("⚡ Performance", "Avg Latency", Text(f"{avg_latency:.0f}ms", style=latency_style))
    table.add_row("", "Min Latency", f"{perf.get('min_latency_ms', 0):.0f}ms")
    table.add_row("", "Max Latency", f"{perf.get('max_latency_ms', 0):.0f}ms")
    
    return table


def create_confidence_panel(summary: dict[str, Any]) -> Panel:
    """Crea panel de distribución de confianza.
    
    Args:
        summary: Diccionario de métricas
        
    Returns:
        Panel Rich con distribución de confianza
    """
    dist = summary.get("confidence_distribution", {})
    
    high = dist.get("high", 0)
    medium = dist.get("medium", 0)
    low = dist.get("low", 0)
    fp = dist.get("false_positive", 0)
    total = high + medium + low + fp
    
    if total == 0:
        content = Text("No confidence data yet", style="dim")
    else:
        lines = []
        
        # Crear barras de progreso ASCII
        bar_width = 20
        
        high_pct = high / total * 100 if total > 0 else 0
        high_bar = "█" * int(high_pct / 100 * bar_width)
        lines.append(Text.assemble(
            ("HIGH     ", "bold green"),
            (f"{high_bar:<{bar_width}}", "green"),
            (f" {high:>3} ({high_pct:.0f}%)", "green"),
        ))
        
        med_pct = medium / total * 100 if total > 0 else 0
        med_bar = "█" * int(med_pct / 100 * bar_width)
        lines.append(Text.assemble(
            ("MEDIUM   ", "bold yellow"),
            (f"{med_bar:<{bar_width}}", "yellow"),
            (f" {medium:>3} ({med_pct:.0f}%)", "yellow"),
        ))
        
        low_pct = low / total * 100 if total > 0 else 0
        low_bar = "█" * int(low_pct / 100 * bar_width)
        lines.append(Text.assemble(
            ("LOW      ", "bold red"),
            (f"{low_bar:<{bar_width}}", "red"),
            (f" {low:>3} ({low_pct:.0f}%)", "red"),
        ))
        
        fp_pct = fp / total * 100 if total > 0 else 0
        fp_bar = "█" * int(fp_pct / 100 * bar_width)
        lines.append(Text.assemble(
            ("FP       ", "bold magenta"),
            (f"{fp_bar:<{bar_width}}", "magenta"),
            (f" {fp:>3} ({fp_pct:.0f}%)", "magenta"),
        ))
        
        content = Text("\n").join(lines)
    
    return Panel(
        content,
        title="🎯 Confidence Distribution",
        border_style="blue",
    )


def create_errors_panel(summary: dict[str, Any]) -> Panel:
    """Crea panel de errores.
    
    Args:
        summary: Diccionario de métricas
        
    Returns:
        Panel Rich con resumen de errores
    """
    errors = summary.get("errors", {})
    by_type = errors.get("by_type", {})
    total = errors.get("total", 0)
    
    if total == 0:
        content = Text("✅ No errors recorded", style="green")
    else:
        lines = [Text(f"Total Errors: {total}", style="bold red"), Text("")]
        
        for error_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
            pct = count / total * 100
            lines.append(Text(f"  {error_type}: {count} ({pct:.0f}%)", style="red"))
        
        content = Text("\n").join(lines)
    
    return Panel(
        content,
        title="❌ Error Summary",
        border_style="red" if total > 0 else "green",
    )


def display_metrics_summary(console: Console | None = None) -> None:
    """Muestra resumen completo de métricas en consola.
    
    Args:
        console: Consola Rich a usar (crea una si no se proporciona)
    """
    if console is None:
        console = Console()
    
    metrics = get_global_metrics()
    summary = metrics.get_summary()
    
    # Header
    console.print()
    console.rule("[bold blue]Strix LLM Metrics Dashboard[/bold blue]")
    console.print()
    
    # Tabla principal
    table = create_metrics_table(summary)
    console.print(table)
    console.print()
    
    # Paneles secundarios en columnas
    confidence_panel = create_confidence_panel(summary)
    errors_panel = create_errors_panel(summary)
    
    console.print(Columns([confidence_panel, errors_panel], equal=True, expand=True))
    
    # Footer con timestamps
    meta = summary.get("meta", {})
    if meta.get("first_request"):
        console.print()
        console.print(
            f"[dim]First request: {meta.get('first_request', 'N/A')} | "
            f"Last request: {meta.get('last_request', 'N/A')}[/dim]"
        )
    
    console.print()


def display_metrics_compact(console: Console | None = None) -> str:
    """Muestra resumen compacto de métricas (una línea).
    
    Args:
        console: Consola Rich a usar
        
    Returns:
        String con resumen compacto
    """
    metrics = get_global_metrics()
    summary = metrics.get_summary()
    
    requests = summary.get("requests", {})
    tokens = summary.get("tokens", {})
    perf = summary.get("performance", {})
    
    compact = (
        f"Requests: {requests.get('total', 0)} "
        f"({requests.get('success_rate_pct', 0):.0f}% success) | "
        f"Tokens: {tokens.get('total_input', 0):,} in / {tokens.get('total_output', 0):,} out | "
        f"Avg Latency: {perf.get('avg_latency_ms', 0):.0f}ms | "
        f"Cost: ${tokens.get('estimated_cost_usd', 0):.4f}"
    )
    
    if console:
        console.print(f"[dim]{compact}[/dim]")
    
    return compact


def display_recent_requests(count: int = 10, console: Console | None = None) -> None:
    """Muestra las últimas requests.
    
    Args:
        count: Número de requests a mostrar
        console: Consola Rich a usar
    """
    if console is None:
        console = Console()
    
    metrics = get_global_metrics()
    recent = metrics.get_recent_requests(count)
    
    if not recent:
        console.print("[dim]No requests recorded yet[/dim]")
        return
    
    table = Table(title=f"Last {count} Requests", show_header=True)
    table.add_column("Time", style="dim", width=12)
    table.add_column("Status", width=8)
    table.add_column("In", justify="right", width=8)
    table.add_column("Out", justify="right", width=8)
    table.add_column("Latency", justify="right", width=10)
    table.add_column("Parsed", width=8)
    table.add_column("Confidence", width=12)
    
    for req in reversed(recent):
        # Extraer solo la hora del timestamp
        time_str = req.get("timestamp", "")
        if "T" in time_str:
            time_str = time_str.split("T")[1][:8]
        
        status = "✅" if req.get("success") else "❌"
        status_style = "green" if req.get("success") else "red"
        
        parsed = "✓" if req.get("tool_parsed") else "✗"
        parsed_style = "green" if req.get("tool_parsed") else "red"
        
        confidence = req.get("confidence") or "-"
        conf_style = {
            "high": "green",
            "medium": "yellow",
            "low": "red",
            "false_positive": "magenta",
        }.get(confidence, "dim")
        
        table.add_row(
            time_str,
            Text(status, style=status_style),
            str(req.get("input_tokens", 0)),
            str(req.get("output_tokens", 0)),
            f"{req.get('latency_ms', 0):.0f}ms",
            Text(parsed, style=parsed_style),
            Text(confidence, style=conf_style),
        )
    
    console.print(table)
