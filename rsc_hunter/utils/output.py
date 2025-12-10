import json
import logging
from datetime import datetime, timezone
from .colors import Colors, colorize

try:
    from rich.console import Console
    from rich.table import Table
    from rich.logging import RichHandler
    console = Console()
    HAS_RICH = True
except ImportError:
    console = None
    HAS_RICH = False

def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    if HAS_RICH:
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(rich_tracebacks=True)]
        )
    else:
        logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")

def print_result(result: dict, verbose: bool = False):
    host = result["host"]
    final_url = result.get("final_url")
    # Simple check if redirected (naive)
    redirected = final_url and final_url != host and final_url != host + "/"

    if result["vulnerable"] is True:
        if HAS_RICH:
            console.print(f"[bold red][VULNERABLE][/bold red] {host} - Status: {result['status_code']}")
            if redirected:
                console.print(f"  -> Redirected to: {final_url}")
        else:
            status = colorize("[VULNERABLE]", Colors.RED + Colors.BOLD)
            print(f"{status} {colorize(host, Colors.WHITE)} - Status: {result['status_code']}")
            if redirected:
                print(f"  -> Redirected to: {final_url}")
    elif result["vulnerable"] is False:
        if HAS_RICH:
            console.print(f"[green][NOT VULNERABLE][/green] {host} - Status: {result['status_code']}")
        else:
            status = colorize("[NOT VULNERABLE]", Colors.GREEN)
            print(f"{status} {host} - Status: {result['status_code']}")
            if redirected and verbose:
                 print(f"  -> Redirected to: {final_url}")
    else:
        # Error
        error_msg = result.get("error", "Unknown error")
        if HAS_RICH:
             console.print(f"[yellow][ERROR][/yellow] {host} - {error_msg}")
        else:
            status = colorize("[ERROR]", Colors.YELLOW)
            print(f"{status} {host} - {error_msg}")

    if verbose and result.get("vulnerable"):
        if HAS_RICH:
            console.print("  Response snippet:", style="cyan")
        else:
            print(colorize("  Response snippet:", Colors.CYAN))
        
        if result.get("response"):
            lines = result["response"].split("\r\n")[:10]
            for line in lines:
                print(f"    {line}")

def save_results(results: list[dict], output_file: str, vulnerable_only: bool = True):
    if vulnerable_only:
        results = [r for r in results if r.get("vulnerable") is True]

    output = {
        "scan_time": datetime.now(timezone.utc).isoformat() + "Z",
        "total_results": len(results),
        "results": results
    }

    try:
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        if HAS_RICH:
            console.print(f"\n[green][+] Results saved to: {output_file}[/green]")
        else:
            print(colorize(f"\n[+] Results saved to: {output_file}", Colors.GREEN))
    except Exception as e:
        if HAS_RICH:
            console.print(f"\n[red][ERROR] Failed to save results: {e}[/red]")
        else:
            print(colorize(f"\n[ERROR] Failed to save results: {e}", Colors.RED))
