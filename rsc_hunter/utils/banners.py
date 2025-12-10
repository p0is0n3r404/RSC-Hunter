from .colors import Colors, colorize

def print_banner():
    """Print the tool banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}RSC-Hunter{Colors.RESET} - Next.js RCE Scanner
{Colors.CYAN}based on research from Assetnote{Colors.RESET}
"""
    print(banner)
