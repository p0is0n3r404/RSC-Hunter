import argparse
import sys
import urllib3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from .utils.banners import print_banner
from .utils.colors import Colors, colorize
from .utils.output import setup_logging, print_result, save_results
from .core.scanner import check_vulnerability
from .core.network import parse_headers

def load_hosts(hosts_file: str) -> list[str]:
    """Load hosts from a file, one per line."""
    hosts = []
    try:
        with open(hosts_file, "r") as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith("#"):
                    hosts.append(host)
    except FileNotFoundError:
        print(colorize(f"[ERROR] File not found: {hosts_file}", Colors.RED))
        sys.exit(1)
    except Exception as e:
        print(colorize(f"[ERROR] Failed to read file: {e}", Colors.RED))
        sys.exit(1)
    return hosts

def main():
    parser = argparse.ArgumentParser(
        description="RSC-Hunter - Next.js RCE Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -l hosts.txt -t 20 -o results.json
  %(prog)s -u https://example.com -H "Authorization: Bearer token"
        """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-u", "--url",
        help="Single URL/host to check"
    )
    input_group.add_argument(
        "-l", "--list",
        help="File containing list of hosts (one per line)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file for results (JSON format)"
    )

    parser.add_argument(
        "--all-results",
        action="store_true",
        help="Save all results to output file, not just vulnerable hosts"
    )

    parser.add_argument(
        "-k", "--insecure",
        default=True,
        action="store_true",
        help="Disable SSL certificate verification"
    )

    parser.add_argument(
        "-H", "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Custom header in 'Key: Value' format (can be used multiple times)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show response snippets for vulnerable hosts)"
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (only show vulnerable hosts)"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    parser.add_argument(
        "--safe-check",
        action="store_true",
        help="Use safe side-channel detection instead of RCE PoC"
    )

    parser.add_argument(
        "--windows",
        action="store_true",
        help="Use Windows PowerShell payload instead of Unix shell"
    )

    parser.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Add junk data to bypass WAF content inspection (default: 128KB)"
    )

    parser.add_argument(
        "--waf-bypass-size",
        type=int,
        default=128,
        metavar="KB",
        help="Size of junk data in KB for WAF bypass (default: 128)"
    )

    parser.add_argument(
        "--vercel-waf-bypass",
        action="store_true",
        help="Use Vercel WAF bypass payload variant"
    )

    args = parser.parse_args()

    # Setup Logging/Output
    if args.no_color:
        Colors.RED = ""
        Colors.GREEN = ""
        Colors.YELLOW = ""
        Colors.BLUE = ""
        Colors.MAGENTA = ""
        Colors.CYAN = ""
        Colors.WHITE = ""
        Colors.BOLD = ""
        Colors.RESET = ""
    
    setup_logging(args.verbose)

    if not args.quiet:
        print_banner()

    if args.url:
        hosts = [args.url]
    else:
        hosts = load_hosts(args.list)

    if not hosts:
        print(colorize("[ERROR] No hosts to scan", Colors.RED))
        sys.exit(1)

    # Adjust timeout for WAF bypass mode
    timeout = args.timeout
    if args.waf_bypass and args.timeout == 10:
        timeout = 20

    if not args.quiet:
        print(colorize(f"[*] Loaded {len(hosts)} host(s) to scan", Colors.CYAN))
        print(colorize(f"[*] Using {args.threads} thread(s)", Colors.CYAN))
        print(colorize(f"[*] Timeout: {timeout}s", Colors.CYAN))

    results = []
    vulnerable_count = 0
    error_count = 0

    verify_ssl = not args.insecure
    custom_headers = parse_headers(args.headers)

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if len(hosts) == 1:
        result = check_vulnerability(hosts[0], timeout, verify_ssl, custom_headers=custom_headers, safe_check=args.safe_check, windows=args.windows, waf_bypass=args.waf_bypass, waf_bypass_size_kb=args.waf_bypass_size, vercel_waf_bypass=args.vercel_waf_bypass)
        results.append(result)
        if not args.quiet or result["vulnerable"]:
            print_result(result, args.verbose)
        if result["vulnerable"]:
            vulnerable_count = 1
    else:
        # Batch mode
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(check_vulnerability, host, timeout, verify_ssl, custom_headers=custom_headers, safe_check=args.safe_check, windows=args.windows, waf_bypass=args.waf_bypass, waf_bypass_size_kb=args.waf_bypass_size, vercel_waf_bypass=args.vercel_waf_bypass): host
                for host in hosts
            }

            with tqdm(
                total=len(hosts),
                desc=colorize("Scanning", Colors.CYAN),
                unit="host",
                ncols=80,
                disable=args.quiet
            ) as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)

                    if result["vulnerable"]:
                        vulnerable_count += 1
                        tqdm.write("") # Clear line
                        print_result(result, args.verbose)
                    elif result["error"]:
                        error_count += 1
                        if not args.quiet and args.verbose:
                            tqdm.write("")
                            print_result(result, args.verbose)
                    elif not args.quiet and args.verbose:
                        tqdm.write("")
                        print_result(result, args.verbose)

                    pbar.update(1)

    if not args.quiet:
        print()
        print(colorize("=" * 60, Colors.CYAN))
        print(colorize("SCAN SUMMARY", Colors.BOLD))
        print(colorize("=" * 60, Colors.CYAN))
        print(f"  Total hosts scanned: {len(hosts)}")

        if vulnerable_count > 0:
            print(f"  {colorize(f'Vulnerable: {vulnerable_count}', Colors.RED + Colors.BOLD)}")
        else:
            print(f"  Vulnerable: {vulnerable_count}")

        print(f"  Not vulnerable: {len(hosts) - vulnerable_count - error_count}")
        print(f"  Errors: {error_count}")
        print(colorize("=" * 60, Colors.CYAN))

    if args.output:
        save_results(results, args.output, vulnerable_only=not args.all_results)

    if vulnerable_count > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
