import argparse
import os
from config import config
from core.scanner import VurnCheckScanner
from reports.json_report import JSONReporter
from reports.html_report import HTMLReporter
from utils.banner import display_banner
from utils.logger import setup_logger_level, get_logger

logger = get_logger("VurnCheckRunner")

VALID_MODES = {"all", "sqli", "xss", "dom_xss", "headers", "disclosure"}

def parse_args():
    parser = argparse.ArgumentParser(description="VurnCheck - Web Vulnerability Assessment Tool")
    parser.add_argument("-u", "--url", required=True, help="Authorized HTTP/HTTPS target URL")
    parser.add_argument("-d", "--depth", type=int, default=config.MAX_CRAWL_DEPTH, help="Maximum crawl depth")
    parser.add_argument("--max-requests", type=int, default=config.MAX_REQUESTS, help="Maximum HTTP requests")
    parser.add_argument("--delay", type=float, default=config.REQUEST_DELAY_SECONDS, help="Delay between requests in seconds")
    parser.add_argument("--timeout", type=float, default=config.TIMEOUT, help="HTTP timeout in seconds")
    parser.add_argument("--user-agent", default=config.DEFAULT_USER_AGENT, help="HTTP User-Agent")
    parser.add_argument("--scan", default="all", help="Scan mode: all,sqli,xss,dom_xss,headers,disclosure")
    parser.add_argument("--output", default="reports/report.json", help="Base JSON output path")
    parser.add_argument("--json", action="store_true", help="Generate JSON report")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    return parser.parse_args()

def main():
    display_banner()
    args = parse_args()
    setup_logger_level(args.verbose)
    if args.depth < 0 or args.max_requests < 1 or args.delay < 0 or args.timeout <= 0:
        raise SystemExit("Invalid scan configuration.")
    modes = {m.strip().lower() for m in args.scan.split(",") if m.strip()}
    if "all" in modes:
        modes = set(config.SCAN_MODES)
    invalid = modes - VALID_MODES
    if invalid:
        raise SystemExit(f"Invalid scan mode(s): {', '.join(sorted(invalid))}")
    print(f"Target  : {args.url}")
    print(f"Depth   : {args.depth}")
    print(f"Requests: {args.max_requests}")
    print(f"Scans   : {', '.join(sorted(modes))}")
    print()
    try:
        scanner = VurnCheckScanner(args.url, sorted(modes), args.depth, args.max_requests, args.timeout, args.delay, args.user_agent)
        result = scanner.run_assessment(args.url)
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        json_path = args.output if args.output.endswith(".json") else args.output + ".json"
        html_path = json_path[:-5] + ".html"
        generate_json = args.json or not args.html
        generate_html = args.html
        if generate_json:
            with open(json_path, "w", encoding="utf-8") as fh:
                fh.write(JSONReporter().generate_report(result.findings, result.scan_metadata))
        if generate_html:
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(HTMLReporter().generate_report(result.findings, result.scan_metadata))
        counts = {s: sum(1 for f in result.findings if f.severity.value == s) for s in ["Critical","High","Medium","Low","Informational"]}
        print("=" * 50)
        print("                 Scan Completed")
        print("=" * 50)
        print(f"Target          : {args.url}")
        print(f"URLs Tested     : {result.scan_metadata['urls_tested']}")
        print(f"Parameters      : {result.scan_metadata['parameters_tested']}")
        print(f"Requests        : {result.scan_metadata['requests_made']}")
        for s in counts:
            print(f"{s:<16}: {counts[s]}")
        print()
        print(f"JSON Report     : {json_path}" if generate_json else "JSON Report     : disabled")
        print(f"HTML Report     : {html_path}" if generate_html else "HTML Report     : disabled")
        print("=" * 50)
        print("                 VurnCheck")
        print("          Author: Mahadu Suryavanshi")
        print("=" * 50)
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
    except Exception as exc:
        logger.error("Scan failed: %s", exc)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
