"""Main script"""

import argparse
import ipaddress
import sys

from log_utils import get_logger
from plugins import init_plugins, NmapPlugin, SearchsploitPlugin
from plugins.report_exporter import ReportExporter

PLUGINS_DIR = "data"


def setup_arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        "AutoPwner",
        description="Scan network, check for vulnerabilities and try to exploit it.",
    )
    parser.add_argument("target", help="Ip address of network or machine to target.")

    return parser


if __name__ == "__main__":
    main_logger = get_logger("main")
    cli_parser = setup_arguments()
    cli_args = cli_parser.parse_args()

    try:
        # Check target is as IP format
        cli_args.target = str(ipaddress.ip_network(cli_args.target))
    except ValueError:
        main_logger.critical(
            f"Target must be an ip address of machine or network: {cli_args.target}"
        )
        sys.exit(1)

    main_logger.info(f"Running script on {cli_args.target}")

    init_plugins(PLUGINS_DIR)

    nmap_runner = NmapPlugin()
    searchsploit_runner = SearchsploitPlugin()
    exporter = ReportExporter()

    nmap_runner.run(cli_args.target, full=True)
    searchsploit_runner.run(cli_args.target)
    exporter.run()
