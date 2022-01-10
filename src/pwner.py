"""Main script"""
import argparse
import logging
import os
import sys

from log_utils import get_logger
from plugins.core import init_database, target_is_valid
from plugins.exploit_search import exploit_researcher
from plugins.kerbrute import kerbrute_executor
from plugins.nmap import nmap_executor
from plugins.report_exporter import export_results


def setup_arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        "AutoPwner",
        description="Scan network, check for vulnerabilities and try to exploit it.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "target", help="IP address of network or machine to target.", nargs="+"
    )
    parser.add_argument(
        "--user-list", help="User wordlist to use for credentials operations."
    )
    parser.add_argument(
        "--password-list", help="Password wordlist to use for credentials operations."
    )
    parser.add_argument(
        "--database", help="Path of database to use.", default=":memory:"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="Enable debug logs in console.",
        action="store_true",
        default=False,
    )

    return parser


if __name__ == "__main__":

    cli_parser = setup_arguments()
    cli_args = cli_parser.parse_args()

    log_level = logging.DEBUG if cli_args.verbose else logging.INFO
    main_logger = get_logger(cli_parser.prog, log_level=log_level)

    targets = set()

    # check targets and remove duplicates
    for target in cli_args.target:
        if target_is_valid(target):
            targets.add(target)
        else:
            main_logger.critical(f"Invalid target found: {target}")
            sys.exit(1)

    targets = tuple(targets)

    data_dir = os.path.join(os.getcwd(), "data")
    os.makedirs(data_dir, exist_ok=True)
    init_database(cli_args.database, log_level=log_level)

    nmap_executor(*targets, save_dir=data_dir, full_scan=True, log_level=log_level)
    exploit_researcher(*targets, save_dir=data_dir, log_level=log_level)
    kerbrute_executor(
        *targets,
        save_dir=data_dir,
        log_level=log_level,
        user_wordlist=cli_args.user_list,
        password_wordlist=cli_args.password_list,
    )
    export_results(*targets, save_dir=data_dir, log_level=log_level)
