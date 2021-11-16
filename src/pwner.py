"""Main script"""

import argparse

from plugins import init_plugins

PLUGINS_DIR = "data"


def setup_arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        "AutoPwner",
        description="Scan network, check for vulnerabilities and try to exploit it.",
    )

    return parser


if __name__ == "__main__":
    cli_parser = setup_arguments()

    cli_args = cli_parser.parse_args()
    init_plugins(PLUGINS_DIR)
