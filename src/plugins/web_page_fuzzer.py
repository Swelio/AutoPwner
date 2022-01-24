import datetime
import logging
import os
import re
import subprocess
from typing import Optional, Union

from plugins.core import (
    HostModel,
    HostUserModel,
    ServiceCredentials,
    ServiceModel,
    database_proxy,
    get_targets_predicate,
    plugin,
)


@plugin("web_page_fuzzer")
def web_page_fuzzer(
    *targets: Union[str, int], save_dir: str, logger: logging.Logger, web_wordlist: str
):
    """
    Run fuzzer tool (gobuster actually) in order to find some pathes on web server.

    :param targets: target to bruteforce. Can be IP address, range of IP or network IP.
    :param save_dir: directory to save raw kerbrute outputs.
    :param logger: task logger.
    :param web_wordlist: wordlist of pathes to use.
    """

    target_predicate = get_targets_predicate(*targets)

    gobuster_targets = (
        HostModel.select(HostModel.ip_address, ServiceModel.port)
        .distinct()
        .join_from(HostModel, ServiceModel, on=(HostModel.id == ServiceModel.host))
        .where(target_predicate & (ServiceModel.name == "http"))
    ).objects()

    if not gobuster_targets.exists():
        logger.info("No web target, skip.")
        return

    web_fuzzing_dir = os.path.join(save_dir, "web_fuzzing")

    os.makedirs(web_fuzzing_dir, exist_ok=True)

    for target_host in gobuster_targets:

        logger.debug(f"Running gobuster on target: {target_host.get_ip()}")
        run_time = datetime.datetime.utcnow().strftime("%Y_%m_%d_%H_%M_%S")
        suffix = f"{run_time}_{target_host.get_ip()}"

        service_fuzzing_basename = os.path.join(web_fuzzing_dir, suffix)
