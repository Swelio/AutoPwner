"""Utilities for script solvers."""

import grp
import os.path
import pwd
import subprocess
import xml.etree.ElementTree as ET

from src.log_utils import get_logger

RESULT_DIR = "results"
NMAP_DIR = os.path.join(RESULT_DIR, "nmap")

logger = get_logger("nmap_lib")


def init_solver():
    for path in (NMAP_DIR,):
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)


def service_discovery(host: str, full: bool = False):
    """
    Use Nmap to discover host services. If full is True, then scan all ports.
    For each service, yield data as: (port, name, product, version)
    """

    result_path = os.path.join(NMAP_DIR, "services")
    xml_path = result_path + ".xml"

    if os.path.exists(xml_path):
        logger.info(f"NMap result exists at '{xml_path}', skip scan.")
    else:
        logger.info(f"Scanning host '{host}' to find services")

        cmd = ["/usr/bin/sudo", "/usr/bin/nmap", "-v", "-n", "-sS", "-sV", "-Pn"]
        if full is True:
            cmd.append("-p-")
        cmd.extend(["-oA", result_path, host])

        logger.info(f"Running command: {' '.join(cmd)}")
        try:
            subprocess.check_call(cmd)
        finally:
            pw_info = pwd.getpwuid(os.getuid())
            subprocess.check_call(
                [
                    "/usr/bin/sudo",
                    "/usr/bin/chown",
                    "--recursive",
                    f"{pw_info.pw_name}:{grp.getgrgid(pw_info.pw_gid).gr_name}",
                    RESULT_DIR,
                ]
            )

    xml_result = ET.parse(xml_path).getroot()

    logger.info(f"Parsing result file '{xml_path}'")

    for port_node in xml_result.iterfind('.//port/state[@state="open"]/..'):
        port_number = int(port_node.attrib["portid"])

        service_node = port_node.find("./service")
        service_name = service_node.attrib["name"]
        service_product = service_node.attrib.get("product")
        service_version = service_node.attrib.get("version")

        yield port_number, service_name, service_product, service_version
