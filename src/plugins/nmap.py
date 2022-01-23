import grp
import ipaddress
import logging
import os
import pwd
import subprocess
import xml.etree.ElementTree as ET

from plugins.core import HostModel, ServiceModel, database_proxy, plugin


@plugin("nmap")
def nmap_executor(
    *targets: str, save_dir: str, logger: logging.Logger, full_scan: bool = False
):
    """
    Scan targets with nmap and register found hosts and services into database.

    :param targets: targets to scan. Can be IP address, range of IP or network IP.
    :param save_dir: directory path to task results.
    :param logger: task logger.
    :param full_scan: on True, scan all ports.
    """

    logger.info(f"Analysis will run on {', '.join(targets)}")
    result_path = os.path.join(save_dir, "scan")
    xml_path = result_path + ".xml"

    if os.path.exists(xml_path):
        logger.info(f"NMap result exists at '{xml_path}', skip scan.")
    else:
        logger.info(
            f"Scanning host{'s' if len(targets) > 1 else ''} "
            f"'{', '.join(targets)}' to find services"
        )

        cmd = ["/usr/bin/sudo", "nmap", "-v", "-n", "-sS", "-sV"]

        if full_scan is True:
            cmd.append("-p-")

        cmd.extend(["-oA", str(result_path)])
        cmd.extend(targets)

        logger.info(f"Running command: {' '.join(cmd)}")
        try:
            subprocess.check_call(cmd)
        finally:
            pw_info = pwd.getpwuid(os.getuid())
            subprocess.check_call(
                [
                    "/usr/bin/sudo",
                    "/usr/bin/chown",
                    "--recursive",  # apply to whole directory
                    # current user id and group
                    f"{pw_info.pw_name}:{grp.getgrgid(pw_info.pw_gid).gr_name}",
                    # results dir
                    save_dir,
                ]
            )

    logger.info(f"Raw results are available at '{result_path}'")
    logger.debug("Processing results...")

    # parse result file and retrieve root node
    xml_root = ET.parse(xml_path).getroot()

    hosts_to_update = []
    services_to_update = []

    for host_node in xml_root.iterfind(".//host"):
        host_addr = int(ipaddress.ip_address(host_node.find("address").attrib["addr"]))
        host_data, _ = HostModel.get_or_create(ip_address=host_addr)

        hosts_to_update.append(host_data)

        for port_node in host_node.iterfind('.//port/state[@state="open"]/..'):
            service_node = port_node.find("service")

            # Host info from service
            host_data.hostname = service_node.attrib.get("hostname")
            host_data.operating_system = service_node.attrib.get("ostype")

            # Service data
            protocol = port_node.attrib["protocol"]
            port = int(port_node.attrib["portid"])

            service_data, _ = ServiceModel.get_or_create(
                host=host_data, port=port, protocol=protocol
            )
            service_data.name = service_node.attrib.get("name")
            service_data.version = service_node.attrib.get("version")
            service_data.product = service_node.attrib.get("product")
            service_data.extra_info = service_node.attrib.get("extrainfo")

            services_to_update.append(service_data)

    with database_proxy.atomic():
        logger.info(
            f"Found {len(hosts_to_update)} hosts and {len(services_to_update)} services"
        )

        if len(hosts_to_update) > 0:
            HostModel.bulk_update(
                hosts_to_update, [HostModel.hostname, HostModel.operating_system]
            )

        if len(services_to_update) > 0:
            ServiceModel.bulk_update(
                services_to_update,
                [
                    ServiceModel.name,
                    ServiceModel.version,
                    ServiceModel.product,
                    ServiceModel.extra_info,
                ],
            )

    logger.info("Done.")
