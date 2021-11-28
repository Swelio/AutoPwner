import grp
import ipaddress
import json
import os
import pwd
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from plugins.base_plugin import BasePlugin


class NmapPlugin(BasePlugin):
    name = "nmap"

    def get_result_file(self) -> Path:
        return self.get_plugin_dir() / "services.xml"

    def get_parsed_file(self) -> Path:
        return self.get_plugin_dir() / "parsed.json"

    def run(self, host: str, full: bool = False):
        """
        Use Nmap to discover host services. If full is True, then scan all ports.
        For each service, yield data as: (port, name, product, version)
        """
        super().run()
        self.get_logger().info(f"Analysis will run on {host}")

        xml_path = self.get_result_file()
        result_path = Path(str(xml_path).removesuffix(".xml"))

        if xml_path.exists():
            self.get_logger().info(f"NMap result exists at '{xml_path}', skip scan.")
        else:
            self.get_logger().info(f"Scanning host '{host}' to find services")

            cmd = ["/usr/bin/sudo", "/usr/bin/nmap", "-v", "-n", "-sS", "-sV"]
            if full is True:
                cmd.append("-p-")
            cmd.extend(["-oA", str(result_path), host])

            self.get_logger().info(f"Running command: {' '.join(cmd)}")
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
                        self.plugins_dir,
                    ]
                )

        self.get_logger().info(f"Raw results available at '{result_path}'")

        if not self.get_parsed_file().exists():
            with self.get_parsed_file().open("w") as parsed_file_save:
                parsed_file_save.write(json.dumps(self.get_results()))

        self.get_logger().info(
            f"Parsed results available at '{self.get_parsed_file()}'"
        )

    def get_results(self) -> dict[str, dict[str, ...]]:
        """
        Parse nmap xml file and for each host return its opened services.
        :return: {
            host: { "services": [] }
        }
        """

        # result dictionary as described in docstring
        result = {}

        # parse result file and retrieve root node
        xml_root = ET.parse(self.get_result_file()).getroot()

        self.get_logger().info("Parsing nmap result file...")

        for host_node in xml_root.iterfind(".//host"):
            host_services = []
            host_addr = str(
                ipaddress.ip_network(host_node.find("address").attrib["addr"])
            )

            for port_node in host_node.iterfind('.//port/state[@state="open"]/..'):
                service_node = port_node.find("service")

                service_data = {
                    "protocol": port_node.attrib["protocol"],
                    "port": int(port_node.attrib["portid"]),
                    "name": service_node.attrib.get("name"),
                    "hostname": service_node.attrib.get("hostname"),
                    "version": service_node.attrib.get("version"),
                    "product": service_node.attrib.get("product"),
                    "ostype": service_node.attrib.get("ostype"),
                    "extrainfo": service_node.attrib.get("extrainfo"),
                }

                host_services.append(service_data)

            result[host_addr] = {"services": host_services}

        self.get_logger().info("Done.")

        return result
