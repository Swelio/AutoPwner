import grp
import os
import pwd
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from plugins.base_plugin import BasePlugin


class NmapPlugin(BasePlugin):
    name = "nmap"

    @classmethod
    def init_plugin(cls, base_dir: Path):
        super().init_plugin(base_dir)

        result_dir = cls.get_plugin_dir()

        if not result_dir.exists():
            os.makedirs(result_dir, exist_ok=True)

        cls.logger.info(
            f"{cls.name} plugin results are available at '{cls.get_plugin_dir()}'"
        )

    @classmethod
    def get_plugin_dir(cls) -> Path:
        return cls.plugins_dir.absolute() / cls.name

    def __call__(self, host: str, full: bool = False):
        """
        Use Nmap to discover host services. If full is True, then scan all ports.
        For each service, yield data as: (port, name, product, version)
        """

        result_path = self.plugins_dir / "services"
        xml_path = Path(str(result_path) + ".xml")

        if xml_path.exists():
            self.logger.info(f"NMap result exists at '{xml_path}', skip scan.")
        else:
            self.logger.info(f"Scanning host '{host}' to find services")

            cmd = ["/usr/bin/sudo", "/usr/bin/nmap", "-v", "-n", "-sS", "-sV", "-Pn"]
            if full is True:
                cmd.append("-p-")
            cmd.extend(["-oA", result_path, host])

            self.logger.info(f"Running command: {' '.join(cmd)}")
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

        xml_result = ET.parse(xml_path).getroot()

        self.logger.info(f"Parsing result file '{xml_path}'")

        for port_node in xml_result.iterfind('.//port/state[@state="open"]/..'):
            port_number = int(port_node.attrib["portid"])

            service_node = port_node.find("./service")
            service_name = service_node.attrib["name"]
            service_product = service_node.attrib.get("product")
            service_version = service_node.attrib.get("version")

            yield port_number, service_name, service_product, service_version
