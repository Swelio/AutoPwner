import grp
import os
import pwd
import subprocess
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

        cls.get_logger().info(
            f"{cls.name} plugin results are available at '{cls.get_plugin_dir()}'"
        )

    @classmethod
    def get_plugin_dir(cls) -> Path:
        return cls.plugins_dir.absolute() / cls.name

    def run(self, host: str, full: bool = False):
        """
        Use Nmap to discover host services. If full is True, then scan all ports.
        For each service, yield data as: (port, name, product, version)
        """
        super().run()
        self.get_logger().info(f"Analysis will run on {host}")

        result_path = self.plugins_dir / "services"
        xml_path = Path(str(result_path) + ".xml")

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

        self.get_logger().info(f"Results available at '{result_path}'")
