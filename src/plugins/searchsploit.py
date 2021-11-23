import json
import subprocess

from plugins.base_plugin import BasePlugin, PluginError
from plugins.nmap import NmapPlugin


class SearchsploitPlugin(BasePlugin):
    name = "searchsploit"
    requirements = [NmapPlugin]

    def run(self, host: str):
        """
        Use searchsploit tool to find exploits from nmap result file.
        """
        super().run()
        self.get_logger().info("Looking for known exploit on nmap results")

        result_path = self.get_plugin_dir() / "exploits.json"

        if not result_path.exists():
            for path in NmapPlugin.get_plugin_dir().iterdir():
                if str(path).endswith(".xml"):
                    nmap_result_path = path
                    break
            else:
                error = f"No nmap xml file found on '{NmapPlugin.get_plugin_dir()}'."
                self.get_logger().error(error)
                raise PluginError(error)

            cmd = [
                "/usr/bin/searchsploit",
                "--nmap",
                str(nmap_result_path),
                "--json",
                "--www",
                "--id",
            ]

            self.get_logger().info(f"Running command: {' '.join(cmd)}")
            proc_result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)

            results = []
            current_result = ""
            for line in proc_result.decode().splitlines(keepends=False):
                if line == "":
                    if current_result == "":
                        continue
                    result = json.loads(current_result)

                    # make ensure there is some findings in result
                    for key, value in result.items():
                        if key.lower().startswith("results_") and len(value) > 0:
                            results.append(result)
                            break
                    current_result = ""
                    continue

                current_result += line.strip()

            with result_path.open("w") as results_file:
                results_file.write(json.dumps(results))

        self.get_logger().info(f"Results available at '{str(result_path)}'")
