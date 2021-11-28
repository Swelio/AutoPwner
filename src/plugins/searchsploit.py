import functools
import json
import subprocess
from pathlib import Path

from plugins.base_plugin import BasePlugin, PluginError
from plugins.nmap import NmapPlugin


@functools.cache
def searchsploit(search_terms: str) -> dict[str, ...]:
    """
    Start searchsploit with provided search terms. Then return results as json.
    """

    cmd = [
        "/usr/bin/searchsploit",
        str(search_terms),
        "--json",
        "--www",
        "--id",
    ]

    proc_result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)

    result_lines = map(str.strip, proc_result.decode().splitlines(keepends=False))
    json_results = "".join(result_lines)

    return json.loads(json_results)


class SearchsploitPlugin(BasePlugin):
    name = "searchsploit"
    requirements = [NmapPlugin]

    def run(self, host: str):
        """
        Use searchsploit tool to find exploits from nmap result file.
        Raw results are stored into file in order to keep as much information as
        possible. Then, raw results are parsed to provided following structure:
        {
            host: { "services": { "proto/port": { "exploits": [] }}}
        }
        """
        super().run()
        self.get_logger().info("Looking for known exploit on nmap results")

        result_path = self.get_result_file()

        if not result_path.exists():
            nmap_results_path = NmapPlugin.get_parsed_file()
            if nmap_results_path.exists():
                with nmap_results_path.open("r") as nmap_results_file:
                    nmap_results = json.loads(nmap_results_file.read())
            else:
                error = f"No nmap xml file found on '{NmapPlugin.get_plugin_dir()}'."
                self.get_logger().error(error)
                raise PluginError(error)

            raw_results = []
            results = {}

            # for each service of each host, run
            for host, host_data in nmap_results.items():
                # { "proto/port": { "exploits": []" }}
                services_exploits = {}
                for service_key, service_data in host_data["services"].items():
                    service_exploits = []
                    for key in ("name", "product"):
                        if service_data[key] is not None:
                            terms = service_data[key].lower().replace("-", " ")
                            raw_result = searchsploit(terms)
                            raw_results.append(raw_result)
                            service_exploits = raw_result["RESULTS_EXPLOIT"]

                            for exploit in service_exploits:
                                if exploit not in service_exploits:
                                    service_exploits.append(exploit)

                    services_exploits[service_key] = {"exploits": service_exploits}

                results[host] = {"services": services_exploits}

            with result_path.open("w") as results_file:
                results_file.write(json.dumps(raw_results))

            with self.get_parsed_file().open("w") as parsed_results_file:
                parsed_results_file.write(json.dumps(results))

        self.get_logger().info(f"Raw results available at '{str(result_path)}'")

    @classmethod
    def get_result_file(cls) -> Path:
        return cls.get_plugin_dir() / "exploits.json"
