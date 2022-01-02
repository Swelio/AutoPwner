import ipaddress
import json
import re
import subprocess

from plugins.base_plugin import BasePlugin, PluginError
from plugins.credentials_manager import CredentialsManager
from plugins.nmap import NmapPlugin


class GetUserSPNsPlugin(BasePlugin):
    name = "user_spns"

    requirements = [NmapPlugin]
    optional = True

    def run_impacket(
        self,
        host: str,
        host_data: dict[str, ...],
    ) -> set[tuple[str, str]]:
        """
        Use impacket to gather users with ServicePrincipalName and their hashes.

        Return set of found credentials as: { ( username, hash ), }
        """

        host_addr = str(ipaddress.ip_address(host.removesuffix("/32")))

        raw_data = json.dumps(host_data)
        root_domain_regex = re.compile(
            r"Domain:\s(?P<domain>[^/]+)0\.,\sSite:\sDefault-First-Site-Name"
        )

        root_domain_match = root_domain_regex.search(raw_data)

        if root_domain_match is None:
            raise PluginError(f"No domain found for host {host}")

        root_domain = root_domain_match.group("domain")

        self.get_logger().info(f"Attacking Kerberos on domain {root_domain}")

        hashes = set()
        credentials = CredentialsManager.get_credentials()



    def run(self, user_wordlist: str, password_wordlist: str):
        super().run()

        # cannot run without provided wordlists
        if None in (user_wordlist, password_wordlist):
            return

        with NmapPlugin.get_parsed_file().open("r") as nmap_file:
            nmap_results = json.loads(nmap_file.read())

        # dictionary of found credentials
        results = {}
        found_credentials = set()

        for host, host_data in nmap_results.items():
            for service, service_data in host_data["services"].items():
                if service_data["name"] == "kerberos-sec":
                    break
            else:
                continue

            host_credentials = self.run_kerbrute(
                user_wordlist, password_wordlist, host, host_data
            )
            found_credentials |= host_credentials
            results[host] = {"credentials": list(host_credentials)}

        CredentialsManager.store_credentials(*found_credentials)

        with self.get_parsed_file().open("w") as result_file:
            result_file.write(json.dumps(results))
