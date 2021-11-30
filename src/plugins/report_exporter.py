import copy
import datetime
import itertools
import json
from pathlib import Path

from plugins import CredentialsManager
from plugins.base_plugin import BasePlugin, get_subclasses


def deep_update(*merged_dicts: dict) -> dict:
    """Merge provided dictionaries into one without individual modifications."""

    result = {}

    for dico in merged_dicts:
        for key, value in dico.items():
            if isinstance(value, dict):
                result_value = result.get(key, dict())
                result[key] = deep_update(result_value, value)

            elif isinstance(value, (list, tuple)):
                result_value = result.get(key, list())

                for item in value:
                    if isinstance(item, list):
                        item = tuple(item)
                    if item not in result_value:
                        result_value.append(copy.deepcopy(item))

                result[key] = result_value

            elif isinstance(value, set):
                result_value = result.get(key, set())
                result[key] = result_value | value

            elif key in result.keys():
                raise KeyError(
                    f"Key already exists and is not mutable: {key} with value {value}"
                )

            else:
                result[key] = value

    return result


def merge_results() -> dict[str, dict[str, ...]]:
    """
    Merge plugin parsed results into a common dictionary as:
    {
        "host": {
            "services": {
                "proto/port": data
            }
        }
    }
    """

    result = {}

    for plugin_class in get_subclasses(BasePlugin):
        if (
            plugin_class.name is None
            or plugin_class == ReportExporter
            or plugin_class == CredentialsManager
        ):
            continue

        try:
            with plugin_class.get_parsed_file().open() as f:
                parse = json.loads(f.read())
            result = deep_update(result, parse)
        except FileNotFoundError:
            if plugin_class.optional is False:
                raise

    return result


class ReportExporter(BasePlugin):
    name = "report"

    @classmethod
    def get_result_file(cls) -> Path:
        return cls.get_plugin_dir() / "merged.json"

    @classmethod
    def get_parsed_file(cls) -> Path:
        return cls.get_plugin_dir() / "report.md"

    def run(self):
        """
        Export results as markdown text document structured as following:
        # Automatic scan report

        ## Targets

        target list

        ## Detailed findings

        ### Target_1 (x findings)

        #### proto/port - name (x findings)

        ### Target_2

        service list
        """
        super().run()

        results = merge_results()

        with self.get_result_file().open("w") as f:
            f.write(json.dumps(results))

        today = datetime.date.today().strftime("%Y-%m-%d")

        # Lines ending with '\n' have 1 blank line after
        lines = [
            f"# Automatic scan report - {today}\n\n",
            f"## Targets ({len(results.keys())})\n\n",
        ]

        # Structured as: [
        #   [ title_line, service_lines ]
        # ]
        detailed_findings = []

        for host, host_data in results.items():
            finding_count = 0
            host_os = None
            hostname = None

            host_lines = []
            service_titles = []
            service_lines = []

            for service, service_data in host_data["services"].items():
                if len(service_data["exploits"]) == 0:
                    continue

                # build service title as: '#### proto/port - product - name'
                service_split_title = [
                    x
                    for x in (
                        service_data["product"],
                        service_data["name"],
                        service_data["version"],
                    )
                    if x
                ]
                service_title = " - ".join(service_split_title)
                service_title_line = (
                    f"{service} - {service_title} "
                    f"({len(service_data['exploits'])} findings)\n"
                )
                service_titles.append(f"\t- {service_title_line}")
                service_lines.append(f"#### {service_title_line}\n")

                if host_os is None and service_data["ostype"] is not None:
                    host_os = service_data["ostype"]

                if hostname is None and service_data["hostname"] is not None:
                    hostname = service_data["hostname"]

                for finding in service_data["exploits"]:
                    service_lines.extend(
                        [f"- {finding['Title']}\n", f"\t- {finding['URL']}\n"]
                    )

                finding_count += len(service_data["exploits"])

            # build resumed line as: '- host (OS - x findings)'
            host_os = host_os or "Unknown"
            lines.append(
                f"- {host} ({host_os} - {len(host_data['services'])} services)\n"
            )
            lines.extend(service_titles)

            # build host section title: '### host (OS - x findings)'
            host_lines.append(f"### {host} ({host_os} - {finding_count} findings)\n\n")
            # host data
            host_lines.extend([f"Hostname: {hostname}\n\n"])
            # complete host section and global lines
            host_lines.extend(service_lines)
            detailed_findings.append(host_lines)

        lines.append("\n")  # blank line separator
        lines.append("## Detailed findings\n\n")
        lines.extend(itertools.chain(*detailed_findings))

        with self.get_parsed_file().open("w") as export_file:
            export_file.writelines(lines)
