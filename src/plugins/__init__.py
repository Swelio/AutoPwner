from os import PathLike
from pathlib import Path
from typing import Union

from plugins.base_plugin import BasePlugin, PluginError, get_subclasses  # noqa: F401
from plugins.nmap import NmapPlugin  # noqa: F401
from plugins.report_exporter import ReportExporter  # noqa: F401
from plugins.searchsploit import SearchsploitPlugin  # noqa: F401


def init_plugins(plugin_dir: Union[str, PathLike]):
    if isinstance(plugin_dir, str):
        plugin_dir = Path(plugin_dir)

    for plugin_class in get_subclasses(BasePlugin):
        # Skip plugin with undefined name
        if plugin_class.name is None:
            continue

        plugin_class.plugins_dir = plugin_dir
