import copy
import json
from os import PathLike
from pathlib import Path
from typing import Union

from plugins.base_plugin import BasePlugin, PluginError, get_subclasses  # noqa: F401
from plugins.nmap import NmapPlugin  # noqa: F401
from plugins.searchsploit import SearchsploitPlugin  # noqa: F401


def init_plugins(plugin_dir: Union[str, PathLike]):
    if isinstance(plugin_dir, str):
        plugin_dir = Path(plugin_dir)

    for plugin_class in get_subclasses(BasePlugin):
        # Skip plugin with undefined name
        if plugin_class.name is None:
            continue

        plugin_class.plugins_dir = plugin_dir


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
        if plugin_class.name is None:
            continue

        with plugin_class.get_parsed_file().open() as f:
            parse = json.loads(f.read())
        result = deep_update(result, parse)

    return result
