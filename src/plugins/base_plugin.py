import os
from logging import Logger
from pathlib import Path
from typing import Type, Iterator

from log_utils import get_logger


def get_subclasses(base_class: Type) -> Iterator[Type]:
    """Iterate over each subclass of base_class object.
    That means it can find only loaded classes (using import by e.g).

    :param base_class: root of subclasses found.
    :return: generator which does yield each subclass of base_class.
    """
    for subclass in base_class.__subclasses__():
        yield subclass
        yield from get_subclasses(subclass)


class PluginError(Exception):
    """Plugin has failed to run."""


# TODO: plugin subcommand parser to integrate into a global command parser
class BasePlugin:
    name: str = None
    requirements: list["BasePlugin"] = []

    plugins_dir: Path = None
    _logger = None

    def __init__(self):
        self.init_plugin(self.plugins_dir)
        self.get_logger().debug("Plugin ready!")

    @classmethod
    def get_logger(cls) -> Logger:
        if cls._logger is None:
            cls._logger = get_logger(cls.name)

        return cls._logger

    @classmethod
    def init_plugin(cls, base_dir: Path):
        """
        Setup initialization for plugin when program starts.

        :param base_dir: plugins base directory installation.
        """
        cls.get_logger().info(f"Initialize plugin {cls.name}")
        cls.plugins_dir = base_dir.absolute()

        result_dir = cls.get_plugin_dir()

        if not result_dir.exists():
            os.makedirs(result_dir, exist_ok=True)

        cls.get_logger().info(
            f"{cls.name} plugin results are available at '{cls.get_plugin_dir()}'"
        )

    @classmethod
    def get_plugin_dir(cls) -> Path:
        """Return path of plugin folder."""
        return cls.plugins_dir.absolute() / cls.name

    @classmethod
    def get_parsed_file(cls) -> Path:
        return cls.get_plugin_dir() / "parsed.json"

    @classmethod
    def get_result_file(cls) -> Path:
        raise NotImplementedError

    def run(self, *args, **kwargs):
        """Plugin executable task."""
        for plugin in self.requirements:
            if not plugin.get_parsed_file().exists():
                self.get_logger().error(
                    f"Plugin requirement not satisfied: {plugin.name}"
                )
                return

        self.get_logger().info("Start running")
