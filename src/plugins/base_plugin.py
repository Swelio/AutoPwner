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


class BasePlugin:
    name: str = None
    logger = get_logger(name)
    plugins_dir: Path = None

    @classmethod
    def init_plugin(cls, base_dir: Path):
        """
        Setup initialization for plugin when program starts.

        :param base_dir: plugins base directory installation.
        """
        cls.logger.info(f"Initialize plugin {cls.name}")
        cls.plugins_dir = base_dir.absolute()

    @classmethod
    def get_plugin_dir(cls) -> Path:
        """Return path of plugin folder."""
        raise NotImplementedError

    def __call__(self, *args, **kwargs):
        """Plugin executable task."""
