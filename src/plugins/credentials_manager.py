import json
from pathlib import Path

from plugins.base_plugin import BasePlugin


class CredentialsManager(BasePlugin):
    """Utility plugin to store found credentials as a list of tuple."""

    name = "credentials_manager"
    optional = True

    @classmethod
    def store_hashes(cls, *hashes: str):
        """Store provided hashes into result file as list."""

        try:
            with cls.get_hashes_path().open("r") as hashes_file:
                known_hashes = hashes_file.readlines()
        except FileNotFoundError:
            known_hashes = set()

        known_hashes |= set(hashes)

        with cls.get_hashes_path().open("w") as hashes_file:
            hashes_file.writelines(map(lambda x: x.strip() + "\n", known_hashes))

        cls.get_logger().debug(
            f"Stored {len(hashes)} hashes into {cls.get_parsed_file()}"
        )

    @classmethod
    def get_hashes_path(cls) -> Path:
        return cls.get_plugin_dir() / "hashes.txt"

    @classmethod
    def store_credentials(cls, *credentials: tuple[str, str]):
        """Store provided credentials into result file as json list."""

        try:
            with cls.get_parsed_file().open("r") as credentials_file:
                known_credentials = set(map(tuple, json.loads(credentials_file.read())))
        except FileNotFoundError:
            known_credentials = set()

        known_credentials |= set(credentials)
        edited_known_credentials = json.dumps(list(known_credentials))

        with cls.get_parsed_file().open("w") as credentials_file:
            credentials_file.write(edited_known_credentials)

        cls.get_logger().debug(
            f"Stored {len(credentials)} credentials into {cls.get_parsed_file()}"
        )

    @classmethod
    def get_credentials(cls) -> set[tuple[str, str]]:

        try:
            with cls.get_parsed_file().open("r") as credentials_file:
                return set(json.loads(credentials_file.read()))
        except FileNotFoundError:
            return set()
