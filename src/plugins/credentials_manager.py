import json

from plugins.base_plugin import BasePlugin


class CredentialsManager(BasePlugin):
    """Utility plugin to store found credentials as a list of tuple."""

    name = "credentials_manager"
    optional = True

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
