import functools
import ipaddress
import logging
import os
from typing import Iterator, Type, Union

import peewee

from log_utils import get_logger

database_proxy = peewee.DatabaseProxy()


@functools.cache
def target_is_valid(target: Union[str, int]) -> bool:
    """Check if target is ip address."""

    return is_ip_address(target) or is_ip_network(target) or is_ip_range(target)


@functools.cache
def is_ip_address(target: Union[str, int]) -> bool:
    try:
        target_addr = ipaddress.ip_address(target)
    except ValueError:
        return False
    else:
        return (
            target_addr.is_global or target_addr.is_link_local or target_addr.is_private
        ) and not (
            target_addr.is_loopback
            or target_addr.is_multicast
            or target_addr.is_unspecified
        )


@functools.cache
def is_ip_range(target: str) -> bool:
    try:
        get_ip_range_limits(target)
    except ValueError:
        return False
    else:
        return True


@functools.cache
def get_ip_range_limits(ranged_target: str) -> tuple[int, int]:
    if ranged_target.count("-") == 1:
        min_target, max_target = map(
            lambda x: int(ipaddress.ip_address(x)), ranged_target.split("-", 1)
        )

        if (
            target_is_valid(min_target)
            and target_is_valid(max_target)
            and min_target < max_target
        ):
            return min_target, max_target

    raise ValueError(f"Invalid target: {ranged_target}")


@functools.cache
def is_ip_network(target: Union[str, int]) -> bool:
    try:
        return all(map(is_ip_address, get_ip_network_limits(target)))
    except ValueError:
        return False


@functools.cache
def get_targets_predicate(*targets: Union[str, int]) -> peewee.Expression:
    """
    Build predicate over HostModel.ip_address in order to select only provided targets.
    """

    target_ips = set()
    target_ranges = set()

    for target in targets:
        if is_ip_address(target):
            target_ips.add(target)
        elif is_ip_range(target):
            target_ranges.add(get_ip_range_limits(target))
        elif is_ip_network(target):
            target_ranges.add(get_ip_network_limits(target))
        else:
            raise ValueError(f"Invalid target: {target}")

    predicate = HostModel.ip_address << tuple(
        map(
            lambda x: x if isinstance(x, int) else int(ipaddress.ip_address(x)),
            target_ips,
        )
    )

    for min_ip, max_ip in target_ranges:
        predicate |= (min_ip <= HostModel.ip_address) & (HostModel.ip_address <= max_ip)

    return predicate


@functools.cache
def get_ip_network_limits(network_target: str) -> tuple[int, int]:
    net_target = ipaddress.ip_network(network_target)
    hosts = list(net_target.hosts())
    return hosts[0], hosts[-1]


def plugin(plugin_name: str):
    """Wrap plugin function."""

    def plugin_decorator(func):
        @functools.wraps(func)
        def wrapper(
            *targets: Union[str, int],
            save_dir: str,
            log_level: Union[str, int] = logging.DEBUG,
            **kwargs,
        ):
            for target in targets:
                if target_is_valid(target) is False:
                    raise ValueError(f"Invalid target: {target}")

            logger = get_logger(plugin_name, log_level=log_level)
            save_dir = os.path.join(save_dir, plugin_name)
            os.makedirs(save_dir, exist_ok=True)

            logger.debug(f"Created plugin data directory at: {save_dir}")
            logger.info("Started")

            return func(*targets, save_dir=save_dir, logger=logger, **kwargs)

        return wrapper

    return plugin_decorator


def init_database(database_path: str = ":memory:", log_level: int = logging.DEBUG):
    """Initialize database, creating tables."""

    logger = get_logger("database", log_level=log_level)
    logger.info(f"Initialize database: '{database_path}'")

    database = peewee.SqliteDatabase(database_path)
    database_proxy.initialize(database)

    tables = tuple(filter(lambda x: x.is_table is True, get_db_models()))

    logger.debug(f"Creating following tables: {tables}")

    with database_proxy.atomic():
        database.create_tables(tables)

    logger.info(f"{len(tables)} tables created")


def get_db_models() -> Iterator[Type["BaseModel"]]:
    """Model subclasses iterator."""

    for model in get_subclasses(BaseModel):
        yield model


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


class BaseModel(peewee.Model):
    """Base model for task results."""

    is_table: bool = False  # on True, the model is created as a table into database

    class Meta:
        database = database_proxy


class HostModel(BaseModel):
    is_table = True

    ip_address = peewee.IntegerField(unique=True, index=True)
    operating_system = peewee.CharField(index=True, null=True)
    hostname = peewee.CharField(null=True)
    domain = peewee.CharField(null=True)

    class Meta:
        db_table = "host"

    @functools.cache
    def get_ip(self) -> str:
        return str(ipaddress.ip_address(self.ip_address))


class ServiceModel(BaseModel):
    PROTOCOL_TCP = "tcp"
    PROTOCOL_UDP = "udp"
    PROTOCOL_CHOICES = (
        (PROTOCOL_TCP, "TCP"),
        (PROTOCOL_UDP, "UDP"),
    )

    is_table = True

    host = peewee.ForeignKeyField(HostModel, on_delete="CASCADE", backref="services")
    port = peewee.IntegerField()
    protocol = peewee.CharField(choices=PROTOCOL_CHOICES)

    name = peewee.CharField(null=True)
    version = peewee.CharField(null=True)
    product = peewee.CharField(null=True)
    extra_info = peewee.CharField(null=True)

    class Meta:
        db_table = "service"
        indexes = ((("host", "port", "protocol"), True),)


class HostUserModel(BaseModel):
    is_table = True

    host = peewee.ForeignKeyField(HostModel, backref="users")
    username = peewee.CharField(index=True)

    class Meta:
        db_table = "host_user"
        indexes = ((("host", "username"), True),)


class ServiceCredentials(BaseModel):
    is_table = True

    service = peewee.ForeignKeyField(ServiceModel)
    username = peewee.CharField(index=True)
    password = peewee.CharField()

    class Meta:
        db_table = "service_credentials"
        indexes = ((("service", "username", "password"), True),)
