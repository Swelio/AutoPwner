import collections
import datetime
import ipaddress
import itertools
import logging
import os.path
from typing import Union

import peewee

from plugins.core import HostModel, ServiceCredentials, ServiceModel, plugin
from plugins.exploit_search import ExploitModel


@plugin("export_results")
def export_results(*targets: Union[str, int], save_dir: str, logger: logging.Logger):
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

    targets_query = (
        HostModel.select()
        .where(
            HostModel.ip_address
            << [int(ipaddress.ip_address(target_ip)) for target_ip in targets]
        )
        .order_by(HostModel.ip_address.asc())
    )

    result = (
        f"# Automatic scan report - "
        f"{datetime.datetime.utcnow().isoformat(sep=' ', timespec='minutes')}\n\n"
    )
    result += f"Targets ({targets_query.count()})\n\n"

    for target_host in targets_query:
        target_block = get_target_block(target_host)
        result += target_block

    report_path = os.path.join(save_dir, "report.md")
    with open(report_path, "w") as report_file:
        report_file.write(result)

    logger.info(f"Report saved at {report_path}")


def get_target_block(target_host: HostModel) -> str:
    """
    Export target result in markdown block as following:

    ```
    ### Target_1 (x findings)

    #### proto/port - name (x findings)
    ``̀`

    :param target_host: HostModel to print.
    :return: markdown string with target findings.
    """

    def query_models_data_constructor(**row):
        model = collections.namedtuple("SelectMerger", ("service", "exploit"))
        return model(service=ServiceModel(**row), exploit=ExploitModel(**row))

    target_ip = ipaddress.ip_address(target_host.ip_address)

    services_query = (
        ServiceModel.select(ServiceModel, ExploitModel)
        .join_from(
            ServiceModel,
            ExploitModel,
            join_type=peewee.JOIN.LEFT_OUTER,
            on=(ServiceModel.id == ExploitModel.service),
        )
        .where(ServiceModel.host == target_host)
        .order_by(ServiceModel.port.asc())
    ).objects(query_models_data_constructor)

    credentials_query = (
        ServiceCredentials.select(ServiceCredentials)
        .join_from(
            ServiceCredentials,
            ServiceModel,
            on=(ServiceCredentials.service == ServiceModel.id),
        )
        .where(ServiceModel.host == target_host)
        .order_by(ServiceModel.port.asc())
    )

    result = (
        f"### {str(target_ip)} - "
        f"({services_query.where(ExploitModel.id.is_null(False)).count()} exploits, "
        f"{credentials_query.count()} credentials)\n\n"
    )
    result += f"Hostname = {target_host.hostname}\n\n"

    for service, credentials in itertools.groupby(
        credentials_query, key=lambda x: x.service
    ):
        credentials_list = list(credentials)

        result += (
            f"#### {service.protocol}/{service.port} - {service.product} - "
            f"({len(credentials_list)} credentials)\n\n"
        )

        for credential in credentials_list:
            result += f"{credential.username}:'{credential.password}'\n"

        result += "\n"

    for service, exploits in itertools.groupby(services_query, key=lambda x: x.service):
        exploits_list = list(
            filter(lambda x: x.title, map(lambda m: m.exploit, exploits))
        )

        result += (
            f"#### {service.protocol}/{service.port} - {service.product} - "
            f"{service.version} - ({len(exploits_list)} exploits)\n\n"
        )

        for exploit in exploits_list:
            result += f"- {exploit.title}\n"
            result += f"\t- {exploit.get_url()}\n"

        result += "\n"

    return result
