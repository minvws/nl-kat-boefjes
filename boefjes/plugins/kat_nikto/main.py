"""Boefje script for scanning nikto on webservers"""
from typing import Union, Tuple

import docker

from config import settings
from job import BoefjeMeta

NIKTO_IMAGE = "frapsoft/nikto:latest"


def run(boefje_meta: BoefjeMeta) -> Tuple[BoefjeMeta, Union[bytes, str]]:
    client = docker.from_env()
    input_ = boefje_meta.arguments["input"]
    hostname = input_["hostname"]["name"]
    ip_service = input_["ip_service"]
    # since wpscan can give positive exit codes on completion, docker-py's run() can fail on this
    container = client.containers.run(
        NIKTO_IMAGE,
        [
            "-h",
            ip_service["address"]["address"],  # the ip we are testing
            "-port",
            ip_service["port"],  # the port we are testing
            "-vhost",
            hostname,  # the specific hostname
            "-nolookup",  # we already fed the ip and host info
            "-o" "-ask",
            "no",  # dont update
            "-Display",
            "V",  # verbose
            "-C",
            "all",
            "-nointeractive",  # all cgi bin dirs  # dont ask
            "-useragent",
            "Openkat.nl Nikto",  # identify ourselves
            "-o",
            "/output/output.json",
        ],
        detach=True,
        tmpfs={"/output": "size=5M,uid=1000"},
    )

    # wait for container to exit, read its output in the logs and remove container
    container.wait()
    output = container.logs()
    outputfile = container.get_archive("/output/output.json")
    container.remove()

    return boefje_meta, outputfile
