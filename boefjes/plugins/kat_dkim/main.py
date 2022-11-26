"""Boefje script for getting dkim record"""
import json
import logging
from typing import Union, Tuple

import dns.resolver
from dns.name import Name
from dns.resolver import Answer

from boefjes.job_models import BoefjeMeta

logger = logging.getLogger(__name__)


class ZoneNotFoundException(Exception):
    pass

def run(boefje_meta: BoefjeMeta) -> Tuple[BoefjeMeta, Union[bytes, str]]:

    input_ = boefje_meta.arguments["input"]

    hostname = input_["hostname"]["name"] 
    selector = input_["selector"]

    try:
        answer: Answer = dns.resolver.resolve(f"{selector}._domainkey.{hostname}", 'TXT')
    except dns.resolver.NoAnswer:
        return boefje_meta, "NoAnswer"
    except dns.resolver.NXDOMAIN:
        return boefje_meta, "NXDOMAIN"
    except dns.resolver.Timeout:
        pass
    
    results = {
      "dkim": answer.response.to_text()
    }

    return boefje_meta, json.dumps(results)
