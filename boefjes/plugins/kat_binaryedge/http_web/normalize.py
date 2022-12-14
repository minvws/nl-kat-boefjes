import ipaddress
import json
from typing import Iterator, Union

from octopoes.models import OOI, Reference
from octopoes.models.ooi.network import (
    IPPort,
    Protocol,
    PortState,
    IPAddressV4,
    IPAddressV6,
    Network,
)
from octopoes.models.ooi.software import Software, SoftwareInstance

from boefjes.plugins.kat_binaryedge.services.normalize import get_name_from_cpe
from boefjes.job_models import NormalizerMeta


def run(normalizer_meta: NormalizerMeta, raw: Union[bytes, str]) -> Iterator[OOI]:
    results = json.loads(raw)
    boefje_meta = normalizer_meta.raw_data.boefje_meta
    input_ = boefje_meta.arguments["input"]
    pk_ooi = Reference.from_str(boefje_meta.input_ooi)
    network = Network(name="internet").reference

    # Structure based on https://docs.binaryedge.io/modules/<accepted_modules_name>/
    accepted_modules = (
        "webv2",
        " web-enrich",
    )  # http/https: deprecated, so not implemented.
    for scan in results["results"]:
        module = scan["origin"]["type"]
        if module not in accepted_modules:
            continue

        port_nr = int(scan["target"]["port"])
        protocol = scan["target"]["protocol"]
        ip = scan["target"]["ip"]

        if input_["object_type"] in ["IPAddressV4", "IPAddressV6"]:
            ip_ref = pk_ooi
        else:
            ipvx = ipaddress.ip_address(ip)
            if ipvx.version == 4:
                ip_ooi = IPAddressV4(
                    address=ip,
                    network=network,
                )
            else:
                ip_ooi = IPAddressV6(
                    address=ip,
                    network=network,
                )
            yield ip_ooi
            ip_ref = ip_ooi.reference

        ip_port_ooi = IPPort(
            address=ip_ref,
            protocol=Protocol(protocol),
            port=port_nr,
            state=PortState("open"),
        )
        yield ip_port_ooi

        if module == "webv2":
            response = scan.get("result", {}).get("data", {}).get("response", {})
            # (potential) TODO:
            # - url [string]
            # - protocol_version [int]
            # - redirects [list]
            # - headers.headers [object]
            # - plugin (name+version) of {wordpress,joomla}

            for app in response.get("apps", {}):
                if "cpe" in app:
                    software_ooi = Software(name=get_name_from_cpe(app["cpe"]), cpe=app["cpe"])
                    yield software_ooi
                    yield SoftwareInstance(
                        ooi=ip_port_ooi.reference, software=software_ooi.reference
                    )
                else:
                    software_name = app["name"]
                    if "version" in app:
                        software_ooi = Software(
                            name=software_name, version=app["version"]
                        )
                        yield software_ooi
                        yield SoftwareInstance(
                            ooi=ip_port_ooi.reference,
                            software=software_ooi.reference,
                        )
                    else:
                        software_ooi = Software(name=software_name)
                        yield software_ooi
                        yield SoftwareInstance(
                            ooi=ip_port_ooi.reference,
                            software=software_ooi.reference,
                        )
        elif module == "web-enrich":
            # (potential) TODO:
            # - http_version [string]
            # - headers [object]
            # - redirects [list]
            # - url [string]

            data = scan.get("result", {}).get("data", {})
            for potential_software in data:
                # Check all values for 'cpe'
                if isinstance(potential_software, dict) and "cpe" in potential_software:
                    software_ooi = Software(
                        name=get_name_from_cpe(potential_software["cpe"]), cpe=potential_software["cpe"]
                    )
                    yield software_ooi
                    yield SoftwareInstance(
                        ooi=ip_port_ooi.reference, software=software_ooi.reference
                    )

            key_software = {
                "secrets": "AWS Secrets",
                "f5_bigip_loadbalancer": "F5 BigIP Loadblancer",
                "f5_bigip": "F5 BigIP",
                "citrix_netscaler": "Citrix NetScaler",
            }
            for ks_key, ks_software in key_software.items():
                if ks_key in data:
                    software_ooi = Software(name=ks_software)
                    yield software_ooi
                    yield SoftwareInstance(
                        ooi=ip_port_ooi.reference, software=software_ooi.reference
                    )
