
from typing import Iterator, Union
import csv

from octopoes.models import OOI, Reference
from octopoes.models.ooi.findings import CVEFindingType, Finding, NessusFindingType
from octopoes.models.ooi.network import IPPort, Protocol, IPAddressV4, Network
from octopoes.models.ooi.organization import Dochteronderneming

from boefjes.job_models import NormalizerMeta


def run(normalizer_meta: NormalizerMeta, raw: Union[bytes, str]) -> Iterator[OOI]:

    csvIterator = iter(csv.reader(raw.decode().splitlines(), delimiter=','))
    columns = enumerate((next(csvIterator)))
    columnDict = dict((j,i) for i,j in columns) #columndict to keep track which colums is at what index for example: plugin ID:0, CVE: 1, CVSS v2.0 Base Score: 2

    ipRef = Reference.from_str(normalizer_meta.raw_data.boefje_meta.input_ooi)

    dochterOndernemingName = ipRef.tokenized.network.dochter_onderneming.__root__.get("name")
    networkName = ipRef.tokenized.network.__root__.get("name")

    dochterondernemingObject = Dochteronderneming(name=dochterOndernemingName)
    networkObject = Network(name=networkName, dochter_onderneming=dochterondernemingObject.reference)

    yield dochterondernemingObject
    yield networkObject

    for i in csvIterator:
        cve = i[columnDict["CVE"]]
        if cve: #When the column has a cve get that as findingtype to have a more unified standard with other scanners, else make a nessus findingtype
            findingType = CVEFindingType(id=cve)
        else:
            pluginId = i[columnDict["Plugin ID"]]
            findingType = NessusFindingType(id=pluginId)

        ip = i[columnDict["Host"]]

        ipAdr = IPAddressV4(network=networkObject.reference, address=ip)
        yield(ipAdr)

        protocol = i[columnDict["Protocol"]]
        port = i[columnDict["Port"]]

        ip_port = None

        if port != "0":

            ip_port = IPPort(
            address=ipAdr.reference,
            protocol=Protocol(protocol),
            port=int(port),
            )
            yield ip_port


        if ip_port is None: #if the Nessus scanner found a port associated with this vulnerability add as a reference else use the IP-adres as reference
            finding = Finding(finding_type=findingType.reference, ooi=ipAdr.reference)

        else:
            finding = Finding(finding_type=findingType.reference, ooi=ip_port.reference)

        yield findingType
        yield finding