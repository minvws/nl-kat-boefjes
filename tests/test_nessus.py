from unittest import TestCase

from octopoes.models.types import (
    CVEFindingType,
    Finding
)
from octopoes.models.ooi.findings import NessusFindingType, CVEFindingType
from octopoes.models.ooi.network import IPPort, Protocol, IPAddressV4, Network
from octopoes.models.ooi.organization import Dochteronderneming

from boefjes.plugins.kat_nessus.normalize import run
from boefjes.job_models import NormalizerMeta
from tests.stubs import get_dummy_data


class NessusTest(TestCase):
    maxDiff = None

    def test_nessus_findings(self):
        meta = NormalizerMeta.parse_raw(get_dummy_data("nessus-normalizer.json"))

        oois = list(
            run(
                meta,
                get_dummy_data("inputs/nessusExample.csv"),
            )
        )

        network = Network(name="network-NS")

        ipAdr = IPAddressV4(network=network.reference, address="10.0.2.7")

        input = [ipAdr, network]

        portDNS = IPPort(address=ipAdr.reference,protocol=Protocol("udp"),port=53)
        portFTP = IPPort(address=ipAdr.reference,protocol=Protocol("tcp"),port=21)
        portHTTP = IPPort(address=ipAdr.reference,protocol=Protocol("tcp"),port=80)
        portREXECD = IPPort(address=ipAdr.reference,protocol=Protocol("tcp"),port=512)
        portRLOGIN = IPPort(address=ipAdr.reference,protocol=Protocol("tcp"),port=513)
        portSSH = IPPort(address=ipAdr.reference,protocol=Protocol("tcp"),port=22)

        ports = [portSSH, portDNS, portREXECD, portRLOGIN, portHTTP, portFTP]


        findingDNS = NessusFindingType(id="10028")
        findingFTP = NessusFindingType(id="10092")
        findingHTTP = NessusFindingType(id="10107")
        findingICMP = CVEFindingType(id="CVE-1999-0524")
        findingREXECD = CVEFindingType(id="CVE-1999-0618")
        findingRLOGIN = CVEFindingType(id="CVE-1999-0651")
        findingSSH = NessusFindingType(id="10267")

        findings = [findingDNS, findingFTP, findingHTTP, findingICMP, findingREXECD, findingRLOGIN, findingSSH]

        findings.append(Finding(finding_type=findingDNS.reference, ooi=portDNS.reference))
        findings.append(Finding(finding_type=findingFTP.reference, ooi=portFTP.reference))
        findings.append(Finding(finding_type=findingHTTP.reference, ooi=portHTTP.reference))
        findings.append(Finding(finding_type=findingREXECD.reference, ooi=portREXECD.reference))
        findings.append(Finding(finding_type=findingRLOGIN.reference, ooi=portRLOGIN.reference))
        findings.append(Finding(finding_type=findingSSH.reference, ooi=portSSH.reference))
        findings.append(Finding(finding_type=findingICMP.reference, ooi=ipAdr.reference))

        expected = findings + ports + input

        oois = [*set(oois)]

        self.assertCountEqual(expected, oois)
