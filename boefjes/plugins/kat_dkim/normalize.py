import json
#from ipaddress import IPv4Address, IPv6Address
from typing import Iterator, Union, List, Dict

from dns.message import from_text, Message
from dns.rdtypes.ANY.TXT import TXT

from octopoes.models import OOI, Reference
#from octopoes.models.ooi.dns.zone import Hostname, DNSZone
#from octopoes.models.ooi.network import IPAddressV4, IPAddressV6, Network
from octopoes.models.ooi.email_security import DKIMKey
from octopoes.models import OOI, Reference

from boefjes.job_models import NormalizerMeta

def run(normalizer_meta: NormalizerMeta, raw: Union[bytes, str]) -> Iterator[OOI]:
  results = json.loads(raw)

  if "ANSWER" in results['dkim']:
    for rrset in from_text(results['dkim']).answer:
      for rr in rrset:
        rr: Rdata
        if isinstance(rr, TXT):
            yield DKIMKey(
                dkim_selector=Reference.from_str(normalizer_meta.boefje_meta.input_ooi),
                key=str(rr).strip('"')
            )

#normalizer_1           | Normaliser raw:
#normalizer_1           | {'dkim': '\n\nid 59473\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\ndefault._domainkey.cloudaware.eu. IN TXT\n;ANSWER\ndefault._domainkey.cloudaware.eu. 3078 IN TXT "v=DKIM1; k=rsa; " "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApPZ/EB7u2peXptWSekdVD51n6Az9ponwCA+hBNljw6J1eSWvptWQz5vwCPZefq3KV3Pfbviy7049av+0xQuYu1LIqNN42LfkdqduOoYjrLEZfOFhjRfb9F6mcWWYJeWATHOV1wPdOc+0lL2Mn+FeIjM8UhqXYN7FqMLJhgc8p380BgcB/eRjaPeHxdmUmA9Q3PQHHJiJnbUt/m" "jW6Pyqm98CEHK+S8pEFpCdQPKMOk0UKbSJUsCB8Mtv6C8KGKhvD0aKmaGcYWiAjSafeTYSwnlqikn07OgcrO+agU4SdsEAC4Vst3iWfQcMVU0g8NSsjmAMFC6IbdWuNTCbZdLaFQIDAQAB"\n;AUTHORITY\ncloudaware.eu. 3078 IN NS epsys76a.epsys.nl.\ncloudaware.eu. 3078 IN NS epsys74a.epsys.nl.\n;ADDITIONAL'}
#normalizer_1           | Normaliser meta:
#normalizer_1           | id='c2b7317aa7414836a74ca8df9db3ff7c' started_at=datetime.datetime(2022, 11, 25, 15, 20, 4, 97972, tzinfo=datetime.timezone.utc) ended_at=None boefje_meta=BoefjeMeta(id='7f2babf2-bf1a-459b-804e-b5b00e105174', started_at=datetime.datetime(2022, 11, 25, 15, 19, 3, 94740, tzinfo=datetime.timezone.utc), ended_at=datetime.datetime(2022, 11, 25, 15, 19, 3, 167180, tzinfo=datetime.timezone.utc), boefje=Boefje(id='dkim', version=None), input_ooi='DKIMSelector|default|internet|cloudaware.eu', arguments={'input': {'object_type': 'DKIMSelector', 'scan_profile': "reference=Reference('DKIMSelector|default|internet|cloudaware.eu') level=2 scan_profile_type='declared'", 'primary_key': 'DKIMSelector|default|internet|cloudaware.eu', 'selector': 'default', 'hostname': {'network': {'name': 'internet'}, 'name': 'cloudaware.eu'}}}, organization='_dev') normalizer=Normalizer(id='kat_dkim_normalize', version=None)

