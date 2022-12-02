from boefjes.models import Boefje, Normalizer, SCAN_LEVEL

Nikto = Boefje(
    id="nikto",
    name="nikto",
    consumes={"Website"},
    produces={"Software", "HTTPHeader", "HostnameHTTPURL", "Finding"},
    scan_level=SCAN_LEVEL.L3,
)

BOEFJES = [Nikto]
NORMALIZERS = [
    Normalizer(
        name="kat_nikto_normalize",
        module="kat_nikto.normalize",
        consumes=[Nikto.id],
        produces=Nikto.produces,
    )
]
