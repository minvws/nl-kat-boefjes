import json
from typing import Union, Iterator
from octopoes.models import OOI, Reference
from octopoes.models.ooi.web import HTTPHeader

from boefjes.job_models import NormalizerMeta
from octopoes.models.ooi.findings import KATFindingType, Finding

from io import BytesIO

from PIL import Image, DecompressionBombWarning, UnidentifiedImageError
from PIL.ExifTags import TAGS


def run(normalizer_meta: NormalizerMeta, raw: Union[bytes, str]) -> Iterator[OOI]:

    # fetch a reference to the original resource where these headers where downloaded from
    resource = Reference.from_str(normalizer_meta.raw_data.boefje_meta.input_ooi)
    image = Image.open(BytesIO(raw))
    image.MAX_IMAGE_PIXELS = 7680 * 4320
    # 8K pixels for now

    try:
        image_info = {
            "size": image.size,
            "height": image.height,
            "width": image.width,
            "format": image.format,
            "mode": image.mode,
            "is_animated": getattr(image, "is_animated", False),
            "frames": getattr(image, "n_frames", 1),
        }
        exifdata = image.getexif()
        for tag_id in exifdata:
            # humna readbable tag name
            tag = TAGS.get(tag_id, tag_id)
            tagdata = exifdata.get(tag_id)
            if isinstance(tagdata, bytes):
                tagdata = tagdata.decode()
            image_info[tag] = tagdata
    except UnidentifiedImageError:
        kat_number = "BrokenImage"
        kat_ooi = KATFindingType(id=kat_number)
        yield Finding(
            finding_type=kat_ooi.reference,
            ooi=resource,
            description="Image is not recognized, possibly served with broken mime-type.",
        )

    except DecompressionBombWarning:
        kat_number = "DecompressionBomb"
        kat_ooi = KATFindingType(id=kat_number)
        yield Finding(
            finding_type=kat_ooi.reference,
            ooi=resource,
            description="Image ended up bigger than %d Pixels, possible decompression Bomb" % image.MAX_IMAGE_PIXELS,
        )
    else:
        yield ImageMetadata(resource=resource, **image_info)
