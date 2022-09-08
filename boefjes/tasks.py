import logging
from typing import Dict, List
from uuid import uuid4

import pydantic
import requests
from octopoes.models import Reference
from requests import RequestException

from boefjes.app import app
from boefjes.plugins.models import BOEFJES_DIR, Boefje
from boefjes.config import settings
from boefjes.job import BoefjeMeta, NormalizerMeta
from boefjes.job_handler import (
    handle_boefje_job,
    handle_normalizer_job,
    _find_ooi_in_past,
    get_octopoes_api_connector,
    serialize_ooi,
)
from boefjes.katalogus.boefjes import resolve_boefjes, resolve_normalizers
from boefjes.katalogus.models import PluginType, Normalizer
from boefjes.lxd.lxd_runner import LXDBoefjeJobRunner
from boefjes.runner import LocalBoefjeJobRunner, get_plugin, get_environment_settings

logger = logging.getLogger(__name__)


def get_all_plugins(organisation: str) -> List[PluginType]:
    res = requests.get(
        f"{settings.katalogus_api}/v1/organisations/{organisation}/plugins"
    )

    return pydantic.parse_raw_as(List[PluginType], res.content)


@app.task(queue="boefjes", name="tasks.handle_boefje")
def handle_boefje(job: Dict) -> Dict:
    boefje_meta = BoefjeMeta(**job)

    input_ooi = _find_ooi_in_past(
        Reference.from_str(boefje_meta.input_ooi),
        get_octopoes_api_connector(boefje_meta.organization),
    )
    boefje_meta.arguments["input"] = serialize_ooi(input_ooi)

    if "/" not in boefje_meta.boefje.id:
        boefjes = resolve_boefjes(BOEFJES_DIR)
        boefje_resource = boefjes[boefje_meta.boefje.id]

        logger.info("Running local boefje plugin")

        try:
            environment = get_environment_settings(boefje_meta, boefje_resource)
        except RequestException:
            logger.error("Error getting environment settings", exc_info=True)
            environment = {}

        job_runner = LocalBoefjeJobRunner(boefje_meta, boefje_resource, environment)
        updated_job = handle_boefje_job(boefje_meta, job_runner)

        dispatch_normalizers(boefje_resource, updated_job)

        return updated_job.dict()

    repository, plugin_id = boefje_meta.boefje.id.split("/")
    plugin = get_plugin(
        boefje_meta.organization, repository, plugin_id, boefje_meta.boefje.version
    )

    logger.info("Running remote boefje plugin")
    updated_job = handle_boefje_job(
        boefje_meta, LXDBoefjeJobRunner(boefje_meta, plugin)
    )
    all_plugins = get_all_plugins(boefje_meta.organization)
    normalizer_jobs = normalizers_for_meta(updated_job, all_plugins)

    for normalizer_meta in normalizer_jobs:
        normalizer_meta = {
            "id": str(uuid4()),
            "normalizer": {"name": normalizer_meta.id},
            "boefje_meta": boefje_meta.dict(),
        }
        logger.info("Dispatching normalizer: %s", normalizer_meta["normalizer"])
        handle_normalizer.delay(normalizer_meta)

    return updated_job.dict()


def normalizers_for_meta(
    boefje_meta: BoefjeMeta,
    all_plugins: List[PluginType],
) -> List[Normalizer]:
    def right_boefje_check(plugin: PluginType):
        return plugin.type == "boefje" and plugin.id == boefje_meta.boefje.id

    boefje_for_meta = list(filter(right_boefje_check, all_plugins))
    assert any(boefje_for_meta), "Plugin not found"

    boefje_plugin = boefje_for_meta[0]

    return [
        normalizer
        for normalizer in all_plugins
        if normalizer.type == "normalizer"
        and set(normalizer.consumes) & set(boefje_plugin.produces)
    ]


def dispatch_normalizers(boefje: Boefje, updated_job: BoefjeMeta):
    all_normalizers = resolve_normalizers(BOEFJES_DIR)

    normalizers = {
        normalize_id: normalizer
        for normalize_id, normalizer in all_normalizers.items()
        if boefje.id in normalizer.consumes
    }

    logging.info(f"Dispatching normalizers: {normalizers}")

    for normalizer in normalizers:
        normalizer_meta = {
            "id": str(uuid4()),
            "normalizer": {"name": normalizer},
            "boefje_meta": updated_job.dict(),
        }

        handle_normalizer.delay(normalizer_meta)


@app.task(queue="normalizers", name="tasks.handle_normalizer")
def handle_normalizer(normalizer_job: Dict) -> None:
    data = normalizer_job.copy()
    boefje_meta = BoefjeMeta(**data.pop("boefje_meta"))

    normalizer_meta = NormalizerMeta(boefje_meta=boefje_meta, **data)
    normalizers = resolve_normalizers(BOEFJES_DIR)
    normalizer = normalizers[normalizer_meta.normalizer.name]

    handle_normalizer_job(normalizer_meta, normalizer)
