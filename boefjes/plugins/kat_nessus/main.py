from typing import Tuple, Union

from os import getenv
from time import sleep
import requests

from boefjes.job_models import BoefjeMeta


def run(boefje_meta: BoefjeMeta) -> Tuple[BoefjeMeta, Union[bytes, str]]:

    input_ = boefje_meta.arguments["input"]
    ip = input_["address"]

    apiAcceskey = getenv("NESSUS_ACCESSKEY")
    apiSecretkey = getenv("NESSUS_SECRETKEY")

    headers = {"X-ApiKeys" : f"accessKey={apiAcceskey}; secretKey={apiSecretkey}"}
    endpoint = f"https://{ip}:8834" 

    allScansEndpoint = f"{endpoint}/scans"
    allScansGetRequest = requests.get(allScansEndpoint, verify=False, headers=headers)
    allScans = allScansGetRequest.json()["scans"]

    scanId = max(scan['id'] for scan in allScans) #get the highest id of the scans, the scan with the highest id is the latest scan that was performed

    scanEndpoint = f"{endpoint}/scans/{str(scanId)}/export"

    scanPostBody = {
        "format": "csv",
        "scan_id": scanId
    }

    scanPostRequest = requests.post(scanEndpoint, verify=False, data=scanPostBody, headers=headers)

    fileId = scanPostRequest.json()['file']

    statusEndPoint = f"{endpoint}/scans/{str(scanId)}/export/{fileId}/status"

    loopCount = 0 #loop counter to prevent endless loop
    while True:
        if loopCount > 20:
            raise Exception("Nessus scanner timedout.")
        sleep(0.5) #give nessus time to parse file
        statusGetRequest = requests.get(statusEndPoint, verify=False, headers=headers)
        if statusGetRequest.json()["status"] == "ready":
            break
        loopCount = loopCount + 1

    downloadEndPoint = f"{endpoint}/scans/{str(scanId)}/export/{fileId}/download"
    downloadGetRequest = requests.get(downloadEndPoint, verify=False, headers=headers)

    decodedContent = downloadGetRequest.text
    decodedContent = decodedContent.encode("latin1", "ignore")

    return [(set(), decodedContent)]
