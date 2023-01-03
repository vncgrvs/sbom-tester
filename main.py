from analyser import assess_sbom
import json
import urllib.request


def load_cyclonedx_schema():
    with open("bom-1.4.schema.json", "r") as file:
        data = json.loads(file.read())
    return data


def get_licenses():
    with urllib.request.urlopen("https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json") as url:
        data = json.load(url)

    vaild_license_ids = []

    for license in data['licenses']:
        license_id = license['licenseId']
        vaild_license_ids.append(license_id)

    return vaild_license_ids


if __name__ == "__main__":
    with open("cyd-bom.json", "r") as file:
        sbom = json.loads(file.read())

    license_list = get_licenses()
    cyclonedx_schema = load_cyclonedx_schema()
    result = assess_sbom(sbom, license_list, cyclonedx_schema)

