from analyser import assess_sboms
import json
import os
import urllib.request
from pathlib import Path
import argparse



def load_cyclonedx_schema():
    with open("bom-1.4.schema.json", "r") as file:
        data = json.loads(file.read())
    return data

def get_sboms(path):
    target_dir = Path(path)

    sboms_files = list()


    if os.path.isfile(target_dir):
        file_name = os.path.splitext(target_dir)
        file_extension = file_name[1]
        if file_extension == ".json":
            sboms_files.append(f"{target_dir}")
    else:
        if not target_dir.exists():
            print("The target directory doesn't exist")
            raise SystemExit(1)

        for file in target_dir.iterdir():
            file_name = os.path.splitext(file)
            file_extension = file_name[1]
            if file_extension == ".json":
                sboms_files.append(f"{file}")
    
    return sboms_files

def get_licenses():
    with urllib.request.urlopen("https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json") as url:
        data = json.load(url)

    vaild_license_ids = []

    for license in data['licenses']:
        license_id = license['licenseId']
        vaild_license_ids.append(license_id)

    return vaild_license_ids

def get_sboms(path):
    target_dir = Path(path)

    sboms_files = list()


    if os.path.isfile(target_dir):
        file_name = os.path.splitext(target_dir)
        file_extension = file_name[1]
        if file_extension == ".json":
            sboms_files.append(f"{target_dir}")
    else:
        if not target_dir.exists():
            print("The target directory doesn't exist")
            raise SystemExit(1)

        for file in target_dir.iterdir():
            file_name = os.path.splitext(file)
            file_extension = file_name[1]
            if file_extension == ".json":
                sboms_files.append(f"{file}")
    
    return sboms_files



if __name__ == "__main__":
    cli = argparse.ArgumentParser(prog='SBOM Tester',
                              description='Tests an SBOM for different quality measurements')

    cli.add_argument("path")
    cli.add_argument("--report", help="generate output report",
                    action="store_true")

    args = cli.parse_args()
    license_list = get_licenses()
    cyclonedx_schema = load_cyclonedx_schema()

    sboms=get_sboms(args.path)
    assess_sboms(sboms,license_list,cyclonedx_schema, args.report)


    
