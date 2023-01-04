from packageurl import PackageURL
import os
import json
from jsonschema import validate
from jsonschema import ValidationError


def strip_purl(purl):
    purl_encoded = PackageURL.from_string(purl)

    purl_dict = purl_encoded.to_dict()

    if not purl_dict['namespace']:
        temp = 'pkg:'+purl_dict['type']+'/' + \
            purl_dict['name']+'@'+purl_dict['version']
    else:
        temp = 'pkg:'+purl_dict['type']+'/'+purl_dict['namespace'] + \
            '/'+purl_dict['name']+'@'+purl_dict['version']

    return temp


def validate_purls(sbom):

    valid_purls = []
    invalid_purls = []

    for obj in sbom['components']:

        if obj['type'] == "library":
            try:
                purl = obj['purl']
                stripped_purl = strip_purl(purl)
                valid_purls.append(stripped_purl)
            except Exception as e:
                invalid_purls.append(purl)

    total_purls = len(valid_purls) + len(invalid_purls)

    return valid_purls, invalid_purls, total_purls


def grade_sbom(has_dependency_tree, valid_bom, has_os, perc_valid_purls, perc_has_valid_license):
    weights = {
        "has_dependency_tree": 0.2,
        "valid_bom": 0.1,
        "has_operating_system": 0.1,
        "valid_licenses": 0.1,
        "valid_purls": 0.5

    }

    if has_dependency_tree:
        score_dep_tree = 1
    else:
        score_dep_tree = 0

    if valid_bom:
        score_valid_bom = 1
    else:
        score_valid_bom = 0

    if has_os:
        score_operating_systems = 1
    else:
        score_operating_systems = 0

    if (perc_valid_purls >= 0) and (perc_valid_purls <= 0.80):
        score_purls = 0.2
    elif (perc_valid_purls >= 0.81) and (perc_valid_purls <= 0.90):
        score_purls = 0.9
    elif (perc_valid_purls >= 0.91) and (perc_valid_purls <= 0.99):
        score_purls = 0.95
    else:
        score_purls = 1

    if (perc_has_valid_license >= 0) and (perc_has_valid_license <= 0.50):
        score_licenses = 0.5
    elif (perc_has_valid_license >= 0.51) and (perc_has_valid_license <= 0.75):
        score_licenses = 0.8
    elif (perc_has_valid_license >= 0.76) and (perc_has_valid_license <= 0.90):
        score_licenses = 0.9
    elif (perc_has_valid_license >= 0.91) and (perc_has_valid_license <= 0.99):
        score_licenses = 0.95
    else:
        score_licenses = 1

    score = (score_dep_tree * weights['has_dependency_tree']) + (score_valid_bom * weights['valid_bom']) + (
        score_operating_systems * weights['has_operating_system']) + (score_licenses * weights['valid_licenses']) + (score_purls * weights['valid_purls'])

    return round(score, 3)


def has_extraction_tool(sbom):
    has_tool = False

    tools = []

    if "metadata" in sbom:
        if "tools" in sbom['metadata']:
            if sbom['metadata']['tools']:
                has_tool = True
                for tool in sbom['metadata']['tools']:
                    tools.append(tool)

    return has_tool, tools


def has_operating_systems(sbom):
    has_operating_systems = False
    operating_systems_found = []

    for component in sbom['components']:
        if component['type'] == "operating-system":
            has_operating_systems = True
            operating_systems_found.append(component)

    return has_operating_systems, operating_systems_found


def validate_sbom(sbom, schema):
    try:
        validate(instance=sbom, schema=schema)
    except ValidationError as err:
        return False
    return True


def has_dependency_tree(sbom):

    has_dep_tree = False

    if "dependencies" in sbom:
        has_dep_tree = True

    return has_dep_tree


def validate_licenses(sbom, license_list):

    results = {}

    purls = []

    for lib in sbom['components']:

        if lib["type"] == "library":
            res = {}
            res['purl'] = lib['purl']

            if "licenses" in lib:
                valid_license_ids = []
                invalid_license_ids = []

                for license in lib['licenses']:

                    # if licenses are stored in expression
                    if "expression" in license:
                        license_id = license['expression']

                        # check if license is valid
                        if license_id in license_list:
                            valid_license_ids.append(license_id)
                        else:
                            invalid_license_ids.append(license_id)

                    elif "license" in license:

                        license_data = license['license']
                        

                        if "id" in license_data:
                            license_id = license_data['id']
                            

                            if license_id in license_list:
                                valid_license_ids.append(license_id)
                            else:
                                invalid_license_ids.append(license_id)
                        else:
                            invalid_license_ids.append(license_data['name'])

                res['invalid_licenses'] = invalid_license_ids
                res['valid_licenses'] = valid_license_ids
                res['has_licenses'] = True

                purls.append(res)

            else:
                # if no licenses are available
                res = {}
                res['purl'] = lib['purl']
                res['invalid_licenses'] = []
                res['valid_licenses'] = []
                res['has_licenses'] = False
                purls.append(res)

    return purls


def summarize_license_analysis(analysis):
    number_of_purls = len(analysis)
    number_of_purls_wo_license = 0
    number_of_purls_w_license = 0

    # for libs with licenses
    number_of_valid_licenses = 0
    number_of_invalid_licenses = 0

    purls_with_licenses = []

    for lib in analysis:
        # analyse whether lib has any licenses at all
        if not lib['has_licenses']:
            number_of_purls_wo_license += 1

        else:
            number_of_purls_w_license += 1
            purls_with_licenses.append(lib)

    for lib in purls_with_licenses:

        if len(lib['valid_licenses']) >= 1:
            number_of_valid_licenses += 1

        if len(lib['invalid_licenses']) >= 1:
            number_of_invalid_licenses += 1

    output = {
        "no_of_purls": number_of_purls,
        "no_purls_w_license": number_of_purls_w_license,
        "no_purls_wo_license": number_of_purls_wo_license,
        "no_valid_license_w_license": number_of_valid_licenses
    }

    return output


def assess_sbom(sbom, license_list, schema):
    """
        checks
        1. valid CycloneDX 1.4 schema
        2. valid purls
        3. valid licenses (if present)
        4. number of purls 
        4.1 number of invalid purls (i.e. invalid / total)
        5. presence of dependency tree (i.e dependencies object present and != null / None)
        6. declared tool used for extraction (i.e. metadata > tools > {})
        7. captures operating system
        8. presence of licenses
     """

    is_sbom_valid = validate_sbom(sbom, schema)
    valid_purls, invalid_purls, total_purls = validate_purls(sbom)
    temp_license = validate_licenses(sbom, license_list)
    license_check = summarize_license_analysis(temp_license)
    has_dep_tree = has_dependency_tree(sbom)
    has_os, operating_systems_found = has_operating_systems(sbom)
    has_tool, tools = has_extraction_tool(sbom)

    perc_valid_purl = round(len(valid_purls)/total_purls, 2)
    perc_has_license = round(
        license_check['no_purls_w_license']/total_purls, 2)
    perc_has_valid_license = round(
        license_check['no_valid_license_w_license']/total_purls, 2)

    score = grade_sbom(has_dep_tree, is_sbom_valid, has_os,
                       perc_valid_purl, perc_has_valid_license)

    

    print("Results \n")
    print(f"Found {total_purls} purls.")
    print(f"{len(valid_purls)} / {total_purls} ({perc_valid_purl * 100}%) purls are valid.")

    if license_check['no_purls_w_license'] != 0:
        print(
            f"{license_check['no_valid_license_w_license']} / {total_purls} ({perc_has_valid_license * 100}%) contain SPDX-compliant license ids.")
    else:
        print(f"0/{total_purls} have license information.")

    if is_sbom_valid:
        print("SBOM is schema compliant.")
    else:
        print("SBOM is not CycloneDX schema (v1.4) compliant.")

    if has_os:
        print(f"SBOM contains OS information - {operating_systems_found}.")
    else:
        print("SBOM does not contain OS information.")

    if has_tool:
        print(f"The SBOM generation tool was found: {tools}.")
    else:
        print("No SBOM generation tool was found.")

    if has_dep_tree:
        print("The SBOM contains a dependency tree.")
    else:
        print("The SBOM does not contain a dependency tree.")
    
    print(f"The overall SBOM quality score is: {score}/1.")

    return score
