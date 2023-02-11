from packageurl import PackageURL
import json
from jsonschema import validate
from jsonschema import ValidationError
from tqdm import tqdm


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

    if "components" in sbom:
        has_purls = True

        for obj in sbom['components']:

            if obj['type'] == "library":
                try:
                    purl = obj['purl']
                    stripped_purl = strip_purl(purl)
                    valid_purls.append(stripped_purl)
                except Exception as e:
                    invalid_purls.append(purl)

        total_purls = len(valid_purls) + len(invalid_purls)
    else:
        total_purls = 0
        valid_purls = None
        invalid_purls = None
        has_purls = False

    return valid_purls, invalid_purls, total_purls, has_purls


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

    number_purls = len(sbom['components'])
    counter_no_lic = 0

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
                has_licenses = True

                purls.append(res)

            else:
                # if no licenses are available
                res = {}
                res['purl'] = lib['purl']
                res['invalid_licenses'] = []
                res['valid_licenses'] = []
                res['has_licenses'] = False
                counter_no_lic += 1
                purls.append(res)

    if counter_no_lic == number_purls:
        has_licenses = False
    return purls, has_licenses


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


def print_results(report):

    if report['has_purls']:
        print("Results \n")
        print(f"Found {report['purls']} purls.")
        print(f"{report['percentage_valid_purl'] * 100}% purls are valid.")

        print(
            f"{report['licenses']['percentage_valid_license_id'] * 100}% contain SPDX-compliant license ids.")

        if report['is_schema_compliant']:
            print("SBOM is schema compliant.")
        else:
            print("SBOM is not CycloneDX schema (v1.4) compliant.")

        if report['operating_system']['has_os']:
            print(
                f"SBOM contains OS information: {report['operating_system']['os_found']}")
        else:
            print("SBOM does not contain OS information.")

        if report['sbom_tool']['has_tool']:
            print(
                f"SBOM generation tool are present: {report['sbom_tool']['tools']}")
        else:
            print("No SBOM generation tool was found.")

        if report['has_dependency_tree']:
            print("The SBOM contains a dependency tree.")
        else:
            print("The SBOM does not contain a dependency tree.")

        print(
            f"The overall SBOM quality score is: {report['quality_score']}/1.")

    else:
        print("Results \n")
        print("SBOM has no purls.")


def assess_sbom(sbom, license_list, schema, verbose):
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
    valid_purls, invalid_purls, total_purls, has_purls = validate_purls(sbom)
    if has_purls:
        temp_license, has_licenses = validate_licenses(sbom, license_list)
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
    else:
        has_os = False
        has_tool = False
        score = None
        perc_valid_purl = 0
        has_licenses = False
        has_dep_tree = False

    if has_os:
        os_found = list()
        for os in operating_systems_found:
            if "name" in os:
                os_name = os['name']
            else:
                os_name = None

            if "version" in os:
                os_version = os['version']
            else:
                os_version = None

            temp_os = {
                "os_name": os_name,
                "os_version": os_version
            }
            os_found.append(temp_os)
    else:
        os_found = None

    if has_tool:
        tools_found = list()
        for tool in tools_found:
            if "vendor" in tool:
                tool_vendor = tool['vendor']
            else:
                tool_vendor = None

            if 'name' in tool:
                tool_name = tool['name']
            else:
                tool_name = None

            if 'version' in tool:
                tool_version = tool['version']
            else:
                tool_version = None

            temp_tools = {
                "tool_vendor": tool_vendor,
                "tool_name": tool_name,
                "tool_version": tool_version
            }
            tools_found.append(temp_tools)
    else:
        tools_found = None

    if has_purls:
        report = {
            "purls": total_purls,
            "has_purls": has_purls,
            "percentage_valid_purl": round(perc_valid_purl, 2),
            "licenses": {
                "has_license": has_licenses,
                "valid_licenses": license_check['no_valid_license_w_license'],
                "percentage_valid_license_id": round(perc_has_valid_license, 2)

            },
            "is_schema_compliant": is_sbom_valid,
            "operating_system": {
                "has_os": has_os,
                "os_found": os_found
            },
            "sbom_tool": {
                "has_tool": has_tool,
                "tools": tools_found
            },
            "has_dependency_tree": has_dep_tree,
            "quality_score": score
        }
    elif has_purls and has_licenses:
        report = {
            "purls": total_purls,
            "has_purls": has_purls,
            "percentage_valid_purl": round(perc_valid_purl, 2),
            "licenses": {
                "has_license": has_licenses,
                "valid_licenses": license_check['no_valid_license_w_license'],
                "percentage_valid_license_id": round(perc_has_valid_license, 2)

            },
            "is_schema_compliant": is_sbom_valid,
            "operating_system": {
                "has_os": has_os,
                "os_found": os_found
            },
            "sbom_tool": {
                "has_tool": has_tool,
                "tools": tools_found
            },
            "has_dependency_tree": has_dep_tree,
            "quality_score": score
        }
    else:
        report = {
            "purls": total_purls,
            "has_purls": has_purls,
            "percentage_valid_purl": 0.0,
            "licenses": {
                "has_license": has_licenses,
                "valid_licenses": None,
                "percentage_valid_license_id": None

            },
            "is_schema_compliant": is_sbom_valid,
            "operating_system": {
                "has_os": has_os,
                "os_found": None
            },
            "sbom_tool": {
                "has_tool": has_tool,
                "tools": None
            },
            "has_dependency_tree": has_dep_tree,
            "quality_score": None
        }

    if verbose:
        print_results(report)

    return report


def assess_sboms(sboms, license_list, schema, generate_report, verbose=False):

    reports = list()

    for sbom_path in (pbar := tqdm(sboms)):
        pbar.set_description(f"Processing {sbom_path}")

        with open(sbom_path, "r") as file:
            sbom = json.loads(file.read())
        if verbose:
            print(f"Analysing {sbom_path}")

        report_raw = assess_sbom(sbom, license_list, schema, verbose)
        new_report = dict()
        new_report['filename'] = sbom_path
        new_report.update(report_raw)

        reports.append(new_report)

    if generate_report:
        
        with open("report.json", "w") as out:
            out.write(json.dumps(reports, indent=2))
        
        tqdm.write(f"generated report at report.json.")
