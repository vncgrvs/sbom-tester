## Bom-Tester

This a simple script that takes a [CycloneDX SBOM](https://cyclonedx.org/) in JSON format and analyses it against certain quality factors. Namely,
1. Correctness and presence of [PURLs](https://github.com/package-url/purl-spec).
2. Correctness and presence of licenses per purl. Note: it correlates against [SPDX-license ids](https://github.com/spdx/license-list-data).
3. Whether the SBOM entails the dependency tree
4. The presence of a operating system
5. Whether the SBOM contains information on the tool that was used to create it


### Usage

1. Install required libraries
```python
pip install -r requirements.txt
```

Note: create a virtual env first
```bash

python -m env venv

source env/bin/activate

```

2. load a JSON CycloneDX file in `main.py`

```python
with open("<your-sbom.json>", "r") as file:
        sbom = json.loads(file.read())

```


3. Run `main.py`
```bash
python main.py
```

4. Example output
```python
Results 

Found 301 purls.
301 / 301 (100.0%) purls are valid.
293 / 301 (97.0%) contain SPDX-compliant license ids.
SBOM is schema compliant.
SBOM does not contain OS information.
The SBOM generation tool was found: [{'vendor': 'CycloneDX', 'name': 'cyclonedx-gradle-plugin', 'version': '1.7.3'}].
The SBOM contains a dependency tree.
The overall SBOM quality score is: 0.895/1.

```

Note the `./test` folder contains CycloneDX SBOMs created for the [vsm-webshop project](https://github.com/leanix-public/vsm-webshop-demo) with the [CycloneDX python plugin](https://github.com/CycloneDX/cyclonedx-python), [Syft](https://github.com/anchore/syft) and [Trivy](https://github.com/aquasecurity/trivy). Feel free to play with those.

### Contact
Feel free to contact me for any queries under vincent.groves@leanix.net .