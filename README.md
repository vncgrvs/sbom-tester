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

### Contact
Feel free to contact me for any queries under vincent.groves@leanix.net .