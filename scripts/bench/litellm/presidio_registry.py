"""Start the Presidio analyzer with the Turkish support Presidio itself ships.

Runs inside the presidio-analyzer image. Presidio 2.2.364 ships TrNationalIdRecognizer
and TrLicensePlateRecognizer disabled and declared for language `tr`; LiteLLM asks the
analyzer for `en`. This enables both for `en` and adds TR to the phone recognizer's
regions, the same region shim adds. Everything else is Presidio's default registry.
"""

import os

import yaml
from presidio_analyzer.predefined_recognizers import PhoneRecognizer

DEFAULT = "presidio_analyzer/conf/default_recognizers.yaml"
TUNED = "/tmp/recognizers.yaml"

with open(DEFAULT, encoding="utf-8") as source:
    registry = yaml.safe_load(source)
for recognizer in registry["recognizers"]:
    if recognizer.get("country_code") == "tr":
        recognizer.update(enabled=True, supported_languages=["en"])
    if recognizer.get("name") == "PhoneRecognizer":
        recognizer["supported_regions"] = [
            *PhoneRecognizer.DEFAULT_SUPPORTED_REGIONS,
            "TR",
        ]
with open(TUNED, "w", encoding="utf-8") as target:
    yaml.safe_dump(registry, target)
os.environ["RECOGNIZER_REGISTRY_CONF_FILE"] = TUNED
os.execv("./entrypoint.sh", ["./entrypoint.sh"])
