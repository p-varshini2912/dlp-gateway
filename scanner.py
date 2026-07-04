# scanner.py
# Presidio wrapper - detects + redacts PII from raw text.
# Keeping analyzer/anonymizer setup in one place so main.py doesn't
# need to know anything about Presidio internals.

from typing import List, Dict, Any

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


class ScanError(Exception):
    # generic wrapper so main.py only has to catch one exception type
    pass


class DLPScanner:

    ENTITIES = [
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "CREDIT_CARD",
        "ENTERPRISE_ASSET_ID",
    ]

    def __init__(self):
        try:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            })
            nlp_engine = provider.create_engine()

            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
            self.anonymizer = AnonymizerEngine()
        except Exception as e:
            raise ScanError(f"couldn't start presidio engines: {e}")

        self._add_asset_id_recognizer()

    def _add_asset_id_recognizer(self):
        # custom entity - fictional internal asset/key IDs
        # format looks like: CORP-ID-12345 / SECURE-KEY-99999
        # 2-10 uppercase letters, then ID or KEY, then exactly 5 digits
        pattern = Pattern(
            name="asset_id_pattern",
            regex=r"\b[A-Z]{2,10}-(?:ID|KEY)-\d{5}\b",
            score=0.9,
        )

        recognizer = PatternRecognizer(
            supported_entity="ENTERPRISE_ASSET_ID",
            patterns=[pattern],
            context=["asset", "corp", "secure", "key", "id"],
        )

        try:
            self.analyzer.registry.add_recognizer(recognizer)
        except Exception as e:
            raise ScanError(f"failed registering custom recognizer: {e}")

    def analyze(self, text: str) -> List[Any]:
        if not text:
            return []

        try:
            return self.analyzer.analyze(text=text, entities=self.ENTITIES, language="en")
        except Exception as e:
            raise ScanError(f"analysis blew up: {e}")

    def redact(self, text: str, results: List[Any]) -> str:
        if not results:
            return text

        ops = {
            "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
            "ENTERPRISE_ASSET_ID": OperatorConfig("replace", {"new_value": "[REDACTED-ASSET-ID]"}),
        }

        try:
            out = self.anonymizer.anonymize(text=text, analyzer_results=results, operators=ops)
            return out.text
        except Exception as e:
            raise ScanError(f"anonymize step failed: {e}")

    def scan(self, text: str) -> Dict[str, Any]:
        results = self.analyze(text)
        redacted = self.redact(text, results)
        types_found = sorted(set(r.entity_type for r in results))

        return {
            "redacted_text": redacted,
            "hits": len(results),
            "entity_types": types_found,
        }


# load once - Presidio's model load is heavy, don't want it per-request
scanner = DLPScanner()
