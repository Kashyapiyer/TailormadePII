import os
import re, pandas as pd 
from presidio_analyzer import AnalyzerEngine, PatternRecognizer,Pattern, RecognizerRegistry, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import json 
from typing import Union, List, Dict
defaultoperators = {
            "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
            "PHONE_NUMBER": OperatorConfig("mask", {"chars_to_mask": 4, "masking_char": "*", "from_end": True}),
            "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
            "CREDIT_CARD": OperatorConfig("mask", {"chars_to_mask": 12, "masking_char": "X", "from_end": True}),
            "US_SSN": OperatorConfig("hash", {}),
            "URL": OperatorConfig("replace", {"new_value": "<URL>"}),
            "IN_PAN": OperatorConfig("mask", {"chars_to_mask": 4, "masking_char": "*", "from_end": True})
        }
regulatorypatterns = [
            Pattern(
                name="314b_request",
                regex=r'\b314b\b',
                score=0.0
            ),
            Pattern(
                name="regulatory_tin",
                regex=r'\b(?:institution\s+)?TIN\s+\d{8}\b',
                score=0.0
            ),
            Pattern(
                name="sar_reference",
                regex=r'\bSAR\b',
                score=0.0
            )
        ]
class Tailoredpiiguardrail:
    def __init__(self,regulatorycontexts,regulatorypatterns=regulatorypatterns, defaultoperators=defaultoperators,contxtlkpsize=60):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.regulatory_contexts = regulatorycontexts
        self.regulatory_patterns = regulatorypatterns
        self.default_operators = defaultoperators
        self.language = 'en'
        self.entities = set(defaultoperators.keys())
        self.contxtlkpsize = contxtlkpsize        
        self.regulatory_recognizer = PatternRecognizer(
            supported_entity="REGULATORY_TERM",
            patterns=self.regulatory_patterns
        )
        self.analyzer.registry.add_recognizer(self.regulatory_recognizer)
    def is_regulatory_context(self, text: str, span_text: str, span_start: int) -> bool:
        """Check if detected text is in a regulatory context"""
        context_start = max(0, span_start - self.contxtlkpsize)
        context_end = min(len(text), span_start + len(span_text) + self.contxtlkpsize)
        context = text[context_start:context_end]
        for term, patterns in self.regulatory_contexts.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    return True
        return False
    def filter_regulatory_terms(self, text: str, analyzer_results: list) -> list:
        """Filter out regulatory terms from PII detection results"""
        filtered_results = []
        print(f"Analyzerresult:{analyzer_results}")
        for result in analyzer_results:
            span_text = text[result.start:result.end]
            if self.is_regulatory_context(text, span_text, result.start):
                continue

            filtered_results.append(result)

        return filtered_results
    def detect_pii(self, texts: Union[str, List[str]]) -> Dict[str, list]:
        """Detect PII in texts while considering regulatory contexts"""
        if isinstance(texts, str):
            texts = [texts]
        results = {}
        for text in texts:
            analyzer_results = self.analyzer.analyze(
                text=text,
                language=self.language,
                entities=self.entities
            )
            filtered_results = self.filter_regulatory_terms(text, analyzer_results)
            results[text] = filtered_results

        return results
    def process_context(self, text: str) -> Dict[str, dict]:
        """Process a single text and return detailed results"""
        result = {}
        result['Textobserved'] = text
        analyzerresult = self.detect_pii(text)[text]
        filtered_results = [
            result for result in analyzerresult
            if not self.is_regulatory_context(text, text[result.start:result.end], result.start)
        ]
        if filtered_results:
            anonymized = self.anonymizer.anonymize(
                text=text,
                analyzer_results=filtered_results,
                operators=self.default_operators
            )
            anonymized_text = anonymized.text
        else:
            anonymized_text = text
        result['piidetected'] =  list(map(
                                            lambda r: {
                                                'entity_type': r.entity_type,
                                                'text': text[r.start:r.end],
                                                'score': r.score,
                                                'is_regulatory': self.is_regulatory_context(text, text[r.start:r.end], r.start)
                                            },
                                            analyzerresult
                                        ))
        result['Anonymizedtxt'] =  anonymized_text
        result['status'] =  True  if not any(result['piidetected']) or not any(d['is_regulatory'] for d in result['piidetected'] if isinstance(d, dict) and 'is_regulatory' in d) else False
        return result
