# remediation/__init__.py
from .recommender import generate_remediation_plan
from .ai_assistant import explain_finding_with_ai, generate_local_explanation

__all__ = [
    "generate_remediation_plan",
    "explain_finding_with_ai",
    "generate_local_explanation"
]
