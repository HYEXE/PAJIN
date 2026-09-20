"""Opt-in, operator-approved local browser assessments (WEB-003/WEB-004)."""

from pajin.web_assessment.models import (
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentResult,
    WebAssessmentPlan,
)
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import (
    LocalWebAssessmentArtifacts,
    ProvisionedLocalWebAssessmentAccount,
    issue_local_web_assessment_authorization,
    provision_local_web_assessment_account,
    run_local_web_assessment,
)

__all__ = [
    "LocalWebAssessmentArtifacts",
    "LocalWebAssessmentAuthorization",
    "LocalWebAssessmentResult",
    "ProvisionedLocalWebAssessmentAccount",
    "WebAssessmentPlan",
    "issue_local_web_assessment_authorization",
    "juice_shop_plan",
    "provision_local_web_assessment_account",
    "run_local_web_assessment",
]
