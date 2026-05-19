# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_update_confidence
short_description: Query Cisco Hypershield deployment confidence scores
description:
  - Retrieve confidence scores for pending or in-progress updates.
  - Provides detailed scoring breakdown, compatibility analysis, and risk assessment.
  - This is an info module and makes no changes.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  campaign_id:
    description:
      - Campaign ID to query confidence scores for.
      - Mutually exclusive with I(update_version).
    type: str
  update_version:
    description:
      - Specific update version to assess confidence for.
      - Mutually exclusive with I(campaign_id).
    type: str
  scope:
    description:
      - Scope to evaluate confidence against.
    type: str
    choices: [all, zone, group]
    default: all
  scope_filter:
    description:
      - Filter expression when I(scope) is C(zone) or C(group).
    type: str
  include_breakdown:
    description:
      - Include detailed per-factor scoring breakdown.
    type: bool
    default: true
  include_compatibility:
    description:
      - Include compatibility analysis for each enforcement point.
    type: bool
    default: false
  include_risk:
    description:
      - Include risk assessment details.
    type: bool
    default: true
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Get confidence score for a campaign
  stevefulme1.cisco_hypershield.hypershield_update_confidence:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    campaign_id: "camp-abc123"
    include_breakdown: true
    include_risk: true
  register: confidence

- name: Assess confidence for a specific version
  stevefulme1.cisco_hypershield.hypershield_update_confidence:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    update_version: "2.4.1"
    include_compatibility: true
  register: version_confidence

- name: Check confidence for a specific zone
  stevefulme1.cisco_hypershield.hypershield_update_confidence:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    campaign_id: "camp-abc123"
    scope: zone
    scope_filter: "zone=production"
  register: zone_confidence
"""

RETURN = r"""
confidence:
  description: Overall confidence assessment.
  returned: always
  type: dict
  contains:
    overall_score:
      description: Aggregate confidence score (0-100).
      type: int
    recommendation:
      description: Promotion recommendation (promote, wait, block).
      type: str
    assessment_time:
      description: Timestamp of the assessment.
      type: str
breakdown:
  description: Per-factor scoring breakdown.
  returned: when I(include_breakdown) is true
  type: list
  elements: dict
  contains:
    factor:
      description: Scoring factor name.
      type: str
    score:
      description: Individual factor score (0-100).
      type: int
    weight:
      description: Weight of this factor in overall score.
      type: float
    details:
      description: Explanation of the score.
      type: str
compatibility:
  description: Per-enforcement-point compatibility analysis.
  returned: when I(include_compatibility) is true
  type: list
  elements: dict
  contains:
    enforcement_point:
      description: Enforcement point identifier.
      type: str
    compatible:
      description: Whether the update is compatible.
      type: bool
    issues:
      description: List of compatibility issues found.
      type: list
      elements: str
risk_assessment:
  description: Risk assessment details.
  returned: when I(include_risk) is true
  type: dict
  contains:
    risk_level:
      description: Overall risk level (low, medium, high, critical).
      type: str
    risk_factors:
      description: List of identified risk factors.
      type: list
      elements: dict
    mitigation_steps:
      description: Recommended mitigation steps.
      type: list
      elements: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        campaign_id=dict(type="str"),
        update_version=dict(type="str"),
        scope=dict(type="str", default="all", choices=["all", "zone", "group"]),
        scope_filter=dict(type="str"),
        include_breakdown=dict(type="bool", default=True),
        include_compatibility=dict(type="bool", default=False),
        include_risk=dict(type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[("campaign_id", "update_version")],
        required_one_of=[("campaign_id", "update_version")],
    )
    api = HypershieldAPI(module)
    result = dict(changed=False, confidence={})

    try:
        params = {"scope": module.params["scope"]}
        if module.params.get("scope_filter"):
            params["scope_filter"] = module.params["scope_filter"]
        params["include_breakdown"] = module.params["include_breakdown"]
        params["include_compatibility"] = module.params["include_compatibility"]
        params["include_risk"] = module.params["include_risk"]

        if module.params.get("campaign_id"):
            path = "/updates/campaigns/{0}/confidence".format(module.params["campaign_id"])
        else:
            path = "/updates/versions/{0}/confidence".format(module.params["update_version"])

        data = api.get(path, params=params)
        result["confidence"] = data.get("confidence", {})

        if module.params["include_breakdown"]:
            result["breakdown"] = data.get("breakdown", [])
        if module.params["include_compatibility"]:
            result["compatibility"] = data.get("compatibility", [])
        if module.params["include_risk"]:
            result["risk_assessment"] = data.get("risk_assessment", {})

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
