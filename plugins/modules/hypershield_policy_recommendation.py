#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Steve Fulmer <sfulmer@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_policy_recommendation
short_description: Retrieve and act on AI-recommended Hypershield policies
version_added: "1.0.0"
description:
  - Retrieve AI-generated policy recommendations from a Cisco Hypershield controller.
  - Hypershield analyzes observed network traffic patterns and produces policy
    recommendations that tighten security posture with minimal disruption.
  - Recommendations can be accepted (creating real policies), rejected, or deferred.
  - Filter recommendations by confidence level, impact scope, category, or zone.
  - This module manages the recommendation lifecycle, not the policies themselves.
author:
  - Steve Fulmer (@stevefulmer)
options:
  recommendation_id:
    description:
      - ID of a specific recommendation to act on.
      - Required when I(action) is specified.
    type: str
  action:
    description:
      - Action to take on a recommendation.
      - C(accept) converts the recommendation into an active policy.
      - C(reject) dismisses the recommendation with an optional reason.
      - C(defer) postpones the recommendation for later review.
      - C(request_analysis) triggers deeper traffic analysis for the recommendation.
    type: str
    choices: [accept, reject, defer, request_analysis]
  accept_options:
    description:
      - Options to apply when accepting a recommendation.
    type: dict
    suboptions:
      enforcement_mode:
        description: Enforcement mode for the created policy.
        type: str
        choices: [enforced, dry_run, staged]
        default: dry_run
      policy_name:
        description: Override name for the created policy.
        type: str
      version_comment:
        description: Comment for the initial version.
        type: str
      priority:
        description: Priority for the created policy.
        type: int
  reject_reason:
    description:
      - Reason for rejecting a recommendation. Feeds back into the AI model.
    type: str
  defer_until:
    description:
      - ISO 8601 date until which to defer the recommendation.
    type: str
  confidence_min:
    description:
      - Minimum confidence score filter (0.0 to 1.0).
      - Only return recommendations at or above this confidence level.
    type: float
  confidence_max:
    description:
      - Maximum confidence score filter (0.0 to 1.0).
    type: float
  category:
    description:
      - Filter recommendations by category.
    type: str
    choices: [microsegmentation, zone_policy, exploit_protection, network_rule, access_control]
  zone:
    description:
      - Filter recommendations by security zone.
    type: str
  impact_scope:
    description:
      - Filter recommendations by expected impact scope.
    type: str
    choices: [low, medium, high, critical]
  status:
    description:
      - Filter recommendations by processing status.
    type: str
    choices: [pending, accepted, rejected, deferred, analyzing]
    default: pending
  batch_action:
    description:
      - Apply an action to multiple recommendations at once.
      - Requires I(recommendation_ids) to be specified.
    type: str
    choices: [accept, reject, defer]
  recommendation_ids:
    description:
      - List of recommendation IDs for batch operations.
    type: list
    elements: str
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Get high-confidence pending recommendations
  stevefulme1.cisco_hypershield.hypershield_policy_recommendation:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    confidence_min: 0.85
    status: pending
  register: high_confidence

- name: Accept a recommendation in dry-run mode
  stevefulme1.cisco_hypershield.hypershield_policy_recommendation:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    recommendation_id: rec-abc123
    action: accept
    accept_options:
      enforcement_mode: dry_run
      version_comment: Accepted from AI recommendation

- name: Reject a recommendation with reason
  stevefulme1.cisco_hypershield.hypershield_policy_recommendation:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    recommendation_id: rec-def456
    action: reject
    reject_reason: Traffic pattern is from quarterly batch job, not normal flow

- name: Defer a recommendation for later review
  stevefulme1.cisco_hypershield.hypershield_policy_recommendation:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    recommendation_id: rec-ghi789
    action: defer
    defer_until: "2026-07-01T00:00:00Z"

- name: Batch accept high-confidence microsegmentation recommendations
  stevefulme1.cisco_hypershield.hypershield_policy_recommendation:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    batch_action: accept
    recommendation_ids:
      - rec-001
      - rec-002
      - rec-003
    accept_options:
      enforcement_mode: staged
"""

RETURN = r"""
recommendations:
  description: List of recommendations (when querying without an action).
  returned: when no action is specified
  type: list
  elements: dict
  contains:
    id:
      description: Recommendation ID.
      type: str
    category:
      description: Policy category.
      type: str
    confidence:
      description: AI confidence score (0.0-1.0).
      type: float
    impact_scope:
      description: Expected impact scope.
      type: str
    summary:
      description: Human-readable summary of the recommendation.
      type: str
    suggested_policy:
      description: The suggested policy definition.
      type: dict
    traffic_analysis:
      description: Traffic analysis data supporting the recommendation.
      type: dict
    status:
      description: Current status of the recommendation.
      type: str
    created_at:
      description: ISO 8601 timestamp when the recommendation was generated.
      type: str
result:
  description: Result of an action on a recommendation.
  returned: when action is specified
  type: dict
  contains:
    recommendation_id:
      description: The recommendation ID that was acted on.
      type: str
    action:
      description: The action that was taken.
      type: str
    policy_id:
      description: ID of the created policy (when action is accept).
      type: str
    status:
      description: New status of the recommendation.
      type: str
batch_results:
  description: Results of batch action operations.
  returned: when batch_action is specified
  type: dict
  contains:
    succeeded:
      description: Number of successful operations.
      type: int
    failed:
      description: Number of failed operations.
      type: int
    details:
      description: Per-recommendation results.
      type: list
      elements: dict
count:
  description: Total number of recommendations matching the query.
  returned: when no action is specified
  type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldAPIError,
    HypershieldError,
)


def handle_single_action(module, api):
    """Process a single recommendation action."""
    rec_id = module.params["recommendation_id"]
    action = module.params["action"]

    payload = {"action": action}
    if action == "accept" and module.params.get("accept_options"):
        payload["accept_options"] = module.params["accept_options"]
    if action == "reject" and module.params.get("reject_reason"):
        payload["reject_reason"] = module.params["reject_reason"]
    if action == "defer" and module.params.get("defer_until"):
        payload["defer_until"] = module.params["defer_until"]

    if module.check_mode:
        module.exit_json(
            changed=True,
            result={"recommendation_id": rec_id, "action": action, "status": "pending"},
        )
        return

    result = api.post("/policy-recommendations/{0}/actions".format(rec_id), data=payload)
    module.exit_json(changed=True, result=result)


def handle_batch_action(module, api):
    """Process batch recommendation actions."""
    batch_action = module.params["batch_action"]
    rec_ids = module.params["recommendation_ids"]

    payload = {
        "action": batch_action,
        "recommendation_ids": rec_ids,
    }
    if batch_action == "accept" and module.params.get("accept_options"):
        payload["accept_options"] = module.params["accept_options"]

    if module.check_mode:
        module.exit_json(
            changed=True,
            batch_results={"succeeded": len(rec_ids), "failed": 0,
                           "details": [{"id": rid, "status": "pending"} for rid in rec_ids]},
        )
        return

    result = api.post("/policy-recommendations/batch-actions", data=payload)
    changed = result.get("succeeded", 0) > 0
    module.exit_json(changed=changed, batch_results=result)


def run_module():
    argument_spec = dict(
        recommendation_id=dict(type="str"),
        action=dict(type="str", choices=["accept", "reject", "defer", "request_analysis"]),
        accept_options=dict(
            type="dict",
            options=dict(
                enforcement_mode=dict(type="str", choices=["enforced", "dry_run", "staged"],
                                      default="dry_run"),
                policy_name=dict(type="str"),
                version_comment=dict(type="str"),
                priority=dict(type="int"),
            ),
        ),
        reject_reason=dict(type="str"),
        defer_until=dict(type="str"),
        confidence_min=dict(type="float"),
        confidence_max=dict(type="float"),
        category=dict(type="str", choices=["microsegmentation", "zone_policy",
                                           "exploit_protection", "network_rule",
                                           "access_control"]),
        zone=dict(type="str"),
        impact_scope=dict(type="str", choices=["low", "medium", "high", "critical"]),
        status=dict(type="str", choices=["pending", "accepted", "rejected", "deferred",
                                         "analyzing"],
                    default="pending"),
        batch_action=dict(type="str", choices=["accept", "reject", "defer"]),
        recommendation_ids=dict(type="list", elements="str"),
        **HypershieldAPI.hypershield_argument_spec()
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("action", "accept", ("recommendation_id",)),
            ("action", "reject", ("recommendation_id",)),
            ("action", "defer", ("recommendation_id",)),
            ("action", "request_analysis", ("recommendation_id",)),
        ],
        required_by={
            "batch_action": "recommendation_ids",
        },
        mutually_exclusive=[
            ("action", "batch_action"),
            ("recommendation_id", "recommendation_ids"),
        ],
    )

    api = HypershieldAPI(module)

    try:
        if module.params.get("action"):
            handle_single_action(module, api)
            return

        if module.params.get("batch_action"):
            handle_batch_action(module, api)
            return

        # Query mode
        params = {}
        for field in ("confidence_min", "confidence_max", "category", "zone",
                      "impact_scope", "status"):
            value = module.params.get(field)
            if value is not None:
                params[field] = value

        recommendations = api.list_paginated("/policy-recommendations", params=params)
        module.exit_json(
            changed=False,
            recommendations=recommendations,
            count=len(recommendations),
        )

    except HypershieldAPIError as e:
        api.fail_json_from_error(e)
    except HypershieldError as e:
        api.fail_json_from_error(e)


def main():
    run_module()


if __name__ == "__main__":
    main()
