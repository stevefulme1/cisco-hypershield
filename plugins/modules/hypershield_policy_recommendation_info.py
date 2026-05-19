#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Steve Fulmer <sfulmer@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_policy_recommendation_info
short_description: Query Cisco Hypershield policy recommendation history and acceptance rates
version_added: "1.0.0"
description:
  - Retrieve historical data about AI-generated policy recommendations from a Cisco Hypershield controller.
  - Provides acceptance rates, rejection reasons, and trend analysis over time.
  - Useful for auditing AI recommendation quality and tuning confidence thresholds.
  - Can retrieve a single recommendation's full details or aggregate statistics.
author:
  - Steve Fulmer (@stevefulmer)
options:
  recommendation_id:
    description:
      - Retrieve full details for a specific recommendation by ID.
      - Includes traffic analysis data, suggested policy, and action history.
    type: str
  category:
    description:
      - Filter recommendation history by policy category.
    type: str
    choices: [microsegmentation, zone_policy, exploit_protection, network_rule, access_control]
  zone:
    description:
      - Filter by security zone.
    type: str
  status:
    description:
      - Filter by recommendation status.
    type: str
    choices: [pending, accepted, rejected, deferred, analyzing, expired]
  date_from:
    description:
      - Filter recommendations created on or after this ISO 8601 date.
    type: str
  date_to:
    description:
      - Filter recommendations created on or before this ISO 8601 date.
    type: str
  include_statistics:
    description:
      - Whether to include aggregate statistics (acceptance rate, rejection reasons breakdown).
    type: bool
    default: false
  include_traffic_data:
    description:
      - Whether to include the underlying traffic analysis data for each recommendation.
      - Increases response size significantly.
    type: bool
    default: false
  confidence_min:
    description:
      - Minimum confidence score filter (0.0 to 1.0).
    type: float
  sort_by:
    description:
      - Field to sort results by.
    type: str
    choices: [created_at, confidence, impact_scope, status]
    default: created_at
  sort_order:
    description:
      - Sort direction.
    type: str
    choices: [asc, desc]
    default: desc
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Get full details for a specific recommendation
  stevefulme1.cisco_hypershield.hypershield_policy_recommendation_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    recommendation_id: rec-abc123
    include_traffic_data: true
  register: rec_detail

- name: Get acceptance statistics for the last 30 days
  stevefulme1.cisco_hypershield.hypershield_policy_recommendation_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    date_from: "2026-04-19T00:00:00Z"
    include_statistics: true
  register: monthly_stats

- name: List rejected recommendations to analyze rejection patterns
  stevefulme1.cisco_hypershield.hypershield_policy_recommendation_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    status: rejected
    sort_by: created_at
    sort_order: desc
  register: rejected_recs

- name: High-confidence recommendations in a specific zone
  stevefulme1.cisco_hypershield.hypershield_policy_recommendation_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    zone: production
    confidence_min: 0.9
    category: microsegmentation
    include_statistics: true
  register: prod_recs
"""

RETURN = r"""
recommendation:
  description: Full recommendation details (when I(recommendation_id) is specified).
  returned: when recommendation_id is specified
  type: dict
  contains:
    id:
      description: Recommendation ID.
      type: str
    category:
      description: Policy category.
      type: str
    confidence:
      description: AI confidence score.
      type: float
    impact_scope:
      description: Expected impact scope.
      type: str
    summary:
      description: Recommendation summary.
      type: str
    suggested_policy:
      description: The suggested policy definition.
      type: dict
    traffic_analysis:
      description: Supporting traffic analysis data.
      type: dict
    action_history:
      description: History of actions taken on this recommendation.
      type: list
      elements: dict
    status:
      description: Current status.
      type: str
    created_at:
      description: ISO 8601 timestamp of creation.
      type: str
recommendations:
  description: List of recommendations matching the query.
  returned: when recommendation_id is not specified
  type: list
  elements: dict
statistics:
  description: Aggregate statistics (when I(include_statistics=true)).
  returned: when include_statistics is true
  type: dict
  contains:
    total:
      description: Total number of recommendations in the period.
      type: int
    accepted:
      description: Number accepted.
      type: int
    rejected:
      description: Number rejected.
      type: int
    deferred:
      description: Number deferred.
      type: int
    pending:
      description: Number still pending.
      type: int
    acceptance_rate:
      description: Percentage of recommendations accepted.
      type: float
    avg_confidence_accepted:
      description: Average confidence score of accepted recommendations.
      type: float
    avg_confidence_rejected:
      description: Average confidence score of rejected recommendations.
      type: float
    top_rejection_reasons:
      description: Most common rejection reasons.
      type: list
      elements: dict
count:
  description: Total number of recommendations matching the query.
  returned: always
  type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldAPIError,
    HypershieldError,
)


def run_module():
    argument_spec = dict(
        recommendation_id=dict(type="str"),
        category=dict(type="str", choices=["microsegmentation", "zone_policy",
                                           "exploit_protection", "network_rule",
                                           "access_control"]),
        zone=dict(type="str"),
        status=dict(type="str", choices=["pending", "accepted", "rejected", "deferred",
                                         "analyzing", "expired"]),
        date_from=dict(type="str"),
        date_to=dict(type="str"),
        include_statistics=dict(type="bool", default=False),
        include_traffic_data=dict(type="bool", default=False),
        confidence_min=dict(type="float"),
        sort_by=dict(type="str", choices=["created_at", "confidence", "impact_scope", "status"],
                     default="created_at"),
        sort_order=dict(type="str", choices=["asc", "desc"], default="desc"),
        **HypershieldAPI.hypershield_argument_spec()
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        rec_id = module.params.get("recommendation_id")

        if rec_id:
            params = {}
            if module.params["include_traffic_data"]:
                params["expand"] = "traffic_analysis,action_history"
            else:
                params["expand"] = "action_history"
            recommendation = api.get(
                "/policy-recommendations/{0}".format(rec_id), params=params
            )
            module.exit_json(changed=False, recommendation=recommendation, count=1)
            return

        params = {}
        for field in ("category", "zone", "status", "date_from", "date_to",
                      "confidence_min", "sort_by", "sort_order"):
            value = module.params.get(field)
            if value is not None:
                params[field] = value
        if module.params["include_traffic_data"]:
            params["expand"] = "traffic_analysis"

        recommendations = api.list_paginated("/policy-recommendations", params=params)

        result = dict(
            changed=False,
            recommendations=recommendations,
            count=len(recommendations),
        )

        if module.params["include_statistics"]:
            stat_params = {}
            for field in ("category", "zone", "date_from", "date_to"):
                value = module.params.get(field)
                if value is not None:
                    stat_params[field] = value
            statistics = api.get("/policy-recommendations/statistics", params=stat_params)
            result["statistics"] = statistics

        module.exit_json(**result)

    except HypershieldAPIError as e:
        api.fail_json_from_error(e)
    except HypershieldError as e:
        api.fail_json_from_error(e)


def main():
    run_module()


if __name__ == "__main__":
    main()
