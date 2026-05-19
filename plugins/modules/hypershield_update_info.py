# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_update_info
short_description: Query Cisco Hypershield update campaign status and history
description:
  - Retrieve information about update campaigns, including status, history, and pending updates.
  - Filter by campaign name, status, or time range.
  - This is an info module and makes no changes.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  campaign_name:
    description:
      - Filter results to a specific campaign by name.
    type: str
  campaign_id:
    description:
      - Filter results to a specific campaign by ID.
    type: str
  status:
    description:
      - Filter campaigns by status.
    type: str
    choices: [pending, running, paused, completed, failed, cancelled]
  include_history:
    description:
      - Include historical update events for each campaign.
    type: bool
    default: false
  include_pending:
    description:
      - Include pending updates not yet assigned to a campaign.
    type: bool
    default: false
  since:
    description:
      - Return campaigns created after this ISO 8601 timestamp.
    type: str
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all update campaigns
  stevefulme1.cisco_hypershield.hypershield_update_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: all_campaigns

- name: Get details of a specific campaign
  stevefulme1.cisco_hypershield.hypershield_update_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    campaign_name: security-patch-2026-05
    include_history: true
  register: campaign_detail

- name: List pending updates
  stevefulme1.cisco_hypershield.hypershield_update_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    include_pending: true
  register: pending_updates

- name: List failed campaigns since a date
  stevefulme1.cisco_hypershield.hypershield_update_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    status: failed
    since: "2026-05-01T00:00:00Z"
  register: failed_campaigns
"""

RETURN = r"""
campaigns:
  description: List of update campaigns matching the query.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Campaign unique identifier.
      type: str
    name:
      description: Campaign name.
      type: str
    status:
      description: Current campaign status.
      type: str
    rollout_strategy:
      description: Rollout strategy used.
      type: str
    target_version:
      description: Target software version.
      type: str
    progress:
      description: Completion percentage (0-100).
      type: int
    created_at:
      description: Creation timestamp.
      type: str
    updated_at:
      description: Last update timestamp.
      type: str
pending_updates:
  description: List of available updates not yet in a campaign.
  returned: when I(include_pending) is true
  type: list
  elements: dict
  contains:
    version:
      description: Available update version.
      type: str
    severity:
      description: Update severity level.
      type: str
    release_date:
      description: Release date of the update.
      type: str
total:
  description: Total number of campaigns matching the query.
  returned: always
  type: int
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
        campaign_name=dict(type="str"),
        campaign_id=dict(type="str"),
        status=dict(type="str", choices=["pending", "running", "paused", "completed", "failed", "cancelled"]),
        include_history=dict(type="bool", default=False),
        include_pending=dict(type="bool", default=False),
        since=dict(type="str"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api = HypershieldAPI(module)
    result = dict(changed=False, campaigns=[], total=0)

    try:
        if module.params.get("campaign_id"):
            campaign = api.get("/updates/campaigns/{0}".format(module.params["campaign_id"]))
            if module.params.get("include_history"):
                campaign["history"] = api.get(
                    "/updates/campaigns/{0}/history".format(campaign["id"])
                ).get("events", [])
            result["campaigns"] = [campaign]
            result["total"] = 1
        else:
            params = {}
            if module.params.get("campaign_name"):
                params["name"] = module.params["campaign_name"]
            if module.params.get("status"):
                params["status"] = module.params["status"]
            if module.params.get("since"):
                params["since"] = module.params["since"]

            campaigns = api.list_paginated("/updates/campaigns", params=params)

            if module.params.get("include_history"):
                for campaign in campaigns:
                    campaign["history"] = api.get(
                        "/updates/campaigns/{0}/history".format(campaign["id"])
                    ).get("events", [])

            result["campaigns"] = campaigns
            result["total"] = len(campaigns)

        if module.params.get("include_pending"):
            pending = api.get("/updates/available")
            result["pending_updates"] = pending.get("updates", [])

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
