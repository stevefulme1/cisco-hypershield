# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_update
short_description: Manage Cisco Hypershield self-qualifying security updates
description:
  - Initiate, configure, and manage self-qualifying security update campaigns.
  - Define rollout strategies, confidence thresholds, and maintenance windows.
  - Supports check mode for dry-run validation.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  state:
    description:
      - Desired state of the update campaign.
    type: str
    choices: [present, absent, started, paused]
    default: present
  campaign_name:
    description:
      - Unique name for the update campaign.
    type: str
    required: true
  rollout_strategy:
    description:
      - Strategy for rolling out updates across enforcement points.
    type: str
    choices: [canary, rolling, immediate, blue_green]
    default: rolling
  confidence_threshold:
    description:
      - Minimum confidence score (0-100) required before promoting an update.
    type: int
    default: 90
  maintenance_window:
    description:
      - Maintenance window configuration for the campaign.
    type: dict
    suboptions:
      start_time:
        description:
          - Start time in ISO 8601 format.
        type: str
        required: true
      end_time:
        description:
          - End time in ISO 8601 format.
        type: str
        required: true
      timezone:
        description:
          - Timezone for the maintenance window.
        type: str
        default: UTC
  target_version:
    description:
      - Target software version for the update.
      - If omitted, the latest available version is used.
    type: str
  target_scope:
    description:
      - Scope of enforcement points to target.
    type: str
    choices: [all, zone, group]
    default: all
  target_filter:
    description:
      - Filter expression for selecting specific enforcement points.
      - Used when I(target_scope) is C(zone) or C(group).
    type: str
  max_parallel:
    description:
      - Maximum number of enforcement points updated in parallel.
    type: int
    default: 5
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Create a rolling update campaign
  stevefulme1.cisco_hypershield.hypershield_update:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    campaign_name: security-patch-2026-05
    rollout_strategy: rolling
    confidence_threshold: 95
    target_version: "2.4.1"
    maintenance_window:
      start_time: "2026-05-20T02:00:00"
      end_time: "2026-05-20T06:00:00"
      timezone: US/Eastern

- name: Pause an active campaign
  stevefulme1.cisco_hypershield.hypershield_update:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    campaign_name: security-patch-2026-05
    state: paused

- name: Remove a completed campaign
  stevefulme1.cisco_hypershield.hypershield_update:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    campaign_name: security-patch-2026-05
    state: absent
"""

RETURN = r"""
campaign:
  description: The update campaign object.
  returned: success
  type: dict
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
      description: Configured rollout strategy.
      type: str
    confidence_threshold:
      description: Minimum confidence score for promotion.
      type: int
    target_version:
      description: Target software version.
      type: str
    created_at:
      description: Campaign creation timestamp.
      type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def find_campaign(api, name):
    """Find a campaign by name."""
    campaigns = api.get("/updates/campaigns", params={"name": name})
    items = campaigns.get("items", [])
    return items[0] if items else None


def build_campaign_payload(params):
    """Build API payload from module parameters."""
    payload = {
        "name": params["campaign_name"],
        "rollout_strategy": params["rollout_strategy"],
        "confidence_threshold": params["confidence_threshold"],
        "target_scope": params["target_scope"],
        "max_parallel": params["max_parallel"],
    }
    if params.get("target_version"):
        payload["target_version"] = params["target_version"]
    if params.get("target_filter"):
        payload["target_filter"] = params["target_filter"]
    if params.get("maintenance_window"):
        payload["maintenance_window"] = params["maintenance_window"]
    return payload


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        state=dict(type="str", default="present", choices=["present", "absent", "started", "paused"]),
        campaign_name=dict(type="str", required=True),
        rollout_strategy=dict(type="str", default="rolling", choices=["canary", "rolling", "immediate", "blue_green"]),
        confidence_threshold=dict(type="int", default=90),
        maintenance_window=dict(type="dict"),
        target_version=dict(type="str"),
        target_scope=dict(type="str", default="all", choices=["all", "zone", "group"]),
        target_filter=dict(type="str"),
        max_parallel=dict(type="int", default=5),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api = HypershieldAPI(module)
    state = module.params["state"]
    result = dict(changed=False, campaign={})

    try:
        existing = find_campaign(api, module.params["campaign_name"])

        if state == "absent":
            if existing:
                if not module.check_mode:
                    api.delete("/updates/campaigns/{0}".format(existing["id"]))
                result["changed"] = True
            module.exit_json(**result)

        if state in ("present", "started"):
            payload = build_campaign_payload(module.params)
            if existing:
                # Check for differences
                changed_fields = {k: v for k, v in payload.items() if existing.get(k) != v}
                if changed_fields or (state == "started" and existing.get("status") != "running"):
                    if not module.check_mode:
                        campaign = api.put("/updates/campaigns/{0}".format(existing["id"]), data=payload)
                        if state == "started" and campaign.get("status") != "running":
                            campaign = api.post("/updates/campaigns/{0}/start".format(existing["id"]))
                        result["campaign"] = campaign
                    result["changed"] = True
                else:
                    result["campaign"] = existing
            else:
                if not module.check_mode:
                    campaign = api.post("/updates/campaigns", data=payload)
                    if state == "started":
                        campaign = api.post("/updates/campaigns/{0}/start".format(campaign["id"]))
                    result["campaign"] = campaign
                result["changed"] = True

        elif state == "paused":
            if existing and existing.get("status") != "paused":
                if not module.check_mode:
                    result["campaign"] = api.post("/updates/campaigns/{0}/pause".format(existing["id"]))
                result["changed"] = True
            elif existing:
                result["campaign"] = existing
            else:
                module.fail_json(msg="Campaign '{0}' not found".format(module.params["campaign_name"]))

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
