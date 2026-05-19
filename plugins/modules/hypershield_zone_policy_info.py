#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Steve Fulmer <sfulmer@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_zone_policy_info
short_description: Query Cisco Hypershield zone policies and zone membership
version_added: "1.0.0"
description:
  - Retrieve information about zone-based firewall policies from a Cisco Hypershield controller.
  - Filter by policy name, source/destination zones, or enabled state.
  - Optionally include zone membership details and rule definitions.
author:
  - Steve Fulmer (@stevefulmer)
options:
  name:
    description:
      - Filter by exact zone policy name.
    type: str
  source_zone:
    description:
      - Filter policies by source security zone.
    type: str
  destination_zone:
    description:
      - Filter policies by destination security zone.
    type: str
  enabled:
    description:
      - Filter by enabled/disabled state.
    type: bool
  include_rules:
    description:
      - Whether to include the full rule definitions in the response.
    type: bool
    default: true
  include_members:
    description:
      - Whether to include zone membership details.
    type: bool
    default: false
  zone_name:
    description:
      - Query membership of a specific zone by name.
      - When specified, returns zone details and all associated members
        instead of zone policies.
    type: str
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all zone policies
  stevefulme1.cisco_hypershield.hypershield_zone_policy_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: all_zone_policies

- name: Get policies for a specific source zone
  stevefulme1.cisco_hypershield.hypershield_zone_policy_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    source_zone: dmz
  register: dmz_policies

- name: Query zone membership details
  stevefulme1.cisco_hypershield.hypershield_zone_policy_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    zone_name: production
    include_members: true
  register: prod_zone

- name: Find policies between two specific zones
  stevefulme1.cisco_hypershield.hypershield_zone_policy_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    source_zone: dmz
    destination_zone: internal
    include_rules: true
  register: dmz_internal_policies
"""

RETURN = r"""
policies:
  description: List of zone policy objects matching the query.
  returned: when zone_name is not specified
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier of the zone policy.
      type: str
    name:
      description: Policy name.
      type: str
    source_zone:
      description: Source security zone.
      type: str
    destination_zone:
      description: Destination security zone.
      type: str
    default_action:
      description: Default traffic action.
      type: str
    enabled:
      description: Whether the policy is enabled.
      type: bool
    priority:
      description: Policy evaluation priority.
      type: int
    rule_count:
      description: Number of rules.
      type: int
    rules:
      description: Rule definitions (when I(include_rules=true)).
      type: list
      elements: dict
    created_at:
      description: ISO 8601 timestamp of creation.
      type: str
    updated_at:
      description: ISO 8601 timestamp of last update.
      type: str
zone:
  description: Zone details when querying a specific zone.
  returned: when zone_name is specified
  type: dict
  contains:
    name:
      description: Zone name.
      type: str
    members:
      description: List of zone members (when I(include_members=true)).
      type: list
      elements: dict
    policy_count:
      description: Number of policies referencing this zone.
      type: int
count:
  description: Total number of results.
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
        name=dict(type="str"),
        source_zone=dict(type="str"),
        destination_zone=dict(type="str"),
        enabled=dict(type="bool"),
        include_rules=dict(type="bool", default=True),
        include_members=dict(type="bool", default=False),
        zone_name=dict(type="str"),
        **HypershieldAPI.hypershield_argument_spec()
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("name", "zone_name"),
        ],
    )

    api = HypershieldAPI(module)

    try:
        zone_name = module.params.get("zone_name")
        if zone_name:
            params = {"name": zone_name}
            if module.params["include_members"]:
                params["expand"] = "members"
            zone_data = api.get("/zones", params=params)
            items = zone_data.get("items", [])
            zone = items[0] if items else {}
            module.exit_json(changed=False, zone=zone, count=1 if zone else 0)
            return

        params = {}
        for field in ("name", "source_zone", "destination_zone", "enabled"):
            value = module.params.get(field)
            if value is not None:
                params[field] = value
        if module.params["include_rules"]:
            params["expand"] = "rules"
        if module.params["include_members"]:
            expand = params.get("expand", "")
            params["expand"] = "{0},members".format(expand) if expand else "members"

        policies = api.list_paginated("/zone-policies", params=params)

        module.exit_json(
            changed=False,
            policies=policies,
            count=len(policies),
        )

    except HypershieldAPIError as e:
        api.fail_json_from_error(e)
    except HypershieldError as e:
        api.fail_json_from_error(e)


def main():
    run_module()


if __name__ == "__main__":
    main()
