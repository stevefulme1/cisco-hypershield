#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Steve Fulmer <sfulmer@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_network_rule_info
short_description: Query Cisco Hypershield network access rules
version_added: "1.0.0"
description:
  - Retrieve information about network access rules (L3/L4 firewall rules)
    from a Cisco Hypershield controller.
  - Filter by name, parent policy, protocol, action, direction, or enabled state.
  - Optionally includes hit count statistics and schedule details.
  - Supports querying standalone rules or rules within a specific policy.
author:
  - Steve Fulmer (@stevefulmer)
options:
  name:
    description:
      - Filter by exact rule name.
    type: str
  policy_id:
    description:
      - Filter rules belonging to a specific policy by ID.
    type: str
  policy_name:
    description:
      - Filter rules belonging to a specific policy by name.
      - Mutually exclusive with I(policy_id).
    type: str
  protocol:
    description:
      - Filter rules by protocol.
    type: str
    choices: [tcp, udp, icmp, sctp, gre, esp, ah, any]
  action:
    description:
      - Filter rules by action.
    type: str
    choices: [allow, deny, drop, reject, log]
  direction:
    description:
      - Filter rules by traffic direction.
    type: str
    choices: [inbound, outbound, bidirectional]
  enabled:
    description:
      - Filter by enabled/disabled state.
    type: bool
  source_address:
    description:
      - Filter rules that include this source address or CIDR.
    type: str
  destination_address:
    description:
      - Filter rules that include this destination address or CIDR.
    type: str
  destination_port:
    description:
      - Filter rules that include this destination port.
    type: str
  include_hit_counts:
    description:
      - Whether to include traffic hit count statistics for each rule.
    type: bool
    default: false
  include_schedule:
    description:
      - Whether to include time-based schedule details for each rule.
    type: bool
    default: true
  standalone_only:
    description:
      - When C(true), only return rules that are not associated with any policy.
    type: bool
    default: false
  sort_by:
    description:
      - Field to sort results by.
    type: str
    choices: [name, priority, created_at, hit_count]
    default: priority
  sort_order:
    description:
      - Sort direction.
    type: str
    choices: [asc, desc]
    default: asc
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all network rules
  stevefulme1.cisco_hypershield.hypershield_network_rule_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: all_rules

- name: Get rules for a specific policy with hit counts
  stevefulme1.cisco_hypershield.hypershield_network_rule_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    policy_name: web-tier-policy
    include_hit_counts: true
  register: policy_rules

- name: Find all deny rules for TCP protocol
  stevefulme1.cisco_hypershield.hypershield_network_rule_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    protocol: tcp
    action: deny
  register: deny_rules

- name: Find rules matching a specific destination
  stevefulme1.cisco_hypershield.hypershield_network_rule_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    destination_address: "10.2.0.0/24"
    destination_port: "443"
  register: matching_rules

- name: List standalone rules not attached to any policy
  stevefulme1.cisco_hypershield.hypershield_network_rule_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    standalone_only: true
    sort_by: created_at
    sort_order: desc
  register: standalone_rules

- name: Get disabled rules sorted by hit count
  stevefulme1.cisco_hypershield.hypershield_network_rule_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    enabled: false
    include_hit_counts: true
    sort_by: hit_count
    sort_order: desc
  register: disabled_rules
"""

RETURN = r"""
rules:
  description: List of network rule objects matching the query.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier of the rule.
      type: str
    name:
      description: Rule name.
      type: str
    description:
      description: Rule description.
      type: str
    policy_id:
      description: Parent policy ID (null for standalone rules).
      type: str
    source_addresses:
      description: Source address list.
      type: list
      elements: str
    destination_addresses:
      description: Destination address list.
      type: list
      elements: str
    protocol:
      description: Matched protocol.
      type: str
    source_ports:
      description: Source port list.
      type: list
      elements: str
    destination_ports:
      description: Destination port list.
      type: list
      elements: str
    action:
      description: Rule action.
      type: str
    direction:
      description: Traffic direction.
      type: str
    log_enabled:
      description: Whether logging is enabled.
      type: bool
    enabled:
      description: Whether the rule is active.
      type: bool
    priority:
      description: Evaluation priority.
      type: int
    hit_count:
      description: Number of times matched (when I(include_hit_counts=true)).
      type: int
    last_hit:
      description: ISO 8601 timestamp of last match (when I(include_hit_counts=true)).
      type: str
    schedule:
      description: Time-based schedule (when I(include_schedule=true)).
      type: dict
    created_at:
      description: ISO 8601 timestamp of creation.
      type: str
    updated_at:
      description: ISO 8601 timestamp of last update.
      type: str
count:
  description: Total number of rules matching the query.
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
        policy_id=dict(type="str"),
        policy_name=dict(type="str"),
        protocol=dict(type="str", choices=["tcp", "udp", "icmp", "sctp", "gre", "esp", "ah", "any"]),
        action=dict(type="str", choices=["allow", "deny", "drop", "reject", "log"]),
        direction=dict(type="str", choices=["inbound", "outbound", "bidirectional"]),
        enabled=dict(type="bool"),
        source_address=dict(type="str"),
        destination_address=dict(type="str"),
        destination_port=dict(type="str"),
        include_hit_counts=dict(type="bool", default=False),
        include_schedule=dict(type="bool", default=True),
        standalone_only=dict(type="bool", default=False),
        sort_by=dict(type="str", choices=["name", "priority", "created_at", "hit_count"],
                     default="priority"),
        sort_order=dict(type="str", choices=["asc", "desc"], default="asc"),
        **HypershieldAPI.hypershield_argument_spec()
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("policy_id", "policy_name"),
        ],
    )

    api = HypershieldAPI(module)

    try:
        params = {}
        for field in ("name", "policy_id", "policy_name", "protocol", "action",
                      "direction", "enabled", "source_address", "destination_address",
                      "destination_port", "sort_by", "sort_order"):
            value = module.params.get(field)
            if value is not None:
                params[field] = value

        if module.params["standalone_only"]:
            params["standalone"] = True

        expand_parts = []
        if module.params["include_hit_counts"]:
            expand_parts.append("hit_counts")
        if module.params["include_schedule"]:
            expand_parts.append("schedule")
        if expand_parts:
            params["expand"] = ",".join(expand_parts)

        rules = api.list_paginated("/network-rules", params=params)

        module.exit_json(
            changed=False,
            rules=rules,
            count=len(rules),
        )

    except HypershieldAPIError as e:
        api.fail_json_from_error(e)
    except HypershieldError as e:
        api.fail_json_from_error(e)


def main():
    run_module()


if __name__ == "__main__":
    main()
