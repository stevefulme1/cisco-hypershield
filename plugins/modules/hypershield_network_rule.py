#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Steve Fulmer <sfulmer@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_network_rule
short_description: Manage Cisco Hypershield network access rules
version_added: "1.0.0"
description:
  - Create, update, and delete individual network access rules (L3/L4 firewall rules)
    within Cisco Hypershield policies.
  - Network rules define granular traffic control at the IP protocol and port level.
  - Rules can be standalone or associated with a parent policy.
  - Supports bidirectional rules, time-based scheduling, and connection tracking options.
  - Idempotent — will not modify a rule if it already matches the desired state.
author:
  - Steve Fulmer (@stevefulmer)
options:
  name:
    description:
      - Unique name of the network rule.
    type: str
    required: true
  state:
    description:
      - Desired state of the network rule.
    type: str
    choices: [present, absent]
    default: present
  description:
    description:
      - Description of the network rule purpose.
    type: str
  policy_id:
    description:
      - ID of the parent policy this rule belongs to.
      - If not specified, the rule is created as a standalone rule.
    type: str
  policy_name:
    description:
      - Name of the parent policy (resolved to ID by the controller).
      - Mutually exclusive with I(policy_id).
    type: str
  source_addresses:
    description:
      - List of source IP addresses, CIDR blocks, or address object names.
    type: list
    elements: str
    default: ["any"]
  destination_addresses:
    description:
      - List of destination IP addresses, CIDR blocks, or address object names.
    type: list
    elements: str
    default: ["any"]
  protocol:
    description:
      - IP protocol to match.
    type: str
    choices: [tcp, udp, icmp, sctp, gre, esp, ah, any]
    default: any
  source_ports:
    description:
      - List of source ports or port ranges (e.g., '1024-65535').
      - Only applicable for TCP, UDP, and SCTP protocols.
    type: list
    elements: str
  destination_ports:
    description:
      - List of destination ports or port ranges (e.g., '443', '8080-8090').
      - Only applicable for TCP, UDP, and SCTP protocols.
    type: list
    elements: str
  action:
    description:
      - Action to take for matched traffic.
    type: str
    choices: [allow, deny, drop, reject, log]
    default: allow
  direction:
    description:
      - Direction of traffic this rule applies to.
    type: str
    choices: [inbound, outbound, bidirectional]
    default: bidirectional
  log_enabled:
    description:
      - Whether to log traffic matched by this rule.
    type: bool
    default: false
  log_prefix:
    description:
      - Prefix string added to log entries for this rule.
    type: str
  enabled:
    description:
      - Whether the rule is administratively enabled.
    type: bool
    default: true
  priority:
    description:
      - Rule evaluation priority within its policy. Lower numbers are evaluated first.
    type: int
    default: 1000
  schedule:
    description:
      - Time-based schedule for when this rule is active.
    type: dict
    suboptions:
      start_time:
        description: Daily start time in HH:MM format (24-hour).
        type: str
      end_time:
        description: Daily end time in HH:MM format (24-hour).
        type: str
      days:
        description: Days of the week the rule is active.
        type: list
        elements: str
        choices: [monday, tuesday, wednesday, thursday, friday, saturday, sunday]
      timezone:
        description: Timezone for schedule evaluation (e.g., 'America/New_York').
        type: str
        default: UTC
  connection_tracking:
    description:
      - Connection tracking options for stateful inspection.
    type: dict
    suboptions:
      state:
        description: Connection states to match.
        type: list
        elements: str
        choices: [new, established, related, invalid]
      timeout:
        description: Connection tracking timeout in seconds.
        type: int
  comment:
    description:
      - Operational comment for the rule (not the description).
    type: str
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Create a rule allowing HTTPS traffic to web servers
  stevefulme1.cisco_hypershield.hypershield_network_rule:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: allow-https-web
    policy_name: web-tier-policy
    source_addresses: ["10.0.0.0/8"]
    destination_addresses: ["10.2.0.0/24"]
    protocol: tcp
    destination_ports: ["443"]
    action: allow
    direction: inbound
    log_enabled: true
    log_prefix: "WEB-HTTPS"

- name: Create a time-based rule for maintenance windows
  stevefulme1.cisco_hypershield.hypershield_network_rule:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: maintenance-ssh-access
    description: Allow SSH during maintenance windows
    source_addresses: ["10.100.0.0/24"]
    destination_addresses: ["any"]
    protocol: tcp
    destination_ports: ["22"]
    action: allow
    schedule:
      start_time: "02:00"
      end_time: "06:00"
      days: [saturday, sunday]
      timezone: America/New_York

- name: Deny all traffic from a specific CIDR
  stevefulme1.cisco_hypershield.hypershield_network_rule:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: block-suspicious-net
    source_addresses: ["192.168.99.0/24"]
    destination_addresses: ["any"]
    protocol: any
    action: deny
    log_enabled: true
    priority: 10

- name: Delete a network rule
  stevefulme1.cisco_hypershield.hypershield_network_rule:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: deprecated-rule
    state: absent
"""

RETURN = r"""
rule:
  description: The network rule object after the operation.
  returned: success
  type: dict
  contains:
    id:
      description: Unique identifier of the rule.
      type: str
    name:
      description: Rule name.
      type: str
    policy_id:
      description: ID of the parent policy, if associated.
      type: str
    source_addresses:
      description: Source address list.
      type: list
    destination_addresses:
      description: Destination address list.
      type: list
    protocol:
      description: Matched protocol.
      type: str
    action:
      description: Rule action.
      type: str
    direction:
      description: Traffic direction.
      type: str
    enabled:
      description: Whether the rule is enabled.
      type: bool
    priority:
      description: Evaluation priority.
      type: int
    hit_count:
      description: Number of times the rule has been matched.
      type: int
    created_at:
      description: ISO 8601 timestamp of creation.
      type: str
    updated_at:
      description: ISO 8601 timestamp of last update.
      type: str
diff:
  description: Changes applied to the rule.
  returned: changed
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldAPIError,
    HypershieldError,
)


def build_payload(params):
    """Build API payload from module parameters."""
    payload = {"name": params["name"]}
    simple_fields = ("description", "policy_id", "policy_name", "protocol", "action",
                     "direction", "log_enabled", "log_prefix", "enabled", "priority", "comment")
    for field in simple_fields:
        if params.get(field) is not None:
            payload[field] = params[field]
    for list_field in ("source_addresses", "destination_addresses", "source_ports",
                       "destination_ports"):
        if params.get(list_field):
            payload[list_field] = params[list_field]
    if params.get("schedule"):
        payload["schedule"] = params["schedule"]
    if params.get("connection_tracking"):
        payload["connection_tracking"] = params["connection_tracking"]
    return payload


def rules_differ(existing, desired):
    """Compare existing rule with desired state."""
    diff = {}
    simple_fields = ("description", "policy_id", "policy_name", "protocol", "action",
                     "direction", "log_enabled", "log_prefix", "enabled", "priority", "comment")
    for field in simple_fields:
        if field in desired and desired[field] is not None:
            if existing.get(field) != desired[field]:
                diff[field] = {"before": existing.get(field), "after": desired[field]}
    for list_field in ("source_addresses", "destination_addresses", "source_ports",
                       "destination_ports"):
        if list_field in desired and desired[list_field]:
            existing_val = existing.get(list_field, [])
            if sorted(existing_val) != sorted(desired[list_field]):
                diff[list_field] = {"before": existing_val, "after": desired[list_field]}
    for dict_field in ("schedule", "connection_tracking"):
        if dict_field in desired and desired[dict_field]:
            if existing.get(dict_field) != desired[dict_field]:
                diff[dict_field] = {"before": existing.get(dict_field), "after": desired[dict_field]}
    return diff


def run_module():
    argument_spec = dict(
        name=dict(type="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
        description=dict(type="str"),
        policy_id=dict(type="str"),
        policy_name=dict(type="str"),
        source_addresses=dict(type="list", elements="str", default=["any"]),
        destination_addresses=dict(type="list", elements="str", default=["any"]),
        protocol=dict(type="str", choices=["tcp", "udp", "icmp", "sctp", "gre", "esp", "ah", "any"],
                      default="any"),
        source_ports=dict(type="list", elements="str"),
        destination_ports=dict(type="list", elements="str"),
        action=dict(type="str", choices=["allow", "deny", "drop", "reject", "log"], default="allow"),
        direction=dict(type="str", choices=["inbound", "outbound", "bidirectional"],
                       default="bidirectional"),
        log_enabled=dict(type="bool", default=False),
        log_prefix=dict(type="str"),
        enabled=dict(type="bool", default=True),
        priority=dict(type="int", default=1000),
        schedule=dict(
            type="dict",
            options=dict(
                start_time=dict(type="str"),
                end_time=dict(type="str"),
                days=dict(type="list", elements="str",
                          choices=["monday", "tuesday", "wednesday", "thursday",
                                   "friday", "saturday", "sunday"]),
                timezone=dict(type="str", default="UTC"),
            ),
        ),
        connection_tracking=dict(
            type="dict",
            options=dict(
                state=dict(type="list", elements="str",
                           choices=["new", "established", "related", "invalid"]),
                timeout=dict(type="int"),
            ),
        ),
        comment=dict(type="str"),
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
    name = module.params["name"]
    state = module.params["state"]

    try:
        existing = None
        rules = api.get("/network-rules", params={"name": name})
        items = rules.get("items", [])
        if items:
            existing = items[0]

        if state == "absent":
            if existing is None:
                module.exit_json(changed=False, msg="Network rule does not exist")
            if module.check_mode:
                module.exit_json(changed=True, diff={"before": existing, "after": None})
            api.delete("/network-rules/{0}".format(existing["id"]))
            module.exit_json(changed=True, msg="Network rule deleted", rule={})
            return

        desired = build_payload(module.params)

        if existing is None:
            if module.check_mode:
                module.exit_json(changed=True, diff={"before": None, "after": desired})
            result = api.post("/network-rules", data=desired)
            module.exit_json(changed=True, rule=result, msg="Network rule created")
            return

        diff = rules_differ(existing, desired)
        if not diff:
            module.exit_json(changed=False, rule=existing, msg="Network rule already in desired state")
            return

        if module.check_mode:
            module.exit_json(changed=True, diff=diff)
        result = api.put("/network-rules/{0}".format(existing["id"]), data=desired)
        module.exit_json(changed=True, rule=result, diff=diff, msg="Network rule updated")

    except HypershieldAPIError as e:
        api.fail_json_from_error(e)
    except HypershieldError as e:
        api.fail_json_from_error(e)


def main():
    run_module()


if __name__ == "__main__":
    main()
