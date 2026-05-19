#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Steve Fulmer <sfulmer@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_zone_policy
short_description: Manage Cisco Hypershield zone-based firewall policies
version_added: "1.0.0"
description:
  - Create, update, and delete zone-based firewall policies on a Cisco Hypershield controller.
  - Zone policies define security boundaries and inter-zone traffic rules spanning
    physical, virtual, and cloud infrastructure.
  - Supports creating zones, assigning members, and defining directional inter-zone rules.
  - Idempotent — will not modify a policy if it already matches the desired state.
author:
  - Steve Fulmer (@stevefulmer)
options:
  name:
    description:
      - Unique name of the zone policy.
    type: str
    required: true
  state:
    description:
      - Desired state of the zone policy.
    type: str
    choices: [present, absent]
    default: present
  description:
    description:
      - Human-readable description of the zone policy.
    type: str
  source_zone:
    description:
      - Name of the source security zone for this policy.
    type: str
  destination_zone:
    description:
      - Name of the destination security zone for this policy.
    type: str
  default_action:
    description:
      - Default action for traffic between the specified zones when no rule matches.
    type: str
    choices: [allow, deny, log_and_deny]
    default: deny
  rules:
    description:
      - List of inter-zone firewall rules.
    type: list
    elements: dict
    default: []
    suboptions:
      name:
        description: Rule name.
        type: str
        required: true
      source_cidrs:
        description: List of source CIDR blocks.
        type: list
        elements: str
      destination_cidrs:
        description: List of destination CIDR blocks.
        type: list
        elements: str
      protocols:
        description: List of protocols to match.
        type: list
        elements: str
      ports:
        description: List of destination ports or port ranges.
        type: list
        elements: str
      action:
        description: Action for matched traffic.
        type: str
        choices: [allow, deny, log_and_deny, log_and_allow]
        default: allow
      enabled:
        description: Whether this rule is active.
        type: bool
        default: true
      log:
        description: Whether to log matched traffic.
        type: bool
        default: false
  zone_members:
    description:
      - List of infrastructure members (hosts, subnets, workloads) to assign to this zone policy scope.
    type: list
    elements: dict
    suboptions:
      type:
        description: Type of zone member.
        type: str
        choices: [subnet, host, workload_group, vpc, vlan]
        required: true
      value:
        description: Identifier for the member (CIDR, hostname, group name, VPC ID, VLAN ID).
        type: str
        required: true
  enabled:
    description:
      - Whether the zone policy is administratively enabled.
    type: bool
    default: true
  priority:
    description:
      - Policy priority. Lower numbers are evaluated first.
    type: int
    default: 100
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Create a zone policy between DMZ and internal zones
  stevefulme1.cisco_hypershield.hypershield_zone_policy:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: dmz-to-internal
    description: Controls traffic from DMZ to internal network
    source_zone: dmz
    destination_zone: internal
    default_action: deny
    rules:
      - name: allow-https-to-web
        source_cidrs: ["10.1.0.0/24"]
        destination_cidrs: ["10.2.0.0/24"]
        protocols: [tcp]
        ports: ["443"]
        action: allow
        log: true
      - name: allow-dns
        protocols: [udp]
        ports: ["53"]
        action: allow
    zone_members:
      - type: subnet
        value: "10.1.0.0/24"
      - type: vpc
        value: vpc-0abc123

- name: Disable a zone policy
  stevefulme1.cisco_hypershield.hypershield_zone_policy:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: dmz-to-internal
    enabled: false

- name: Delete a zone policy
  stevefulme1.cisco_hypershield.hypershield_zone_policy:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: deprecated-zone-policy
    state: absent
"""

RETURN = r"""
policy:
  description: The zone policy object after the operation.
  returned: success
  type: dict
  contains:
    id:
      description: Unique identifier of the zone policy.
      type: str
    name:
      description: Policy name.
      type: str
    source_zone:
      description: Source zone name.
      type: str
    destination_zone:
      description: Destination zone name.
      type: str
    default_action:
      description: Default traffic action.
      type: str
    enabled:
      description: Whether the policy is enabled.
      type: bool
    rule_count:
      description: Number of rules in the policy.
      type: int
    created_at:
      description: ISO 8601 timestamp of creation.
      type: str
    updated_at:
      description: ISO 8601 timestamp of last update.
      type: str
diff:
  description: Changes applied to the policy.
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
    """Build the API request payload from module parameters."""
    payload = {"name": params["name"]}
    for field in ("description", "source_zone", "destination_zone", "default_action",
                  "enabled", "priority"):
        if params.get(field) is not None:
            payload[field] = params[field]
    if params.get("rules"):
        payload["rules"] = params["rules"]
    if params.get("zone_members"):
        payload["zone_members"] = params["zone_members"]
    return payload


def policies_differ(existing, desired):
    """Compare existing policy with desired state, return dict of differences."""
    diff = {}
    compare_fields = ("description", "source_zone", "destination_zone", "default_action",
                      "enabled", "priority")
    for field in compare_fields:
        if field in desired and desired[field] is not None:
            if existing.get(field) != desired[field]:
                diff[field] = {"before": existing.get(field), "after": desired[field]}
    if "rules" in desired and desired["rules"]:
        if existing.get("rules", []) != desired["rules"]:
            diff["rules"] = {"before": existing.get("rules", []), "after": desired["rules"]}
    if "zone_members" in desired and desired["zone_members"]:
        if existing.get("zone_members", []) != desired["zone_members"]:
            diff["zone_members"] = {"before": existing.get("zone_members", []),
                                    "after": desired["zone_members"]}
    return diff


def run_module():
    argument_spec = dict(
        name=dict(type="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
        description=dict(type="str"),
        source_zone=dict(type="str"),
        destination_zone=dict(type="str"),
        default_action=dict(type="str", choices=["allow", "deny", "log_and_deny"], default="deny"),
        rules=dict(
            type="list",
            elements="dict",
            default=[],
            options=dict(
                name=dict(type="str", required=True),
                source_cidrs=dict(type="list", elements="str"),
                destination_cidrs=dict(type="list", elements="str"),
                protocols=dict(type="list", elements="str"),
                ports=dict(type="list", elements="str"),
                action=dict(type="str", choices=["allow", "deny", "log_and_deny", "log_and_allow"],
                            default="allow"),
                enabled=dict(type="bool", default=True),
                log=dict(type="bool", default=False),
            ),
        ),
        zone_members=dict(
            type="list",
            elements="dict",
            options=dict(
                type=dict(type="str", required=True,
                          choices=["subnet", "host", "workload_group", "vpc", "vlan"]),
                value=dict(type="str", required=True),
            ),
        ),
        enabled=dict(type="bool", default=True),
        priority=dict(type="int", default=100),
        **HypershieldAPI.hypershield_argument_spec()
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "present", ("source_zone", "destination_zone"), True),
        ],
    )

    api = HypershieldAPI(module)
    name = module.params["name"]
    state = module.params["state"]

    try:
        existing = None
        policies = api.get("/zone-policies", params={"name": name})
        items = policies.get("items", [])
        if items:
            existing = items[0]

        if state == "absent":
            if existing is None:
                module.exit_json(changed=False, msg="Zone policy does not exist")
            if module.check_mode:
                module.exit_json(changed=True, diff={"before": existing, "after": None})
            api.delete("/zone-policies/{0}".format(existing["id"]))
            module.exit_json(changed=True, msg="Zone policy deleted", policy={})
            return

        desired = build_payload(module.params)

        if existing is None:
            if module.check_mode:
                module.exit_json(changed=True, diff={"before": None, "after": desired})
            result = api.post("/zone-policies", data=desired)
            module.exit_json(changed=True, policy=result, msg="Zone policy created")
            return

        diff = policies_differ(existing, desired)
        if not diff:
            module.exit_json(changed=False, policy=existing, msg="Zone policy already in desired state")
            return

        if module.check_mode:
            module.exit_json(changed=True, diff=diff)
        result = api.put("/zone-policies/{0}".format(existing["id"]), data=desired)
        module.exit_json(changed=True, policy=result, diff=diff, msg="Zone policy updated")

    except HypershieldAPIError as e:
        api.fail_json_from_error(e)
    except HypershieldError as e:
        api.fail_json_from_error(e)


def main():
    run_module()


if __name__ == "__main__":
    main()
