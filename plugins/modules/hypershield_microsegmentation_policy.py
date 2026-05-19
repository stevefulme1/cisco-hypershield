#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Steve Fulmer <sfulmer@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_microsegmentation_policy
short_description: Manage Cisco Hypershield microsegmentation policies
version_added: "1.0.0"
description:
  - Create, update, and delete microsegmentation policies on a Cisco Hypershield controller.
  - Microsegmentation policies define allow/deny rules based on application identity,
    network attributes, and workload metadata.
  - Supports policy versioning, staged rollout, and dry-run mode for safe deployment.
  - Idempotent — will not modify a policy if it already matches the desired state.
author:
  - Steve Fulmer (@stevefulmer)
options:
  name:
    description:
      - Unique name of the microsegmentation policy.
    type: str
    required: true
  state:
    description:
      - Desired state of the policy.
    type: str
    choices: [present, absent]
    default: present
  description:
    description:
      - Human-readable description of the policy purpose.
    type: str
  zone:
    description:
      - Security zone to which this policy applies.
    type: str
  action:
    description:
      - Default action for traffic matching this policy.
    type: str
    choices: [allow, deny, log]
    default: allow
  priority:
    description:
      - Policy evaluation priority. Lower numbers are evaluated first.
    type: int
    default: 100
  rules:
    description:
      - List of microsegmentation rules within this policy.
      - Each rule specifies source/destination criteria and an action.
    type: list
    elements: dict
    default: []
    suboptions:
      name:
        description: Rule name.
        type: str
        required: true
      source_app_id:
        description: Source application identity label.
        type: str
      destination_app_id:
        description: Destination application identity label.
        type: str
      source_network:
        description: Source CIDR or network object reference.
        type: str
      destination_network:
        description: Destination CIDR or network object reference.
        type: str
      protocol:
        description: IP protocol to match.
        type: str
        choices: [tcp, udp, icmp, any]
        default: any
      port:
        description: Destination port or port range (e.g., '443' or '8080-8090').
        type: str
      action:
        description: Action for matched traffic.
        type: str
        choices: [allow, deny, log]
        default: allow
      workload_labels:
        description: Dict of workload metadata labels to match.
        type: dict
  enforcement_mode:
    description:
      - Enforcement mode for the policy.
      - C(enforced) applies rules to live traffic.
      - C(dry_run) logs matches without blocking.
      - C(staged) prepares the policy for gradual rollout.
    type: str
    choices: [enforced, dry_run, staged]
    default: enforced
  version_comment:
    description:
      - Comment describing this version of the policy for audit trail.
    type: str
  enabled:
    description:
      - Whether the policy is administratively enabled.
    type: bool
    default: true
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Create a microsegmentation policy allowing web to database traffic
  stevefulme1.cisco_hypershield.hypershield_microsegmentation_policy:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: web-to-db
    description: Allow web tier to reach database tier on port 5432
    zone: production
    enforcement_mode: dry_run
    version_comment: Initial policy creation
    rules:
      - name: allow-postgres
        source_app_id: web-frontend
        destination_app_id: postgres-primary
        protocol: tcp
        port: "5432"
        action: allow
      - name: deny-all-other
        source_app_id: web-frontend
        destination_app_id: postgres-primary
        action: deny

- name: Update policy to enforced mode after validation
  stevefulme1.cisco_hypershield.hypershield_microsegmentation_policy:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: web-to-db
    enforcement_mode: enforced
    version_comment: Promoting to enforced after 7-day dry-run

- name: Delete a microsegmentation policy
  stevefulme1.cisco_hypershield.hypershield_microsegmentation_policy:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: deprecated-legacy-policy
    state: absent
"""

RETURN = r"""
policy:
  description: The microsegmentation policy object after the operation.
  returned: success
  type: dict
  contains:
    id:
      description: Unique identifier of the policy.
      type: str
    name:
      description: Policy name.
      type: str
    version:
      description: Current version number of the policy.
      type: int
    enforcement_mode:
      description: Active enforcement mode.
      type: str
    enabled:
      description: Whether the policy is enabled.
      type: bool
    rule_count:
      description: Number of rules in the policy.
      type: int
    created_at:
      description: ISO 8601 timestamp of policy creation.
      type: str
    updated_at:
      description: ISO 8601 timestamp of last modification.
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


def build_policy_payload(params):
    """Build the API request payload from module parameters."""
    payload = {"name": params["name"]}
    for field in ("description", "zone", "action", "priority", "enforcement_mode", "enabled", "version_comment"):
        if params.get(field) is not None:
            payload[field] = params[field]
    if params.get("rules"):
        payload["rules"] = params["rules"]
    return payload


def policies_differ(existing, desired):
    """Compare existing policy with desired state, return dict of differences."""
    diff = {}
    compare_fields = ("description", "zone", "action", "priority", "enforcement_mode", "enabled")
    for field in compare_fields:
        if field in desired and desired[field] is not None:
            if existing.get(field) != desired[field]:
                diff[field] = {"before": existing.get(field), "after": desired[field]}
    if "rules" in desired and desired["rules"]:
        existing_rules = existing.get("rules", [])
        if existing_rules != desired["rules"]:
            diff["rules"] = {"before": existing_rules, "after": desired["rules"]}
    return diff


def run_module():
    argument_spec = dict(
        name=dict(type="str", required=True),
        state=dict(type="str", choices=["present", "absent"], default="present"),
        description=dict(type="str"),
        zone=dict(type="str"),
        action=dict(type="str", choices=["allow", "deny", "log"], default="allow"),
        priority=dict(type="int", default=100),
        rules=dict(
            type="list",
            elements="dict",
            default=[],
            options=dict(
                name=dict(type="str", required=True),
                source_app_id=dict(type="str"),
                destination_app_id=dict(type="str"),
                source_network=dict(type="str"),
                destination_network=dict(type="str"),
                protocol=dict(type="str", choices=["tcp", "udp", "icmp", "any"], default="any"),
                port=dict(type="str"),
                action=dict(type="str", choices=["allow", "deny", "log"], default="allow"),
                workload_labels=dict(type="dict"),
            ),
        ),
        enforcement_mode=dict(type="str", choices=["enforced", "dry_run", "staged"], default="enforced"),
        version_comment=dict(type="str"),
        enabled=dict(type="bool", default=True),
        **HypershieldAPI.hypershield_argument_spec()
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)
    name = module.params["name"]
    state = module.params["state"]

    try:
        existing = None
        policies = api.get("/microsegmentation/policies", params={"name": name})
        items = policies.get("items", [])
        if items:
            existing = items[0]

        if state == "absent":
            if existing is None:
                module.exit_json(changed=False, msg="Policy does not exist")
            if module.check_mode:
                module.exit_json(changed=True, diff={"before": existing, "after": None})
            api.delete("/microsegmentation/policies/{0}".format(existing["id"]))
            module.exit_json(changed=True, msg="Policy deleted", policy={})
            return

        desired = build_policy_payload(module.params)

        if existing is None:
            if module.check_mode:
                module.exit_json(changed=True, diff={"before": None, "after": desired})
            result = api.post("/microsegmentation/policies", data=desired)
            module.exit_json(changed=True, policy=result, msg="Policy created")
            return

        diff = policies_differ(existing, desired)
        if not diff:
            module.exit_json(changed=False, policy=existing, msg="Policy already in desired state")
            return

        if module.check_mode:
            module.exit_json(changed=True, diff=diff)
        result = api.put(
            "/microsegmentation/policies/{0}".format(existing["id"]),
            data=desired,
        )
        module.exit_json(changed=True, policy=result, diff=diff, msg="Policy updated")

    except HypershieldAPIError as e:
        api.fail_json_from_error(e)
    except HypershieldError as e:
        api.fail_json_from_error(e)


def main():
    run_module()


if __name__ == "__main__":
    main()
