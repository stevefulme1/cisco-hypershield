#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent_group
short_description: Manage Cisco Hypershield agent groups for policy targeting
version_added: "1.0.0"
description:
  - Create, update, or delete agent groups in the Hypershield management plane.
  - Agent groups are used to organize agents and target security policies.
  - Groups can be defined by explicit membership or label selectors.
author:
  - Steve Fulmer (@stevefulmer)
options:
  group_id:
    description:
      - Unique identifier of the agent group.
      - Required when I(state=absent) or when updating an existing group by ID.
    type: str
  name:
    description:
      - Display name of the agent group.
      - Required when I(state=present) and the group does not yet exist.
      - Used for idempotent lookup when I(group_id) is not provided.
    type: str
  description:
    description:
      - Human-readable description of the group's purpose.
    type: str
  state:
    description:
      - Desired state of the agent group.
    type: str
    choices: [present, absent]
    default: present
  membership_type:
    description:
      - How agents are added to this group.
      - C(static) requires explicit agent assignment.
      - C(dynamic) uses I(label_selector) to auto-populate membership.
    type: str
    choices: [static, dynamic]
    default: static
  label_selector:
    description:
      - Label selector for dynamic group membership.
      - Dictionary of key-value pairs that agents must match to join.
      - Only used when I(membership_type=dynamic).
    type: dict
  agent_ids:
    description:
      - List of agent IDs to include in a static group.
      - Only used when I(membership_type=static).
    type: list
    elements: str
  policy_ids:
    description:
      - List of security policy IDs to associate with this group.
    type: list
    elements: str
  priority:
    description:
      - Group priority for policy evaluation order.
      - Lower values have higher priority.
    type: int
    default: 100
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Create a static agent group
  stevefulme1.cisco_hypershield.hypershield_agent_group:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: web-servers
    description: Frontend web server agents
    membership_type: static
    agent_ids:
      - ag-abc123
      - ag-def456
    state: present

- name: Create a dynamic agent group using label selectors
  stevefulme1.cisco_hypershield.hypershield_agent_group:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: production-database
    description: All production database agents
    membership_type: dynamic
    label_selector:
      environment: production
      tier: database
    priority: 50

- name: Delete an agent group
  stevefulme1.cisco_hypershield.hypershield_agent_group:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    group_id: grp-xyz789
    state: absent
"""

RETURN = r"""
group:
  description: The agent group object after the operation.
  returned: success, except on delete
  type: dict
  contains:
    id:
      description: Unique group identifier.
      type: str
    name:
      description: Display name.
      type: str
    description:
      description: Group description.
      type: str
    membership_type:
      description: Static or dynamic membership.
      type: str
    member_count:
      description: Number of agents in the group.
      type: int
    label_selector:
      description: Label selector for dynamic groups.
      type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def find_group(api, group_id=None, name=None):
    """Find an existing group by ID or name."""
    if group_id:
        try:
            return api.get("/agent-groups/{0}".format(group_id))
        except HypershieldError:
            return None
    if name:
        groups = api.list_paginated("/agent-groups", params={"name": name})
        for group in groups:
            if group.get("name") == name:
                return group
    return None


def build_payload(module):
    """Build the API request body from module parameters."""
    payload = {}
    for key in ("name", "description", "membership_type", "label_selector", "agent_ids", "policy_ids", "priority"):
        value = module.params.get(key)
        if value is not None:
            payload[key] = value
    return payload


def needs_update(existing, desired):
    """Check whether the existing group differs from the desired state."""
    for key, value in desired.items():
        if value is not None and existing.get(key) != value:
            return True
    return False


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        group_id=dict(type="str"),
        name=dict(type="str"),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        membership_type=dict(type="str", default="static", choices=["static", "dynamic"]),
        label_selector=dict(type="dict"),
        agent_ids=dict(type="list", elements="str"),
        policy_ids=dict(type="list", elements="str"),
        priority=dict(type="int", default=100),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "absent", ["group_id"]),
        ],
    )

    api = HypershieldAPI(module)
    state = module.params["state"]
    result = dict(changed=False)

    try:
        existing = find_group(api, module.params.get("group_id"), module.params.get("name"))

        if state == "absent":
            if existing:
                result["changed"] = True
                result["diff"] = dict(before=existing, after={})
                if not module.check_mode:
                    api.delete("/agent-groups/{0}".format(existing["id"]))
            module.exit_json(**result)

        # state == present
        payload = build_payload(module)
        if existing:
            if needs_update(existing, payload):
                result["changed"] = True
                result["diff"] = dict(before=existing, after=payload)
                if not module.check_mode:
                    group = api.put("/agent-groups/{0}".format(existing["id"]), data=payload)
                    result["group"] = group
                else:
                    result["group"] = existing
            else:
                result["group"] = existing
        else:
            if not module.params.get("name"):
                module.fail_json(msg="Parameter 'name' is required when creating a new group")
            result["changed"] = True
            if not module.check_mode:
                group = api.post("/agent-groups", data=payload)
                result["group"] = group
            else:
                result["group"] = payload

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
