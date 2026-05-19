#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent_label
short_description: Manage labels and tags on Cisco Hypershield agents
version_added: "1.0.0"
description:
  - Add, update, or remove labels on Tesseract Security Agents.
  - Labels are key-value pairs used for classification, policy targeting, and dynamic group membership.
  - Supports setting labels on individual agents or across groups.
author:
  - Steve Fulmer (@stevefulmer)
options:
  agent_id:
    description:
      - ID of the agent to label.
      - Mutually exclusive with I(agent_ids) and I(group_id).
    type: str
  agent_ids:
    description:
      - List of agent IDs to label in bulk.
      - Mutually exclusive with I(agent_id) and I(group_id).
    type: list
    elements: str
  group_id:
    description:
      - Apply labels to all agents in this group.
      - Mutually exclusive with I(agent_id) and I(agent_ids).
    type: str
  labels:
    description:
      - Dictionary of labels to set on the target agents.
      - When I(state=present) with I(exclusive=false), these labels are merged with existing labels.
      - When I(state=present) with I(exclusive=true), these labels replace all existing labels.
      - When I(state=absent), these label keys are removed from the agents.
    type: dict
    required: true
  state:
    description:
      - Whether the specified labels should be present or absent.
      - C(present) adds or updates the labels.
      - C(absent) removes the specified label keys.
    type: str
    choices: [present, absent]
    default: present
  exclusive:
    description:
      - When I(state=present), whether the provided labels should replace all existing labels.
      - When false (default), labels are merged with existing ones.
    type: bool
    default: false
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Add labels to a single agent
  stevefulme1.cisco_hypershield.hypershield_agent_label:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
    labels:
      environment: production
      tier: frontend
      owner: platform-team

- name: Replace all labels on an agent
  stevefulme1.cisco_hypershield.hypershield_agent_label:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
    labels:
      environment: staging
    exclusive: true

- name: Remove specific labels from multiple agents
  stevefulme1.cisco_hypershield.hypershield_agent_label:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_ids:
      - ag-abc123
      - ag-def456
    labels:
      deprecated: ""
      temp_flag: ""
    state: absent

- name: Label all agents in a group
  stevefulme1.cisco_hypershield.hypershield_agent_label:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    group_id: grp-web-servers
    labels:
      compliance: pci-dss
      scan_priority: high
"""

RETURN = r"""
results:
  description: List of label operation results per agent.
  returned: always
  type: list
  elements: dict
  contains:
    agent_id:
      description: Agent identifier.
      type: str
    changed:
      description: Whether labels were modified on this agent.
      type: bool
    labels:
      description: Final labels on the agent after the operation.
      type: dict
total_changed:
  description: Number of agents whose labels were modified.
  returned: always
  type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def resolve_agent_ids(api, module):
    """Resolve the list of agent IDs to operate on."""
    if module.params.get("agent_id"):
        return [module.params["agent_id"]]
    if module.params.get("agent_ids"):
        return module.params["agent_ids"]
    if module.params.get("group_id"):
        members = api.list_paginated(
            "/agent-groups/{0}/members".format(module.params["group_id"])
        )
        return [m["id"] for m in members]
    return []


def compute_desired_labels(existing_labels, desired_labels, state, exclusive):
    """Compute the final label set based on the operation."""
    if state == "absent":
        new_labels = dict(existing_labels)
        for key in desired_labels:
            new_labels.pop(key, None)
        return new_labels

    # state == present
    if exclusive:
        return dict(desired_labels)

    new_labels = dict(existing_labels)
    new_labels.update(desired_labels)
    return new_labels


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        agent_id=dict(type="str"),
        agent_ids=dict(type="list", elements="str"),
        group_id=dict(type="str"),
        labels=dict(type="dict", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        exclusive=dict(type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("agent_id", "agent_ids", "group_id"),
        ],
        required_one_of=[
            ("agent_id", "agent_ids", "group_id"),
        ],
    )

    api = HypershieldAPI(module)
    state = module.params["state"]
    desired_labels = module.params["labels"]
    exclusive = module.params["exclusive"]

    try:
        agent_ids = resolve_agent_ids(api, module)
        if not agent_ids:
            module.exit_json(changed=False, results=[], total_changed=0)

        results = []
        total_changed = 0

        for aid in agent_ids:
            agent = api.get("/agents/{0}".format(aid))
            existing_labels = agent.get("labels", {})
            new_labels = compute_desired_labels(existing_labels, desired_labels, state, exclusive)

            agent_changed = new_labels != existing_labels
            if agent_changed:
                total_changed += 1
                if not module.check_mode:
                    api.patch("/agents/{0}".format(aid), data={"labels": new_labels})

            results.append({
                "agent_id": aid,
                "changed": agent_changed,
                "labels": new_labels,
            })

        module.exit_json(
            changed=total_changed > 0,
            results=results,
            total_changed=total_changed,
        )

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
