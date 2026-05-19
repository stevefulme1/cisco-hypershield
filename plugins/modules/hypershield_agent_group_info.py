#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent_group_info
short_description: Query Cisco Hypershield agent group membership and configuration
version_added: "1.0.0"
description:
  - Retrieve information about agent groups and their members.
  - Can query a specific group or list all groups with optional filtering.
  - Returns group configuration, membership details, and associated policies.
author:
  - Steve Fulmer (@stevefulmer)
options:
  group_id:
    description:
      - Retrieve a single group by its unique ID.
    type: str
  name:
    description:
      - Filter groups by display name (substring match).
    type: str
  membership_type:
    description:
      - Filter groups by membership type.
    type: str
    choices: [static, dynamic]
  include_members:
    description:
      - Whether to include the list of member agents for each group.
      - Can increase response time for large groups.
    type: bool
    default: false
  include_policies:
    description:
      - Whether to include associated policy details for each group.
    type: bool
    default: false
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Get details of a specific group
  stevefulme1.cisco_hypershield.hypershield_agent_group_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    group_id: grp-web-servers
    include_members: true
  register: group_detail

- name: List all dynamic groups
  stevefulme1.cisco_hypershield.hypershield_agent_group_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    membership_type: dynamic
  register: dynamic_groups

- name: Search groups by name with policies
  stevefulme1.cisco_hypershield.hypershield_agent_group_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: production
    include_policies: true
  register: prod_groups
"""

RETURN = r"""
groups:
  description: List of agent group objects matching the query.
  returned: always
  type: list
  elements: dict
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
    members:
      description: List of member agent summaries (when include_members is true).
      type: list
    policies:
      description: Associated policy details (when include_policies is true).
      type: list
    priority:
      description: Group priority for policy evaluation.
      type: int
count:
  description: Number of groups returned.
  returned: always
  type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def enrich_group(api, group, include_members, include_policies):
    """Add member and policy details to a group object."""
    if include_members:
        try:
            members = api.list_paginated(
                "/agent-groups/{0}/members".format(group["id"])
            )
            group["members"] = members
        except HypershieldError:
            group["members"] = []

    if include_policies:
        try:
            policies = api.list_paginated(
                "/agent-groups/{0}/policies".format(group["id"])
            )
            group["policies"] = policies
        except HypershieldError:
            group["policies"] = []

    return group


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        group_id=dict(type="str"),
        name=dict(type="str"),
        membership_type=dict(type="str", choices=["static", "dynamic"]),
        include_members=dict(type="bool", default=False),
        include_policies=dict(type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)
    include_members = module.params["include_members"]
    include_policies = module.params["include_policies"]

    try:
        if module.params.get("group_id"):
            group = api.get("/agent-groups/{0}".format(module.params["group_id"]))
            group = enrich_group(api, group, include_members, include_policies)
            module.exit_json(changed=False, groups=[group], count=1)

        params = {}
        if module.params.get("name"):
            params["name"] = module.params["name"]
        if module.params.get("membership_type"):
            params["membership_type"] = module.params["membership_type"]

        groups = api.list_paginated("/agent-groups", params=params)

        if include_members or include_policies:
            groups = [
                enrich_group(api, g, include_members, include_policies)
                for g in groups
            ]

        module.exit_json(changed=False, groups=groups, count=len(groups))

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
