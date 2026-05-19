#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Steve Fulmer <sfulmer@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_microsegmentation_policy_info
short_description: Query Cisco Hypershield microsegmentation policies
version_added: "1.0.0"
description:
  - Retrieve information about microsegmentation policies from a Cisco Hypershield controller.
  - Filter policies by name, zone, application identity, or enforcement status.
  - Returns detailed policy objects including rules, version history, and enforcement state.
author:
  - Steve Fulmer (@stevefulmer)
options:
  name:
    description:
      - Filter by exact policy name. Returns a single policy if found.
    type: str
  zone:
    description:
      - Filter policies by security zone.
    type: str
  app_id:
    description:
      - Filter policies referencing this application identity in any rule.
    type: str
  enforcement_mode:
    description:
      - Filter policies by enforcement mode.
    type: str
    choices: [enforced, dry_run, staged]
  enabled:
    description:
      - Filter by enabled/disabled state.
    type: bool
  include_rules:
    description:
      - Whether to include the full rule definitions in the response.
      - Set to C(false) for summary-only queries to reduce response size.
    type: bool
    default: true
  include_versions:
    description:
      - Whether to include version history metadata.
    type: bool
    default: false
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all microsegmentation policies
  stevefulme1.cisco_hypershield.hypershield_microsegmentation_policy_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: all_policies

- name: Get a specific policy by name
  stevefulme1.cisco_hypershield.hypershield_microsegmentation_policy_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: web-to-db
  register: policy_detail

- name: Find all policies in dry-run mode for the production zone
  stevefulme1.cisco_hypershield.hypershield_microsegmentation_policy_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    zone: production
    enforcement_mode: dry_run
  register: dryrun_policies

- name: Find policies referencing a specific application
  stevefulme1.cisco_hypershield.hypershield_microsegmentation_policy_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    app_id: postgres-primary
    include_versions: true
  register: app_policies
"""

RETURN = r"""
policies:
  description: List of microsegmentation policy objects matching the query.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier of the policy.
      type: str
    name:
      description: Policy name.
      type: str
    description:
      description: Policy description.
      type: str
    zone:
      description: Security zone the policy belongs to.
      type: str
    enforcement_mode:
      description: Current enforcement mode.
      type: str
    enabled:
      description: Whether the policy is enabled.
      type: bool
    version:
      description: Current version number.
      type: int
    rule_count:
      description: Number of rules in the policy.
      type: int
    rules:
      description: List of rules (included when I(include_rules=true)).
      type: list
      elements: dict
    versions:
      description: Version history (included when I(include_versions=true)).
      type: list
      elements: dict
    created_at:
      description: ISO 8601 timestamp of creation.
      type: str
    updated_at:
      description: ISO 8601 timestamp of last update.
      type: str
count:
  description: Total number of policies matching the query.
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
        zone=dict(type="str"),
        app_id=dict(type="str"),
        enforcement_mode=dict(type="str", choices=["enforced", "dry_run", "staged"]),
        enabled=dict(type="bool"),
        include_rules=dict(type="bool", default=True),
        include_versions=dict(type="bool", default=False),
        **HypershieldAPI.hypershield_argument_spec()
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        params = {}
        for field in ("name", "zone", "app_id", "enforcement_mode", "enabled"):
            value = module.params.get(field)
            if value is not None:
                params[field] = value
        if module.params["include_rules"]:
            params["expand"] = "rules"
        if module.params["include_versions"]:
            params["expand"] = params.get("expand", "") + ",versions" if params.get("expand") else "versions"

        policies = api.list_paginated("/microsegmentation/policies", params=params)

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
