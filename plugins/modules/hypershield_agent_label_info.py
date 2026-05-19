#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent_label_info
short_description: Query Cisco Hypershield agent labels
version_added: "1.0.0"
description:
  - Retrieve information about Cisco Hypershield labels.
  - This is a read-only module that does not modify any resources.
author:
  - Steve Fulmer (@stevefulmer)
options:
  agent_id:
    description:
      - Filter labels by agent ID.
    type: str
  key:
    description:
      - Filter labels by key name.
    type: str
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all labels
  stevefulme1.cisco_hypershield.hypershield_agent_label_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: result

- name: Get labels for a specific agent
  stevefulme1.cisco_hypershield.hypershield_agent_label_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: example-id-123
  register: result
"""

RETURN = r"""
labels:
  description: List of labels matching the query.
  returned: always
  type: list
  elements: dict
count:
  description: Number of results returned.
  returned: always
  type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        agent_id=dict(type="str"),
        key=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        params = {}
        if module.params.get("agent_id"):
            params["agent_id"] = module.params["agent_id"]
        if module.params.get("key"):
            params["key"] = module.params["key"]

        if module.params.get("agent_id"):
            result = api.get("/agents/labels/{0}".format(module.params["agent_id"]))
            module.exit_json(changed=False, labels=[result], count=1)

        results = api.list_paginated("/agents/labels", params=params)
        module.exit_json(changed=False, labels=results, count=len(results))
    except HypershieldError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
