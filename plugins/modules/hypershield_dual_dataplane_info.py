#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_dual_dataplane_info
short_description: Query Cisco Hypershield dual data plane status
version_added: "1.0.0"
description:
  - Retrieve information about Cisco Hypershield dataplanes.
  - This is a read-only module that does not modify any resources.
author:
  - Steve Fulmer (@stevefulmer)
options:
  node_id:
    description:
      - Filter by node ID.
    type: str
  mode:
    description:
      - Filter by dataplane mode.
    type: str
    choices: ['active_active', 'active_standby', 'single']
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all dataplanes
  stevefulme1.cisco_hypershield.hypershield_dual_dataplane_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: result

- name: Get dataplanes for a specific node
  stevefulme1.cisco_hypershield.hypershield_dual_dataplane_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    node_id: example-id-123
  register: result
"""

RETURN = r"""
dataplanes:
  description: List of dataplanes matching the query.
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
        node_id=dict(type="str"),
        mode=dict(type="str", choices=['active_active', 'active_standby', 'single']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        params = {}
        if module.params.get("node_id"):
            params["node_id"] = module.params["node_id"]
        if module.params.get("mode"):
            params["mode"] = module.params["mode"]

        if module.params.get("node_id"):
            result = api.get("/dual-dataplane/status/{0}".format(module.params["node_id"]))
            module.exit_json(changed=False, dataplanes=[result], count=1)

        results = api.list_paginated("/dual-dataplane/status", params=params)
        module.exit_json(changed=False, dataplanes=results, count=len(results))
    except HypershieldError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
