#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_dpu_config_info
short_description: Query Cisco Hypershield DPU configuration
version_added: "1.0.0"
description:
  - Retrieve information about Cisco Hypershield dpu configs.
  - This is a read-only module that does not modify any resources.
author:
  - Steve Fulmer (@stevefulmer)
options:
  dpu_id:
    description:
      - Retrieve configuration for a specific DPU.
    type: str
  status:
    description:
      - Filter by DPU status.
    type: str
    choices: ['active', 'standby', 'error']
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all dpu configs
  stevefulme1.cisco_hypershield.hypershield_dpu_config_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: result

- name: Get dpu configs for a specific dpu
  stevefulme1.cisco_hypershield.hypershield_dpu_config_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    dpu_id: example-id-123
  register: result
"""

RETURN = r"""
dpu_configs:
  description: List of dpu configs matching the query.
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
        dpu_id=dict(type="str"),
        status=dict(type="str", choices=['active', 'standby', 'error']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        params = {}
        if module.params.get("dpu_id"):
            params["dpu_id"] = module.params["dpu_id"]
        if module.params.get("status"):
            params["status"] = module.params["status"]

        if module.params.get("dpu_id"):
            result = api.get("/dpus/configs/{0}".format(module.params["dpu_id"]))
            module.exit_json(changed=False, dpu_configs=[result], count=1)

        results = api.list_paginated("/dpus/configs", params=params)
        module.exit_json(changed=False, dpu_configs=results, count=len(results))
    except HypershieldError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
