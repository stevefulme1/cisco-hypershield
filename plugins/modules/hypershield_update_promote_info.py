#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_update_promote_info
short_description: Query Cisco Hypershield update promotion status
version_added: "1.0.0"
description:
  - Retrieve information about Cisco Hypershield promotions.
  - This is a read-only module that does not modify any resources.
author:
  - Steve Fulmer (@stevefulmer)
options:
  update_id:
    description:
      - Filter promotions by update ID.
    type: str
  status:
    description:
      - Filter by promotion status.
    type: str
    choices: ['pending', 'approved', 'promoted', 'rejected']
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all promotions
  stevefulme1.cisco_hypershield.hypershield_update_promote_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: result

- name: Get promotions for a specific update
  stevefulme1.cisco_hypershield.hypershield_update_promote_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    update_id: example-id-123
  register: result
"""

RETURN = r"""
promotions:
  description: List of promotions matching the query.
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
        update_id=dict(type="str"),
        status=dict(type="str", choices=['pending', 'approved', 'promoted', 'rejected']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        params = {}
        if module.params.get("update_id"):
            params["update_id"] = module.params["update_id"]
        if module.params.get("status"):
            params["status"] = module.params["status"]

        if module.params.get("update_id"):
            result = api.get("/updates/promotions/{0}".format(module.params["update_id"]))
            module.exit_json(changed=False, promotions=[result], count=1)

        results = api.list_paginated("/updates/promotions", params=params)
        module.exit_json(changed=False, promotions=results, count=len(results))
    except HypershieldError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
