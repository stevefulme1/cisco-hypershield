#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent_registration_info
short_description: Query Cisco Hypershield agent registration tokens
version_added: "1.0.0"
description:
  - Retrieve information about Cisco Hypershield registration tokens.
  - This is a read-only module that does not modify any resources.
author:
  - Steve Fulmer (@stevefulmer)
options:
  token_id:
    description:
      - Retrieve a single registration token by ID.
    type: str
  status:
    description:
      - Filter by token status.
    type: str
    choices: ['active', 'expired', 'revoked']
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all registration tokens
  stevefulme1.cisco_hypershield.hypershield_agent_registration_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: result

- name: Get registration tokens for a specific token
  stevefulme1.cisco_hypershield.hypershield_agent_registration_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    token_id: example-id-123
  register: result
"""

RETURN = r"""
registration_tokens:
  description: List of registration tokens matching the query.
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
        token_id=dict(type="str"),
        status=dict(type="str", choices=['active', 'expired', 'revoked']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        params = {}
        if module.params.get("token_id"):
            params["token_id"] = module.params["token_id"]
        if module.params.get("status"):
            params["status"] = module.params["status"]

        if module.params.get("token_id"):
            result = api.get("/agents/registration-tokens/{0}".format(module.params["token_id"]))
            module.exit_json(changed=False, registration_tokens=[result], count=1)

        results = api.list_paginated("/agents/registration-tokens", params=params)
        module.exit_json(changed=False, registration_tokens=results, count=len(results))
    except HypershieldError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
