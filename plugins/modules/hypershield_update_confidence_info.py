#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_update_confidence_info
short_description: Query Cisco Hypershield update confidence scores
version_added: "1.0.0"
description:
  - Retrieve information about Cisco Hypershield confidence scores.
  - This is a read-only module that does not modify any resources.
author:
  - Steve Fulmer (@stevefulmer)
options:
  update_id:
    description:
      - Filter confidence scores by update ID.
    type: str
  min_score:
    description:
      - Return only scores above this threshold.
    type: int
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all confidence scores
  stevefulme1.cisco_hypershield.hypershield_update_confidence_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: result

- name: Get confidence scores for a specific update
  stevefulme1.cisco_hypershield.hypershield_update_confidence_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    update_id: example-id-123
  register: result
"""

RETURN = r"""
confidence_scores:
  description: List of confidence scores matching the query.
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
        min_score=dict(type="int"),
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
        if module.params.get("min_score") is not None:
            params["min_score"] = module.params["min_score"]

        if module.params.get("update_id"):
            result = api.get("/updates/confidence/{0}".format(module.params["update_id"]))
            module.exit_json(changed=False, confidence_scores=[result], count=1)

        results = api.list_paginated("/updates/confidence", params=params)
        module.exit_json(changed=False, confidence_scores=results, count=len(results))
    except HypershieldError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
