#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_compliance_report_info
short_description: Query Cisco Hypershield compliance reports
version_added: "1.0.0"
description:
  - Retrieve information about Cisco Hypershield reports.
  - This is a read-only module that does not modify any resources.
author:
  - Steve Fulmer (@stevefulmer)
options:
  report_id:
    description:
      - Retrieve a single report by ID.
    type: str
  standard:
    description:
      - Filter by compliance standard.
    type: str
  status:
    description:
      - Filter by report status.
    type: str
    choices: ['compliant', 'non_compliant', 'in_progress']
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all reports
  stevefulme1.cisco_hypershield.hypershield_compliance_report_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: result

- name: Get reports for a specific report
  stevefulme1.cisco_hypershield.hypershield_compliance_report_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    report_id: example-id-123
  register: result
"""

RETURN = r"""
reports:
  description: List of reports matching the query.
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
        report_id=dict(type="str"),
        standard=dict(type="str"),
        status=dict(type="str", choices=['compliant', 'non_compliant', 'in_progress']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        params = {}
        if module.params.get("report_id"):
            params["report_id"] = module.params["report_id"]
        if module.params.get("standard"):
            params["standard"] = module.params["standard"]
        if module.params.get("status"):
            params["status"] = module.params["status"]

        if module.params.get("report_id"):
            result = api.get("/compliance/reports/{0}".format(module.params["report_id"]))
            module.exit_json(changed=False, reports=[result], count=1)

        results = api.list_paginated("/compliance/reports", params=params)
        module.exit_json(changed=False, reports=results, count=len(results))
    except HypershieldError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
