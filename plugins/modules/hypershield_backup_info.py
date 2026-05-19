#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_backup_info
short_description: Query Cisco Hypershield backup configurations
version_added: "1.0.0"
description:
  - Retrieve information about Cisco Hypershield backups.
  - This is a read-only module that does not modify any resources.
author:
  - Steve Fulmer (@stevefulmer)
options:
  backup_id:
    description:
      - Retrieve a single backup by ID.
    type: str
  backup_name:
    description:
      - Filter backups by name.
    type: str
  status:
    description:
      - Filter by backup status.
    type: str
    choices: ['completed', 'in_progress', 'failed']
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: List all backups
  stevefulme1.cisco_hypershield.hypershield_backup_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: result

- name: Get backups for a specific backup
  stevefulme1.cisco_hypershield.hypershield_backup_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    backup_id: example-id-123
  register: result
"""

RETURN = r"""
backups:
  description: List of backups matching the query.
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
        backup_id=dict(type="str"),
        backup_name=dict(type="str"),
        status=dict(type="str", choices=['completed', 'in_progress', 'failed']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        params = {}
        if module.params.get("backup_id"):
            params["backup_id"] = module.params["backup_id"]
        if module.params.get("backup_name"):
            params["backup_name"] = module.params["backup_name"]
        if module.params.get("status"):
            params["status"] = module.params["status"]

        if module.params.get("backup_id"):
            result = api.get("/backups/{0}".format(module.params["backup_id"]))
            module.exit_json(changed=False, backups=[result], count=1)

        results = api.list_paginated("/backups", params=params)
        module.exit_json(changed=False, backups=results, count=len(results))
    except HypershieldError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
