# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_backup
short_description: Backup and restore Cisco Hypershield configuration
description:
  - Create, manage, and restore backups of Hypershield configuration including
    policies, network zones, agent configurations, and integration settings.
  - Supports full and selective backup scopes.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  state:
    description:
      - Desired state of the backup operation.
      - C(present) creates a new backup.
      - C(absent) removes an existing backup.
      - C(restored) restores from an existing backup.
    type: str
    choices: [present, absent, restored]
    default: present
  backup_name:
    description:
      - Name for the backup.
    type: str
    required: true
  backup_id:
    description:
      - ID of an existing backup (required for I(state=restored) or I(state=absent)).
    type: str
  description:
    description:
      - Human-readable description for the backup.
    type: str
    default: ""
  scope:
    description:
      - What to include in the backup.
    type: list
    elements: str
    choices: [policies, zones, agents, integrations, telemetry, all]
    default: [all]
  encryption_enabled:
    description:
      - Encrypt the backup data.
    type: bool
    default: true
  encryption_passphrase:
    description:
      - Passphrase for backup encryption.
      - Required when I(encryption_enabled) is true and I(state) is C(present) or C(restored).
    type: str
    no_log: true
  retention_days:
    description:
      - Number of days to retain the backup before automatic deletion.
      - Set to 0 for indefinite retention.
    type: int
    default: 90
  restore_scope:
    description:
      - Specific components to restore from the backup.
      - If omitted during restore, all components in the backup are restored.
    type: list
    elements: str
    choices: [policies, zones, agents, integrations, telemetry]
  wait:
    description:
      - Wait for backup or restore operation to complete.
    type: bool
    default: true
  wait_timeout:
    description:
      - Maximum time in seconds to wait for operation completion.
    type: int
    default: 600
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Create a full encrypted backup
  stevefulme1.cisco_hypershield.hypershield_backup:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    backup_name: full-backup-2026-05
    description: "Monthly full backup"
    scope:
      - all
    encryption_passphrase: "{{ vault_backup_passphrase }}"
    retention_days: 365

- name: Restore from a backup
  stevefulme1.cisco_hypershield.hypershield_backup:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    backup_name: full-backup-2026-05
    backup_id: "bkp-abc123"
    state: restored
    encryption_passphrase: "{{ vault_backup_passphrase }}"

- name: Remove an old backup
  stevefulme1.cisco_hypershield.hypershield_backup:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    backup_name: old-backup
    backup_id: "bkp-old123"
    state: absent
"""

RETURN = r"""
backup:
  description: Backup object details.
  returned: success
  type: dict
  contains:
    id:
      description: Backup unique identifier.
      type: str
    name:
      description: Backup name.
      type: str
    status:
      description: Backup status (creating, completed, failed, restoring, restored).
      type: str
    scope:
      description: Components included in the backup.
      type: list
      elements: str
    size_bytes:
      description: Backup size in bytes.
      type: int
    created_at:
      description: Backup creation timestamp.
      type: str
restore_result:
  description: Restore operation result with status and restored components.
  returned: when I(state=restored)
  type: dict
"""

import time

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def find_backup(api, name):
    """Find a backup by name."""
    backups = api.get("/backups", params={"name": name})
    items = backups.get("items", [])
    return items[0] if items else None


def wait_for_operation(api, backup_id, timeout):
    """Poll backup status until operation completes."""
    start = time.time()
    while time.time() - start < timeout:
        backup = api.get("/backups/{0}".format(backup_id))
        if backup.get("status") in ("completed", "failed", "restored"):
            return backup
        time.sleep(10)
    return None


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        state=dict(type="str", default="present", choices=["present", "absent", "restored"]),
        backup_name=dict(type="str", required=True),
        backup_id=dict(type="str"),
        description=dict(type="str", default=""),
        scope=dict(type="list", elements="str", default=["all"],
                   choices=["policies", "zones", "agents", "integrations", "telemetry", "all"]),
        encryption_enabled=dict(type="bool", default=True),
        encryption_passphrase=dict(type="str", no_log=True),
        retention_days=dict(type="int", default=90),
        restore_scope=dict(type="list", elements="str",
                           choices=["policies", "zones", "agents", "integrations", "telemetry"]),
        wait=dict(type="bool", default=True),
        wait_timeout=dict(type="int", default=600),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "absent", ("backup_id",)),
            ("state", "restored", ("backup_id",)),
        ],
    )
    api = HypershieldAPI(module)
    state = module.params["state"]
    result = dict(changed=False, backup={})

    try:
        if state == "absent":
            existing = api.get("/backups/{0}".format(module.params["backup_id"]))
            if existing:
                if not module.check_mode:
                    api.delete("/backups/{0}".format(module.params["backup_id"]))
                result["changed"] = True
            module.exit_json(**result)

        if state == "restored":
            if module.check_mode:
                result["changed"] = True
                module.exit_json(**result)

            restore_payload = {}
            if module.params.get("encryption_passphrase"):
                restore_payload["passphrase"] = module.params["encryption_passphrase"]
            if module.params.get("restore_scope"):
                restore_payload["scope"] = module.params["restore_scope"]

            restore = api.post(
                "/backups/{0}/restore".format(module.params["backup_id"]),
                data=restore_payload,
            )

            if module.params["wait"]:
                final = wait_for_operation(api, module.params["backup_id"], module.params["wait_timeout"])
                if final:
                    result["backup"] = final
                else:
                    module.fail_json(msg="Restore timed out", **result)
            else:
                result["backup"] = restore

            result["restore_result"] = restore.get("restore_result", restore)
            result["changed"] = True
            module.exit_json(**result)

        # state == present
        if module.check_mode:
            result["changed"] = True
            module.exit_json(**result)

        payload = {
            "name": module.params["backup_name"],
            "description": module.params["description"],
            "scope": module.params["scope"],
            "encryption_enabled": module.params["encryption_enabled"],
            "retention_days": module.params["retention_days"],
        }
        if module.params.get("encryption_passphrase"):
            payload["passphrase"] = module.params["encryption_passphrase"]

        backup = api.post("/backups", data=payload)
        result["changed"] = True

        if module.params["wait"] and backup.get("id"):
            final = wait_for_operation(api, backup["id"], module.params["wait_timeout"])
            if final:
                result["backup"] = final
                if final.get("status") == "failed":
                    module.fail_json(msg="Backup creation failed", **result)
            else:
                module.fail_json(msg="Backup timed out", **result)
        else:
            result["backup"] = backup

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
