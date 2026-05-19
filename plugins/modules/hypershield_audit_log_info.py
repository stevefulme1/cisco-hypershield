# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_audit_log_info
short_description: Query Cisco Hypershield audit logs
description:
  - Retrieve audit log entries for configuration changes, policy modifications,
    administrative actions, and system events.
  - Filter by action type, user, resource, and time range.
  - This is an info module and makes no changes.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  action_type:
    description:
      - Filter audit logs by action type.
    type: str
    choices: [create, update, delete, login, logout, execute, approve, deny, restore]
  resource_type:
    description:
      - Filter by the type of resource that was acted upon.
    type: str
    choices: [policy, zone, agent, integration, user, role, backup, campaign, telemetry]
  resource_id:
    description:
      - Filter by specific resource identifier.
    type: str
  user:
    description:
      - Filter by the user who performed the action.
    type: str
  since:
    description:
      - Return logs after this ISO 8601 timestamp.
    type: str
  until:
    description:
      - Return logs before this ISO 8601 timestamp.
    type: str
  severity:
    description:
      - Filter by log entry severity.
    type: str
    choices: [info, warning, critical]
  source_ip:
    description:
      - Filter by source IP address of the action.
    type: str
  include_details:
    description:
      - Include full change details (before/after values) for each entry.
    type: bool
    default: false
  limit:
    description:
      - Maximum number of audit log entries to return.
    type: int
    default: 100
  sort_order:
    description:
      - Sort order for results.
    type: str
    choices: [asc, desc]
    default: desc
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Get all audit logs from the last 24 hours
  stevefulme1.cisco_hypershield.hypershield_audit_log_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    since: "2026-05-18T00:00:00Z"
  register: recent_logs

- name: Get policy changes by a specific user
  stevefulme1.cisco_hypershield.hypershield_audit_log_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    resource_type: policy
    action_type: update
    user: admin@example.com
    include_details: true
  register: policy_changes

- name: Get all delete actions with details
  stevefulme1.cisco_hypershield.hypershield_audit_log_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    action_type: delete
    include_details: true
    limit: 50
  register: deletions

- name: Get critical severity audit events
  stevefulme1.cisco_hypershield.hypershield_audit_log_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    severity: critical
    since: "2026-05-01T00:00:00Z"
  register: critical_events

- name: Audit trail for a specific resource
  stevefulme1.cisco_hypershield.hypershield_audit_log_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    resource_type: zone
    resource_id: "zone-prod-123"
    sort_order: asc
  register: resource_history
"""

RETURN = r"""
audit_logs:
  description: List of audit log entries matching the query.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Audit log entry unique identifier.
      type: str
    timestamp:
      description: When the action occurred.
      type: str
    action_type:
      description: Type of action performed.
      type: str
    resource_type:
      description: Type of resource acted upon.
      type: str
    resource_id:
      description: Identifier of the affected resource.
      type: str
    resource_name:
      description: Human-readable name of the affected resource.
      type: str
    user:
      description: User who performed the action.
      type: str
    source_ip:
      description: IP address from which the action was performed.
      type: str
    severity:
      description: Log entry severity.
      type: str
    result:
      description: Action result (success, failure, denied).
      type: str
    details:
      description: Change details with before/after values.
      type: dict
      returned: when I(include_details) is true
total:
  description: Total number of audit log entries matching the query.
  returned: always
  type: int
summary:
  description: Summary of audit log entries by action type.
  returned: always
  type: dict
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
        action_type=dict(
            type="str",
            choices=["create", "update", "delete", "login", "logout", "execute", "approve", "deny", "restore"],
        ),
        resource_type=dict(
            type="str",
            choices=["policy", "zone", "agent", "integration", "user", "role", "backup", "campaign", "telemetry"],
        ),
        resource_id=dict(type="str"),
        user=dict(type="str"),
        since=dict(type="str"),
        until=dict(type="str"),
        severity=dict(type="str", choices=["info", "warning", "critical"]),
        source_ip=dict(type="str"),
        include_details=dict(type="bool", default=False),
        limit=dict(type="int", default=100),
        sort_order=dict(type="str", default="desc", choices=["asc", "desc"]),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api = HypershieldAPI(module)
    result = dict(changed=False, audit_logs=[], total=0, summary={})

    try:
        params = {
            "limit": module.params["limit"],
            "sort_order": module.params["sort_order"],
            "include_details": module.params["include_details"],
        }
        optional_keys = (
            "action_type", "resource_type", "resource_id",
            "user", "since", "until", "severity", "source_ip",
        )
        for key in optional_keys:
            if module.params.get(key):
                params[key] = module.params[key]

        data = api.get("/audit/logs", params=params)
        logs = data.get("items", [])
        result["audit_logs"] = logs
        result["total"] = data.get("total", len(logs))

        # Build summary by action type
        summary = {}
        for entry in logs:
            action = entry.get("action_type", "unknown")
            summary[action] = summary.get(action, 0) + 1
        result["summary"] = summary

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
