# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_telemetry
short_description: Configure Cisco Hypershield telemetry collection and export
description:
  - Manage telemetry collection settings including flow logs, process events,
    sampling rates, export destinations, and retention policies.
  - Supports configuring multiple export destinations simultaneously.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  state:
    description:
      - Desired state of the telemetry configuration.
    type: str
    choices: [present, absent]
    default: present
  name:
    description:
      - Unique name for this telemetry configuration.
    type: str
    required: true
  flow_logs:
    description:
      - Enable flow log collection.
    type: bool
    default: true
  process_events:
    description:
      - Enable process lifecycle event collection.
    type: bool
    default: true
  file_events:
    description:
      - Enable file system event collection.
    type: bool
    default: false
  network_events:
    description:
      - Enable network connection event collection.
    type: bool
    default: true
  sampling_rate:
    description:
      - Sampling rate for telemetry data (1-100 percent).
    type: int
    default: 100
  destinations:
    description:
      - List of export destinations for telemetry data.
    type: list
    elements: dict
    suboptions:
      type:
        description:
          - Destination type.
        type: str
        choices: [syslog, splunk, s3, kafka, otlp]
        required: true
      endpoint:
        description:
          - Destination endpoint URL or address.
        type: str
        required: true
      format:
        description:
          - Data export format.
        type: str
        choices: [json, cef, leef, otlp]
        default: json
      tls_enabled:
        description:
          - Enable TLS for the destination connection.
        type: bool
        default: true
  retention_days:
    description:
      - Number of days to retain telemetry data locally.
    type: int
    default: 30
  scope:
    description:
      - Scope of enforcement points for telemetry collection.
    type: str
    choices: [all, zone, group]
    default: all
  scope_filter:
    description:
      - Filter expression when I(scope) is C(zone) or C(group).
    type: str
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Configure full telemetry with Splunk export
  stevefulme1.cisco_hypershield.hypershield_telemetry:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: production-telemetry
    flow_logs: true
    process_events: true
    network_events: true
    sampling_rate: 100
    destinations:
      - type: splunk
        endpoint: https://splunk.example.com:8088
        format: json
        tls_enabled: true
    retention_days: 90

- name: Remove telemetry configuration
  stevefulme1.cisco_hypershield.hypershield_telemetry:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: dev-telemetry
    state: absent
"""

RETURN = r"""
telemetry:
  description: The telemetry configuration object.
  returned: success
  type: dict
  contains:
    id:
      description: Configuration unique identifier.
      type: str
    name:
      description: Configuration name.
      type: str
    flow_logs:
      description: Flow log collection enabled.
      type: bool
    process_events:
      description: Process event collection enabled.
      type: bool
    sampling_rate:
      description: Sampling rate percentage.
      type: int
    destinations:
      description: Configured export destinations.
      type: list
      elements: dict
    status:
      description: Configuration operational status.
      type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def find_config(api, name):
    """Find a telemetry configuration by name."""
    configs = api.get("/telemetry/configs", params={"name": name})
    items = configs.get("items", [])
    return items[0] if items else None


def build_payload(params):
    """Build API payload from module parameters."""
    payload = {
        "name": params["name"],
        "flow_logs": params["flow_logs"],
        "process_events": params["process_events"],
        "file_events": params["file_events"],
        "network_events": params["network_events"],
        "sampling_rate": params["sampling_rate"],
        "retention_days": params["retention_days"],
        "scope": params["scope"],
    }
    if params.get("destinations"):
        payload["destinations"] = params["destinations"]
    if params.get("scope_filter"):
        payload["scope_filter"] = params["scope_filter"]
    return payload


def configs_differ(existing, desired):
    """Check if existing config differs from desired state."""
    for key in ("flow_logs", "process_events", "file_events", "network_events",
                "sampling_rate", "retention_days", "scope"):
        if existing.get(key) != desired.get(key):
            return True
    if desired.get("destinations") and existing.get("destinations") != desired["destinations"]:
        return True
    return False


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        name=dict(type="str", required=True),
        flow_logs=dict(type="bool", default=True),
        process_events=dict(type="bool", default=True),
        file_events=dict(type="bool", default=False),
        network_events=dict(type="bool", default=True),
        sampling_rate=dict(type="int", default=100),
        destinations=dict(type="list", elements="dict"),
        retention_days=dict(type="int", default=30),
        scope=dict(type="str", default="all", choices=["all", "zone", "group"]),
        scope_filter=dict(type="str"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api = HypershieldAPI(module)
    state = module.params["state"]
    result = dict(changed=False, telemetry={})

    try:
        existing = find_config(api, module.params["name"])

        if state == "absent":
            if existing:
                if not module.check_mode:
                    api.delete("/telemetry/configs/{0}".format(existing["id"]))
                result["changed"] = True
            module.exit_json(**result)

        # state == present
        desired = build_payload(module.params)
        if existing:
            if configs_differ(existing, desired):
                if not module.check_mode:
                    result["telemetry"] = api.put(
                        "/telemetry/configs/{0}".format(existing["id"]), data=desired
                    )
                result["changed"] = True
            else:
                result["telemetry"] = existing
        else:
            if not module.check_mode:
                result["telemetry"] = api.post("/telemetry/configs", data=desired)
            result["changed"] = True

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
