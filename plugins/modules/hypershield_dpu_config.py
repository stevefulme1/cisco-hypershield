#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_dpu_config
short_description: Configure NVIDIA BlueField DPU security offload for Hypershield agents
version_added: "1.0.0"
description:
  - Configure Data Processing Unit (DPU) settings on agents with NVIDIA BlueField hardware.
  - Manages security function offloading from host CPU to DPU for line-rate enforcement.
  - Supports configuring flow classification, encryption offload, and microsegmentation.
author:
  - Steve Fulmer (@stevefulmer)
options:
  agent_id:
    description:
      - ID of the agent whose DPU to configure.
    type: str
    required: true
  state:
    description:
      - Whether the DPU offload should be enabled or disabled.
    type: str
    choices: [present, absent]
    default: present
  offload_mode:
    description:
      - DPU offload operating mode.
      - C(full) offloads all supported security functions to the DPU.
      - C(selective) allows choosing specific functions to offload.
      - C(monitor) offloads in observation-only mode.
    type: str
    choices: [full, selective, monitor]
    default: full
  offload_functions:
    description:
      - List of security functions to offload when I(offload_mode=selective).
      - Ignored when I(offload_mode) is C(full) or C(monitor).
    type: list
    elements: str
    choices: [flow_classification, encryption, microsegmentation, intrusion_detection, traffic_mirroring]
  flow_table_size:
    description:
      - Maximum number of flow entries in the DPU flow table.
      - Higher values use more DPU memory but support more concurrent flows.
    type: int
    default: 100000
  encryption_offload:
    description:
      - Whether to offload TLS/IPsec encryption to the DPU hardware.
    type: bool
    default: true
  microsegmentation:
    description:
      - Whether to enable microsegmentation enforcement on the DPU.
    type: bool
    default: true
  firmware_channel:
    description:
      - DPU firmware update channel.
    type: str
    choices: [stable, preview, lts]
    default: stable
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Enable full DPU offload on an agent
  stevefulme1.cisco_hypershield.hypershield_dpu_config:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
    state: present
    offload_mode: full
    flow_table_size: 200000

- name: Enable selective DPU offload
  stevefulme1.cisco_hypershield.hypershield_dpu_config:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
    offload_mode: selective
    offload_functions:
      - flow_classification
      - encryption
      - microsegmentation

- name: Disable DPU offload
  stevefulme1.cisco_hypershield.hypershield_dpu_config:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
    state: absent
"""

RETURN = r"""
dpu_config:
  description: The DPU configuration after the operation.
  returned: success
  type: dict
  contains:
    agent_id:
      description: Agent identifier.
      type: str
    enabled:
      description: Whether DPU offload is enabled.
      type: bool
    offload_mode:
      description: Current offload mode.
      type: str
    offload_functions:
      description: List of offloaded functions.
      type: list
    flow_table_size:
      description: Configured flow table size.
      type: int
    encryption_offload:
      description: Whether encryption offload is enabled.
      type: bool
    microsegmentation:
      description: Whether microsegmentation is enabled.
      type: bool
    firmware_version:
      description: Current DPU firmware version.
      type: str
    firmware_channel:
      description: Firmware update channel.
      type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def build_dpu_payload(module):
    """Build the DPU configuration payload."""
    payload = {
        "offload_mode": module.params["offload_mode"],
        "flow_table_size": module.params["flow_table_size"],
        "encryption_offload": module.params["encryption_offload"],
        "microsegmentation": module.params["microsegmentation"],
        "firmware_channel": module.params["firmware_channel"],
    }
    if module.params["offload_mode"] == "selective" and module.params.get("offload_functions"):
        payload["offload_functions"] = module.params["offload_functions"]
    return payload


def configs_differ(existing, desired):
    """Check if the existing DPU config differs from the desired state."""
    for key, value in desired.items():
        if value is not None and existing.get(key) != value:
            return True
    return False


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        agent_id=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        offload_mode=dict(type="str", default="full", choices=["full", "selective", "monitor"]),
        offload_functions=dict(
            type="list", elements="str",
            choices=[
                "flow_classification", "encryption",
                "microsegmentation", "intrusion_detection",
                "traffic_mirroring",
            ],
        ),
        flow_table_size=dict(type="int", default=100000),
        encryption_offload=dict(type="bool", default=True),
        microsegmentation=dict(type="bool", default=True),
        firmware_channel=dict(type="str", default="stable", choices=["stable", "preview", "lts"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("offload_mode", "selective", ["offload_functions"]),
        ],
    )

    api = HypershieldAPI(module)
    agent_id = module.params["agent_id"]
    state = module.params["state"]
    result = dict(changed=False)
    dpu_path = "/agents/{0}/dpu".format(agent_id)

    try:
        try:
            existing = api.get(dpu_path)
        except HypershieldError:
            existing = None

        if state == "absent":
            if existing and existing.get("enabled", False):
                result["changed"] = True
                result["diff"] = dict(before=existing, after={"enabled": False})
                if not module.check_mode:
                    config = api.put(dpu_path, data={"enabled": False})
                    result["dpu_config"] = config
                else:
                    result["dpu_config"] = {"enabled": False}
            else:
                result["dpu_config"] = existing or {"enabled": False}
            module.exit_json(**result)

        # state == present
        payload = build_dpu_payload(module)
        payload["enabled"] = True

        if existing:
            if not existing.get("enabled") or configs_differ(existing, payload):
                result["changed"] = True
                result["diff"] = dict(before=existing, after=payload)
                if not module.check_mode:
                    config = api.put(dpu_path, data=payload)
                    result["dpu_config"] = config
                else:
                    result["dpu_config"] = payload
            else:
                result["dpu_config"] = existing
        else:
            result["changed"] = True
            if not module.check_mode:
                config = api.put(dpu_path, data=payload)
                result["dpu_config"] = config
            else:
                result["dpu_config"] = payload

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
