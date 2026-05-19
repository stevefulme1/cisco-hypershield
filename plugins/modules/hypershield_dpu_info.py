#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_dpu_info
short_description: Query NVIDIA BlueField DPU status and configuration
version_added: "1.0.0"
description:
  - Retrieve DPU hardware status, firmware version, and offload configuration.
  - Can query a specific agent's DPU or list all DPU-equipped agents.
  - Returns detailed hardware information and offload statistics.
author:
  - Steve Fulmer (@stevefulmer)
options:
  agent_id:
    description:
      - Retrieve DPU information for a specific agent.
    type: str
  group_id:
    description:
      - Retrieve DPU information for all agents in a group.
    type: str
  dpu_capable_only:
    description:
      - When listing across a fleet, only return agents with DPU hardware.
    type: bool
    default: true
  include_statistics:
    description:
      - Whether to include offload performance statistics.
      - Includes flow counts, throughput, and CPU savings metrics.
    type: bool
    default: false
  include_firmware:
    description:
      - Whether to include detailed firmware information.
    type: bool
    default: false
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Get DPU info for a specific agent
  stevefulme1.cisco_hypershield.hypershield_dpu_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
    include_statistics: true
  register: dpu_info

- name: List all DPU-capable agents with firmware details
  stevefulme1.cisco_hypershield.hypershield_dpu_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    include_firmware: true
  register: all_dpus

- name: Get DPU status for a group
  stevefulme1.cisco_hypershield.hypershield_dpu_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    group_id: grp-web-servers
    include_statistics: true
    include_firmware: true
  register: group_dpus
"""

RETURN = r"""
dpus:
  description: List of DPU information objects.
  returned: always
  type: list
  elements: dict
  contains:
    agent_id:
      description: Associated agent identifier.
      type: str
    agent_name:
      description: Associated agent display name.
      type: str
    enabled:
      description: Whether DPU offload is enabled.
      type: bool
    offload_mode:
      description: Current offload mode.
      type: str
    hardware:
      description: DPU hardware information.
      type: dict
      contains:
        model:
          description: BlueField DPU model.
          type: str
        cores:
          description: Number of ARM cores.
          type: int
        memory_gb:
          description: DPU memory in gigabytes.
          type: int
    firmware:
      description: Firmware details (when include_firmware is true).
      type: dict
    statistics:
      description: Offload performance statistics (when include_statistics is true).
      type: dict
count:
  description: Number of DPU records returned.
  returned: always
  type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def enrich_dpu(api, dpu, include_statistics, include_firmware):
    """Add statistics and firmware details to a DPU record."""
    agent_id = dpu.get("agent_id")
    if include_statistics:
        try:
            stats = api.get("/agents/{0}/dpu/statistics".format(agent_id))
            dpu["statistics"] = stats
        except HypershieldError:
            dpu["statistics"] = {}

    if include_firmware:
        try:
            fw = api.get("/agents/{0}/dpu/firmware".format(agent_id))
            dpu["firmware"] = fw
        except HypershieldError:
            dpu["firmware"] = {}

    return dpu


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        agent_id=dict(type="str"),
        group_id=dict(type="str"),
        dpu_capable_only=dict(type="bool", default=True),
        include_statistics=dict(type="bool", default=False),
        include_firmware=dict(type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("agent_id", "group_id"),
        ],
    )

    api = HypershieldAPI(module)
    include_stats = module.params["include_statistics"]
    include_fw = module.params["include_firmware"]

    try:
        if module.params.get("agent_id"):
            agent_id = module.params["agent_id"]
            dpu = api.get("/agents/{0}/dpu".format(agent_id))
            dpu["agent_id"] = agent_id
            dpu = enrich_dpu(api, dpu, include_stats, include_fw)
            module.exit_json(changed=False, dpus=[dpu], count=1)

        params = {}
        if module.params.get("group_id"):
            params["group_id"] = module.params["group_id"]
        if module.params["dpu_capable_only"]:
            params["dpu_capable"] = True

        agents = api.list_paginated("/agents", params=params)
        dpus = []
        for agent in agents:
            if not module.params["dpu_capable_only"] or agent.get("dpu_capable", False):
                try:
                    dpu = api.get("/agents/{0}/dpu".format(agent["id"]))
                    dpu["agent_id"] = agent["id"]
                    dpu["agent_name"] = agent.get("name", "")
                    dpu = enrich_dpu(api, dpu, include_stats, include_fw)
                    dpus.append(dpu)
                except HypershieldError:
                    continue

        module.exit_json(changed=False, dpus=dpus, count=len(dpus))

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
