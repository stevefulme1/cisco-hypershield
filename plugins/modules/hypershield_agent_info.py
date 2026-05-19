#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent_info
short_description: Query Cisco Hypershield agent status and information
version_added: "1.0.0"
description:
  - Retrieve information about one or more Tesseract Security Agents.
  - Can query by agent ID, name, host, status, group, or labels.
  - Returns detailed agent metadata including version, health, and enforcement mode.
author:
  - Steve Fulmer (@stevefulmer)
options:
  agent_id:
    description:
      - Retrieve a single agent by its unique ID.
    type: str
  name:
    description:
      - Filter agents by display name (exact match).
    type: str
  host:
    description:
      - Filter agents by host IP or FQDN.
    type: str
  status:
    description:
      - Filter agents by their current status.
    type: str
    choices: [running, stopped, error, deploying, upgrading, unknown]
  group_id:
    description:
      - Filter agents by group membership.
    type: str
  label_selector:
    description:
      - Filter agents by labels.
      - Dictionary of key-value pairs that must all match.
    type: dict
  include_health:
    description:
      - Whether to include detailed health check data for each agent.
      - Increases response time for large fleets.
    type: bool
    default: false
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Get info about a specific agent
  stevefulme1.cisco_hypershield.hypershield_agent_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
  register: agent_result

- name: List all running agents in production
  stevefulme1.cisco_hypershield.hypershield_agent_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    status: running
    label_selector:
      environment: production
  register: prod_agents

- name: List all agents with health data
  stevefulme1.cisco_hypershield.hypershield_agent_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    include_health: true
  register: all_agents

- name: Find agents in a specific group
  stevefulme1.cisco_hypershield.hypershield_agent_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    group_id: grp-web-servers
  register: group_agents
"""

RETURN = r"""
agents:
  description: List of agent objects matching the query.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Unique agent identifier.
      type: str
    name:
      description: Display name.
      type: str
    host:
      description: Host address.
      type: str
    status:
      description: Current agent status.
      type: str
    version:
      description: Installed agent version.
      type: str
    enforcement_mode:
      description: Current enforcement mode.
      type: str
    labels:
      description: Labels assigned to the agent.
      type: dict
    health:
      description: Health check details (when include_health is true).
      type: dict
count:
  description: Number of agents returned.
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
        agent_id=dict(type="str"),
        name=dict(type="str"),
        host=dict(type="str"),
        status=dict(type="str", choices=["running", "stopped", "error", "deploying", "upgrading", "unknown"]),
        group_id=dict(type="str"),
        label_selector=dict(type="dict"),
        include_health=dict(type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    api = HypershieldAPI(module)

    try:
        if module.params.get("agent_id"):
            agent = api.get("/agents/{0}".format(module.params["agent_id"]))
            if module.params.get("include_health"):
                try:
                    health = api.get("/agents/{0}/health".format(agent["id"]))
                    agent["health"] = health
                except HypershieldError:
                    agent["health"] = {"status": "unknown", "error": "Health data unavailable"}
            module.exit_json(changed=False, agents=[agent], count=1)

        params = {}
        for key in ("name", "host", "status", "group_id"):
            value = module.params.get(key)
            if value:
                params[key] = value

        if module.params.get("label_selector"):
            for lk, lv in module.params["label_selector"].items():
                params["label.{0}".format(lk)] = lv

        agents = api.list_paginated("/agents", params=params)

        if module.params.get("include_health"):
            for agent in agents:
                try:
                    health = api.get("/agents/{0}/health".format(agent["id"]))
                    agent["health"] = health
                except HypershieldError:
                    agent["health"] = {"status": "unknown", "error": "Health data unavailable"}

        module.exit_json(changed=False, agents=agents, count=len(agents))

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
