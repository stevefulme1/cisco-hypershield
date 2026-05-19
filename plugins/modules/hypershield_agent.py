#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent
short_description: Deploy and manage Cisco Hypershield Tesseract Security Agents
version_added: "1.0.0"
description:
  - Deploy, configure, start, stop, or remove Tesseract Security Agents on target hosts.
  - Manages agent lifecycle through the Hypershield management plane API.
  - Supports idempotent operations with check mode.
author:
  - Steve Fulmer (@stevefulmer)
options:
  agent_id:
    description:
      - Unique identifier of the agent.
      - Required when I(state) is C(absent), C(started), or C(stopped).
    type: str
  name:
    description:
      - Display name for the agent.
      - Required when I(state=present) and the agent does not yet exist.
    type: str
  host:
    description:
      - Target host IP or FQDN where the agent should be deployed.
    type: str
  state:
    description:
      - Desired state of the agent.
    type: str
    choices: [present, absent, started, stopped]
    default: present
  version:
    description:
      - Agent version to deploy or upgrade to.
      - If not specified, the latest available version is used.
    type: str
  enforcement_mode:
    description:
      - Enforcement mode for the agent.
    type: str
    choices: [monitor, enforce, adaptive]
    default: monitor
  labels:
    description:
      - Dictionary of labels to apply to the agent.
    type: dict
    default: {}
  group_id:
    description:
      - ID of the agent group to assign this agent to.
    type: str
  dpu_offload:
    description:
      - Whether to enable NVIDIA BlueField DPU offload on this agent.
    type: bool
    default: false
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Deploy a Hypershield agent in monitor mode
  stevefulme1.cisco_hypershield.hypershield_agent:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: web-server-agent-01
    host: 10.0.1.50
    state: present
    enforcement_mode: monitor
    labels:
      environment: production
      tier: frontend

- name: Stop an agent for maintenance
  stevefulme1.cisco_hypershield.hypershield_agent:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
    state: stopped

- name: Remove an agent
  stevefulme1.cisco_hypershield.hypershield_agent:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
    state: absent
"""

RETURN = r"""
agent:
  description: The agent object after the operation.
  returned: success, except on delete
  type: dict
  contains:
    id:
      description: Unique agent identifier.
      type: str
    name:
      description: Display name.
      type: str
    host:
      description: Target host address.
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
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def find_agent(api, agent_id=None, name=None, host=None):
    """Find an existing agent by ID, name, or host."""
    if agent_id:
        try:
            return api.get("/agents/{0}".format(agent_id))
        except HypershieldError:
            return None
    if name or host:
        params = {}
        if name:
            params["name"] = name
        if host:
            params["host"] = host
        items = api.list_paginated("/agents", params=params)
        for item in items:
            if (name and item.get("name") == name) or (host and item.get("host") == host):
                return item
    return None


def build_agent_payload(module):
    """Build the API request body from module parameters."""
    payload = {}
    for key in ("name", "host", "version", "enforcement_mode", "labels", "group_id", "dpu_offload"):
        value = module.params.get(key)
        if value is not None:
            payload[key] = value
    return payload


def needs_update(existing, desired):
    """Check whether the existing agent differs from the desired state."""
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
        agent_id=dict(type="str"),
        name=dict(type="str"),
        host=dict(type="str"),
        state=dict(type="str", default="present", choices=["present", "absent", "started", "stopped"]),
        version=dict(type="str"),
        enforcement_mode=dict(type="str", default="monitor", choices=["monitor", "enforce", "adaptive"]),
        labels=dict(type="dict", default={}),
        group_id=dict(type="str"),
        dpu_offload=dict(type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "absent", ["agent_id"]),
            ("state", "started", ["agent_id"]),
            ("state", "stopped", ["agent_id"]),
        ],
    )

    api = HypershieldAPI(module)
    state = module.params["state"]
    result = dict(changed=False)

    try:
        existing = find_agent(api, module.params.get("agent_id"), module.params.get("name"), module.params.get("host"))

        if state == "absent":
            if existing:
                result["changed"] = True
                result["diff"] = dict(before=existing, after={})
                if not module.check_mode:
                    api.delete("/agents/{0}".format(existing["id"]))
            module.exit_json(**result)

        if state in ("started", "stopped"):
            if not existing:
                module.fail_json(msg="Agent {0} not found".format(module.params["agent_id"]))
            desired_status = "running" if state == "started" else "stopped"
            if existing.get("status") != desired_status:
                result["changed"] = True
                if not module.check_mode:
                    action = "start" if state == "started" else "stop"
                    api.post("/agents/{0}/{1}".format(existing["id"], action))
                    existing = api.get("/agents/{0}".format(existing["id"]))
            result["agent"] = existing
            module.exit_json(**result)

        # state == present
        payload = build_agent_payload(module)
        if existing:
            if needs_update(existing, payload):
                result["changed"] = True
                result["diff"] = dict(before=existing, after=payload)
                if not module.check_mode:
                    agent = api.patch("/agents/{0}".format(existing["id"]), data=payload)
                    result["agent"] = agent
                else:
                    result["agent"] = existing
            else:
                result["agent"] = existing
        else:
            if not module.params.get("name"):
                module.fail_json(msg="Parameter 'name' is required when creating a new agent")
            result["changed"] = True
            if not module.check_mode:
                agent = api.post("/agents", data=payload)
                result["agent"] = agent
            else:
                result["agent"] = payload

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
