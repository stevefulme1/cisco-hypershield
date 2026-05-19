#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent_registration
short_description: Register or deregister Cisco Hypershield agents with the management plane
version_added: "1.0.0"
description:
  - Register new agents with the Hypershield management plane using registration tokens.
  - Deregister agents to remove them from management and revoke their credentials.
  - Manage registration tokens for automated agent enrollment.
  - Supports bulk registration and approval workflows.
author:
  - Steve Fulmer (@stevefulmer)
options:
  state:
    description:
      - Desired registration state.
      - C(registered) ensures the agent is registered and approved.
      - C(deregistered) removes the agent from the management plane.
      - C(pending) places the agent in pending approval state.
      - C(token) creates or retrieves a registration token.
    type: str
    choices: [registered, deregistered, pending, token]
    default: registered
  agent_id:
    description:
      - ID of the agent to register or deregister.
      - Required when I(state) is C(deregistered).
    type: str
  name:
    description:
      - Display name for the agent being registered.
    type: str
  host:
    description:
      - Target host IP or FQDN for the agent.
      - Required when I(state=registered) and the agent is new.
    type: str
  registration_token:
    description:
      - Pre-shared registration token for agent enrollment.
      - If not provided when I(state=registered), a new token is generated.
    type: str
  token_name:
    description:
      - Name for the registration token when I(state=token).
    type: str
  expiry_hours:
    description:
      - How many hours until the registration token expires.
      - Only used when I(state=token).
    type: int
    default: 24
  max_uses:
    description:
      - Maximum number of agents that can register with this token.
      - Set to 0 for unlimited uses.
      - Only used when I(state=token).
    type: int
    default: 1
  auto_approve:
    description:
      - Whether to automatically approve the agent after registration.
      - If false, the agent enters a pending approval state.
    type: bool
    default: true
  labels:
    description:
      - Labels to apply to the agent upon registration.
    type: dict
    default: {}
  group_id:
    description:
      - Agent group to assign the agent to upon registration.
    type: str
  force_deregister:
    description:
      - Force deregistration even if the agent is actively running.
      - Without this, deregistration of running agents is blocked.
    type: bool
    default: false
  cleanup_data:
    description:
      - Whether to delete all agent data (logs, metrics, policies) upon deregistration.
    type: bool
    default: false
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Register a new agent with auto-approval
  stevefulme1.cisco_hypershield.hypershield_agent_registration:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: db-server-agent-01
    host: 10.0.2.10
    state: registered
    labels:
      environment: production
      tier: database
    group_id: grp-databases

- name: Register using an existing token
  stevefulme1.cisco_hypershield.hypershield_agent_registration:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: app-server-agent-03
    host: 10.0.1.30
    registration_token: "{{ registration_token }}"
    state: registered

- name: Create a registration token for bulk enrollment
  stevefulme1.cisco_hypershield.hypershield_agent_registration:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    state: token
    token_name: datacenter-rollout-q3
    expiry_hours: 72
    max_uses: 50
  register: token_result

- name: Deregister an agent and clean up data
  stevefulme1.cisco_hypershield.hypershield_agent_registration:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
    state: deregistered
    force_deregister: true
    cleanup_data: true
"""

RETURN = r"""
agent:
  description: The registered agent object.
  returned: when state is registered or pending
  type: dict
  contains:
    id:
      description: Unique agent identifier assigned upon registration.
      type: str
    name:
      description: Agent display name.
      type: str
    host:
      description: Agent host address.
      type: str
    registration_status:
      description: Current registration status (registered, pending, deregistered).
      type: str
token:
  description: Registration token details.
  returned: when state is token
  type: dict
  contains:
    id:
      description: Token identifier.
      type: str
    name:
      description: Token name.
      type: str
    value:
      description: The token value (only shown once at creation).
      type: str
    expires_at:
      description: Token expiration timestamp (ISO 8601).
      type: str
    max_uses:
      description: Maximum registration uses.
      type: int
    uses_remaining:
      description: Remaining registration uses.
      type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def find_agent_by_host(api, host):
    """Find an agent by its host address."""
    agents = api.list_paginated("/agents", params={"host": host})
    for agent in agents:
        if agent.get("host") == host:
            return agent
    return None


def handle_token_state(api, module):
    """Create or retrieve a registration token."""
    payload = {
        "name": module.params.get("token_name", "ansible-generated"),
        "expiry_hours": module.params["expiry_hours"],
        "max_uses": module.params["max_uses"],
    }
    if module.check_mode:
        return dict(changed=True, token=payload)
    token = api.post("/registration-tokens", data=payload)
    return dict(changed=True, token=token)


def handle_register(api, module):
    """Register a new agent or verify existing registration."""
    host = module.params.get("host")

    existing = None
    if host:
        existing = find_agent_by_host(api, host)
    if existing and existing.get("registration_status") in ("registered", "approved"):
        return dict(changed=False, agent=existing)

    payload = {"auto_approve": module.params["auto_approve"]}
    for key in ("name", "host", "labels", "group_id"):
        value = module.params.get(key)
        if value is not None:
            payload[key] = value
    if module.params.get("registration_token"):
        payload["registration_token"] = module.params["registration_token"]

    if module.check_mode:
        return dict(changed=True, agent=payload)

    agent = api.post("/agents/register", data=payload)
    return dict(changed=True, agent=agent)


def handle_deregister(api, module):
    """Deregister an agent from the management plane."""
    agent_id = module.params["agent_id"]
    try:
        existing = api.get("/agents/{0}".format(agent_id))
    except HypershieldError:
        return dict(changed=False)

    if existing.get("registration_status") == "deregistered":
        return dict(changed=False)

    if existing.get("status") == "running" and not module.params["force_deregister"]:
        module.fail_json(
            msg="Agent {0} is running. Set force_deregister=true to proceed.".format(agent_id)
        )

    if module.check_mode:
        return dict(changed=True, diff=dict(before=existing, after={"registration_status": "deregistered"}))

    payload = {
        "force": module.params["force_deregister"],
        "cleanup_data": module.params["cleanup_data"],
    }
    api.post("/agents/{0}/deregister".format(agent_id), data=payload)
    return dict(changed=True)


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        state=dict(type="str", default="registered", choices=["registered", "deregistered", "pending", "token"]),
        agent_id=dict(type="str"),
        name=dict(type="str"),
        host=dict(type="str"),
        registration_token=dict(type="str", no_log=True),
        token_name=dict(type="str"),
        expiry_hours=dict(type="int", default=24),
        max_uses=dict(type="int", default=1),
        auto_approve=dict(type="bool", default=True),
        labels=dict(type="dict", default={}),
        group_id=dict(type="str"),
        force_deregister=dict(type="bool", default=False),
        cleanup_data=dict(type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "deregistered", ["agent_id"]),
            ("state", "registered", ["host"]),
        ],
    )

    api = HypershieldAPI(module)
    state = module.params["state"]

    try:
        if state == "token":
            result = handle_token_state(api, module)
        elif state in ("registered", "pending"):
            if state == "pending":
                module.params["auto_approve"] = False
            result = handle_register(api, module)
        elif state == "deregistered":
            result = handle_deregister(api, module)
        else:
            module.fail_json(msg="Unexpected state: {0}".format(state))

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
