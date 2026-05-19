#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent_upgrade
short_description: Orchestrate Cisco Hypershield agent upgrades with confidence scoring
version_added: "1.0.0"
description:
  - Upgrade Tesseract Security Agents to a specified or latest version.
  - Supports staged rollouts with confidence scoring and automatic rollback.
  - Can target individual agents, agent groups, or the entire fleet.
author:
  - Steve Fulmer (@stevefulmer)
options:
  agent_ids:
    description:
      - List of agent IDs to upgrade.
      - Mutually exclusive with I(group_id) and I(all_agents).
    type: list
    elements: str
  group_id:
    description:
      - Upgrade all agents in this group.
      - Mutually exclusive with I(agent_ids) and I(all_agents).
    type: str
  all_agents:
    description:
      - Upgrade all agents in the fleet.
      - Mutually exclusive with I(agent_ids) and I(group_id).
    type: bool
    default: false
  target_version:
    description:
      - Version to upgrade to.
      - If not specified, upgrades to the latest available version.
    type: str
  strategy:
    description:
      - Upgrade rollout strategy.
      - C(immediate) upgrades all targets at once.
      - C(rolling) upgrades in batches with health checks between batches.
      - C(canary) upgrades a small percentage first, then proceeds if healthy.
    type: str
    choices: [immediate, rolling, canary]
    default: rolling
  batch_size:
    description:
      - Number of agents to upgrade per batch when using I(strategy=rolling).
    type: int
    default: 5
  confidence_threshold:
    description:
      - Minimum confidence score (0-100) required to proceed with the upgrade.
      - The API calculates confidence based on agent health and compatibility.
    type: int
    default: 80
  auto_rollback:
    description:
      - Whether to automatically rollback on upgrade failure.
    type: bool
    default: true
  wait:
    description:
      - Whether to wait for the upgrade operation to complete.
    type: bool
    default: true
  wait_timeout:
    description:
      - Maximum time in seconds to wait for upgrade completion.
    type: int
    default: 600
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Upgrade specific agents with rolling strategy
  stevefulme1.cisco_hypershield.hypershield_agent_upgrade:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_ids:
      - ag-abc123
      - ag-def456
    target_version: "2.4.1"
    strategy: rolling
    batch_size: 1

- name: Canary upgrade all agents in a group
  stevefulme1.cisco_hypershield.hypershield_agent_upgrade:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    group_id: grp-web-servers
    strategy: canary
    confidence_threshold: 90

- name: Upgrade entire fleet to latest version
  stevefulme1.cisco_hypershield.hypershield_agent_upgrade:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    all_agents: true
    strategy: rolling
    batch_size: 10
    wait_timeout: 1200
"""

RETURN = r"""
upgrade:
  description: Upgrade operation details.
  returned: success
  type: dict
  contains:
    id:
      description: Upgrade operation ID.
      type: str
    status:
      description: Current upgrade status.
      type: str
    target_version:
      description: Version being upgraded to.
      type: str
    total_agents:
      description: Number of agents targeted.
      type: int
    completed:
      description: Number of agents successfully upgraded.
      type: int
    failed:
      description: Number of agents that failed upgrade.
      type: int
    confidence_score:
      description: Pre-upgrade confidence score.
      type: int
"""

import time

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def build_upgrade_payload(module):
    """Build the upgrade request payload."""
    payload = {
        "strategy": module.params["strategy"],
        "confidence_threshold": module.params["confidence_threshold"],
        "auto_rollback": module.params["auto_rollback"],
    }
    if module.params.get("target_version"):
        payload["target_version"] = module.params["target_version"]
    if module.params.get("agent_ids"):
        payload["agent_ids"] = module.params["agent_ids"]
    elif module.params.get("group_id"):
        payload["group_id"] = module.params["group_id"]
    elif module.params.get("all_agents"):
        payload["scope"] = "all"
    if module.params["strategy"] == "rolling":
        payload["batch_size"] = module.params["batch_size"]
    return payload


def wait_for_upgrade(api, upgrade_id, timeout):
    """Poll upgrade status until completion or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        upgrade = api.get("/upgrades/{0}".format(upgrade_id))
        status = upgrade.get("status", "")
        if status in ("completed", "failed", "rolled_back"):
            return upgrade
        time.sleep(10)
    return api.get("/upgrades/{0}".format(upgrade_id))


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        agent_ids=dict(type="list", elements="str"),
        group_id=dict(type="str"),
        all_agents=dict(type="bool", default=False),
        target_version=dict(type="str"),
        strategy=dict(type="str", default="rolling", choices=["immediate", "rolling", "canary"]),
        batch_size=dict(type="int", default=5),
        confidence_threshold=dict(type="int", default=80),
        auto_rollback=dict(type="bool", default=True),
        wait=dict(type="bool", default=True),
        wait_timeout=dict(type="int", default=600),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("agent_ids", "group_id", "all_agents"),
        ],
        required_one_of=[
            ("agent_ids", "group_id", "all_agents"),
        ],
    )

    api = HypershieldAPI(module)

    try:
        payload = build_upgrade_payload(module)

        # Pre-flight confidence check
        preflight = api.post("/upgrades/preflight", data=payload)
        score = preflight.get("confidence_score", 0)
        if score < module.params["confidence_threshold"]:
            module.fail_json(
                msg="Confidence score {0} is below threshold {1}. Reasons: {2}".format(
                    score, module.params["confidence_threshold"],
                    ", ".join(preflight.get("warnings", ["unknown"]))
                ),
                confidence_score=score,
                preflight=preflight,
            )

        if module.check_mode:
            module.exit_json(
                changed=True,
                upgrade={"status": "preflight_passed", "confidence_score": score},
            )

        upgrade = api.post("/upgrades", data=payload)

        if module.params["wait"]:
            upgrade = wait_for_upgrade(api, upgrade["id"], module.params["wait_timeout"])
            if upgrade.get("status") == "failed":
                module.fail_json(
                    msg="Upgrade {0} failed: {1}".format(
                        upgrade["id"], upgrade.get("error", "unknown error")
                    ),
                    upgrade=upgrade,
                )

        module.exit_json(changed=True, upgrade=upgrade)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
