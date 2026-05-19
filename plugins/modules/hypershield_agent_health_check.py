#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_agent_health_check
short_description: Run health checks on Cisco Hypershield agents and return diagnostics
version_added: "1.0.0"
description:
  - Trigger on-demand health checks on one or more Tesseract Security Agents.
  - Returns detailed diagnostic information including connectivity, resource usage, and component status.
  - Can optionally fail the task if any agent reports unhealthy status.
author:
  - Steve Fulmer (@stevefulmer)
options:
  agent_id:
    description:
      - Run a health check on a single agent.
      - Mutually exclusive with I(agent_ids) and I(group_id).
    type: str
  agent_ids:
    description:
      - List of agent IDs to health check.
      - Mutually exclusive with I(agent_id) and I(group_id).
    type: list
    elements: str
  group_id:
    description:
      - Run health checks on all agents in this group.
      - Mutually exclusive with I(agent_id) and I(agent_ids).
    type: str
  checks:
    description:
      - List of specific health check categories to run.
      - If not specified, all checks are run.
    type: list
    elements: str
    choices: [connectivity, resources, components, policies, dpu, certificates, dns]
  fail_on_unhealthy:
    description:
      - Whether to fail the task if any agent reports an unhealthy status.
      - Useful for validation gates in deployment pipelines.
    type: bool
    default: false
  wait:
    description:
      - Whether to wait for all health checks to complete before returning.
    type: bool
    default: true
  wait_timeout:
    description:
      - Maximum time in seconds to wait for health checks to complete.
    type: int
    default: 120
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Run full health check on a single agent
  stevefulme1.cisco_hypershield.hypershield_agent_health_check:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_id: ag-abc123
  register: health

- name: Check connectivity and resources for multiple agents
  stevefulme1.cisco_hypershield.hypershield_agent_health_check:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    agent_ids:
      - ag-abc123
      - ag-def456
    checks:
      - connectivity
      - resources

- name: Validate group health with failure gate
  stevefulme1.cisco_hypershield.hypershield_agent_health_check:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    group_id: grp-web-servers
    fail_on_unhealthy: true
  register: group_health
"""

RETURN = r"""
results:
  description: List of health check results per agent.
  returned: always
  type: list
  elements: dict
  contains:
    agent_id:
      description: Agent identifier.
      type: str
    agent_name:
      description: Agent display name.
      type: str
    overall_status:
      description: Overall health status (healthy, degraded, unhealthy).
      type: str
    checks:
      description: Individual check results.
      type: dict
    diagnostics:
      description: Diagnostic messages and recommendations.
      type: list
      elements: str
    timestamp:
      description: Time the health check was performed (ISO 8601).
      type: str
summary:
  description: Aggregated health summary across all checked agents.
  returned: always
  type: dict
  contains:
    total:
      description: Total agents checked.
      type: int
    healthy:
      description: Number of healthy agents.
      type: int
    degraded:
      description: Number of degraded agents.
      type: int
    unhealthy:
      description: Number of unhealthy agents.
      type: int
"""

import time

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def resolve_agent_ids(api, module):
    """Resolve the list of agent IDs to check."""
    if module.params.get("agent_id"):
        return [module.params["agent_id"]]
    if module.params.get("agent_ids"):
        return module.params["agent_ids"]
    if module.params.get("group_id"):
        members = api.list_paginated(
            "/agent-groups/{0}/members".format(module.params["group_id"])
        )
        return [m["id"] for m in members]
    return []


def run_health_check(api, agent_id, checks, wait, wait_timeout):
    """Trigger and optionally wait for a health check on one agent."""
    payload = {}
    if checks:
        payload["checks"] = checks

    result = api.post("/agents/{0}/health-check".format(agent_id), data=payload)

    if not wait:
        return result

    check_id = result.get("check_id", "")
    deadline = time.time() + wait_timeout
    while time.time() < deadline:
        status = api.get("/agents/{0}/health-check/{1}".format(agent_id, check_id))
        if status.get("status") in ("completed", "failed", "timeout"):
            return status
        time.sleep(5)

    return api.get("/agents/{0}/health-check/{1}".format(agent_id, check_id))


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        agent_id=dict(type="str"),
        agent_ids=dict(type="list", elements="str"),
        group_id=dict(type="str"),
        checks=dict(
            type="list", elements="str",
            choices=["connectivity", "resources", "components", "policies", "dpu", "certificates", "dns"],
        ),
        fail_on_unhealthy=dict(type="bool", default=False),
        wait=dict(type="bool", default=True),
        wait_timeout=dict(type="int", default=120),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("agent_id", "agent_ids", "group_id"),
        ],
        required_one_of=[
            ("agent_id", "agent_ids", "group_id"),
        ],
    )

    api = HypershieldAPI(module)
    checks = module.params.get("checks")
    wait = module.params["wait"]
    wait_timeout = module.params["wait_timeout"]

    try:
        agent_ids = resolve_agent_ids(api, module)
        if not agent_ids:
            module.fail_json(msg="No agents found matching criteria")

        if module.check_mode:
            module.exit_json(
                changed=False,
                results=[{"agent_id": aid, "overall_status": "check_mode"} for aid in agent_ids],
                summary={"total": len(agent_ids), "healthy": 0, "degraded": 0, "unhealthy": 0},
            )

        results = []
        summary = {"total": len(agent_ids), "healthy": 0, "degraded": 0, "unhealthy": 0}

        for aid in agent_ids:
            try:
                check_result = run_health_check(api, aid, checks, wait, wait_timeout)
                overall = check_result.get("overall_status", "unknown")
                if overall == "healthy":
                    summary["healthy"] += 1
                elif overall == "degraded":
                    summary["degraded"] += 1
                else:
                    summary["unhealthy"] += 1
                results.append(check_result)
            except HypershieldError as e:
                summary["unhealthy"] += 1
                results.append({
                    "agent_id": aid,
                    "overall_status": "error",
                    "diagnostics": [e.message],
                })

        if module.params["fail_on_unhealthy"] and summary["unhealthy"] > 0:
            module.fail_json(
                msg="{0} agent(s) reported unhealthy status".format(summary["unhealthy"]),
                results=results,
                summary=summary,
            )

        module.exit_json(changed=False, results=results, summary=summary)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
