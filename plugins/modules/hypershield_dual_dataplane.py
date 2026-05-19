# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_dual_dataplane
short_description: Configure Cisco Hypershield shadow dataplane for update testing
description:
  - Manage the dual-dataplane architecture for zero-downtime update validation.
  - Deploy updates to the shadow dataplane, monitor behavior, and manage
    the promotion workflow to production.
  - Supports enabling, disabling, and configuring the shadow dataplane.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  state:
    description:
      - Desired state of the shadow dataplane configuration.
    type: str
    choices: [present, absent]
    default: present
  scope:
    description:
      - Scope of enforcement points for dual-dataplane operation.
    type: str
    choices: [all, zone, group]
    default: all
  scope_filter:
    description:
      - Filter expression when I(scope) is C(zone) or C(group).
    type: str
  shadow_mode:
    description:
      - Operating mode for the shadow dataplane.
    type: str
    choices: [mirror, selective, passive]
    default: mirror
  traffic_percentage:
    description:
      - Percentage of traffic mirrored to the shadow dataplane (0-100).
      - Only applies when I(shadow_mode) is C(selective).
    type: int
    default: 100
  monitoring_duration:
    description:
      - Duration in hours to monitor the shadow dataplane before allowing promotion.
    type: int
    default: 24
  auto_rollback:
    description:
      - Automatically roll back shadow deployment on detected anomalies.
    type: bool
    default: true
  anomaly_threshold:
    description:
      - Number of anomalies that trigger automatic rollback.
    type: int
    default: 5
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Enable shadow dataplane with full mirroring
  stevefulme1.cisco_hypershield.hypershield_dual_dataplane:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    state: present
    shadow_mode: mirror
    monitoring_duration: 48

- name: Enable selective mirroring at 25% traffic
  stevefulme1.cisco_hypershield.hypershield_dual_dataplane:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    state: present
    shadow_mode: selective
    traffic_percentage: 25
    scope: zone
    scope_filter: "zone=dmz"

- name: Disable shadow dataplane
  stevefulme1.cisco_hypershield.hypershield_dual_dataplane:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    state: absent
"""

RETURN = r"""
shadow_dataplane:
  description: Shadow dataplane configuration and status.
  returned: success
  type: dict
  contains:
    enabled:
      description: Whether the shadow dataplane is active.
      type: bool
    shadow_mode:
      description: Current operating mode.
      type: str
    traffic_percentage:
      description: Percentage of traffic being mirrored.
      type: int
    monitoring_duration:
      description: Configured monitoring duration in hours.
      type: int
    status:
      description: Current operational status of the shadow dataplane.
      type: str
    health:
      description: Health status summary.
      type: dict
    enforcement_points:
      description: Number of enforcement points with active shadow dataplanes.
      type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def build_config_payload(params):
    """Build the shadow dataplane configuration payload."""
    payload = {
        "shadow_mode": params["shadow_mode"],
        "traffic_percentage": params["traffic_percentage"],
        "monitoring_duration": params["monitoring_duration"],
        "auto_rollback": params["auto_rollback"],
        "anomaly_threshold": params["anomaly_threshold"],
        "scope": params["scope"],
    }
    if params.get("scope_filter"):
        payload["scope_filter"] = params["scope_filter"]
    return payload


def configs_differ(existing, desired):
    """Check whether existing config differs from desired."""
    for key, value in desired.items():
        if existing.get(key) != value:
            return True
    return False


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        scope=dict(type="str", default="all", choices=["all", "zone", "group"]),
        scope_filter=dict(type="str"),
        shadow_mode=dict(type="str", default="mirror", choices=["mirror", "selective", "passive"]),
        traffic_percentage=dict(type="int", default=100),
        monitoring_duration=dict(type="int", default=24),
        auto_rollback=dict(type="bool", default=True),
        anomaly_threshold=dict(type="int", default=5),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api = HypershieldAPI(module)
    state = module.params["state"]
    result = dict(changed=False, shadow_dataplane={})

    try:
        current = api.get("/dataplane/shadow/config")
        is_enabled = current.get("enabled", False)

        if state == "absent":
            if is_enabled:
                if not module.check_mode:
                    api.post("/dataplane/shadow/disable")
                result["changed"] = True
            module.exit_json(**result)

        # state == present
        desired = build_config_payload(module.params)
        if is_enabled:
            if configs_differ(current, desired):
                if not module.check_mode:
                    result["shadow_dataplane"] = api.put("/dataplane/shadow/config", data=desired)
                result["changed"] = True
            else:
                result["shadow_dataplane"] = current
        else:
            if not module.check_mode:
                api.post("/dataplane/shadow/enable", data=desired)
                result["shadow_dataplane"] = api.get("/dataplane/shadow/config")
            result["changed"] = True

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
