# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_splunk_integration
short_description: Configure Cisco Hypershield Splunk HEC integration
description:
  - Manage Splunk HTTP Event Collector (HEC) integration for Hypershield telemetry.
  - Configure HEC endpoints, index assignments, source types, correlation
    rules, and monitor pipeline health.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  state:
    description:
      - Desired state of the Splunk integration.
    type: str
    choices: [present, absent]
    default: present
  name:
    description:
      - Unique name for this Splunk integration.
    type: str
    required: true
  hec_endpoint:
    description:
      - Splunk HEC endpoint URL.
    type: str
  hec_token:
    description:
      - Splunk HEC authentication token.
    type: str
  index:
    description:
      - Default Splunk index for Hypershield events.
    type: str
    default: hypershield
  source_type:
    description:
      - Splunk source type for events.
    type: str
    default: "cisco:hypershield"
  index_assignments:
    description:
      - Map specific event categories to different Splunk indexes.
    type: dict
    suboptions:
      flow_logs:
        description: Index for flow log events.
        type: str
      security_events:
        description: Index for security events.
        type: str
      audit:
        description: Index for audit log events.
        type: str
      compliance:
        description: Index for compliance events.
        type: str
  tls_enabled:
    description:
      - Enable TLS for HEC connection.
    type: bool
    default: true
  tls_verify:
    description:
      - Verify Splunk server TLS certificate.
    type: bool
    default: true
  batch_size:
    description:
      - Number of events per batch sent to Splunk.
    type: int
    default: 100
  batch_interval:
    description:
      - Maximum interval in seconds between batch sends.
    type: int
    default: 10
  correlation_rules:
    description:
      - List of correlation rule names to enable in Splunk.
    type: list
    elements: str
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Configure Splunk HEC integration
  stevefulme1.cisco_hypershield.hypershield_splunk_integration:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: prod-splunk
    hec_endpoint: https://splunk.example.com:8088
    hec_token: "{{ vault_hec_token }}"
    index: hypershield_prod
    index_assignments:
      flow_logs: netflow
      security_events: security
      audit: audit_trail
    correlation_rules:
      - lateral_movement_detection
      - policy_violation_alert

- name: Remove Splunk integration
  stevefulme1.cisco_hypershield.hypershield_splunk_integration:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    name: prod-splunk
    state: absent
"""

RETURN = r"""
integration:
  description: The Splunk integration configuration.
  returned: success
  type: dict
  contains:
    id:
      description: Integration unique identifier.
      type: str
    name:
      description: Integration name.
      type: str
    hec_endpoint:
      description: Configured HEC endpoint.
      type: str
    index:
      description: Default Splunk index.
      type: str
    source_type:
      description: Configured source type.
      type: str
    status:
      description: Integration connection status.
      type: str
    events_sent_total:
      description: Total events sent since integration creation.
      type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def find_integration(api, name):
    """Find a Splunk integration by name."""
    integrations = api.get("/integrations/splunk", params={"name": name})
    items = integrations.get("items", [])
    return items[0] if items else None


def build_payload(params):
    """Build API payload from module parameters."""
    payload = {
        "name": params["name"],
        "index": params["index"],
        "source_type": params["source_type"],
        "tls_enabled": params["tls_enabled"],
        "tls_verify": params["tls_verify"],
        "batch_size": params["batch_size"],
        "batch_interval": params["batch_interval"],
    }
    if params.get("hec_endpoint"):
        payload["hec_endpoint"] = params["hec_endpoint"]
    if params.get("hec_token"):
        payload["hec_token"] = params["hec_token"]
    if params.get("index_assignments"):
        payload["index_assignments"] = params["index_assignments"]
    if params.get("correlation_rules"):
        payload["correlation_rules"] = params["correlation_rules"]
    return payload


def configs_differ(existing, desired):
    """Check if existing config differs from desired."""
    compare_keys = ("index", "source_type", "tls_enabled", "tls_verify",
                    "batch_size", "batch_interval", "hec_endpoint")
    for key in compare_keys:
        if key in desired and existing.get(key) != desired[key]:
            return True
    if desired.get("index_assignments") and existing.get("index_assignments") != desired["index_assignments"]:
        return True
    existing_rules = sorted(existing.get("correlation_rules", []))
    desired_rules = sorted(desired.get("correlation_rules", []))
    if desired.get("correlation_rules") and existing_rules != desired_rules:
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
        hec_endpoint=dict(type="str"),
        hec_token=dict(type="str", no_log=True),
        index=dict(type="str", default="hypershield"),
        source_type=dict(type="str", default="cisco:hypershield"),
        index_assignments=dict(type="dict"),
        tls_enabled=dict(type="bool", default=True),
        tls_verify=dict(type="bool", default=True),
        batch_size=dict(type="int", default=100),
        batch_interval=dict(type="int", default=10),
        correlation_rules=dict(type="list", elements="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[("state", "present", ("hec_endpoint",), True)],
    )
    api = HypershieldAPI(module)
    state = module.params["state"]
    result = dict(changed=False, integration={})

    try:
        existing = find_integration(api, module.params["name"])

        if state == "absent":
            if existing:
                if not module.check_mode:
                    api.delete("/integrations/splunk/{0}".format(existing["id"]))
                result["changed"] = True
            module.exit_json(**result)

        # state == present
        desired = build_payload(module.params)
        if existing:
            if configs_differ(existing, desired):
                if not module.check_mode:
                    result["integration"] = api.put(
                        "/integrations/splunk/{0}".format(existing["id"]), data=desired
                    )
                result["changed"] = True
            else:
                result["integration"] = existing
        else:
            if not module.check_mode:
                result["integration"] = api.post("/integrations/splunk", data=desired)
            result["changed"] = True

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
