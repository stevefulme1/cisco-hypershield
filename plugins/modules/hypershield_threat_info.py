# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_threat_info
short_description: Query Cisco Hypershield detected threats and security events
description:
  - Retrieve information about detected threats, security events, enforcement
    actions taken, and remediation recommendations.
  - Filter by severity, threat type, time range, and enforcement point.
  - This is an info module and makes no changes.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  threat_id:
    description:
      - Retrieve a specific threat by its unique ID.
    type: str
  severity:
    description:
      - Filter threats by severity level.
    type: str
    choices: [critical, high, medium, low, informational]
  threat_type:
    description:
      - Filter by threat type category.
    type: str
    choices: [exploit, lateral_movement, data_exfiltration, privilege_escalation,
             malware, policy_violation, anomaly]
  status:
    description:
      - Filter by threat status.
    type: str
    choices: [active, mitigated, resolved, investigating]
  enforcement_point:
    description:
      - Filter threats by enforcement point identifier.
    type: str
  zone:
    description:
      - Filter threats by network zone.
    type: str
  since:
    description:
      - Return threats detected after this ISO 8601 timestamp.
    type: str
  until:
    description:
      - Return threats detected before this ISO 8601 timestamp.
    type: str
  include_remediation:
    description:
      - Include remediation recommendations for each threat.
    type: bool
    default: true
  include_enforcement_actions:
    description:
      - Include details of enforcement actions taken.
    type: bool
    default: true
  limit:
    description:
      - Maximum number of threats to return.
    type: int
    default: 50
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Get all active critical threats
  stevefulme1.cisco_hypershield.hypershield_threat_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    severity: critical
    status: active
  register: critical_threats

- name: Get threats from the last 24 hours
  stevefulme1.cisco_hypershield.hypershield_threat_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    since: "2026-05-18T00:00:00Z"
    include_remediation: true
  register: recent_threats

- name: Get lateral movement threats in DMZ
  stevefulme1.cisco_hypershield.hypershield_threat_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    threat_type: lateral_movement
    zone: dmz
  register: lateral_threats

- name: Get specific threat details
  stevefulme1.cisco_hypershield.hypershield_threat_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    threat_id: "threat-abc123"
  register: threat_detail
"""

RETURN = r"""
threats:
  description: List of detected threats matching the query.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: Threat unique identifier.
      type: str
    severity:
      description: Threat severity level.
      type: str
    threat_type:
      description: Threat type category.
      type: str
    status:
      description: Current threat status.
      type: str
    description:
      description: Human-readable threat description.
      type: str
    source:
      description: Source of the threat (IP, process, etc.).
      type: dict
    target:
      description: Target of the threat.
      type: dict
    enforcement_point:
      description: Enforcement point that detected the threat.
      type: str
    zone:
      description: Network zone where threat was detected.
      type: str
    detected_at:
      description: Detection timestamp.
      type: str
    enforcement_actions:
      description: Actions taken to mitigate the threat.
      type: list
      elements: dict
    remediation:
      description: Recommended remediation steps.
      type: list
      elements: str
    cve_ids:
      description: Associated CVE identifiers if applicable.
      type: list
      elements: str
total:
  description: Total number of threats matching the query.
  returned: always
  type: int
summary:
  description: Threat summary by severity.
  returned: always
  type: dict
  contains:
    critical:
      description: Number of critical threats.
      type: int
    high:
      description: Number of high severity threats.
      type: int
    medium:
      description: Number of medium severity threats.
      type: int
    low:
      description: Number of low severity threats.
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
        threat_id=dict(type="str"),
        severity=dict(type="str", choices=["critical", "high", "medium", "low", "informational"]),
        threat_type=dict(
            type="str",
            choices=["exploit", "lateral_movement", "data_exfiltration",
                     "privilege_escalation", "malware", "policy_violation", "anomaly"],
        ),
        status=dict(type="str", choices=["active", "mitigated", "resolved", "investigating"]),
        enforcement_point=dict(type="str"),
        zone=dict(type="str"),
        since=dict(type="str"),
        until=dict(type="str"),
        include_remediation=dict(type="bool", default=True),
        include_enforcement_actions=dict(type="bool", default=True),
        limit=dict(type="int", default=50),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api = HypershieldAPI(module)
    result = dict(changed=False, threats=[], total=0, summary={})

    try:
        if module.params.get("threat_id"):
            threat = api.get("/threats/{0}".format(module.params["threat_id"]))
            if not module.params["include_remediation"]:
                threat.pop("remediation", None)
            if not module.params["include_enforcement_actions"]:
                threat.pop("enforcement_actions", None)
            result["threats"] = [threat]
            result["total"] = 1
        else:
            params = {"limit": module.params["limit"]}
            for key in ("severity", "threat_type", "status", "enforcement_point",
                        "zone", "since", "until"):
                if module.params.get(key):
                    params[key] = module.params[key]
            params["include_remediation"] = module.params["include_remediation"]
            params["include_enforcement_actions"] = module.params["include_enforcement_actions"]

            data = api.get("/threats", params=params)
            result["threats"] = data.get("items", [])
            result["total"] = data.get("total", len(result["threats"]))

        # Build summary
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for threat in result["threats"]:
            sev = threat.get("severity", "informational")
            if sev in summary:
                summary[sev] += 1
        result["summary"] = summary

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
