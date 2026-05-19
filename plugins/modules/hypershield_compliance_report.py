# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_compliance_report
short_description: Generate Cisco Hypershield compliance reports
description:
  - Generate compliance reports against industry frameworks such as CIS,
    NIST, and PCI-DSS.
  - Assess policy compliance, enforcement coverage, and identify gaps.
  - Reports can be generated on demand or retrieved from previously
    generated reports.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  state:
    description:
      - Whether to generate a new report or retrieve an existing one.
    type: str
    choices: [present, absent]
    default: present
  report_name:
    description:
      - Name for the compliance report.
    type: str
    required: true
  framework:
    description:
      - Compliance framework to assess against.
    type: str
    choices: [cis, nist_800_53, nist_csf, pci_dss, soc2, hipaa, iso_27001]
    required: true
  scope:
    description:
      - Scope of the compliance assessment.
    type: str
    choices: [all, zone, group]
    default: all
  scope_filter:
    description:
      - Filter expression when I(scope) is C(zone) or C(group).
    type: str
  include_evidence:
    description:
      - Include detailed evidence for each compliance control.
    type: bool
    default: false
  include_remediation:
    description:
      - Include remediation steps for non-compliant controls.
    type: bool
    default: true
  include_gap_analysis:
    description:
      - Include gap analysis identifying missing controls.
    type: bool
    default: true
  export_format:
    description:
      - Format for the generated report.
    type: str
    choices: [json, pdf, csv]
    default: json
  wait:
    description:
      - Wait for report generation to complete.
    type: bool
    default: true
  wait_timeout:
    description:
      - Maximum time in seconds to wait for report generation.
    type: int
    default: 300
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Generate a PCI-DSS compliance report
  stevefulme1.cisco_hypershield.hypershield_compliance_report:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    report_name: pci-dss-q2-2026
    framework: pci_dss
    include_gap_analysis: true
    include_remediation: true
  register: pci_report

- name: Remove an old report
  stevefulme1.cisco_hypershield.hypershield_compliance_report:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    report_name: pci-dss-q1-2026
    framework: pci_dss
    state: absent
"""

RETURN = r"""
report:
  description: The compliance report object.
  returned: success
  type: dict
  contains:
    id:
      description: Report unique identifier.
      type: str
    name:
      description: Report name.
      type: str
    framework:
      description: Compliance framework assessed.
      type: str
    status:
      description: Report generation status.
      type: str
    overall_score:
      description: Overall compliance score (0-100).
      type: float
    compliant_controls:
      description: Number of compliant controls.
      type: int
    non_compliant_controls:
      description: Number of non-compliant controls.
      type: int
    generated_at:
      description: Report generation timestamp.
      type: str
    download_url:
      description: URL to download the report in requested format.
      type: str
gap_analysis:
  description: Gap analysis identifying missing controls.
  returned: when I(include_gap_analysis) is true
  type: dict
  contains:
    total_gaps:
      description: Total number of compliance gaps.
      type: int
    critical_gaps:
      description: Number of critical compliance gaps.
      type: int
    gaps:
      description: List of identified gaps with details.
      type: list
      elements: dict
"""

import time

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def find_report(api, name, framework):
    """Find a report by name and framework."""
    reports = api.get("/compliance/reports", params={"name": name, "framework": framework})
    items = reports.get("items", [])
    return items[0] if items else None


def wait_for_report(api, report_id, timeout):
    """Poll report status until completed or timeout."""
    start = time.time()
    while time.time() - start < timeout:
        report = api.get("/compliance/reports/{0}".format(report_id))
        if report.get("status") in ("completed", "failed"):
            return report
        time.sleep(10)
    return None


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        report_name=dict(type="str", required=True),
        framework=dict(
            type="str", required=True,
            choices=["cis", "nist_800_53", "nist_csf", "pci_dss", "soc2", "hipaa", "iso_27001"],
        ),
        scope=dict(type="str", default="all", choices=["all", "zone", "group"]),
        scope_filter=dict(type="str"),
        include_evidence=dict(type="bool", default=False),
        include_remediation=dict(type="bool", default=True),
        include_gap_analysis=dict(type="bool", default=True),
        export_format=dict(type="str", default="json", choices=["json", "pdf", "csv"]),
        wait=dict(type="bool", default=True),
        wait_timeout=dict(type="int", default=300),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api = HypershieldAPI(module)
    state = module.params["state"]
    result = dict(changed=False, report={})

    try:
        existing = find_report(api, module.params["report_name"], module.params["framework"])

        if state == "absent":
            if existing:
                if not module.check_mode:
                    api.delete("/compliance/reports/{0}".format(existing["id"]))
                result["changed"] = True
            module.exit_json(**result)

        # state == present
        if module.check_mode:
            result["changed"] = True
            module.exit_json(**result)

        payload = {
            "name": module.params["report_name"],
            "framework": module.params["framework"],
            "scope": module.params["scope"],
            "include_evidence": module.params["include_evidence"],
            "include_remediation": module.params["include_remediation"],
            "include_gap_analysis": module.params["include_gap_analysis"],
            "export_format": module.params["export_format"],
        }
        if module.params.get("scope_filter"):
            payload["scope_filter"] = module.params["scope_filter"]

        report = api.post("/compliance/reports", data=payload)
        result["changed"] = True

        if module.params["wait"] and report.get("id"):
            final = wait_for_report(api, report["id"], module.params["wait_timeout"])
            if final:
                result["report"] = final
                if final.get("status") == "failed":
                    module.fail_json(msg="Report generation failed", **result)
                if module.params["include_gap_analysis"]:
                    gaps = api.get("/compliance/reports/{0}/gaps".format(final["id"]))
                    result["gap_analysis"] = gaps
            else:
                result["msg"] = "Report generation timed out after {0}s".format(module.params["wait_timeout"])
                module.fail_json(**result)
        else:
            result["report"] = report

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
