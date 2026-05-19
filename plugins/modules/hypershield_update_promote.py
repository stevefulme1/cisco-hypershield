# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_update_promote
short_description: Promote tested updates from shadow to production dataplane
description:
  - Promote updates that have been validated in the shadow dataplane to the
    production dataplane.
  - Performs pre-flight checks, prepares rollback snapshots, and executes
    the promotion workflow.
  - Supports confidence score validation before promotion.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  campaign_id:
    description:
      - ID of the update campaign to promote.
    type: str
    required: true
  force:
    description:
      - Force promotion even if confidence threshold is not met.
      - Use with caution in production environments.
    type: bool
    default: false
  pre_flight_checks:
    description:
      - Run pre-flight validation checks before promotion.
    type: bool
    default: true
  create_rollback_snapshot:
    description:
      - Create a configuration snapshot before promotion for rollback.
    type: bool
    default: true
  rollback_timeout:
    description:
      - Time in minutes to keep the rollback snapshot before automatic cleanup.
    type: int
    default: 120
  promotion_scope:
    description:
      - Scope of enforcement points to promote.
    type: str
    choices: [all, zone, group]
    default: all
  scope_filter:
    description:
      - Filter expression when I(promotion_scope) is C(zone) or C(group).
    type: str
  wait:
    description:
      - Wait for promotion to complete before returning.
    type: bool
    default: true
  wait_timeout:
    description:
      - Maximum time in seconds to wait for promotion to complete.
    type: int
    default: 600
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Promote an update campaign to production
  stevefulme1.cisco_hypershield.hypershield_update_promote:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    campaign_id: "camp-abc123"
    pre_flight_checks: true
    create_rollback_snapshot: true
  register: promotion_result

- name: Force promote without waiting
  stevefulme1.cisco_hypershield.hypershield_update_promote:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    campaign_id: "camp-abc123"
    force: true
    wait: false

- name: Promote only DMZ zone
  stevefulme1.cisco_hypershield.hypershield_update_promote:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    campaign_id: "camp-abc123"
    promotion_scope: zone
    scope_filter: "zone=dmz"
    rollback_timeout: 240
"""

RETURN = r"""
promotion:
  description: Promotion operation result.
  returned: success
  type: dict
  contains:
    id:
      description: Promotion operation unique identifier.
      type: str
    campaign_id:
      description: Associated campaign ID.
      type: str
    status:
      description: Promotion status (pending, in_progress, completed, failed, rolled_back).
      type: str
    started_at:
      description: Promotion start timestamp.
      type: str
    completed_at:
      description: Promotion completion timestamp.
      type: str
    enforcement_points_promoted:
      description: Number of enforcement points successfully promoted.
      type: int
    enforcement_points_failed:
      description: Number of enforcement points that failed promotion.
      type: int
pre_flight_results:
  description: Pre-flight check results.
  returned: when I(pre_flight_checks) is true
  type: dict
  contains:
    passed:
      description: Whether all pre-flight checks passed.
      type: bool
    checks:
      description: Individual check results.
      type: list
      elements: dict
rollback_snapshot:
  description: Rollback snapshot details.
  returned: when I(create_rollback_snapshot) is true
  type: dict
  contains:
    snapshot_id:
      description: Snapshot unique identifier.
      type: str
    expires_at:
      description: Snapshot expiration timestamp.
      type: str
"""

import time

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.stevefulme1.cisco_hypershield.plugins.module_utils.hypershield import (
    HypershieldAPI,
    HypershieldError,
)


def wait_for_promotion(api, promotion_id, timeout):
    """Poll promotion status until completed or timeout."""
    start = time.time()
    while time.time() - start < timeout:
        status = api.get("/updates/promotions/{0}".format(promotion_id))
        if status.get("status") in ("completed", "failed", "rolled_back"):
            return status
        time.sleep(10)
    return None


def main():
    argument_spec = dict(
        api_url=dict(type="str", required=True),
        api_key=dict(type="str", required=True, no_log=True),
        validate_certs=dict(type="bool", default=True),
        timeout=dict(type="int", default=30),
        campaign_id=dict(type="str", required=True),
        force=dict(type="bool", default=False),
        pre_flight_checks=dict(type="bool", default=True),
        create_rollback_snapshot=dict(type="bool", default=True),
        rollback_timeout=dict(type="int", default=120),
        promotion_scope=dict(type="str", default="all", choices=["all", "zone", "group"]),
        scope_filter=dict(type="str"),
        wait=dict(type="bool", default=True),
        wait_timeout=dict(type="int", default=600),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api = HypershieldAPI(module)
    campaign_id = module.params["campaign_id"]
    result = dict(changed=False, promotion={})

    try:
        # Check campaign exists and is eligible
        campaign = api.get("/updates/campaigns/{0}".format(campaign_id))
        if campaign.get("status") == "promoted":
            result["promotion"] = {"status": "already_promoted", "campaign_id": campaign_id}
            module.exit_json(**result)

        if module.check_mode:
            result["changed"] = True
            module.exit_json(**result)

        # Pre-flight checks
        if module.params["pre_flight_checks"]:
            preflight = api.post("/updates/campaigns/{0}/preflight".format(campaign_id))
            result["pre_flight_results"] = preflight
            if not preflight.get("passed", False) and not module.params["force"]:
                module.fail_json(
                    msg="Pre-flight checks failed. Use force=true to override.",
                    pre_flight_results=preflight,
                )

        # Create rollback snapshot
        if module.params["create_rollback_snapshot"]:
            snapshot = api.post(
                "/updates/campaigns/{0}/snapshot".format(campaign_id),
                data={"timeout_minutes": module.params["rollback_timeout"]},
            )
            result["rollback_snapshot"] = snapshot

        # Execute promotion
        promote_payload = {
            "force": module.params["force"],
            "scope": module.params["promotion_scope"],
        }
        if module.params.get("scope_filter"):
            promote_payload["scope_filter"] = module.params["scope_filter"]

        promotion = api.post("/updates/campaigns/{0}/promote".format(campaign_id), data=promote_payload)
        result["changed"] = True

        if module.params["wait"] and promotion.get("id"):
            final_status = wait_for_promotion(api, promotion["id"], module.params["wait_timeout"])
            if final_status:
                result["promotion"] = final_status
                if final_status.get("status") == "failed":
                    module.fail_json(msg="Promotion failed", **result)
            else:
                module.fail_json(msg="Promotion timed out after {0}s".format(module.params["wait_timeout"]), **result)
        else:
            result["promotion"] = promotion

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
