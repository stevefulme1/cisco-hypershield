# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: hypershield_telemetry_info
short_description: Query Cisco Hypershield telemetry pipeline status and data flow health
description:
  - Retrieve telemetry pipeline status, data flow metrics, and health information.
  - Monitor destination connectivity, throughput, and error rates.
  - This is an info module and makes no changes.
version_added: "1.0.0"
author:
  - Steve Fulmer (@stevefulmer)
options:
  config_name:
    description:
      - Filter results to a specific telemetry configuration by name.
    type: str
  config_id:
    description:
      - Filter results to a specific telemetry configuration by ID.
    type: str
  include_metrics:
    description:
      - Include throughput and volume metrics.
    type: bool
    default: true
  include_destination_health:
    description:
      - Include per-destination health and connectivity status.
    type: bool
    default: true
  include_errors:
    description:
      - Include recent pipeline errors and warnings.
    type: bool
    default: false
  metrics_period:
    description:
      - Time period for metrics aggregation.
    type: str
    choices: [1h, 6h, 24h, 7d, 30d]
    default: 24h
extends_documentation_fragment:
  - stevefulme1.cisco_hypershield.hypershield
"""

EXAMPLES = r"""
- name: Get overall telemetry pipeline health
  stevefulme1.cisco_hypershield.hypershield_telemetry_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
  register: telemetry_health

- name: Get detailed metrics for a specific config
  stevefulme1.cisco_hypershield.hypershield_telemetry_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    config_name: production-telemetry
    include_metrics: true
    include_errors: true
    metrics_period: 7d
  register: telemetry_detail

- name: Check destination health only
  stevefulme1.cisco_hypershield.hypershield_telemetry_info:
    api_url: https://hypershield.example.com
    api_key: "{{ vault_api_key }}"
    include_metrics: false
    include_destination_health: true
  register: dest_health
"""

RETURN = r"""
pipelines:
  description: List of telemetry pipeline statuses.
  returned: always
  type: list
  elements: dict
  contains:
    config_id:
      description: Telemetry configuration ID.
      type: str
    config_name:
      description: Telemetry configuration name.
      type: str
    status:
      description: Pipeline operational status (active, degraded, down).
      type: str
    uptime_seconds:
      description: Pipeline uptime in seconds.
      type: int
metrics:
  description: Throughput and volume metrics.
  returned: when I(include_metrics) is true
  type: dict
  contains:
    events_per_second:
      description: Current events per second throughput.
      type: float
    total_events:
      description: Total events in the metrics period.
      type: int
    total_bytes:
      description: Total data volume in bytes.
      type: int
    dropped_events:
      description: Number of dropped events.
      type: int
destination_health:
  description: Per-destination connectivity and health status.
  returned: when I(include_destination_health) is true
  type: list
  elements: dict
  contains:
    destination:
      description: Destination endpoint.
      type: str
    type:
      description: Destination type.
      type: str
    status:
      description: Connection status (connected, disconnected, error).
      type: str
    last_successful_send:
      description: Timestamp of last successful data send.
      type: str
    error_rate:
      description: Error rate percentage over metrics period.
      type: float
errors:
  description: Recent pipeline errors and warnings.
  returned: when I(include_errors) is true
  type: list
  elements: dict
  contains:
    timestamp:
      description: Error timestamp.
      type: str
    severity:
      description: Error severity (warning, error, critical).
      type: str
    message:
      description: Error message.
      type: str
    destination:
      description: Affected destination if applicable.
      type: str
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
        config_name=dict(type="str"),
        config_id=dict(type="str"),
        include_metrics=dict(type="bool", default=True),
        include_destination_health=dict(type="bool", default=True),
        include_errors=dict(type="bool", default=False),
        metrics_period=dict(type="str", default="24h", choices=["1h", "6h", "24h", "7d", "30d"]),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api = HypershieldAPI(module)
    result = dict(changed=False, pipelines=[])

    try:
        params = {}
        if module.params.get("config_name"):
            params["name"] = module.params["config_name"]

        if module.params.get("config_id"):
            pipeline = api.get("/telemetry/pipelines/{0}/status".format(module.params["config_id"]))
            result["pipelines"] = [pipeline]
        else:
            pipelines = api.list_paginated("/telemetry/pipelines/status", params=params)
            result["pipelines"] = pipelines

        if module.params["include_metrics"]:
            metrics_params = {"period": module.params["metrics_period"]}
            if module.params.get("config_id"):
                metrics_params["config_id"] = module.params["config_id"]
            result["metrics"] = api.get("/telemetry/metrics", params=metrics_params)

        if module.params["include_destination_health"]:
            health_params = {}
            if module.params.get("config_id"):
                health_params["config_id"] = module.params["config_id"]
            destinations = api.get("/telemetry/destinations/health", params=health_params)
            result["destination_health"] = destinations.get("destinations", [])

        if module.params["include_errors"]:
            error_params = {"period": module.params["metrics_period"]}
            if module.params.get("config_id"):
                error_params["config_id"] = module.params["config_id"]
            errors = api.get("/telemetry/errors", params=error_params)
            result["errors"] = errors.get("errors", [])

        module.exit_json(**result)

    except HypershieldError as e:
        api.fail_json_from_error(e)


if __name__ == "__main__":
    main()
