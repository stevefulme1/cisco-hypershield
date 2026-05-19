# upgrade

Orchestrated Hypershield agent upgrade via dual-dataplane.

## Description

Performs zero-downtime Hypershield agent upgrades using the dual-dataplane architecture. Checks current agent versions, deploys the update to a shadow dataplane, runs validation tests to compute a confidence score, and promotes to production if the confidence threshold is met. Automatically rolls back if validation fails. Supports canary deployments to limit blast radius.

## Requirements

- Ansible >= 2.15
- `stevefulme1.cisco_hypershield` collection
- Hypershield agents deployed and registered
- Dual-dataplane capability enabled in management plane

## Role Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `hypershield_management_plane_url` | `https://hypershield.example.com` | Management plane API URL |
| `hypershield_api_token` | `""` | API authentication token |
| `hypershield_upgrade_target_version` | `""` | Target version (required) |
| `hypershield_confidence_threshold` | `85` | Minimum confidence score to promote (percent) |
| `hypershield_rollback_on_failure` | `true` | Auto-rollback if confidence threshold not met |
| `hypershield_canary_percentage` | `10` | Percentage of agents to upgrade as canary |
| `hypershield_validation_tests_enabled` | `true` | Run validation tests on shadow |
| `hypershield_validation_timeout` | `600` | Validation timeout (seconds) |
| `hypershield_validation_checks` | `[health_check, policy_enforcement, telemetry_flow, connectivity]` | Checks to run |
| `hypershield_auto_promote` | `false` | Auto-promote without confirmation |
| `hypershield_promotion_wait` | `300` | Wait time after canary before full rollout |
| `hypershield_upgrade_agent_group` | `all` | Agent group to upgrade |
| `hypershield_upgrade_exclude_agents` | `[]` | Agents to exclude from upgrade |

## Example Playbook

```yaml
- name: Upgrade Hypershield agents
  hosts: localhost
  roles:
    - role: stevefulme1.cisco_hypershield.upgrade
      vars:
        hypershield_management_plane_url: "https://hypershield.prod.example.com"
        hypershield_api_token: "{{ vault_hypershield_token }}"
        hypershield_upgrade_target_version: "2.1.0"
        hypershield_confidence_threshold: 90
        hypershield_canary_percentage: 5
        hypershield_rollback_on_failure: true
```

## License

GPL-3.0-or-later

## Author

Steve Fulmer
