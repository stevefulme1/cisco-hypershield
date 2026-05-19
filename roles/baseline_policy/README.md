# baseline_policy

Baseline microsegmentation and zone policy configuration for Cisco Hypershield.

## Description

Applies baseline security policies using Hypershield microsegmentation. Discovers existing traffic patterns via discovery mode, reviews AI-generated policy recommendations, applies baseline allow-list policies, creates security zones, configures inter-zone rules, and enables monitoring. Supports observe mode for safe initial deployment.

## Requirements

- Ansible >= 2.15
- `stevefulme1.cisco_hypershield` collection
- Hypershield agents deployed and registered
- API access to Hypershield management plane

## Role Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `hypershield_management_plane_url` | `https://hypershield.example.com` | Management plane API URL |
| `hypershield_api_token` | `""` | API authentication token |
| `hypershield_policy_mode` | `observe` | Policy mode: observe, enforce, disabled |
| `hypershield_auto_approve_high_confidence` | `false` | Auto-approve high-confidence AI recommendations |
| `hypershield_confidence_threshold` | `90` | Minimum confidence score for auto-approve |
| `hypershield_discovery_enabled` | `true` | Enable traffic pattern discovery |
| `hypershield_discovery_duration` | `86400` | Discovery duration in seconds |
| `hypershield_default_policy_action` | `allow` | Default action for new policies |
| `hypershield_policies` | `[]` | List of microsegmentation policies |
| `hypershield_zones` | `[]` | List of security zones |
| `hypershield_inter_zone_default_action` | `deny` | Default inter-zone action |
| `hypershield_inter_zone_rules` | `[]` | List of inter-zone rules |
| `hypershield_policy_monitoring_enabled` | `true` | Enable policy monitoring |

## Example Playbook

```yaml
- name: Apply baseline security policies
  hosts: localhost
  roles:
    - role: stevefulme1.cisco_hypershield.baseline_policy
      vars:
        hypershield_management_plane_url: "https://hypershield.prod.example.com"
        hypershield_api_token: "{{ vault_hypershield_token }}"
        hypershield_policy_mode: "observe"
        hypershield_zones:
          - name: web
            description: "Web tier"
            labels:
              tier: web
          - name: app
            description: "Application tier"
            labels:
              tier: app
          - name: db
            description: "Database tier"
            labels:
              tier: db
        hypershield_inter_zone_rules:
          - source_zone: web
            destination_zone: app
            action: allow
          - source_zone: app
            destination_zone: db
            action: allow
        hypershield_policies:
          - name: web-to-app-http
            source_zone: web
            destination_zone: app
            protocol: tcp
            ports: [8080, 8443]
            action: allow
```

## License

GPL-3.0-or-later

## Author

Steve Fulmer
