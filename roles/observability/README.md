# observability

Complete telemetry, Splunk integration, and monitoring for Cisco Hypershield.

## Description

Sets up comprehensive observability for a Hypershield deployment. Configures telemetry collection across agents, integrates with Splunk via HTTP Event Collector (HEC), creates alerting rules for security events, enables compliance dashboards for frameworks like PCI-DSS and HIPAA, and verifies the end-to-end data pipeline.

## Requirements

- Ansible >= 2.15
- `stevefulme1.cisco_hypershield` collection
- Hypershield agents deployed and registered
- Splunk instance with HEC enabled (if Splunk integration is used)

## Role Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `hypershield_management_plane_url` | `https://hypershield.example.com` | Management plane API URL |
| `hypershield_api_token` | `""` | API authentication token |
| `hypershield_telemetry_enabled` | `true` | Enable telemetry collection |
| `hypershield_telemetry_interval` | `60` | Collection interval (seconds) |
| `hypershield_telemetry_metrics` | `[agent_health, policy_hits, ...]` | Metrics to collect |
| `hypershield_splunk_enabled` | `true` | Enable Splunk HEC integration |
| `hypershield_splunk_hec_url` | `https://splunk.example.com:8088` | Splunk HEC endpoint |
| `hypershield_splunk_hec_token` | `""` | Splunk HEC authentication token |
| `hypershield_splunk_index` | `hypershield` | Splunk target index |
| `hypershield_splunk_source` | `cisco:hypershield` | Splunk source identifier |
| `hypershield_retention_days` | `90` | Data retention period |
| `hypershield_alerting_enabled` | `true` | Enable alerting rules |
| `hypershield_alert_rules` | `[]` | List of alert rule definitions |
| `hypershield_compliance_dashboards_enabled` | `true` | Enable compliance dashboards |
| `hypershield_compliance_frameworks` | `[pci-dss, hipaa, nist-800-53]` | Compliance frameworks |
| `hypershield_pipeline_buffer_size` | `1000` | Pipeline event buffer size |
| `hypershield_pipeline_flush_interval` | `30` | Pipeline flush interval (seconds) |

## Example Playbook

```yaml
- name: Configure Hypershield observability
  hosts: localhost
  roles:
    - role: stevefulme1.cisco_hypershield.observability
      vars:
        hypershield_management_plane_url: "https://hypershield.prod.example.com"
        hypershield_api_token: "{{ vault_hypershield_token }}"
        hypershield_splunk_hec_url: "https://splunk.prod.example.com:8088"
        hypershield_splunk_hec_token: "{{ vault_splunk_hec_token }}"
        hypershield_splunk_index: "hypershield_prod"
        hypershield_alert_rules:
          - name: agent_down
            condition: "agent_status == 'unhealthy'"
            severity: critical
            threshold_duration: 300
          - name: high_threat_volume
            condition: "threat_count > 100"
            severity: high
            threshold_duration: 60
        hypershield_compliance_frameworks:
          - pci-dss
          - hipaa
```

## License

GPL-3.0-or-later

## Author

Steve Fulmer
