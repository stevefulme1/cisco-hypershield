# deploy_agent

End-to-end Cisco Hypershield Tesseract agent deployment.

## Description

Handles the complete lifecycle of deploying a Hypershield Tesseract agent: prerequisite validation (kernel version, eBPF support, management plane connectivity), package installation, agent configuration, registration with the management plane, service management, and health verification.

## Requirements

- Ansible >= 2.15
- `stevefulme1.cisco_hypershield` collection
- Linux kernel >= 5.10 with eBPF support
- Network connectivity to Hypershield management plane
- Root/sudo access on target hosts

## Role Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `hypershield_management_plane_url` | `https://hypershield.example.com` | Management plane API URL |
| `hypershield_api_token` | `""` | API authentication token |
| `hypershield_agent_package` | `hypershield-agent` | Agent package name |
| `hypershield_agent_version` | `latest` | Agent package version |
| `hypershield_enforcement_mode` | `observe` | Enforcement mode: observe, enforce, monitor |
| `hypershield_telemetry_enabled` | `true` | Enable telemetry collection |
| `hypershield_telemetry_interval` | `60` | Telemetry reporting interval (seconds) |
| `hypershield_log_level` | `info` | Agent log level |
| `hypershield_agent_group` | `default` | Agent group for registration |
| `hypershield_agent_labels` | `{}` | Labels to apply to the agent |
| `hypershield_auto_register` | `true` | Auto-register with management plane |
| `hypershield_health_check_retries` | `5` | Health check retry count |
| `hypershield_health_check_delay` | `10` | Delay between health check retries (seconds) |

## Example Playbook

```yaml
- name: Deploy Hypershield agents
  hosts: hypershield_nodes
  become: true
  roles:
    - role: stevefulme1.cisco_hypershield.deploy_agent
      vars:
        hypershield_management_plane_url: "https://hypershield.prod.example.com"
        hypershield_api_token: "{{ vault_hypershield_token }}"
        hypershield_enforcement_mode: "observe"
        hypershield_agent_labels:
          environment: production
          datacenter: us-east-1
```

## License

GPL-3.0-or-later

## Author

Steve Fulmer
