# dpu_setup

NVIDIA BlueField DPU security configuration for Cisco Hypershield.

## Description

Configures NVIDIA BlueField DPUs (Data Processing Units) for Hypershield security offload. Validates DPU hardware and firmware compatibility, installs the Hypershield agent on DPU ARM cores, configures security offload policies (microsegmentation, exploit protection, telemetry), collects performance baselines, and verifies offload is active.

## Requirements

- Ansible >= 2.15
- `stevefulme1.cisco_hypershield` collection
- NVIDIA BlueField-2 or BlueField-3 DPU
- DPU firmware >= 24.40
- Root/sudo access on target hosts

## Role Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `hypershield_management_plane_url` | `https://hypershield.example.com` | Management plane API URL |
| `hypershield_api_token` | `""` | API authentication token |
| `hypershield_dpu_device_type` | `bluefield-3` | Expected DPU device type |
| `hypershield_min_firmware_version` | `24.40` | Minimum firmware version |
| `hypershield_offload_mode` | `full` | Offload mode: full, partial, disabled |
| `hypershield_offload_policies` | `[microsegmentation, exploit_protection, telemetry]` | Policies to offload |
| `hypershield_performance_monitoring` | `true` | Enable performance baseline collection |
| `hypershield_performance_baseline_duration` | `300` | Baseline collection duration (seconds) |
| `hypershield_max_cpu_threshold` | `80` | Max DPU CPU usage threshold (percent) |
| `hypershield_max_memory_threshold` | `85` | Max DPU memory usage threshold (percent) |

## Example Playbook

```yaml
- name: Configure DPU security offload
  hosts: dpu_hosts
  become: true
  roles:
    - role: stevefulme1.cisco_hypershield.dpu_setup
      vars:
        hypershield_management_plane_url: "https://hypershield.prod.example.com"
        hypershield_api_token: "{{ vault_hypershield_token }}"
        hypershield_offload_mode: "full"
        hypershield_dpu_device_type: "bluefield-3"
```

## License

GPL-3.0-or-later

## Author

Steve Fulmer
