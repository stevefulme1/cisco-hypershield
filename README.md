# Ansible Collection: stevefulme1.cisco_hypershield

Ansible Collection for Cisco Hypershield distributed security platform. Provides comprehensive automation for Tesseract agent management, microsegmentation policy, exploit protection, DPU security offload, observability, compliance reporting, and Event-Driven Ansible integration.

## Requirements

- **ansible-core** >= 2.16.0
- **Python** >= 3.10
- **Cisco Hypershield** deployment with API access to Security Cloud Control

## Installation

```bash
ansible-galaxy collection install stevefulme1.cisco_hypershield
```

Or from source:

```bash
ansible-galaxy collection install git+https://github.com/stevefulme1/cisco-hypershield.git
```

## Authentication

All modules require connection to the Hypershield Security Cloud Control API:

```yaml
- name: Example with auth parameters
  stevefulme1.cisco_hypershield.hypershield_agent_info:
    api_url: "https://hypershield.example.com/api/v1"
    api_key: "{{ vault_hypershield_api_key }}"
```

Or set environment variables:

```bash
export HYPERSHIELD_API_URL="https://hypershield.example.com/api/v1"
export HYPERSHIELD_API_KEY="your-api-key"
```

## Modules

### Agent Management

| Module | Description |
|--------|-------------|
| `hypershield_agent` | Deploy, configure, and manage Tesseract Security Agent |
| `hypershield_agent_info` | Query agent status, version, and health across fleet |
| `hypershield_agent_upgrade` | Orchestrate agent upgrades with confidence scoring |
| `hypershield_agent_group` | Manage agent groups for policy targeting |
| `hypershield_agent_group_info` | Query agent group membership and configuration |
| `hypershield_agent_label` | Manage labels and tags on agents |
| `hypershield_agent_health_check` | Run health checks and return diagnostics |
| `hypershield_agent_registration` | Register or deregister agents with management plane |
| `hypershield_dpu_config` | Configure NVIDIA BlueField DPU security offload |
| `hypershield_dpu_info` | Query DPU status, firmware, and offload configuration |

### Policy Management

| Module | Description |
|--------|-------------|
| `hypershield_microsegmentation_policy` | CRUD for microsegmentation policies |
| `hypershield_microsegmentation_policy_info` | Query microsegmentation policy state |
| `hypershield_zone_policy` | Manage zone-based firewall policies |
| `hypershield_zone_policy_info` | Query zone policies and membership |
| `hypershield_exploit_protection` | Configure distributed exploit protection rules |
| `hypershield_exploit_protection_info` | Query exploit protection coverage |
| `hypershield_policy_recommendation` | Retrieve AI-recommended policies |
| `hypershield_policy_recommendation_info` | Query recommendation history |
| `hypershield_network_rule` | Manage L3/L4 network access rules |
| `hypershield_network_rule_info` | Query network rules |

### Update Management

| Module | Description |
|--------|-------------|
| `hypershield_update` | Manage self-qualifying security updates |
| `hypershield_update_info` | Query update campaign status and history |
| `hypershield_dual_dataplane` | Configure shadow dataplane for update testing |
| `hypershield_update_confidence` | Query deployment confidence scores |
| `hypershield_update_promote` | Promote updates from shadow to production |

### Observability & Day-2 Operations

| Module | Description |
|--------|-------------|
| `hypershield_telemetry` | Configure telemetry collection and export |
| `hypershield_telemetry_info` | Query telemetry pipeline status |
| `hypershield_splunk_integration` | Set up Splunk telemetry correlation |
| `hypershield_threat_info` | Query detected threats and security events |
| `hypershield_compliance_report` | Generate compliance reports (CIS, NIST, PCI-DSS) |
| `hypershield_backup` | Backup and restore configuration |
| `hypershield_audit_log_info` | Query audit logs for config changes |

## Roles

| Role | Description |
|------|-------------|
| `deploy_agent` | End-to-end Tesseract agent deployment across fleet |
| `dpu_setup` | NVIDIA BlueField DPU security configuration |
| `baseline_policy` | Apply baseline microsegmentation and zone policies |
| `upgrade` | Orchestrated agent upgrade via dual-dataplane |
| `observability` | Complete telemetry and monitoring setup |

## Plugins

### EDA Event Sources

| Plugin | Description |
|--------|-------------|
| `hypershield_events` | Stream Hypershield security events for Event-Driven Ansible |

### EDA Event Filters

| Plugin | Description |
|--------|-------------|
| `severity_filter` | Filter events by severity threshold |

### Filter Plugins

| Plugin | Description |
|--------|-------------|
| `parse_cve` | Parse CVE identifiers from exploit protection data |
| `policy_diff` | Compare two policy states and return differences |

### Inventory Plugins

| Plugin | Description |
|--------|-------------|
| `hypershield_inventory` | Dynamic inventory from Hypershield agent fleet |

## Event-Driven Ansible Integration

The collection includes EDA event sources for real-time security response:

```yaml
- name: Respond to critical threats
  hosts: localhost
  sources:
    - stevefulme1.cisco_hypershield.hypershield_events:
        api_url: "{{ hypershield_api_url }}"
        api_key: "{{ hypershield_api_key }}"
        severity_filter: critical
  rules:
    - name: Auto-shield critical CVEs
      condition: event.threat.severity == "critical"
      action:
        run_playbook:
          name: remediate_threat.yml
```

## Examples

### Deploy agents across a datacenter

```yaml
- name: Deploy Hypershield agents
  hosts: datacenter
  roles:
    - role: stevefulme1.cisco_hypershield.deploy_agent
      vars:
        hypershield_api_url: "{{ vault_api_url }}"
        hypershield_api_key: "{{ vault_api_key }}"
        agent_enforcement_mode: observe
```

### Apply microsegmentation policy

```yaml
- name: Apply zero-trust microsegmentation
  stevefulme1.cisco_hypershield.hypershield_microsegmentation_policy:
    api_url: "{{ hypershield_api_url }}"
    api_key: "{{ hypershield_api_key }}"
    name: "web-tier-isolation"
    description: "Isolate web tier from database tier"
    rules:
      - action: allow
        source_zone: web
        destination_zone: app
        protocols: [tcp]
        ports: [8080, 8443]
      - action: deny
        source_zone: web
        destination_zone: database
    enforcement_mode: enforce
    state: present
```

### Emergency CVE shielding

```yaml
- name: Deploy exploit protection for critical CVE
  stevefulme1.cisco_hypershield.hypershield_exploit_protection:
    api_url: "{{ hypershield_api_url }}"
    api_key: "{{ hypershield_api_key }}"
    cve_id: "CVE-2024-21762"
    action: block
    scope: all_agents
    state: present
```

## License

GPL-3.0-or-later

## Author

Steve Fulmer (sfulmer@redhat.com)
