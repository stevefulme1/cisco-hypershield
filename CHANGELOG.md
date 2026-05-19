# Changelog

All notable changes to this collection will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-19

### Added

- Initial release of the `stevefulme1.cisco_hypershield` Ansible collection
- Modules for Cisco Hypershield management:
  - `hypershield_policy` - Manage microsegmentation policies
  - `hypershield_policy_info` - Gather policy information
  - `hypershield_ebpf_program` - Manage eBPF programs
  - `hypershield_ebpf_program_info` - Gather eBPF program information
  - `hypershield_dpu` - Manage DPU configuration
  - `hypershield_dpu_info` - Gather DPU information
  - `hypershield_compliance` - Manage compliance rules
  - `hypershield_compliance_info` - Gather compliance information
  - `hypershield_firewall_rule` - Manage firewall rules
  - `hypershield_firewall_rule_info` - Gather firewall rule information
- Module utilities for API client and common helpers
- Doc fragment for shared authentication parameters
- Filter plugins for policy data transformation
- Inventory plugin for Hypershield-managed hosts
- Event-Driven Ansible (EDA) integration:
  - Event source plugin for Hypershield events
  - Event filter plugin for event processing
- Roles:
  - `deploy` - Deploy Hypershield agents
  - `configure` - Configure Hypershield policies
  - `compliance_scan` - Run compliance scans
- Comprehensive documentation and examples

[1.0.0]: https://github.com/stevefulme1/ansible-hypershield/releases/tag/v1.0.0
