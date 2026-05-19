# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
name: hypershield_inventory
short_description: Dynamic inventory from Cisco Hypershield agents
version_added: "1.0.0"
description:
  - Queries the Cisco Hypershield management API for registered Tesseract
    Security Agents and builds dynamic inventory groups.
  - Creates groups by platform, agent status, security zone, and agent labels.
  - Each host is added with Hypershield-specific host variables including
    agent ID, version, enforcement mode, and health status.
author:
  - Steve Fulmer (@stevefulmer)
options:
  plugin:
    description:
      - Must be C(stevefulme1.cisco_hypershield.hypershield_inventory).
    required: true
    choices: ['stevefulme1.cisco_hypershield.hypershield_inventory']
    type: str
  api_url:
    description:
      - URL of the Cisco Hypershield management API.
      - Can also be set via the C(HYPERSHIELD_API_URL) environment variable.
    type: str
    required: true
    env:
      - name: HYPERSHIELD_API_URL
  api_key:
    description:
      - API key for authenticating to the Hypershield management plane.
      - Can also be set via the C(HYPERSHIELD_API_KEY) environment variable.
    type: str
    required: true
    env:
      - name: HYPERSHIELD_API_KEY
  validate_certs:
    description:
      - Whether to validate TLS certificates when connecting to the API.
    type: bool
    default: true
  timeout:
    description:
      - Timeout in seconds for API requests.
    type: int
    default: 30
  status_filter:
    description:
      - Only include agents with this status.
      - If not set, all agents are included.
    type: list
    elements: str
    choices: [running, stopped, error, deploying, upgrading, unknown]
  label_prefix:
    description:
      - Prefix to apply when creating groups from agent labels.
      - For example, with prefix C(label_), a label C(env=prod) creates
        group C(label_env_prod).
    type: str
    default: "label_"
  compose:
    description:
      - Create vars from Jinja2 expressions.
    type: dict
    default: {}
  groups:
    description:
      - Add hosts to group based on Jinja2 conditionals.
    type: dict
    default: {}
  keyed_groups:
    description:
      - Add hosts to group based on the values of a variable.
    type: list
    elements: dict
    default: []
  strict:
    description:
      - If true, errors in conditional/expression are fatal.
    type: bool
    default: false
"""

EXAMPLES = r"""
# Minimal inventory config: hypershield.yml
plugin: stevefulme1.cisco_hypershield.hypershield_inventory
api_url: https://hypershield.example.com
api_key: "{{ lookup('env', 'HYPERSHIELD_API_KEY') }}"

# Filter to only running agents and add keyed groups
plugin: stevefulme1.cisco_hypershield.hypershield_inventory
api_url: https://hypershield.example.com
api_key: "{{ lookup('env', 'HYPERSHIELD_API_KEY') }}"
status_filter:
  - running
  - deploying
keyed_groups:
  - key: hypershield_platform
    prefix: platform
  - key: hypershield_zone
    prefix: zone

# With compose variables
plugin: stevefulme1.cisco_hypershield.hypershield_inventory
api_url: https://hypershield.example.com
api_key: "{{ lookup('env', 'HYPERSHIELD_API_KEY') }}"
compose:
  ansible_host: hypershield_host_ip
  agent_healthy: hypershield_status == 'running'
"""

import json

from ansible.errors import AnsibleParserError
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.urls import open_url
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable


class InventoryModule(BaseInventoryPlugin, Constructable):
    """Dynamic inventory plugin for Cisco Hypershield agents."""

    NAME = "stevefulme1.cisco_hypershield.hypershield_inventory"

    def verify_file(self, path):
        """Verify the inventory source is a valid Hypershield config file.

        Args:
            path: Path to the inventory source file.

        Returns:
            True if the file has a .hypershield.yml or .hypershield.yaml extension.
        """
        if super(InventoryModule, self).verify_file(path):
            if path.endswith((".hypershield.yml", ".hypershield.yaml")):
                return True
        return False

    def _build_url(self, base_url, path, params=None):
        """Build a full API URL.

        Args:
            base_url: Base API URL.
            path: API endpoint path.
            params: Optional query parameters.

        Returns:
            Fully qualified URL string.
        """
        url = "{0}/api/v1{1}".format(base_url.rstrip("/"), path)
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                url = "{0}?{1}".format(url, urlencode(filtered))
        return url

    def _fetch_agents(self):
        """Fetch all agents from the Hypershield API with pagination.

        Returns:
            List of agent dicts from the API.

        Raises:
            AnsibleParserError: On API communication failures.
        """
        api_url = self.get_option("api_url")
        api_key = self.get_option("api_key")
        validate_certs = self.get_option("validate_certs")
        timeout = self.get_option("timeout")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": api_key,
        }

        all_agents = []
        offset = 0
        limit = 100

        while True:
            url = self._build_url(api_url, "/agents", {"limit": limit, "offset": offset})
            try:
                response = open_url(
                    url,
                    method="GET",
                    headers=headers,
                    validate_certs=validate_certs,
                    timeout=timeout,
                )
                data = json.loads(response.read())
            except HTTPError as e:
                raise AnsibleParserError(
                    "Hypershield API error ({0}): {1}".format(e.code, e)
                )
            except URLError as e:
                raise AnsibleParserError(
                    "Could not connect to Hypershield API at {0}: {1}".format(api_url, e)
                )
            except (ValueError, TypeError) as e:
                raise AnsibleParserError(
                    "Invalid JSON response from Hypershield API: {0}".format(e)
                )

            items = data.get("items", [])
            all_agents.extend(items)
            total = data.get("total", len(all_agents))
            if len(all_agents) >= total or not items:
                break
            offset += limit

        return all_agents

    def _sanitize_group_name(self, name):
        """Sanitize a string for use as an Ansible group name.

        Args:
            name: Raw group name string.

        Returns:
            Sanitized string safe for Ansible group names.
        """
        import re
        name = str(name).lower().strip()
        name = re.sub(r'[^a-z0-9_]', '_', name)
        name = re.sub(r'_+', '_', name)
        return name.strip('_')

    def _populate(self, agents):
        """Populate inventory from a list of agent dicts.

        Creates groups by platform, status, security zone, and agent labels.
        Adds each agent as a host with Hypershield-specific variables.

        Args:
            agents: List of agent dicts from the API.
        """
        status_filter = self.get_option("status_filter")
        label_prefix = self.get_option("label_prefix")
        strict = self.get_option("strict")

        for agent in agents:
            agent_status = agent.get("status", "unknown")

            # Apply status filter if configured
            if status_filter and agent_status not in status_filter:
                continue

            # Determine hostname: prefer FQDN, fall back to IP, then agent ID
            hostname = (
                agent.get("fqdn")
                or agent.get("host")
                or agent.get("host_ip")
                or agent.get("id", "unknown")
            )
            self.inventory.add_host(hostname)

            # Set host variables with hypershield_ prefix
            host_vars = {
                "hypershield_agent_id": agent.get("id"),
                "hypershield_agent_name": agent.get("name"),
                "hypershield_host_ip": agent.get("host_ip", agent.get("host")),
                "hypershield_fqdn": agent.get("fqdn"),
                "hypershield_status": agent_status,
                "hypershield_platform": agent.get("platform", "unknown"),
                "hypershield_version": agent.get("version"),
                "hypershield_zone": agent.get("security_zone", agent.get("zone", "default")),
                "hypershield_enforcement_mode": agent.get("enforcement_mode"),
                "hypershield_labels": agent.get("labels", {}),
                "hypershield_group_id": agent.get("group_id"),
                "hypershield_last_seen": agent.get("last_seen"),
            }
            for var_name, var_val in host_vars.items():
                self.inventory.set_variable(hostname, var_name, var_val)

            # Group by platform (linux, windows, kubernetes)
            platform = self._sanitize_group_name(agent.get("platform", "unknown"))
            platform_group = "platform_{0}".format(platform)
            self.inventory.add_group(platform_group)
            self.inventory.add_host(hostname, group=platform_group)

            # Group by agent status (active/running, inactive/stopped, degraded/error)
            status_group = "status_{0}".format(self._sanitize_group_name(agent_status))
            self.inventory.add_group(status_group)
            self.inventory.add_host(hostname, group=status_group)

            # Group by security zone
            zone = self._sanitize_group_name(
                agent.get("security_zone", agent.get("zone", "default"))
            )
            zone_group = "zone_{0}".format(zone)
            self.inventory.add_group(zone_group)
            self.inventory.add_host(hostname, group=zone_group)

            # Group by agent labels
            labels = agent.get("labels", {})
            if isinstance(labels, dict):
                for label_key, label_val in labels.items():
                    group_name = "{0}{1}_{2}".format(
                        label_prefix,
                        self._sanitize_group_name(label_key),
                        self._sanitize_group_name(label_val),
                    )
                    self.inventory.add_group(group_name)
                    self.inventory.add_host(hostname, group=group_name)

            # Apply compose, groups, and keyed_groups from Constructable
            self._set_composite_vars(
                self.get_option("compose"), host_vars, hostname, strict=strict
            )
            self._add_host_to_composed_groups(
                self.get_option("groups"), host_vars, hostname, strict=strict
            )
            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"), host_vars, hostname, strict=strict
            )

    def parse(self, inventory, loader, path, cache=True):
        """Parse the inventory source and populate inventory.

        Args:
            inventory: Ansible inventory object to populate.
            loader: Ansible data loader.
            path: Path to the inventory config file.
            cache: Whether to use caching (unused).
        """
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        self._read_config_data(path)
        agents = self._fetch_agents()
        self._populate(agents)
